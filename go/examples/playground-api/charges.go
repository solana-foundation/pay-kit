package main

// Charge-gated endpoints: TS-reference playground routes, stock data,
// weather, a marketplace purchase with multi-recipient splits, and the
// fortune payment link. The 402 challenge fires before any upstream fetch.

import (
	"fmt"
	"math/rand"
	"net/http"
	"strings"

	"github.com/shopspring/decimal"

	"github.com/solana-foundation/pay-kit/go/paycore"
	"github.com/solana-foundation/pay-kit/go/paykit"
	server "github.com/solana-foundation/pay-kit/go/protocols/mpp/server"
)

// weatherInfo is the canned per-city weather payload.
type weatherInfo struct {
	// Temperature is the air temperature in whole degrees Celsius.
	Temperature int `json:"temperature"`
	// Conditions is the human-readable sky/precipitation label
	// (e.g. "Foggy", "Partly Cloudy").
	Conditions string `json:"conditions"`
	// Humidity is the relative humidity as a whole-number percentage (0-100).
	Humidity int `json:"humidity"`
}

// weatherByCity is the canned weather demo table.
var weatherByCity = map[string]weatherInfo{
	"san-francisco": {Temperature: 15, Conditions: "Foggy", Humidity: 85},
	"new-york":      {Temperature: 22, Conditions: "Partly Cloudy", Humidity: 60},
	"london":        {Temperature: 12, Conditions: "Rainy", Humidity: 90},
	"tokyo":         {Temperature: 26, Conditions: "Sunny", Humidity: 55},
	"paris":         {Temperature: 18, Conditions: "Overcast", Humidity: 70},
	"sydney":        {Temperature: 24, Conditions: "Clear", Humidity: 45},
	"berlin":        {Temperature: 10, Conditions: "Cloudy", Humidity: 75},
	"dubai":         {Temperature: 38, Conditions: "Sunny", Humidity: 30},
}

// product is one marketplace catalog entry.
type product struct {
	// Name is the display title shown in the catalog listing and receipt.
	Name string
	// Price is the seller's list price in USD; the platform and referral
	// basis-point fees are charged on top of it, not carved out of it.
	Price paykit.Price
	// Seller is the base58 wallet address that receives the list price as
	// the charge's primary PayTo recipient.
	Seller string
	// Description is the one-line marketing blurb shown in the listing.
	Description string
}

// products is the canned marketplace catalog.
var products = map[string]product{
	"sol-hoodie": {
		Name:        "Solana Hoodie",
		Price:       paykit.MustParseUSD("2.00"),
		Seller:      "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
		Description: "Premium Solana-branded hoodie",
	},
	"validator-mug": {
		Name:        "Validator Mug",
		Price:       paykit.MustParseUSD("1.00"),
		Seller:      "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
		Description: "Ceramic mug for node operators",
	},
	"nft-sticker-pack": {
		Name:        "NFT Sticker Pack",
		Price:       paykit.MustParseUSD("0.50"),
		Seller:      "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
		Description: "Holographic sticker collection",
	},
}

const (
	platformFeeBps = 500 // 5%
	referralFeeBps = 200 // 2%
)

// fortunes is the canned fortune-cookie pool.
var fortunes = []string{
	"A beautiful, smart, and loving person will be coming into your life.",
	"A faithful friend is a strong defense.",
	"A golden egg of opportunity falls into your lap this month.",
	"All your hard work will soon pay off.",
	"Curiosity kills boredom. Nothing can kill curiosity.",
	"Every day in your life is a special occasion.",
	"Good news will come to you by mail.",
	"If you continually give, you will continually have.",
}

// bps returns the given basis-point percentage of a price, e.g.
// bps(usd 2.00, 500) is usd 0.10.
func bps(p paykit.Price, basisPoints int64) paykit.Price {
	amount := p.Amount().Mul(decimal.NewFromInt(basisPoints)).Div(decimal.NewFromInt(10_000))
	return paykit.MustParseUSD(amount.String())
}

// displayUSD renders a price as the playground's two-decimal USDC label.
func displayUSD(p paykit.Price) string {
	return p.Amount().StringFixed(2) + " USDC"
}

// registerCharges mounts every charge-gated endpoint plus the free
// marketplace catalog.
func registerCharges(mux *http.ServeMux, a *app, client *paykit.Client, dualClient *paykit.Client) error {
	platform := a.recipient

	// logged surfaces the settlement signature once a gated handler runs.
	logged := func(handler http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if payment, ok := paykit.PaymentFrom(r.Context()); ok && payment.Transaction != "" {
				logTx(r.URL.Path, payment.Transaction)
			}
			handler(w, r)
		}
	}

	staticGate := func(amount, name string, describe func(r *http.Request) string) func(*http.Request) (paykit.Gate, error) {
		return func(r *http.Request) (paykit.Gate, error) {
			return paykit.Gate{
				Amount: paykit.MustParseUSD(amount),
				Name:   name,
				Desc:   describe(r),
			}, nil
		}
	}

	// TS-reference fixed charge: clean path, dual-protocol challenge.
	mux.Handle("GET /api/v1/quote/{symbol}",
		dualClient.RequireFunc(staticGate("0.01", "quote", func(r *http.Request) string {
			return "Stock quote: " + r.PathValue("symbol")
		}))(logged(func(w http.ResponseWriter, r *http.Request) {
			symbol := strings.ToUpper(r.PathValue("symbol"))
			via := ""
			if payment, ok := paykit.PaymentFrom(r.Context()); ok {
				via = string(payment.Protocol)
			}
			price := 100
			if symbol != "" {
				price += int(symbol[0]) % 50
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"price":  price,
				"symbol": symbol,
				"via":    via,
			})
		})))

	mux.Handle("GET /api/v1/joke",
		client.Require(paykit.Gate{
			Amount: paykit.MustParseUSD("0.01"),
			Name:   "joke",
			Desc:   "A programmer joke",
		})(logged(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"joke": jokes[rand.Intn(len(jokes))],
			})
		})))

	// Stocks, backed by the same Yahoo Finance endpoints (and response
	// shapes) as the yahoo-finance2 package the TypeScript server uses.
	yahoo := newYahooClient()

	mux.Handle("GET /api/v1/stocks/quote/{symbol}",
		client.RequireFunc(staticGate("0.01", "stockQuote", func(r *http.Request) string {
			return "Stock quote: " + r.PathValue("symbol")
		}))(logged(func(w http.ResponseWriter, r *http.Request) {
			quote, err := yahoo.quote(r.Context(), r.PathValue("symbol"))
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "Failed to fetch quote")
				return
			}
			if quote == nil {
				// Unknown or delisted symbol: an empty 200 body, the way
				// Express serializes res.json(undefined).
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				return
			}
			writeJSON(w, http.StatusOK, quote)
		})))

	mux.Handle("GET /api/v1/stocks/search",
		requireQuery("q", client.RequireFunc(staticGate("0.01", "stockSearch", func(r *http.Request) string {
			return "Stock search: " + r.URL.Query().Get("q")
		}))(logged(func(w http.ResponseWriter, r *http.Request) {
			quotes, err := yahoo.search(r.Context(), r.URL.Query().Get("q"))
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "Failed to search")
				return
			}
			writeJSON(w, http.StatusOK, quotes)
		}))))

	mux.Handle("GET /api/v1/stocks/history/{symbol}",
		client.RequireFunc(staticGate("0.05", "stockHistory", func(r *http.Request) string {
			return "Stock history: " + r.PathValue("symbol")
		}))(logged(func(w http.ResponseWriter, r *http.Request) {
			history, err := yahoo.history(r.Context(), r.PathValue("symbol"), r.URL.Query().Get("range"))
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "Failed to fetch history")
				return
			}
			writeJSON(w, http.StatusOK, history)
		})))

	// Weather: unknown cities 404 before the payment gate.
	mux.Handle("GET /api/v1/weather/{city}", requireKnownCity(
		client.RequireFunc(staticGate("0.01", "weather", func(r *http.Request) string {
			return "Weather for " + r.PathValue("city")
		}))(logged(func(w http.ResponseWriter, r *http.Request) {
			city := r.PathValue("city")
			info := weatherByCity[cityKey(city)]
			writeJSON(w, http.StatusOK, map[string]any{
				"city":        city,
				"temperature": info.Temperature,
				"conditions":  info.Conditions,
				"humidity":    info.Humidity,
			})
		}))))

	// Marketplace: free catalog plus the split purchase.
	mux.HandleFunc("GET /api/v1/marketplace/products", func(w http.ResponseWriter, _ *http.Request) {
		list := []map[string]string{}
		for _, id := range []string{"sol-hoodie", "validator-mug", "nft-sticker-pack"} {
			p := products[id]
			list = append(list, map[string]string{
				"id":          id,
				"name":        p.Name,
				"description": p.Description,
				"price":       displayUSD(p.Price),
				"priceRaw":    p.Price.Amount().Shift(usdcDecimals).Truncate(0).String(),
			})
		}
		writeJSON(w, http.StatusOK, list)
	})

	buyGate := func(r *http.Request) (paykit.Gate, error) {
		p := products[r.PathValue("productId")] // validated before payment, below
		fees := paykit.Fees{paykit.Address(platform): bps(p.Price, platformFeeBps)}
		if referrer := r.URL.Query().Get("referrer"); referrer != "" {
			fees[paykit.Address(referrer)] = bps(p.Price, referralFeeBps)
		}
		return paykit.Gate{
			Amount:   p.Price,
			PayTo:    paykit.Address(p.Seller),
			Name:     "marketplaceBuy",
			Desc:     "Purchase: " + p.Name,
			FeeOnTop: fees,
		}, nil
	}
	mux.Handle("GET /api/v1/marketplace/buy/{productId}", requireKnownProduct(
		client.RequireFunc(buyGate)(logged(func(w http.ResponseWriter, r *http.Request) {
			p := products[r.PathValue("productId")]
			platformFee := bps(p.Price, platformFeeBps)
			total := p.Price.Amount().Add(platformFee.Amount())
			breakdown := map[string]string{
				"seller":      displayUSD(p.Price),
				"platformFee": displayUSD(platformFee),
			}
			if referrer := r.URL.Query().Get("referrer"); referrer != "" {
				referralFee := bps(p.Price, referralFeeBps)
				breakdown["referralFee"] = displayUSD(referralFee)
				total = total.Add(referralFee.Amount())
			}
			breakdown["total"] = total.StringFixed(2) + " USDC"
			writeJSON(w, http.StatusOK, map[string]any{
				"product":   p.Name,
				"breakdown": breakdown,
				"status":    "purchased",
			})
		}))))

	fortuneJSON := dualClient.Require(paykit.Gate{
		Amount: paykit.MustParseUSD("0.01"),
		Name:   "fortune",
		Desc:   "A fortune cookie",
	})(logged(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"fortune": fortunes[rand.Intn(len(fortunes))],
		})
	}))

	// Fortune's API surface follows the TypeScript server (dual x402 exact
	// or MPP charge). Browser payment-link requests still drop to the
	// protocol-layer MPP server so the HTML challenge and service worker flow
	// remain available for the payment-link E2E.
	fortuneMpp, err := server.New(server.Config{
		Recipient:      a.recipient,
		Currency:       paycore.USDCMainnetMint,
		Decimals:       usdcDecimals,
		Network:        a.network,
		RPCURL:         a.rpcURL,
		SecretKey:      a.secretKey,
		HTML:           true,
		FeePayerSigner: a.feePayer,
		RPC:            a.rpcClient,
	})
	if err != nil {
		return fmt.Errorf("fortune mpp server: %w", err)
	}
	fortuneHandler := server.PaymentMiddleware(fortuneMpp, func(*http.Request) (string, server.ChargeOptions, error) {
		return "0.01", server.ChargeOptions{Description: "Open a fortune cookie"}, nil
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fortune := fortunes[rand.Intn(len(fortunes))]
		logPayment(r.URL.Path, w.Header())
		writeJSON(w, http.StatusOK, map[string]string{"fortune": fortune})
	}))
	mux.HandleFunc("GET /api/v1/fortune", func(w http.ResponseWriter, r *http.Request) {
		// The interactive payment page registers its service worker at
		// scope "/" from a script served under /api/v1/fortune, which
		// browsers only allow with this header.
		if server.IsServiceWorkerRequest(r) {
			w.Header().Set("Service-Worker-Allowed", "/")
		}
		if server.IsServiceWorkerRequest(r) || server.AcceptsHTML(r) {
			fortuneHandler.ServeHTTP(w, r)
			return
		}
		fortuneJSON.ServeHTTP(w, r)
	})

	return nil
}

// requireQuery rejects requests missing the given non-empty query parameter
// before the payment gate runs.
func requireQuery(name string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(name) == "" {
			writeJSONError(w, http.StatusBadRequest, "Missing ?"+name+"= parameter")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cityKey normalizes a city path segment onto the weather table key.
func cityKey(city string) string {
	return strings.ReplaceAll(strings.ToLower(city), " ", "-")
}

// requireKnownCity 404s unknown cities before payment.
func requireKnownCity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := weatherByCity[cityKey(r.PathValue("city"))]; !ok {
			writeJSONError(w, http.StatusNotFound,
				"City not found. Available: san-francisco, new-york, london, tokyo, paris, sydney, berlin, dubai")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireKnownProduct 404s unknown products before payment.
func requireKnownProduct(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := products[r.PathValue("productId")]; !ok {
			writeJSONError(w, http.StatusNotFound, "Product not found")
			return
		}
		next.ServeHTTP(w, r)
	})
}

package main

// Charges module mirroring typescript/examples/playground-api/modules/charges.ts:
// stock data, weather, a marketplace purchase with multi-recipient splits
// (all gated through the paykit umbrella client), and the fortune payment
// link served straight from the protocol-layer MPP server with the HTML
// challenge page enabled.
//
// Stock data divergence: the TypeScript example uses the yahoo-finance2
// package; this port calls Yahoo's public chart/search HTTP endpoints with
// plain net/http, so the response field set differs slightly (documented in
// README.md). Payment gating semantics are identical either way: the 402
// challenge fires before any upstream fetch.

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/shopspring/decimal"

	"github.com/solana-foundation/pay-kit/go/paykit"
	server "github.com/solana-foundation/pay-kit/go/protocols/mpp/server"
)

// weatherInfo is the canned per-city weather payload.
type weatherInfo struct {
	Temperature int    `json:"temperature"`
	Conditions  string `json:"conditions"`
	Humidity    int    `json:"humidity"`
}

// weatherByCity mirrors the TypeScript WEATHER table.
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
	Name        string
	Price       paykit.Price
	Seller      string
	Description string
}

// products mirrors the TypeScript PRODUCTS table.
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

// fortunes mirrors the TypeScript FORTUNES table.
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
func registerCharges(mux *http.ServeMux, a *app, client *paykit.Client) error {
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

	// Stocks.
	mux.Handle("GET /api/v1/stocks/quote/{symbol}",
		client.RequireFunc(staticGate("0.01", "stockQuote", func(r *http.Request) string {
			return "Stock quote: " + r.PathValue("symbol")
		}))(logged(func(w http.ResponseWriter, r *http.Request) {
			quote, err := yahooQuote(r.Context(), r.PathValue("symbol"))
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "Failed to fetch quote")
				return
			}
			writeJSON(w, http.StatusOK, quote)
		})))

	mux.Handle("GET /api/v1/stocks/search",
		requireQuery("q", client.RequireFunc(staticGate("0.01", "stockSearch", func(r *http.Request) string {
			return "Stock search: " + r.URL.Query().Get("q")
		}))(logged(func(w http.ResponseWriter, r *http.Request) {
			quotes, err := yahooSearch(r.Context(), r.URL.Query().Get("q"))
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
			history, err := yahooHistory(r.Context(), r.PathValue("symbol"), r.URL.Query().Get("range"))
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "Failed to fetch history")
				return
			}
			writeJSON(w, http.StatusOK, history)
		})))

	// Weather: unknown cities 404 before the payment gate, mirroring the
	// TypeScript middleware order.
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

	// Fortune: a charge payment link with the interactive HTML challenge
	// page. Stays on the protocol layer directly (server.Mpp with HTML
	// enabled) because the paykit dispatcher renders the cross-SDK JSON
	// challenge body; dropping down a layer is the intended escape hatch,
	// same as the TypeScript example.
	fortuneMpp, err := server.New(server.Config{
		Recipient:      a.recipient,
		Currency:       usdcMint,
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
		// browsers only allow with this header (mirrors the TypeScript
		// example stamping it on javascript challenge responses).
		if server.IsServiceWorkerRequest(r) {
			w.Header().Set("Service-Worker-Allowed", "/")
		}
		fortuneHandler.ServeHTTP(w, r)
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
	out := make([]rune, 0, len(city))
	for _, r := range city {
		switch {
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
		case r == ' ':
			out = append(out, '-')
		default:
			out = append(out, r)
		}
	}
	return string(out)
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

// yahooGet fetches a Yahoo Finance public endpoint and decodes the JSON
// response into out.
func yahooGet(ctx context.Context, rawURL string, out any) error {
	callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(callCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "pay-kit-playground/1.0")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("yahoo finance: HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(out)
}

// yahooChart fetches the chart endpoint and returns the first result object.
func yahooChart(ctx context.Context, symbol, chartRange, interval string) (map[string]any, error) {
	chartURL := fmt.Sprintf(
		"https://query1.finance.yahoo.com/v8/finance/chart/%s?range=%s&interval=%s",
		url.PathEscape(symbol), url.QueryEscape(chartRange), url.QueryEscape(interval))
	var body struct {
		Chart struct {
			Result []map[string]any `json:"result"`
			Error  *struct {
				Description string `json:"description"`
			} `json:"error"`
		} `json:"chart"`
	}
	if err := yahooGet(ctx, chartURL, &body); err != nil {
		return nil, err
	}
	if body.Chart.Error != nil {
		return nil, fmt.Errorf("yahoo finance: %s", body.Chart.Error.Description)
	}
	if len(body.Chart.Result) == 0 {
		return nil, fmt.Errorf("yahoo finance: empty chart result")
	}
	return body.Chart.Result[0], nil
}

// yahooQuote returns the live quote metadata for a ticker (the chart
// endpoint's meta object: symbol, regularMarketPrice, currency, ...).
func yahooQuote(ctx context.Context, symbol string) (any, error) {
	result, err := yahooChart(ctx, symbol, "1d", "1d")
	if err != nil {
		return nil, err
	}
	if meta, ok := result["meta"]; ok {
		return meta, nil
	}
	return result, nil
}

// yahooSearch returns the search endpoint's quotes array for a query.
func yahooSearch(ctx context.Context, query string) (any, error) {
	searchURL := "https://query1.finance.yahoo.com/v1/finance/search?q=" + url.QueryEscape(query)
	var body struct {
		Quotes []map[string]any `json:"quotes"`
	}
	if err := yahooGet(ctx, searchURL, &body); err != nil {
		return nil, err
	}
	return body.Quotes, nil
}

// validHistoryRanges mirrors the TypeScript RANGE_TO_DAYS keys.
var validHistoryRanges = map[string]bool{"1d": true, "5d": true, "1mo": true, "3mo": true, "6mo": true, "1y": true}

// yahooHistory returns the full chart result (meta + timestamps + OHLCV
// indicators) for a ticker over the requested range.
func yahooHistory(ctx context.Context, symbol, chartRange string) (any, error) {
	if !validHistoryRanges[chartRange] {
		chartRange = "1mo"
	}
	return yahooChart(ctx, symbol, chartRange, "1d")
}

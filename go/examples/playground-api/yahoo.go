package main

// Yahoo Finance client returning the same JSON shapes as the yahoo-finance2
// npm package (v3), which the playground API contract is defined against:
// the v7 quote endpoint (crumb-authenticated), the v1 search endpoint, and
// the v8 chart endpoint with the package's "array" result layout.
// Epoch-second date fields become ISO-8601 millisecond strings, "low - high"
// range strings become {low, high} objects, and chart indicator columns are
// zipped into per-day quote rows.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// yahooUserAgent is sent on every upstream request; Yahoo rejects the Go
// default agent on the crumb endpoint.
const yahooUserAgent = "Mozilla/5.0 (compatible; pay-kit-playground/1.0)"

// yahooClient calls the public Yahoo Finance endpoints, holding the cookie
// jar and crumb the v7 quote endpoint requires.
type yahooClient struct {
	// httpClient carries the cookie jar shared by the crumb and data calls.
	httpClient *http.Client
	// mu guards crumb.
	mu sync.Mutex
	// crumb is the cached anti-CSRF token for the v7 quote endpoint.
	crumb string
}

// newYahooClient builds a client with a fresh in-memory cookie jar.
func newYahooClient() *yahooClient {
	jar, _ := cookiejar.New(nil)
	return &yahooClient{httpClient: &http.Client{Jar: jar, Timeout: 10 * time.Second}}
}

// get fetches a Yahoo endpoint and returns the raw body for 2xx responses.
func (c *yahooClient) get(ctx context.Context, rawURL string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("User-Agent", yahooUserAgent)
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if response.StatusCode != http.StatusOK {
		return body, response.StatusCode, fmt.Errorf("yahoo finance: HTTP %d", response.StatusCode)
	}
	return body, response.StatusCode, nil
}

// getJSON fetches a Yahoo endpoint and decodes the JSON body. Numbers
// decode to float64, the representation JSON.parse uses, so re-encoding
// renders them identically to yahoo-finance2 output.
func (c *yahooClient) getJSON(ctx context.Context, rawURL string, out any) error {
	body, _, err := c.get(ctx, rawURL)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// getCrumb returns the cached crumb, fetching cookies plus a fresh crumb on
// first use.
func (c *yahooClient) getCrumb(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.crumb != "" {
		return c.crumb, nil
	}
	// Any fc.yahoo.com response sets the session cookie the crumb endpoint
	// checks; the 404 body itself is irrelevant.
	if _, _, err := c.get(ctx, "https://fc.yahoo.com/"); err != nil && !strings.Contains(err.Error(), "HTTP") {
		return "", err
	}
	body, _, err := c.get(ctx, "https://query1.finance.yahoo.com/v1/test/getcrumb")
	if err != nil {
		return "", err
	}
	crumb := strings.TrimSpace(string(body))
	if crumb == "" || strings.Contains(crumb, "Too Many Requests") {
		return "", fmt.Errorf("yahoo finance: could not obtain crumb")
	}
	c.crumb = crumb
	return crumb, nil
}

// invalidateCrumb drops the cached crumb so the next call refreshes it.
func (c *yahooClient) invalidateCrumb() {
	c.mu.Lock()
	c.crumb = ""
	c.mu.Unlock()
}

// quoteDateFields are the v7 quote fields yahoo-finance2 types as Date
// (epoch seconds or date strings upstream, ISO strings in the response).
var quoteDateFields = map[string]bool{
	"dividendDate":               true,
	"earningsTimestamp":          true,
	"earningsTimestampStart":     true,
	"earningsTimestampEnd":       true,
	"earningsCallTimestampStart": true,
	"earningsCallTimestampEnd":   true,
	"expireDate":                 true,
	"expireIsoDate":              true,
	"extendedMarketTime":         true,
	"ipoExpectedDate":            true,
	"nameChangeDate":             true,
	"newListingDate":             true,
	"postMarketTime":             true,
	"preMarketTime":              true,
	"regularMarketTime":          true,
	"startDate":                  true,
}

// quoteDateMsFields are the v7 quote fields typed as millisecond dates.
var quoteDateMsFields = map[string]bool{
	"firstTradeDateMilliseconds": true,
}

// quoteRangeFields are the v7 quote fields delivered as "low - high"
// strings and returned as {low, high} objects.
var quoteRangeFields = map[string]bool{
	"fiftyTwoWeekRange":     true,
	"regularMarketDayRange": true,
}

// searchDateFields are the search-quote fields typed as dates.
var searchDateFields = map[string]bool{
	"newListingDate": true,
	"nameChangeDate": true,
}

// quote returns the first v7 quote for symbol with yahoo-finance2's field
// coercions applied, or nil when the symbol is unknown or delisted.
func (c *yahooClient) quote(ctx context.Context, symbol string) (map[string]any, error) {
	crumb, err := c.getCrumb(ctx)
	if err != nil {
		return nil, err
	}
	quoteURL := "https://query2.finance.yahoo.com/v7/finance/quote?symbols=" +
		url.QueryEscape(symbol) + "&crumb=" + url.QueryEscape(crumb)
	var body struct {
		QuoteResponse struct {
			Result []map[string]any `json:"result"`
			Error  any              `json:"error"`
		} `json:"quoteResponse"`
		Finance struct {
			Error *struct {
				Description string `json:"description"`
			} `json:"error"`
		} `json:"finance"`
	}
	if err := c.getJSON(ctx, quoteURL, &body); err != nil {
		// An expired crumb surfaces as HTTP 401; refresh once and retry.
		c.invalidateCrumb()
		if crumb, err = c.getCrumb(ctx); err != nil {
			return nil, err
		}
		quoteURL = "https://query2.finance.yahoo.com/v7/finance/quote?symbols=" +
			url.QueryEscape(symbol) + "&crumb=" + url.QueryEscape(crumb)
		if err := c.getJSON(ctx, quoteURL, &body); err != nil {
			return nil, err
		}
	}
	if body.Finance.Error != nil {
		return nil, fmt.Errorf("yahoo finance: %s", body.Finance.Error.Description)
	}
	for _, result := range body.QuoteResponse.Result {
		if quoteType, _ := result["quoteType"].(string); quoteType == "NONE" {
			continue
		}
		if err := coerceQuoteFields(result); err != nil {
			return nil, err
		}
		return result, nil
	}
	return nil, nil
}

// search returns the search endpoint's quotes array for query, issuing
// yahoo-finance2's default request parameters so the result list (counts
// included) matches the package's output.
func (c *yahooClient) search(ctx context.Context, query string) ([]map[string]any, error) {
	params := url.Values{
		"q":                          {query},
		"lang":                       {"en-US"},
		"region":                     {"US"},
		"quotesCount":                {"6"},
		"newsCount":                  {"4"},
		"enableFuzzyQuery":           {"false"},
		"quotesQueryId":              {"tss_match_phrase_query"},
		"multiQuoteQueryId":          {"multi_quote_single_token_query"},
		"newsQueryId":                {"news_cie_vespa"},
		"enableCb":                   {"true"},
		"enableNavLinks":             {"true"},
		"enableEnhancedTrivialQuery": {"true"},
	}
	var body struct {
		Quotes []map[string]any `json:"quotes"`
	}
	searchURL := "https://query2.finance.yahoo.com/v1/finance/search?" + params.Encode()
	if err := c.getJSON(ctx, searchURL, &body); err != nil {
		return nil, err
	}
	for _, quote := range body.Quotes {
		for field := range searchDateFields {
			if value, ok := quote[field]; ok {
				coerced, err := coerceDate(value, false)
				if err != nil {
					return nil, err
				}
				quote[field] = coerced
			}
		}
	}
	return body.Quotes, nil
}

// chartRangeDays maps the playground's range parameter onto a day count
// (unknown ranges fall back to 30).
var chartRangeDays = map[string]int{"1d": 1, "5d": 5, "1mo": 30, "3mo": 90, "6mo": 180, "1y": 365}

// chartQuote is one per-day row of the chart "array" layout. Field order
// and nullability match yahoo-finance2's assembled quote objects.
type chartQuote struct {
	// Date is the trading day as an ISO-8601 millisecond string.
	Date string `json:"date"`
	// High is the day's high price, null when Yahoo has no datum.
	High any `json:"high"`
	// Volume is the day's traded volume, null when Yahoo has no datum.
	Volume any `json:"volume"`
	// Open is the day's opening price, null when Yahoo has no datum.
	Open any `json:"open"`
	// Low is the day's low price, null when Yahoo has no datum.
	Low any `json:"low"`
	// Close is the day's closing price, null when Yahoo has no datum.
	Close any `json:"close"`
	// Adjclose is the dividend/split-adjusted close (possibly null),
	// omitted when the upstream response carries no adjclose column.
	Adjclose *any `json:"adjclose,omitempty"`
}

// history returns the v8 chart result for symbol over chartRange in
// yahoo-finance2's default "array" layout: the coerced meta object, the
// indicator columns zipped into per-day quote rows, and dividend/split
// events flattened into arrays.
func (c *yahooClient) history(ctx context.Context, symbol, chartRange string) (map[string]any, error) {
	days, ok := chartRangeDays[chartRange]
	if !ok {
		days = 30
	}
	now := time.Now()
	params := url.Values{
		"useYfid":        {"true"},
		"interval":       {"1d"},
		"includePrePost": {"true"},
		"events":         {"div|split|earn"},
		"lang":           {"en-US"},
		"period1":        {strconv.FormatInt(now.Add(-time.Duration(days)*24*time.Hour).Unix(), 10)},
		"period2":        {strconv.FormatInt(now.Unix(), 10)},
	}
	chartURL := "https://query2.finance.yahoo.com/v8/finance/chart/" +
		url.PathEscape(symbol) + "?" + params.Encode()
	var body struct {
		Chart struct {
			Result []map[string]any `json:"result"`
			Error  *struct {
				Description string `json:"description"`
			} `json:"error"`
		} `json:"chart"`
	}
	if err := c.getJSON(ctx, chartURL, &body); err != nil {
		return nil, err
	}
	if body.Chart.Error != nil {
		return nil, fmt.Errorf("yahoo finance: %s", body.Chart.Error.Description)
	}
	if len(body.Chart.Result) == 0 {
		return nil, fmt.Errorf("yahoo finance: empty chart result")
	}
	return chartToArrayLayout(body.Chart.Result[0])
}

// chartToArrayLayout converts one raw v8 chart result into yahoo-finance2's
// "array" return shape: {meta, quotes[], events?}.
func chartToArrayLayout(result map[string]any) (map[string]any, error) {
	meta, _ := result["meta"].(map[string]any)
	if err := coerceChartMeta(meta); err != nil {
		return nil, err
	}
	out := map[string]any{"meta": meta, "quotes": []chartQuote{}}

	timestamps, _ := result["timestamp"].([]any)
	indicators, _ := result["indicators"].(map[string]any)
	if len(timestamps) > 0 {
		quoteColumns, err := chartIndicatorColumn(indicators, "quote")
		if err != nil {
			return nil, err
		}
		adjcloseColumns, _ := chartIndicatorColumn(indicators, "adjclose")
		var adjclose []any
		if adjcloseColumns != nil {
			adjclose, _ = adjcloseColumns["adjclose"].([]any)
		}
		quotes := make([]chartQuote, len(timestamps))
		for i, timestamp := range timestamps {
			date, err := coerceDate(timestamp, false)
			if err != nil {
				return nil, err
			}
			quotes[i] = chartQuote{
				Date:   date,
				High:   columnValue(quoteColumns, "high", i),
				Volume: columnValue(quoteColumns, "volume", i),
				Open:   columnValue(quoteColumns, "open", i),
				Low:    columnValue(quoteColumns, "low", i),
				Close:  columnValue(quoteColumns, "close", i),
			}
			if adjclose != nil && i < len(adjclose) {
				quotes[i].Adjclose = &adjclose[i]
			}
		}
		out["quotes"] = quotes
	}

	if rawEvents, ok := result["events"].(map[string]any); ok {
		events := map[string]any{}
		for _, kind := range []string{"dividends", "splits"} {
			byTimestamp, ok := rawEvents[kind].(map[string]any)
			if !ok {
				continue
			}
			keys := make([]string, 0, len(byTimestamp))
			for key := range byTimestamp {
				keys = append(keys, key)
			}
			// JS object iteration yields integer-like keys in ascending
			// numeric order; Yahoo keys these maps by epoch seconds.
			sort.Slice(keys, func(i, j int) bool {
				a, _ := strconv.ParseInt(keys[i], 10, 64)
				b, _ := strconv.ParseInt(keys[j], 10, 64)
				return a < b
			})
			items := make([]any, 0, len(keys))
			for _, key := range keys {
				item := byTimestamp[key]
				if event, ok := item.(map[string]any); ok {
					if value, ok := event["date"]; ok {
						date, err := coerceDate(value, false)
						if err != nil {
							return nil, err
						}
						event["date"] = date
					}
				}
				items = append(items, item)
			}
			events[kind] = items
		}
		out["events"] = events
	}
	return out, nil
}

// chartIndicatorColumn returns indicators.<name>[0] as a column map.
func chartIndicatorColumn(indicators map[string]any, name string) (map[string]any, error) {
	rows, ok := indicators[name].([]any)
	if !ok || len(rows) == 0 {
		if name == "quote" {
			return nil, fmt.Errorf("yahoo finance: chart result missing quote indicators")
		}
		return nil, nil
	}
	columns, _ := rows[0].(map[string]any)
	return columns, nil
}

// columnValue returns column[i] or nil when the column is missing/short.
func columnValue(columns map[string]any, name string, i int) any {
	values, _ := columns[name].([]any)
	if i >= len(values) {
		return nil
	}
	return values[i]
}

// chartMetaDateFields are the chart meta fields typed as epoch-second dates.
var chartMetaDateFields = map[string]bool{
	"firstTradeDate":    true,
	"regularMarketTime": true,
}

// coerceChartMeta applies yahoo-finance2's date coercions to the chart meta
// object, including the nested trading-period blocks.
func coerceChartMeta(meta map[string]any) error {
	if meta == nil {
		return nil
	}
	for field := range chartMetaDateFields {
		if value, ok := meta[field]; ok && value != nil {
			coerced, err := coerceDate(value, false)
			if err != nil {
				return err
			}
			meta[field] = coerced
		}
	}
	if current, ok := meta["currentTradingPeriod"].(map[string]any); ok {
		for _, key := range []string{"pre", "regular", "post"} {
			if period, ok := current[key].(map[string]any); ok {
				if err := coerceTradingPeriod(period); err != nil {
					return err
				}
			}
		}
	}
	switch periods := meta["tradingPeriods"].(type) {
	case map[string]any:
		for _, rows := range periods {
			if err := coerceTradingPeriodRows(rows); err != nil {
				return err
			}
		}
	case []any:
		if err := coerceTradingPeriodRows(periods); err != nil {
			return err
		}
	}
	return nil
}

// coerceTradingPeriodRows coerces a [][]tradingPeriod nest.
func coerceTradingPeriodRows(rows any) error {
	outer, ok := rows.([]any)
	if !ok {
		return nil
	}
	for _, inner := range outer {
		periods, ok := inner.([]any)
		if !ok {
			continue
		}
		for _, entry := range periods {
			if period, ok := entry.(map[string]any); ok {
				if err := coerceTradingPeriod(period); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// coerceTradingPeriod coerces one {timezone, start, end, gmtoffset} block.
func coerceTradingPeriod(period map[string]any) error {
	for _, key := range []string{"start", "end"} {
		if value, ok := period[key]; ok && value != nil {
			coerced, err := coerceDate(value, false)
			if err != nil {
				return err
			}
			period[key] = coerced
		}
	}
	return nil
}

// coerceQuoteFields applies the quote schema's date and range coercions to
// one v7 quote result in place.
func coerceQuoteFields(result map[string]any) error {
	for field, value := range result {
		switch {
		case quoteDateFields[field]:
			coerced, err := coerceDate(value, false)
			if err != nil {
				return err
			}
			result[field] = coerced
		case quoteDateMsFields[field]:
			coerced, err := coerceDate(value, true)
			if err != nil {
				return err
			}
			result[field] = coerced
		case quoteRangeFields[field]:
			coerced, err := coerceRange(value)
			if err != nil {
				return err
			}
			result[field] = coerced
		}
	}
	return nil
}

// isoDatePattern matches the bare "YYYY-MM-DD" date strings Yahoo uses for
// listing-change fields.
var isoDatePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// isoDateTimePattern matches full ISO-8601 timestamps with optional
// milliseconds.
var isoDateTimePattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$`)

// coerceDate converts a Yahoo date value (epoch number, {raw} wrapper, or
// date string) into the ISO-8601 millisecond string a serialized JS Date
// produces. inMilliseconds flags fields already scaled to milliseconds.
func coerceDate(value any, inMilliseconds bool) (string, error) {
	switch v := value.(type) {
	case float64:
		if !inMilliseconds {
			v *= 1000
		}
		return formatJSDate(int64(v)), nil
	case map[string]any:
		if raw, ok := v["raw"].(float64); ok {
			return formatJSDate(int64(raw * 1000)), nil
		}
	case string:
		if isoDatePattern.MatchString(v) {
			t, err := time.Parse("2006-01-02", v)
			if err == nil {
				return formatJSDate(t.UnixMilli()), nil
			}
		}
		if isoDateTimePattern.MatchString(v) {
			t, err := time.Parse(time.RFC3339, v)
			if err == nil {
				return formatJSDate(t.UnixMilli()), nil
			}
		}
	}
	return "", fmt.Errorf("yahoo finance: unexpected date value %v", value)
}

// formatJSDate renders epoch milliseconds the way Date.prototype.toJSON
// does: UTC with exactly three fractional digits.
func formatJSDate(unixMilli int64) string {
	return time.UnixMilli(unixMilli).UTC().Format("2006-01-02T15:04:05.000Z")
}

// coerceRange converts a "low - high" string into the {low, high} object
// yahoo-finance2 returns; pre-shaped objects pass through.
func coerceRange(value any) (any, error) {
	switch v := value.(type) {
	case map[string]any:
		return v, nil
	case string:
		parts := strings.SplitN(v, "-", 2)
		if len(parts) == 2 {
			low, errLow := parseFloatPrefix(parts[0])
			high, errHigh := parseFloatPrefix(parts[1])
			if errLow == nil && errHigh == nil {
				return map[string]float64{"low": low, "high": high}, nil
			}
		}
	}
	return nil, fmt.Errorf("yahoo finance: unexpected range value %v", value)
}

// parseFloatPrefix parses a float like JS parseFloat: surrounding
// whitespace is ignored.
func parseFloatPrefix(s string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(f) {
		return 0, fmt.Errorf("not a number: %q", s)
	}
	return f, nil
}

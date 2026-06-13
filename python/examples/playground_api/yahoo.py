# examples/playground_api/yahoo.py
"""Yahoo Finance client returning the same JSON shapes as the yahoo-finance2
npm package (v3), which the playground API contract is defined against: the v7
quote endpoint (crumb-authenticated), the v1 search endpoint, and the v8 chart
endpoint with the package's "array" result layout.

Epoch-second date fields become ISO-8601 millisecond strings, "low - high"
range strings become {low, high} objects, and chart indicator columns are
zipped into per-day quote rows. Mirrors the Go example's ``yahoo.go``.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote as url_quote

import httpx

# Sent on every upstream request; Yahoo rejects the default agent on the crumb
# endpoint.
_USER_AGENT = "Mozilla/5.0 (compatible; pay-kit-playground/1.0)"

# v7 quote fields yahoo-finance2 types as Date (epoch seconds or date strings
# upstream, ISO strings in the response).
_QUOTE_DATE_FIELDS = frozenset(
    {
        "dividendDate",
        "earningsTimestamp",
        "earningsTimestampStart",
        "earningsTimestampEnd",
        "earningsCallTimestampStart",
        "earningsCallTimestampEnd",
        "expireDate",
        "expireIsoDate",
        "extendedMarketTime",
        "ipoExpectedDate",
        "nameChangeDate",
        "newListingDate",
        "postMarketTime",
        "preMarketTime",
        "regularMarketTime",
        "startDate",
    }
)

# v7 quote fields typed as millisecond dates.
_QUOTE_DATE_MS_FIELDS = frozenset({"firstTradeDateMilliseconds"})

# v7 quote fields delivered as "low - high" strings and returned as
# {low, high} objects.
_QUOTE_RANGE_FIELDS = frozenset({"fiftyTwoWeekRange", "regularMarketDayRange"})

# search-quote fields typed as dates.
_SEARCH_DATE_FIELDS = frozenset({"newListingDate", "nameChangeDate"})

# chart meta fields typed as epoch-second dates.
_CHART_META_DATE_FIELDS = frozenset({"firstTradeDate", "regularMarketTime"})

# maps the playground's range parameter onto a day count (unknown ranges fall
# back to 30).
_CHART_RANGE_DAYS = {"1d": 1, "5d": 5, "1mo": 30, "3mo": 90, "6mo": 180, "1y": 365}

_ISO_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_ISO_DATETIME_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$")


class YahooError(Exception):
    """An upstream Yahoo Finance failure (HTTP, decode, or schema)."""


class YahooClient:
    """Calls the public Yahoo Finance endpoints, holding the cookie jar and
    crumb the v7 quote endpoint requires.
    """

    def __init__(self) -> None:
        # A shared cookie jar (httpx persists Set-Cookie across requests on one
        # client) backs the crumb and data calls.
        self._client = httpx.AsyncClient(
            timeout=10.0,
            headers={"User-Agent": _USER_AGENT},
            follow_redirects=True,
        )
        self._crumb: str | None = None
        self._crumb_lock = asyncio.Lock()

    async def aclose(self) -> None:
        """Close the underlying HTTP client (the shutdown hook calls this)."""
        await self._client.aclose()

    async def _get(self, url: str) -> tuple[bytes, int]:
        """Fetch a Yahoo endpoint and return (body, status); raise on non-2xx."""
        response = await self._client.get(url)
        body = response.content
        if response.status_code != 200:
            raise YahooError(f"yahoo finance: HTTP {response.status_code}")
        return body, response.status_code

    async def _get_json(self, url: str) -> Any:
        """Fetch a Yahoo endpoint and decode the JSON body."""
        body, _ = await self._get(url)
        import json

        return json.loads(body)

    async def _get_crumb(self) -> str:
        """Return the cached crumb, fetching cookies plus a fresh crumb on first
        use.
        """
        async with self._crumb_lock:
            if self._crumb:
                return self._crumb
            # Any fc.yahoo.com response sets the session cookie the crumb
            # endpoint checks; the 404 body itself is irrelevant, and an HTTP
            # error here is expected (the cookie is the point).
            with contextlib.suppress(YahooError):
                await self._get("https://fc.yahoo.com/")
            body, _ = await self._get("https://query1.finance.yahoo.com/v1/test/getcrumb")
            crumb = body.decode("utf-8").strip()
            if not crumb or "Too Many Requests" in crumb:
                raise YahooError("yahoo finance: could not obtain crumb")
            self._crumb = crumb
            return crumb

    def _invalidate_crumb(self) -> None:
        """Drop the cached crumb so the next call refreshes it."""
        self._crumb = None

    async def quote(self, symbol: str) -> dict[str, Any] | None:
        """Return the first v7 quote for ``symbol`` with yahoo-finance2's field
        coercions applied, or ``None`` when the symbol is unknown or delisted.
        """
        crumb = await self._get_crumb()
        quote_url = (
            "https://query2.finance.yahoo.com/v7/finance/quote?symbols="
            + url_quote(symbol)
            + "&crumb="
            + url_quote(crumb)
        )
        try:
            body = await self._get_json(quote_url)
        except YahooError:
            # An expired crumb surfaces as HTTP 401; refresh once and retry.
            self._invalidate_crumb()
            crumb = await self._get_crumb()
            quote_url = (
                "https://query2.finance.yahoo.com/v7/finance/quote?symbols="
                + url_quote(symbol)
                + "&crumb="
                + url_quote(crumb)
            )
            body = await self._get_json(quote_url)

        finance_error = (body.get("finance") or {}).get("error") if isinstance(body, dict) else None
        if isinstance(finance_error, dict) and finance_error.get("description"):
            raise YahooError(f"yahoo finance: {finance_error['description']}")

        results = ((body.get("quoteResponse") or {}).get("result") or []) if isinstance(body, dict) else []
        for result in results:
            if not isinstance(result, dict):
                continue
            if result.get("quoteType") == "NONE":
                continue
            _coerce_quote_fields(result)
            return result
        return None

    async def search(self, query: str) -> list[dict[str, Any]]:
        """Return the search endpoint's quotes array for ``query``, issuing
        yahoo-finance2's default request parameters so the result list matches
        the package's output.
        """
        params = {
            "q": query,
            "lang": "en-US",
            "region": "US",
            "quotesCount": "6",
            "newsCount": "4",
            "enableFuzzyQuery": "false",
            "quotesQueryId": "tss_match_phrase_query",
            "multiQuoteQueryId": "multi_quote_single_token_query",
            "newsQueryId": "news_cie_vespa",
            "enableCb": "true",
            "enableNavLinks": "true",
            "enableEnhancedTrivialQuery": "true",
        }
        query_string = "&".join(f"{k}={url_quote(v)}" for k, v in params.items())
        search_url = "https://query2.finance.yahoo.com/v1/finance/search?" + query_string
        body = await self._get_json(search_url)
        quotes = body.get("quotes") or [] if isinstance(body, dict) else []
        for quote in quotes:
            if not isinstance(quote, dict):
                continue
            for field in _SEARCH_DATE_FIELDS:
                if field in quote:
                    quote[field] = _coerce_date(quote[field], in_milliseconds=False)
        return quotes

    async def history(self, symbol: str, chart_range: str) -> dict[str, Any]:
        """Return the v8 chart result for ``symbol`` over ``chart_range`` in
        yahoo-finance2's default "array" layout: the coerced meta object, the
        indicator columns zipped into per-day quote rows, and dividend/split
        events flattened into arrays.
        """
        days = _CHART_RANGE_DAYS.get(chart_range, 30)
        now = int(datetime.now(tz=UTC).timestamp())
        period1 = now - days * 24 * 60 * 60
        params = {
            "useYfid": "true",
            "interval": "1d",
            "includePrePost": "true",
            "events": "div|split|earn",
            "lang": "en-US",
            "period1": str(period1),
            "period2": str(now),
        }
        query_string = "&".join(f"{k}={url_quote(v)}" for k, v in params.items())
        chart_url = (
            "https://query2.finance.yahoo.com/v8/finance/chart/" + url_quote(symbol, safe="") + "?" + query_string
        )
        body = await self._get_json(chart_url)
        chart = body.get("chart") or {} if isinstance(body, dict) else {}
        chart_error = chart.get("error")
        if isinstance(chart_error, dict) and chart_error.get("description"):
            raise YahooError(f"yahoo finance: {chart_error['description']}")
        results = chart.get("result") or []
        if not results:
            raise YahooError("yahoo finance: empty chart result")
        return _chart_to_array_layout(results[0])


def _chart_to_array_layout(result: dict[str, Any]) -> dict[str, Any]:
    """Convert one raw v8 chart result into yahoo-finance2's "array" return
    shape: {meta, quotes[], events?}.
    """
    meta = result.get("meta") if isinstance(result.get("meta"), dict) else {}
    _coerce_chart_meta(meta)
    out: dict[str, Any] = {"meta": meta, "quotes": []}

    timestamps = result.get("timestamp") or []
    indicators = result.get("indicators") if isinstance(result.get("indicators"), dict) else {}
    if timestamps:
        quote_columns = _chart_indicator_column(indicators, "quote")
        adjclose_columns = _chart_indicator_column(indicators, "adjclose")
        adjclose = adjclose_columns.get("adjclose") if adjclose_columns else None

        quotes: list[dict[str, Any]] = []
        for i, timestamp in enumerate(timestamps):
            row: dict[str, Any] = {
                "date": _coerce_date(timestamp, in_milliseconds=False),
                "high": _column_value(quote_columns, "high", i),
                "volume": _column_value(quote_columns, "volume", i),
                "open": _column_value(quote_columns, "open", i),
                "low": _column_value(quote_columns, "low", i),
                "close": _column_value(quote_columns, "close", i),
            }
            if adjclose is not None and i < len(adjclose):
                row["adjclose"] = adjclose[i]
            quotes.append(row)
        out["quotes"] = quotes

    raw_events = result.get("events")
    if isinstance(raw_events, dict):
        events: dict[str, Any] = {}
        for kind in ("dividends", "splits"):
            by_timestamp = raw_events.get(kind)
            if not isinstance(by_timestamp, dict):
                continue
            # JS object iteration yields integer-like keys in ascending numeric
            # order; Yahoo keys these maps by epoch seconds.
            keys = sorted(by_timestamp.keys(), key=lambda k: int(k))
            items: list[Any] = []
            for key in keys:
                item = by_timestamp[key]
                if isinstance(item, dict) and "date" in item:
                    item["date"] = _coerce_date(item["date"], in_milliseconds=False)
                items.append(item)
            events[kind] = items
        out["events"] = events
    return out


def _chart_indicator_column(indicators: dict[str, Any], name: str) -> dict[str, Any] | None:
    """Return indicators.<name>[0] as a column map."""
    rows = indicators.get(name) if isinstance(indicators, dict) else None
    if not isinstance(rows, list) or not rows:
        if name == "quote":
            raise YahooError("yahoo finance: chart result missing quote indicators")
        return None
    columns = rows[0]
    return columns if isinstance(columns, dict) else {}


def _column_value(columns: dict[str, Any] | None, name: str, i: int) -> Any:
    """Return column[i] or None when the column is missing/short."""
    if not columns:
        return None
    values = columns.get(name)
    if not isinstance(values, list) or i >= len(values):
        return None
    return values[i]


def _coerce_chart_meta(meta: dict[str, Any]) -> None:
    """Apply yahoo-finance2's date coercions to the chart meta object,
    including the nested trading-period blocks.
    """
    if not meta:
        return
    for field in _CHART_META_DATE_FIELDS:
        value = meta.get(field)
        if value is not None and field in meta:
            meta[field] = _coerce_date(value, in_milliseconds=False)

    current = meta.get("currentTradingPeriod")
    if isinstance(current, dict):
        for key in ("pre", "regular", "post"):
            period = current.get(key)
            if isinstance(period, dict):
                _coerce_trading_period(period)

    periods = meta.get("tradingPeriods")
    if isinstance(periods, dict):
        for rows in periods.values():
            _coerce_trading_period_rows(rows)
    elif isinstance(periods, list):
        _coerce_trading_period_rows(periods)


def _coerce_trading_period_rows(rows: Any) -> None:
    """Coerce a [[tradingPeriod]] nest."""
    if not isinstance(rows, list):
        return
    for inner in rows:
        if not isinstance(inner, list):
            continue
        for entry in inner:
            if isinstance(entry, dict):
                _coerce_trading_period(entry)


def _coerce_trading_period(period: dict[str, Any]) -> None:
    """Coerce one {timezone, start, end, gmtoffset} block."""
    for key in ("start", "end"):
        value = period.get(key)
        if value is not None and key in period:
            period[key] = _coerce_date(value, in_milliseconds=False)


def _coerce_quote_fields(result: dict[str, Any]) -> None:
    """Apply the quote schema's date and range coercions to one v7 quote result
    in place.
    """
    for field, value in list(result.items()):
        if field in _QUOTE_DATE_FIELDS:
            result[field] = _coerce_date(value, in_milliseconds=False)
        elif field in _QUOTE_DATE_MS_FIELDS:
            result[field] = _coerce_date(value, in_milliseconds=True)
        elif field in _QUOTE_RANGE_FIELDS:
            result[field] = _coerce_range(value)


def _coerce_date(value: Any, *, in_milliseconds: bool) -> str:
    """Convert a Yahoo date value (epoch number, {raw} wrapper, or date string)
    into the ISO-8601 millisecond string a serialized JS Date produces.
    ``in_milliseconds`` flags fields already scaled to milliseconds.
    """
    if isinstance(value, bool):
        # bool is an int subclass in Python; reject it before the numeric arm.
        raise YahooError(f"yahoo finance: unexpected date value {value!r}")
    if isinstance(value, (int, float)):
        millis = value if in_milliseconds else value * 1000
        return _format_js_date(int(millis))
    if isinstance(value, dict):
        raw = value.get("raw")
        if isinstance(raw, (int, float)) and not isinstance(raw, bool):
            return _format_js_date(int(raw * 1000))
    if isinstance(value, str):
        if _ISO_DATE_PATTERN.match(value):
            dt = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
            return _format_js_date(int(dt.timestamp() * 1000))
        if _ISO_DATETIME_PATTERN.match(value):
            normalized = value.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            return _format_js_date(int(dt.timestamp() * 1000))
    raise YahooError(f"yahoo finance: unexpected date value {value!r}")


def _format_js_date(unix_milli: int) -> str:
    """Render epoch milliseconds the way Date.prototype.toJSON does: UTC with
    exactly three fractional digits.
    """
    dt = datetime.fromtimestamp(unix_milli / 1000, tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{unix_milli % 1000:03d}Z"


def _coerce_range(value: Any) -> Any:
    """Convert a "low - high" string into the {low, high} object yahoo-finance2
    returns; pre-shaped objects pass through.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parts = value.split("-", 1)
        if len(parts) == 2:
            low = _parse_float_prefix(parts[0])
            high = _parse_float_prefix(parts[1])
            if low is not None and high is not None:
                return {"low": low, "high": high}
    raise YahooError(f"yahoo finance: unexpected range value {value!r}")


def _parse_float_prefix(text: str) -> float | None:
    """Parse a float like JS parseFloat: surrounding whitespace is ignored."""
    try:
        result = float(text.strip())
    except ValueError:
        return None
    if math.isnan(result):
        return None
    return result

# Simple server

The smallest pay-kit server: one gated endpoint, plain Rack, no
framework. It gates `/` on a `$0.10` charge and serves `/health`
unpaid. Both x402 and MPP gate the same route; the merchant does not
care which protocol settled the request.

## Run it

```sh
bundle install
rackup        # serves on http://127.0.0.1:9292
```

`app.rb` boots with sensible defaults (demo keypair recipient, localnet
network, a fixed demo challenge secret), so there is nothing to
configure to see a 402.

## Drive it

Unpaid request returns `402` with the x402 `PAYMENT-REQUIRED` header and
the MPP `WWW-Authenticate` challenge:

```sh
curl -i http://127.0.0.1:9292/
```

Paid request returns `200`. Drive the client from `pay curl` or one of
the Rust / TS / Go / Python client SDKs:

```sh
pay curl http://127.0.0.1:9292/
```

Ruby ships server support only, so there is no Ruby client to build the
payment.

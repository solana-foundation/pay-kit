# simple-server

The smallest pay_kit server: Python's standard-library `http.server` with one
gated endpoint, driven through the unified `pay_kit` umbrella surface. No web
framework, no wallet setup.

## Run

```sh
pip install -e .
python examples/simple-server/server.py
```

## Drive it

```sh
curl -i http://127.0.0.1:8000/report     # 402 payment required
pay curl http://127.0.0.1:8000/report    # pays and succeeds
```

`/report` is gated at `usd("0.10")` and accepts both x402 and MPP. The server
boots against the hosted Surfpool sandbox with the shipped demo signer as the
recipient, so it runs out of the box. For a framework integration see
[`examples/flask`](../flask).

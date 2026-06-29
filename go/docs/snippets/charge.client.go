//go:build ignore

// Client-side charge: pay a 402-gated endpoint in one retry.
//
// NewClient returns an *http.Client whose transport settles the 402 and
// replays the request with the payment credential. Mirrors the Client section
// of go/README.md. See ../../../docs/snippets-convention.md.
package main

import (
	"fmt"
	"io"

	"github.com/solana-foundation/pay-kit/go/paycore/solanatx"
	x402client "github.com/solana-foundation/pay-kit/go/protocols/x402/client"
)

func main() {
	var signer solanatx.Signer // your wallet signer
	var rpc solanatx.RPCClient // a Solana RPC client

	// snippet:start
	// The returned *http.Client settles a 402 transparently on any call.
	httpClient := x402client.NewClient(signer, rpc)

	resp, err := httpClient.Get("${URL}")
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println(string(body))
	// snippet:end
}

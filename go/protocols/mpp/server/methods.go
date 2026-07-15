package server

import (
	"github.com/solana-foundation/solana-go/v2/programs/system"
	"github.com/solana-foundation/solana-go/v2/programs/token"
)

// Side-effect imports from solana-go register instruction decoders used by verification.
var (
	_ = system.ProgramID
	_ = token.ProgramID
)

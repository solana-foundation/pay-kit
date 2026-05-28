package server

import (
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
)

// Side-effect imports from solana-go register instruction decoders used by verification.
var (
	_ = system.ProgramID
	_ = token.ProgramID
)

package tls

// This file only holds the module's go:generate directive, which regenerates
// the cipher suite table from the ciphersuite.info dataset. The package
// documentation lives in doc.go.

//go:generate go run ./cmd/ciphersgen -output ./ciphers_table.go

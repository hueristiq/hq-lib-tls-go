package tls

// This file only holds the module's go:generate directive, which regenerates
// the cipher suite table inside ciphers.go from the ciphersuite.info dataset.
// The package documentation lives in doc.go.

//go:generate sh -c "cd cmd/ciphersgen && go run . -inplace -output ../../ciphers.go"

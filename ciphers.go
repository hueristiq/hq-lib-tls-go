package tls

import "sort"

// CipherSecurity classifies a TLS cipher suite's security posture, from
// most to least secure.
type CipherSecurity int

const (
	// CipherSecurityInsecure marks suites considered broken: known
	// attacks, no forward secrecy, or cryptographically weak primitives.
	CipherSecurityInsecure CipherSecurity = iota
	// CipherSecurityWeak marks suites that work but rely on aging
	// primitives or lack modern properties.
	CipherSecurityWeak
	// CipherSecuritySecure marks suites that are safe for general use.
	CipherSecuritySecure
	// CipherSecurityRecommended marks the subset of secure suites that are
	// preferred for new deployments.
	CipherSecurityRecommended
)

// CipherSecurityOf returns the classification of a cipher suite ID.
//
// Parameters:
//   - id (uint16): the cipher suite ID.
//
// Returns:
//   - security (CipherSecurity): the classification.
//   - known (bool): whether the suite is in the classification table.
func CipherSecurityOf(id uint16) (security CipherSecurity, known bool) {
	security, known = cipherClassification[id]

	return security, known
}

// CipherSuitesBySecurity lists every cipher suite ID carrying the given
// classification or better, in ascending order. [CipherSecuritySecure]
// therefore includes the recommended suites as well.
//
// Parameters:
//   - security (CipherSecurity): the minimum classification to include.
//
// Returns:
//   - ids ([]uint16): the matching cipher suite IDs, ascending.
func CipherSuitesBySecurity(security CipherSecurity) (ids []uint16) {
	ids = make([]uint16, 0, len(cipherClassification))

	for id, classified := range cipherClassification {
		if classified >= security {
			ids = append(ids, id)
		}
	}

	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})

	return ids
}

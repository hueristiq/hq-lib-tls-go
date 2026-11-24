package ciphers

import (
	"sort"
	"strings"
)

// Protocol version identifiers used in [Suite.Versions]. They mirror the
// constants exported by the client package.
const (
	VersionSSL30 uint16 = 0x0300
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
	VersionTLS13 uint16 = 0x0304
)

// Security classifies a cipher suite's security posture, from most to least
// secure.
type Security int

const (
	// SecurityInsecure marks suites considered broken: known attacks, no
	// forward secrecy, or cryptographically weak primitives.
	SecurityInsecure Security = iota
	// SecurityWeak marks suites that work but rely on aging primitives or
	// lack modern properties.
	SecurityWeak
	// SecuritySecure marks suites that are safe for general use.
	SecuritySecure
	// SecurityRecommended marks the subset of secure suites preferred for new
	// deployments.
	SecurityRecommended
)

// String returns the classification name.
func (s Security) String() (name string) {
	switch s {
	case SecurityInsecure:
		name = "insecure"
	case SecurityWeak:
		name = "weak"
	case SecuritySecure:
		name = "secure"
	case SecurityRecommended:
		name = "recommended"
	default:
		name = "unknown"
	}

	return name
}

// KeyExchange identifies the key-exchange algorithm of a suite.
type KeyExchange string

// Key exchange families.
const (
	KeyExchangeRSA         KeyExchange = "RSA"
	KeyExchangeRSAExport   KeyExchange = "RSA_EXPORT"
	KeyExchangeDHE         KeyExchange = "DHE"
	KeyExchangeDHEExport   KeyExchange = "DHE_EXPORT"
	KeyExchangeECDHE       KeyExchange = "ECDHE"
	KeyExchangeDHAnon      KeyExchange = "DH_ANON"
	KeyExchangeDHAnonExp   KeyExchange = "DH_ANON_EXPORT"
	KeyExchangeTLS13       KeyExchange = "TLS13"
	KeyExchangeUnspecified KeyExchange = "unknown"
)

// Suite is the metadata of one TLS cipher suite.
type Suite struct {
	// ID is the two-byte cipher suite identifier.
	ID uint16
	// Name is the IANA name, e.g. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.
	Name string
	// OpenSSLName is OpenSSL's spelling, e.g. ECDHE-RSA-AES128-GCM-SHA256.
	OpenSSLName string
	// GnuTLSName is GnuTLS's spelling, when it differs.
	GnuTLSName string
	// KeyExchange is the key-exchange family.
	KeyExchange KeyExchange
	// Authentication is the authentication family (RSA, ECDSA, DSS, none).
	Authentication string
	// Encryption is the bulk cipher, e.g. "AES128-GCM".
	Encryption string
	// Hash is the PRF/MAC hash, e.g. "SHA256".
	Hash string
	// Security is the security classification.
	Security Security
	// Versions lists the protocol versions the suite is defined for.
	Versions []uint16
	// Export reports whether this is an export-grade suite.
	Export bool
	// Implemented reports whether the native engine can complete a handshake
	// with this suite.
	Implemented bool
}

// The curated suite table. Metadata is aligned with the IANA registry and
// ciphersuite.info; export suites are restricted to the versions where their
// key derivation is defined.
var suites = []Suite{
	// TLS 1.3
	{ID: 0x1301, Name: "TLS_AES_128_GCM_SHA256", OpenSSLName: "TLS_AES_128_GCM_SHA256", KeyExchange: KeyExchangeTLS13, Authentication: "any", Encryption: "AES128-GCM", Hash: "SHA256", Security: SecurityRecommended, Versions: []uint16{VersionTLS13}, Implemented: true},
	{ID: 0x1302, Name: "TLS_AES_256_GCM_SHA384", OpenSSLName: "TLS_AES_256_GCM_SHA384", KeyExchange: KeyExchangeTLS13, Authentication: "any", Encryption: "AES256-GCM", Hash: "SHA384", Security: SecurityRecommended, Versions: []uint16{VersionTLS13}, Implemented: true},
	{ID: 0x1303, Name: "TLS_CHACHA20_POLY1305_SHA256", OpenSSLName: "TLS_CHACHA20_POLY1305_SHA256", KeyExchange: KeyExchangeTLS13, Authentication: "any", Encryption: "CHACHA20-POLY1305", Hash: "SHA256", Security: SecurityRecommended, Versions: []uint16{VersionTLS13}, Implemented: true},

	// ECDHE + AEAD
	{ID: 0xC02F, Name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", OpenSSLName: "ECDHE-RSA-AES128-GCM-SHA256", KeyExchange: KeyExchangeECDHE, Authentication: "RSA", Encryption: "AES128-GCM", Hash: "SHA256", Security: SecurityRecommended, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0xC030, Name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", OpenSSLName: "ECDHE-RSA-AES256-GCM-SHA384", KeyExchange: KeyExchangeECDHE, Authentication: "RSA", Encryption: "AES256-GCM", Hash: "SHA384", Security: SecurityRecommended, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0xC02B, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", OpenSSLName: "ECDHE-ECDSA-AES128-GCM-SHA256", KeyExchange: KeyExchangeECDHE, Authentication: "ECDSA", Encryption: "AES128-GCM", Hash: "SHA256", Security: SecurityRecommended, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0xC02C, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", OpenSSLName: "ECDHE-ECDSA-AES256-GCM-SHA384", KeyExchange: KeyExchangeECDHE, Authentication: "ECDSA", Encryption: "AES256-GCM", Hash: "SHA384", Security: SecurityRecommended, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0xCCA8, Name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", OpenSSLName: "ECDHE-RSA-CHACHA20-POLY1305", KeyExchange: KeyExchangeECDHE, Authentication: "RSA", Encryption: "CHACHA20-POLY1305", Hash: "SHA256", Security: SecurityRecommended, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0xCCA9, Name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", OpenSSLName: "ECDHE-ECDSA-CHACHA20-POLY1305", KeyExchange: KeyExchangeECDHE, Authentication: "ECDSA", Encryption: "CHACHA20-POLY1305", Hash: "SHA256", Security: SecurityRecommended, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0xCCAA, Name: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", OpenSSLName: "DHE-RSA-CHACHA20-POLY1305", KeyExchange: KeyExchangeDHE, Authentication: "RSA", Encryption: "CHACHA20-POLY1305", Hash: "SHA256", Security: SecurityRecommended, Versions: []uint16{VersionTLS12}, Implemented: true},

	// ECDHE + CBC
	{ID: 0xC013, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", OpenSSLName: "ECDHE-RSA-AES128-SHA", KeyExchange: KeyExchangeECDHE, Authentication: "RSA", Encryption: "AES128-CBC", Hash: "SHA1", Security: SecurityWeak, Versions: []uint16{VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0xC014, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", OpenSSLName: "ECDHE-RSA-AES256-SHA", KeyExchange: KeyExchangeECDHE, Authentication: "RSA", Encryption: "AES256-CBC", Hash: "SHA1", Security: SecurityWeak, Versions: []uint16{VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0xC009, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", OpenSSLName: "ECDHE-ECDSA-AES128-SHA", KeyExchange: KeyExchangeECDHE, Authentication: "ECDSA", Encryption: "AES128-CBC", Hash: "SHA1", Security: SecurityWeak, Versions: []uint16{VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0xC00A, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", OpenSSLName: "ECDHE-ECDSA-AES256-SHA", KeyExchange: KeyExchangeECDHE, Authentication: "ECDSA", Encryption: "AES256-CBC", Hash: "SHA1", Security: SecurityWeak, Versions: []uint16{VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0xC027, Name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", OpenSSLName: "ECDHE-RSA-AES128-SHA256", KeyExchange: KeyExchangeECDHE, Authentication: "RSA", Encryption: "AES128-CBC", Hash: "SHA256", Security: SecuritySecure, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0xC028, Name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", OpenSSLName: "ECDHE-RSA-AES256-SHA384", KeyExchange: KeyExchangeECDHE, Authentication: "RSA", Encryption: "AES256-CBC", Hash: "SHA384", Security: SecuritySecure, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0xC023, Name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", OpenSSLName: "ECDHE-ECDSA-AES128-SHA256", KeyExchange: KeyExchangeECDHE, Authentication: "ECDSA", Encryption: "AES128-CBC", Hash: "SHA256", Security: SecuritySecure, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0xC024, Name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", OpenSSLName: "ECDHE-ECDSA-AES256-SHA384", KeyExchange: KeyExchangeECDHE, Authentication: "ECDSA", Encryption: "AES256-CBC", Hash: "SHA384", Security: SecuritySecure, Versions: []uint16{VersionTLS12}, Implemented: true},

	// RSA key exchange
	{ID: 0x009C, Name: "TLS_RSA_WITH_AES_128_GCM_SHA256", OpenSSLName: "AES128-GCM-SHA256", KeyExchange: KeyExchangeRSA, Authentication: "RSA", Encryption: "AES128-GCM", Hash: "SHA256", Security: SecurityWeak, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0x009D, Name: "TLS_RSA_WITH_AES_256_GCM_SHA384", OpenSSLName: "AES256-GCM-SHA384", KeyExchange: KeyExchangeRSA, Authentication: "RSA", Encryption: "AES256-GCM", Hash: "SHA384", Security: SecurityWeak, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0x002F, Name: "TLS_RSA_WITH_AES_128_CBC_SHA", OpenSSLName: "AES128-SHA", KeyExchange: KeyExchangeRSA, Authentication: "RSA", Encryption: "AES128-CBC", Hash: "SHA1", Security: SecurityWeak, Versions: []uint16{VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0x0035, Name: "TLS_RSA_WITH_AES_256_CBC_SHA", OpenSSLName: "AES256-SHA", KeyExchange: KeyExchangeRSA, Authentication: "RSA", Encryption: "AES256-CBC", Hash: "SHA1", Security: SecurityWeak, Versions: []uint16{VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0x003C, Name: "TLS_RSA_WITH_AES_128_CBC_SHA256", OpenSSLName: "AES128-SHA256", KeyExchange: KeyExchangeRSA, Authentication: "RSA", Encryption: "AES128-CBC", Hash: "SHA256", Security: SecurityWeak, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0x003D, Name: "TLS_RSA_WITH_AES_256_CBC_SHA256", OpenSSLName: "AES256-SHA256", KeyExchange: KeyExchangeRSA, Authentication: "RSA", Encryption: "AES256-CBC", Hash: "SHA256", Security: SecurityWeak, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0x000A, Name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", OpenSSLName: "DES-CBC3-SHA", KeyExchange: KeyExchangeRSA, Authentication: "RSA", Encryption: "3DES-CBC", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0x0005, Name: "TLS_RSA_WITH_RC4_128_SHA", OpenSSLName: "RC4-SHA", KeyExchange: KeyExchangeRSA, Authentication: "RSA", Encryption: "RC4-128", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0x0004, Name: "TLS_RSA_WITH_RC4_128_MD5", OpenSSLName: "RC4-MD5", KeyExchange: KeyExchangeRSA, Authentication: "RSA", Encryption: "RC4-128", Hash: "MD5", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},

	// DHE_RSA
	{ID: 0x009E, Name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", OpenSSLName: "DHE-RSA-AES128-GCM-SHA256", KeyExchange: KeyExchangeDHE, Authentication: "RSA", Encryption: "AES128-GCM", Hash: "SHA256", Security: SecuritySecure, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0x009F, Name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", OpenSSLName: "DHE-RSA-AES256-GCM-SHA384", KeyExchange: KeyExchangeDHE, Authentication: "RSA", Encryption: "AES256-GCM", Hash: "SHA384", Security: SecuritySecure, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0x0033, Name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", OpenSSLName: "DHE-RSA-AES128-SHA", KeyExchange: KeyExchangeDHE, Authentication: "RSA", Encryption: "AES128-CBC", Hash: "SHA1", Security: SecurityWeak, Versions: []uint16{VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0x0039, Name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", OpenSSLName: "DHE-RSA-AES256-SHA", KeyExchange: KeyExchangeDHE, Authentication: "RSA", Encryption: "AES256-CBC", Hash: "SHA1", Security: SecurityWeak, Versions: []uint16{VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0x0067, Name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", OpenSSLName: "DHE-RSA-AES128-SHA256", KeyExchange: KeyExchangeDHE, Authentication: "RSA", Encryption: "AES128-CBC", Hash: "SHA256", Security: SecuritySecure, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0x006B, Name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", OpenSSLName: "DHE-RSA-AES256-SHA256", KeyExchange: KeyExchangeDHE, Authentication: "RSA", Encryption: "AES256-CBC", Hash: "SHA256", Security: SecuritySecure, Versions: []uint16{VersionTLS12}, Implemented: true},
	{ID: 0x0016, Name: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", OpenSSLName: "DHE-RSA-DES-CBC3-SHA", KeyExchange: KeyExchangeDHE, Authentication: "RSA", Encryption: "3DES-CBC", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10, VersionTLS11}, Implemented: true},

	// Anonymous DH
	{ID: 0x001B, Name: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", OpenSSLName: "ADH-DES-CBC3-SHA", KeyExchange: KeyExchangeDHAnon, Authentication: "none", Encryption: "3DES-CBC", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10, VersionTLS11}, Implemented: true},
	{ID: 0x0034, Name: "TLS_DH_anon_WITH_AES_128_CBC_SHA", OpenSSLName: "ADH-AES128-SHA", KeyExchange: KeyExchangeDHAnon, Authentication: "none", Encryption: "AES128-CBC", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},
	{ID: 0x003A, Name: "TLS_DH_anon_WITH_AES_256_CBC_SHA", OpenSSLName: "ADH-AES256-SHA", KeyExchange: KeyExchangeDHAnon, Authentication: "none", Encryption: "AES256-CBC", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionTLS10, VersionTLS11, VersionTLS12}, Implemented: true},

	// Export suites
	{ID: 0x0003, Name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", OpenSSLName: "EXP-RC4-MD5", KeyExchange: KeyExchangeRSAExport, Authentication: "RSA", Encryption: "RC4-40", Hash: "MD5", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10}, Export: true, Implemented: true},
	{ID: 0x0006, Name: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", OpenSSLName: "EXP-RC2-CBC-MD5", KeyExchange: KeyExchangeRSAExport, Authentication: "RSA", Encryption: "RC2-CBC-40", Hash: "MD5", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10}, Export: true, Implemented: true},
	{ID: 0x0008, Name: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", OpenSSLName: "EXP-DES-CBC-SHA", KeyExchange: KeyExchangeRSAExport, Authentication: "RSA", Encryption: "DES40-CBC", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10}, Export: true, Implemented: true},
	{ID: 0x0014, Name: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", OpenSSLName: "EXP-DHE-RSA-DES-CBC-SHA", KeyExchange: KeyExchangeDHEExport, Authentication: "RSA", Encryption: "DES40-CBC", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10}, Export: true, Implemented: true},
	{ID: 0x0017, Name: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", OpenSSLName: "EXP-ADH-RC4-MD5", KeyExchange: KeyExchangeDHAnonExp, Authentication: "none", Encryption: "RC4-40", Hash: "MD5", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10}, Export: true, Implemented: true},
	{ID: 0x0019, Name: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", OpenSSLName: "EXP-ADH-DES-CBC-SHA", KeyExchange: KeyExchangeDHAnonExp, Authentication: "none", Encryption: "DES40-CBC", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionSSL30, VersionTLS10}, Export: true, Implemented: true},
	{ID: 0x0060, Name: "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", OpenSSLName: "EXP1024-RC4-MD5", KeyExchange: KeyExchangeRSAExport, Authentication: "RSA", Encryption: "RC4-56", Hash: "MD5", Security: SecurityInsecure, Versions: []uint16{VersionTLS10}, Export: true, Implemented: true},
	{ID: 0x0061, Name: "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", OpenSSLName: "EXP1024-RC2-CBC-MD5", KeyExchange: KeyExchangeRSAExport, Authentication: "RSA", Encryption: "RC2-CBC-56", Hash: "MD5", Security: SecurityInsecure, Versions: []uint16{VersionTLS10}, Export: true, Implemented: true},
	{ID: 0x0062, Name: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", OpenSSLName: "EXP1024-DES-CBC-SHA", KeyExchange: KeyExchangeRSAExport, Authentication: "RSA", Encryption: "DES-CBC-56", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionTLS10}, Export: true, Implemented: true},
	{ID: 0x0064, Name: "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", OpenSSLName: "EXP1024-RC4-SHA", KeyExchange: KeyExchangeRSAExport, Authentication: "RSA", Encryption: "RC4-56", Hash: "SHA1", Security: SecurityInsecure, Versions: []uint16{VersionTLS10}, Export: true, Implemented: true},
}

var (
	byID   = make(map[uint16]*Suite, len(suites))
	byName = make(map[string]*Suite, len(suites)*3)
)

func init() {
	for i := range suites {
		suite := &suites[i]

		byID[suite.ID] = suite
		byName[strings.ToLower(suite.Name)] = suite
		byName[strings.ToLower(suite.OpenSSLName)] = suite

		if suite.GnuTLSName != "" {
			byName[strings.ToLower(suite.GnuTLSName)] = suite
		}
	}
}

// ByID returns the metadata of a suite the package knows in detail.
func ByID(id uint16) (suite Suite, known bool) {
	if known = byID[id] != nil; known {
		suite = *byID[id]
	}

	return suite, known
}

// ByName resolves a suite by its IANA, OpenSSL, or GnuTLS name, or by its
// 0xNNNN identifier.
func ByName(name string) (suite Suite, known bool) {
	normalized := strings.ToLower(strings.TrimSpace(name))

	if found, ok := byName[normalized]; ok {
		return *found, true
	}

	if id, ok := parseID(normalized); ok {
		return ByID(id)
	}

	return Suite{}, false
}

// Name returns the IANA name of id, falling back to its 0xNNNN identifier.
func Name(id uint16) (name string) {
	if suite, known := ByID(id); known && suite.Name != "" {
		return suite.Name
	}

	return hexID(id)
}

// OpenSSLName returns OpenSSL's spelling of id, falling back to the IANA
// name or the 0xNNNN identifier.
func OpenSSLName(id uint16) (name string) {
	if suite, known := ByID(id); known && suite.OpenSSLName != "" {
		return suite.OpenSSLName
	}

	return Name(id)
}

// Implemented returns every implemented suite, in ascending ID order.
func Implemented() (implemented []Suite) {
	implemented = make([]Suite, 0, len(suites))

	for i := range suites {
		if suites[i].Implemented {
			implemented = append(implemented, suites[i])
		}
	}

	sort.Slice(implemented, func(i, j int) bool {
		return implemented[i].ID < implemented[j].ID
	})

	return implemented
}

// Export returns every implemented export suite.
func Export() (exportSuites []Suite) {
	implemented := Implemented()

	for i := range implemented {
		if implemented[i].Export {
			exportSuites = append(exportSuites, implemented[i])
		}
	}

	return exportSuites
}

// SuitesBySecurity returns every implemented suite carrying the given
// classification or better, in ascending ID order.
func SuitesBySecurity(security Security) (matching []Suite) {
	implemented := Implemented()

	for i := range implemented {
		if implemented[i].Security >= security {
			matching = append(matching, implemented[i])
		}
	}

	return matching
}

// BySecurity returns the IDs of every implemented suite carrying the given
// classification or better, in ascending order. It mirrors the historical
// root-package helper.
func BySecurity(security Security) (ids []uint16) {
	matching := SuitesBySecurity(security)

	ids = make([]uint16, 0, len(matching))

	for i := range matching {
		ids = append(ids, matching[i].ID)
	}

	return ids
}

// SecurityOf returns the security classification of a suite. Implemented
// suites use the curated table; other suites fall back to the ciphersuite.info
// dataset.
func SecurityOf(id uint16) (security Security, known bool) {
	if suite, detailed := ByID(id); detailed {
		return suite.Security, true
	}

	security, known = classification[id]

	return security, known
}

// Supported reports whether suite id can be negotiated at version.
func (s *Suite) Supported(version uint16) (supported bool) {
	for _, candidate := range s.Versions {
		if candidate == version {
			return true
		}
	}

	return false
}

// IsExport reports whether id is an export-grade suite.
func IsExport(id uint16) (export bool) {
	if suite, known := ByID(id); known {
		return suite.Export
	}

	return false
}

// hexID renders id as 0xNNNN.
func hexID(id uint16) (rendered string) {
	const digits = "0123456789abcdef"

	return "0x" + string([]byte{
		digits[(id>>12)&0xf],
		digits[(id>>8)&0xf],
		digits[(id>>4)&0xf],
		digits[id&0xf],
	})
}

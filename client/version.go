package client

import (
	"strings"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

// Protocol version identifiers.
const (
	VersionSSL30 = hqgotlsciphers.VersionSSL30
	VersionTLS10 = hqgotlsciphers.VersionTLS10
	VersionTLS11 = hqgotlsciphers.VersionTLS11
	VersionTLS12 = hqgotlsciphers.VersionTLS12
	VersionTLS13 = hqgotlsciphers.VersionTLS13
)

// Version describes one protocol version the engine speaks.
type Version struct {
	ID   uint16
	Name string
	Slug string
}

var supportedVersions = []Version{
	{ID: VersionSSL30, Name: "SSL 3.0", Slug: "ssl30"},
	{ID: VersionTLS10, Name: "TLS 1.0", Slug: "tls10"},
	{ID: VersionTLS11, Name: "TLS 1.1", Slug: "tls11"},
	{ID: VersionTLS12, Name: "TLS 1.2", Slug: "tls12"},
	{ID: VersionTLS13, Name: "TLS 1.3", Slug: "tls13"},
}

// SupportedVersions returns every protocol version the engine speaks,
// weakest first.
func SupportedVersions() (versions []Version) {
	versions = make([]Version, len(supportedVersions))
	copy(versions, supportedVersions)

	return versions
}

// VersionName returns the display name of version ("SSL 3.0", "TLS 1.2"),
// or "unknown".
func VersionName(version uint16) (name string) {
	for _, candidate := range supportedVersions {
		if candidate.ID == version {
			return candidate.Name
		}
	}

	return "unknown"
}

// CipherSuiteName returns the IANA name of a cipher suite ID, falling back to
// its hexadecimal identifier.
func CipherSuiteName(id uint16) (name string) {
	return hqgotlsciphers.Name(id)
}

// VersionSlug returns the CLI-facing name of version ("ssl30", "tls12"),
// or "unknown".
func VersionSlug(version uint16) (slug string) {
	for _, candidate := range supportedVersions {
		if candidate.ID == version {
			return candidate.Slug
		}
	}

	return "unknown"
}

// ParseVersion converts a version name into its identifier. It accepts the
// slugs ("ssl30", "tls10", "tls13") as well as "ssl3", "tls1.0", "tls1.1",
// "tls1.2", and "tls1.3", case-insensitively.
func ParseVersion(name string) (version uint16, err error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "ssl30", "ssl3", "ssl3.0":
		version = VersionSSL30
	case "tls10", "tls1", "tls1.0":
		version = VersionTLS10
	case "tls11", "tls1.1":
		version = VersionTLS11
	case "tls12", "tls1.2":
		version = VersionTLS12
	case "tls13", "tls1.3":
		version = VersionTLS13
	default:
		err = hqgoerrors.Errorf("invalid input, unrecognized TLS version: %q", name)

		return 0, err
	}

	return version, nil
}

// validVersion reports whether version is one the engine recognizes.
func validVersion(version uint16) (valid bool) {
	switch version {
	case VersionSSL30, VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13:
		valid = true
	}

	return valid
}

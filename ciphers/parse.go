package ciphers

import (
	"strconv"
	"strings"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// ParseSecurity maps a security class name to the Security constant it
// denotes. "all" and "insecure" select SecurityInsecure; the other names
// select their own class.
func ParseSecurity(name string) (security Security, err error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "all", "insecure":
		security = SecurityInsecure
	case "weak":
		security = SecurityWeak
	case "secure":
		security = SecuritySecure
	case "recommended":
		security = SecurityRecommended
	default:
		err = hqgoerrors.Errorf("invalid input, unknown cipher security class: %q", name)
	}

	return security, err
}

// ParseSecurityList maps a list of security class names to the weakest class
// named, so "secure,weak" yields SecurityWeak.
func ParseSecurityList(names []string) (security Security, err error) {
	security = SecurityRecommended

	for _, name := range names {
		candidate, candidateErr := ParseSecurity(name)
		if candidateErr != nil {
			return security, candidateErr
		}

		if candidate < security {
			security = candidate
		}
	}

	return security, nil
}

// ParseList resolves a comma- or space-separated list of suite references.
// Each reference may be a security class ("all", "insecure", "weak",
// "secure", "recommended"), an IANA/OpenSSL/GnuTLS suite name, or a 0xNNNN
// identifier. Duplicates are removed and the input order is preserved.
func ParseList(names string) (ids []uint16, err error) {
	return ParseListArgs(strings.FieldsFunc(names, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}))
}

// ParseListArgs resolves a list of suite references, one per element.
func ParseListArgs(names []string) (ids []uint16, err error) {
	seen := make(map[uint16]struct{}, len(names))

	add := func(id uint16) {
		if _, ok := seen[id]; ok {
			return
		}

		seen[id] = struct{}{}

		ids = append(ids, id)
	}

	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}

		if security, securityErr := ParseSecurity(name); securityErr == nil {
			matching := SuitesBySecurity(security)

			for i := range matching {
				add(matching[i].ID)
			}

			continue
		}

		if id, ok := parseID(name); ok {
			add(id)

			continue
		}

		suite, known := ByName(name)
		if !known {
			err = hqgoerrors.Errorf("invalid input, unknown cipher suite: %q", name)

			return nil, err
		}

		add(suite.ID)
	}

	return ids, nil
}

// parseID parses a 0xNNNN or decimal suite identifier.
func parseID(value string) (id uint16, ok bool) {
	value = strings.TrimSpace(strings.ToLower(value))

	base := 10

	if strings.HasPrefix(value, "0x") {
		value = strings.TrimPrefix(value, "0x")
		base = 16
	}

	parsed, err := strconv.ParseUint(value, base, 16)
	if err != nil && base == 10 {
		parsed, err = strconv.ParseUint(value, 16, 16)
	}

	if err != nil {
		return 0, false
	}

	return uint16(parsed), true
}

package fingerprint

import "testing"

func FuzzJA3(f *testing.F) {
	f.Add([]byte{0x01, 0x00})
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x2c})

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Must never panic, only return an error on malformed input.
		_, _ = JA3(data)
	})
}

func FuzzJA3S(f *testing.F) {
	f.Add([]byte{0x02, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = JA3S(data)
	})
}

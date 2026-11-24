package keys

import (
	"crypto/sha1" //nolint:gosec // G505: SSL 3.0 Finished requires SHA-1.

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
	hqgotlsciphers "github.com/hueristiq/hq-lib-tls-go/ciphers"
)

// cipherParams describes the key-block layout of a suite.
type cipherParams struct {
	macLen         int
	KeyBlockKeyLen int
	fullKeyLen     int
	ivLen          int
	blockSize      int
}

// paramsForSuite returns the key-block parameters for suite.
func paramsForSuite(suite *hqgotlsciphers.Suite) (params cipherParams, err error) {
	switch suite.Encryption {
	case "AES128-GCM", "AES256-GCM", "CHACHA20-POLY1305":
		params.macLen = 0
	default:
		params.macLen = macLength(suite.Hash)
	}

	switch suite.Encryption {
	case "AES128-GCM", "AES128-CBC":
		params.fullKeyLen = 16
		params.blockSize = 16
		params.ivLen = 16
	case "AES256-GCM", "AES256-CBC":
		params.fullKeyLen = 32
		params.blockSize = 16
		params.ivLen = 16
	case "3DES-CBC":
		params.fullKeyLen = 24
		params.blockSize = 8
		params.ivLen = 8
	case "DES40-CBC", "DES-CBC-56":
		params.fullKeyLen = 8
		params.blockSize = 8
		params.ivLen = 8
	case "RC2-CBC-40", "RC2-CBC-56":
		params.fullKeyLen = 16
		params.blockSize = 8
		params.ivLen = 8
	case "RC4-128", "RC4-40", "RC4-56":
		params.fullKeyLen = 16
		params.ivLen = 0
	case "CHACHA20-POLY1305":
		params.fullKeyLen = 32
		params.ivLen = 12
	default:
		return params, hqgoerrors.Errorf("%w: %s", ErrUnsupportedCipherSuite, suite.Name)
	}

	switch suite.Encryption {
	case "AES128-GCM", "AES256-GCM":
		params.ivLen = 4
	case "CHACHA20-POLY1305":
		params.ivLen = 12
	}

	params.KeyBlockKeyLen = params.fullKeyLen

	if suite.Export {
		switch suite.Encryption {
		case "RC4-56", "RC2-CBC-56", "DES-CBC-56":
			params.KeyBlockKeyLen = 7
		default:
			params.KeyBlockKeyLen = 5
		}

		if params.ivLen > 0 {
			params.ivLen = params.blockSize
		} else {
			params.ivLen = 0
		}
	}

	return params, nil
}

// KeyBlock is the key material for one connection.
type KeyBlock struct {
	ClientMAC []byte
	ServerMAC []byte
	ClientKey []byte
	ServerKey []byte
	ClientIV  []byte
	ServerIV  []byte
}

// DeriveKeyBlock computes the key block for a TLS 1.2/1.0/SSL 3.0 connection.
// prfHashName returns the TLS 1.2 PRF hash for a suite. The PRF hash is
// SHA-256 unless the suite's handshake hash is SHA-384; the suite's MAC hash
// is unrelated.
func prfHashName(version uint16, suite *hqgotlsciphers.Suite) (name string) {
	if version >= hqgotlsciphers.VersionTLS12 {
		if suite.Hash == "SHA384" {
			return "SHA384"
		}

		return "SHA256"
	}

	return suite.Hash
}

// DeriveKeyBlock computes the key block for a TLS 1.2/1.0/SSL 3.0 connection.
func DeriveKeyBlock(version uint16, suite *hqgotlsciphers.Suite, master, clientRandom, serverRandom []byte) (block KeyBlock, err error) {
	params, err := paramsForSuite(suite)
	if err != nil {
		return block, err
	}

	prfHash := prfHashName(version, suite)

	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	exportSeed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	exportSeed = append(exportSeed, clientRandom...)
	exportSeed = append(exportSeed, serverRandom...)

	KeyBlockIVLen := params.ivLen
	if suite.Export {
		KeyBlockIVLen = 0
	}

	total := 2 * (params.macLen + params.KeyBlockKeyLen + KeyBlockIVLen)

	material := prf(version, prfHash, master, "key expansion", seed, total)

	block.ClientMAC, material = take(material, params.macLen)
	block.ServerMAC, material = take(material, params.macLen)
	block.ClientKey, material = take(material, params.KeyBlockKeyLen)
	block.ServerKey, material = take(material, params.KeyBlockKeyLen)

	if !suite.Export {
		block.ClientIV, material = take(material, params.ivLen)
		block.ServerIV, _ = take(material, params.ivLen)

		return block, nil
	}

	if version == hqgotlsciphers.VersionSSL30 {
		block.ClientKey = exportPRF30(block.ClientKey, exportSeed, params.fullKeyLen)
		block.ServerKey = exportPRF30(block.ServerKey, exportSeed, params.fullKeyLen)

		if params.ivLen > 0 {
			block.ClientIV = exportPRF30(nil, exportSeed, params.ivLen)
			block.ServerIV = exportPRF30(nil, exportSeed, params.ivLen)
		}

		return block, nil
	}

	block.ClientKey = prf(version, prfHash, block.ClientKey, "client write key", exportSeed, params.fullKeyLen)
	block.ServerKey = prf(version, prfHash, block.ServerKey, "server write key", exportSeed, params.fullKeyLen)

	if params.ivLen == 0 {
		block.ClientIV = nil
		block.ServerIV = nil

		return block, nil
	}

	ivBlock := prf(version, prfHash, nil, "IV block", exportSeed, 2*params.ivLen)

	block.ClientIV, _ = take(ivBlock, params.ivLen)
	block.ServerIV, _ = take(ivBlock[params.ivLen:], params.ivLen)

	return block, nil
}

// DeriveMasterSecret computes the master secret.
func DeriveMasterSecret(version uint16, suite *hqgotlsciphers.Suite, preMaster, clientRandom, serverRandom, transcript []byte, extendedMasterSecret bool) (master []byte) {
	if version == hqgotlsciphers.VersionSSL30 {
		seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
		seed = append(seed, clientRandom...)
		seed = append(seed, serverRandom...)

		return ssl3PRF(preMaster, seed, 48)
	}

	if extendedMasterSecret && version >= hqgotlsciphers.VersionTLS10 {
		sessionHash := transcriptMD5SHA1(transcript)
		if version >= hqgotlsciphers.VersionTLS12 {
			sessionHash = transcriptHash(prfHashName(version, suite), transcript)
		}

		return prf(version, prfHashName(version, suite), preMaster, "extended master secret", sessionHash, 48)
	}

	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	return prf(version, prfHashName(version, suite), preMaster, "master secret", seed, 48)
}

// FinishedVerifyData computes the Finished verify_data for a sender.
func FinishedVerifyData(version uint16, suite *hqgotlsciphers.Suite, master, transcript []byte, sender string) (verifyData []byte) {
	if version == hqgotlsciphers.VersionSSL30 {
		label := []byte(sender)

		material := make([]byte, 0, len(transcript)+len(label)+len(master))
		material = append(material, transcript...)
		material = append(material, label...)
		material = append(material, master...)

		md5Digest := md5Sum(material)
		sha1Digest := sha1Sum(material)

		verifyData = make([]byte, 0, len(md5Digest)+len(sha1Digest))
		verifyData = append(verifyData, md5Digest...)
		verifyData = append(verifyData, sha1Digest...)

		return verifyData
	}

	label := "client finished"
	if sender == "SRVR" {
		label = "server finished"
	}

	hash := transcriptHash(prfHashName(version, suite), transcript)
	if version < hqgotlsciphers.VersionTLS12 {
		hash = transcriptMD5SHA1(transcript)
	}

	return prf(version, prfHashName(version, suite), master, label, hash, 12)
}

// sha1Sum returns the SHA-1 digest of data.
func sha1Sum(data []byte) (sum []byte) {
	digest := sha1.Sum(data) //nolint:gosec // G401: SSL 3.0 Finished requires SHA-1.

	return digest[:]
}

// take splits raw into a prefix of length n and the remainder.
func take(raw []byte, n int) (prefix, rest []byte) {
	if n <= 0 {
		return nil, raw
	}

	if n > len(raw) {
		n = len(raw)
	}

	return raw[:n], raw[n:]
}

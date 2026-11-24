package client

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // SA1019: legacy DSA certificates require it.
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5" //nolint:gosec // G501: legacy TLS requires MD5.
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // G505: legacy TLS requires SHA-1.
	"crypto/sha256"
	"crypto/sha512"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	hqgotlsclientkeys "github.com/hueristiq/hq-lib-tls-go/client/internal/keys"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// tls13ClientCertificateVerifyContext is the CertificateVerify context string.
const tls13ClientCertificateVerifyContext = "TLS 1.3, client CertificateVerify"

// verifySignature verifies a signature over signedData with the certificate's
// public key.
func verifySignature(certificate *x509.Certificate, algorithm uint16, signedData, signature []byte, version uint16) (err error) {
	if certificate == nil {
		return hqgoerrors.Wrap(ErrVerifyFailed, "no certificate")
	}

	if version < VersionTLS12 {
		return verifyLegacySignature(certificate.PublicKey, signedData, signature)
	}

	hash, pss, ed25519Scheme, hashErr := schemeHash(SignatureScheme(algorithm))
	if hashErr != nil {
		return hashErr
	}

	digest, digestErr := hashBytes(hash, signedData)
	if digestErr != nil {
		return digestErr
	}

	switch publicKey := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if ed25519Scheme {
			return hqgoerrors.Wrap(ErrVerifyFailed, "RSA certificate with Ed25519 scheme")
		}

		if pss {
			if verifyErr := rsa.VerifyPSS(publicKey, hash, digest, signature, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			}); verifyErr != nil {
				return hqgoerrors.Join(ErrVerifyFailed, verifyErr)
			}

			return nil
		}

		if verifyErr := rsa.VerifyPKCS1v15(publicKey, hash, digest, signature); verifyErr != nil {
			return hqgoerrors.Join(ErrVerifyFailed, verifyErr)
		}

		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(publicKey, digest, signature) {
			return hqgoerrors.Wrap(ErrVerifyFailed, "ECDSA signature mismatch")
		}

		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(publicKey, signedData, signature) {
			return hqgoerrors.Wrap(ErrVerifyFailed, "Ed25519 signature mismatch")
		}

		return nil
	case *dsa.PublicKey:
		if !dsaVerify(publicKey, digest, signature) {
			return hqgoerrors.Wrap(ErrVerifyFailed, "DSA signature mismatch")
		}

		return nil
	default:
		return hqgoerrors.Errorf("%w: unsupported public key type %T", ErrVerifyFailed, certificate.PublicKey)
	}
}

// verifyLegacySignature verifies a TLS 1.0/SSL 3.0 signature.
func verifyLegacySignature(publicKey any, signedData, signature []byte) (err error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		digest := make([]byte, 0, md5.Size+sha1.Size)
		md5Digest := md5.Sum(signedData)   //nolint:gosec // G401: legacy protocol.
		sha1Digest := sha1.Sum(signedData) //nolint:gosec // G401: legacy protocol.

		digest = append(digest, md5Digest[:]...)
		digest = append(digest, sha1Digest[:]...)

		if verifyErr := rsa.VerifyPKCS1v15(key, crypto.MD5SHA1, digest, signature); verifyErr != nil {
			return hqgoerrors.Join(ErrVerifyFailed, verifyErr)
		}

		return nil
	case *ecdsa.PublicKey:
		digest := sha1.Sum(signedData) //nolint:gosec // G401: legacy protocol.

		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return hqgoerrors.Wrap(ErrVerifyFailed, "ECDSA signature mismatch")
		}

		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(key, signedData, signature) {
			return hqgoerrors.Wrap(ErrVerifyFailed, "Ed25519 signature mismatch")
		}

		return nil
	case *dsa.PublicKey:
		digest := sha1.Sum(signedData) //nolint:gosec // G401: legacy protocol.

		if !dsaVerify(key, digest[:], signature) {
			return hqgoerrors.Wrap(ErrVerifyFailed, "DSA signature mismatch")
		}

		return nil
	default:
		return hqgoerrors.Errorf("%w: unsupported public key type %T", ErrVerifyFailed, publicKey)
	}
}

// signCertificateVerify signs the handshake transcript for a client
// CertificateVerify message.
func signCertificateVerify(certificate *Certificate, transcript []byte, version uint16, request *certificateRequestInfo) (signature []byte, algorithm uint16, err error) {
	signer, ok := certificate.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, 0, hqgoerrors.Errorf("%w: private key type %T is not a crypto.Signer", ErrVerifyFailed, certificate.PrivateKey)
	}

	scheme, hash, pss, ed25519Scheme, err := selectSignatureScheme(signer.Public(), version, request)
	if err != nil {
		return nil, 0, err
	}

	var signedData []byte

	switch {
	case version >= VersionTLS13:
		transcriptDigest := hqgotlsclientkeys.TranscriptHash(hqgotlsclientkeys.HashNameForSuite(suiteHashName(hash)), transcript)

		signedData = make([]byte, 0, 64+len(tls13ClientCertificateVerifyContext)+1+len(transcriptDigest))
		signedData = append(signedData, bytes.Repeat([]byte{0x20}, 64)...)
		signedData = append(signedData, tls13ClientCertificateVerifyContext...)
		signedData = append(signedData, 0)
		signedData = append(signedData, transcriptDigest...)
	case version >= VersionTLS12:
		signedData = transcript
	default:
		signedData = transcript
	}

	var digest []byte

	switch {
	case ed25519Scheme:
		digest = signedData
	case version < VersionTLS12:
		md5Digest := md5.Sum(signedData)   //nolint:gosec // G401: legacy protocol.
		sha1Digest := sha1.Sum(signedData) //nolint:gosec // G401: legacy protocol.
		digest = append(md5Digest[:], sha1Digest[:]...)
	default:
		digest, err = hashBytes(hash, signedData)
		if err != nil {
			return nil, 0, err
		}
	}

	var options crypto.SignerOpts = hash

	if pss {
		options = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       hash,
		}
	}

	if ed25519Scheme {
		options = crypto.Hash(0)
	}

	if version < VersionTLS12 {
		options = crypto.MD5SHA1
	}

	signature, err = signer.Sign(rand.Reader, digest, options)
	if err != nil {
		return nil, 0, hqgoerrors.Wrap(err, "signing CertificateVerify")
	}

	return signature, uint16(scheme), nil
}

// selectSignatureScheme picks a scheme compatible with the public key.
func selectSignatureScheme(publicKey crypto.PublicKey, version uint16, request *certificateRequestInfo) (scheme SignatureScheme, hash crypto.Hash, pss, ed25519Scheme bool, err error) {
	candidates := defaultSchemesForPublicKey(publicKey, version)

	if request != nil && len(request.signatureAlgorithms) > 0 {
		filtered := candidates[:0]

		for _, candidate := range candidates {
			for _, id := range request.signatureAlgorithms {
				if uint16(candidate) == id {
					filtered = append(filtered, candidate)

					break
				}
			}
		}

		if len(filtered) == 0 {
			return 0, 0, false, false, hqgoerrors.Wrap(ErrVerifyFailed, "no compatible signature scheme for client certificate")
		}

		candidates = filtered
	}

	scheme = candidates[0]
	hash, pss, ed25519Scheme, err = schemeHash(scheme)

	return scheme, hash, pss, ed25519Scheme, err
}

// defaultSchemesForPublicKey lists schemes compatible with publicKey.
func defaultSchemesForPublicKey(publicKey crypto.PublicKey, version uint16) (schemes []SignatureScheme) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if version >= VersionTLS13 {
			schemes = []SignatureScheme{stdtls.PSSWithSHA256, stdtls.PSSWithSHA384, stdtls.PSSWithSHA512}
		} else {
			schemes = []SignatureScheme{stdtls.PKCS1WithSHA256, stdtls.PKCS1WithSHA384, stdtls.PKCS1WithSHA512, stdtls.PKCS1WithSHA1}
		}

		_ = key
	case *ecdsa.PublicKey:
		schemes = []SignatureScheme{stdtls.ECDSAWithP256AndSHA256, stdtls.ECDSAWithP384AndSHA384, stdtls.ECDSAWithP521AndSHA512, stdtls.ECDSAWithSHA1}
	case ed25519.PublicKey:
		schemes = []SignatureScheme{stdtls.Ed25519}
	default:
		schemes = []SignatureScheme{stdtls.PKCS1WithSHA256}
	}

	return schemes
}

// schemeHash maps a signature scheme to its hash and signing mode.
func schemeHash(scheme SignatureScheme) (hash crypto.Hash, pss, ed25519Scheme bool, err error) {
	switch scheme { //nolint:exhaustive // only the suites the engine implements are supported.
	case stdtls.PKCS1WithSHA1:
		hash = crypto.SHA1
	case stdtls.PKCS1WithSHA256:
		hash = crypto.SHA256
	case stdtls.PKCS1WithSHA384:
		hash = crypto.SHA384
	case stdtls.PKCS1WithSHA512:
		hash = crypto.SHA512
	case stdtls.PSSWithSHA256:
		hash = crypto.SHA256
		pss = true
	case stdtls.PSSWithSHA384:
		hash = crypto.SHA384
		pss = true
	case stdtls.PSSWithSHA512:
		hash = crypto.SHA512
		pss = true
	case stdtls.ECDSAWithSHA1:
		hash = crypto.SHA1
	case stdtls.ECDSAWithP256AndSHA256:
		hash = crypto.SHA256
	case stdtls.ECDSAWithP384AndSHA384:
		hash = crypto.SHA384
	case stdtls.ECDSAWithP521AndSHA512:
		hash = crypto.SHA512
	case stdtls.Ed25519:
		hash = crypto.Hash(0)
		ed25519Scheme = true
	default:
		err = hqgoerrors.Errorf("%w: unsupported signature scheme %#x", ErrVerifyFailed, uint16(scheme))
	}

	return hash, pss, ed25519Scheme, err
}

// hashBytes hashes data with hash.
func hashBytes(hash crypto.Hash, data []byte) (digest []byte, err error) {
	switch hash { //nolint:exhaustive // only the TLS PRF hashes are supported.
	case crypto.SHA1:
		sum := sha1.Sum(data) //nolint:gosec // G401: legacy protocol.

		return sum[:], nil
	case crypto.SHA256:
		sum := sha256.Sum256(data)

		return sum[:], nil
	case crypto.SHA384:
		sum := sha512.Sum384(data)

		return sum[:], nil
	case crypto.SHA512:
		sum := sha512.Sum512(data)

		return sum[:], nil
	case crypto.MD5SHA1:
		md5Sum := md5.Sum(data)   //nolint:gosec // G401: legacy protocol.
		sha1Sum := sha1.Sum(data) //nolint:gosec // G401: legacy protocol.

		return append(md5Sum[:], sha1Sum[:]...), nil
	default:
		return nil, hqgoerrors.Errorf("%w: unsupported hash %v", ErrVerifyFailed, hash)
	}
}

// dsaVerify verifies an ASN.1 DSA signature.
func dsaVerify(publicKey *dsa.PublicKey, digest, signature []byte) (valid bool) {
	var parsed struct {
		R *big.Int
		S *big.Int
	}

	if _, err := asn1.Unmarshal(signature, &parsed); err != nil {
		return false
	}

	if parsed.R == nil || parsed.S == nil {
		return false
	}

	return dsa.Verify(publicKey, digest, parsed.R, parsed.S)
}

// suiteHashName renders a crypto.Hash as a suite hash name.
func suiteHashName(hash crypto.Hash) (name string) {
	switch hash { //nolint:exhaustive // only the TLS PRF hashes are supported.
	case crypto.SHA1:
		name = "SHA1"
	case crypto.SHA256:
		name = "SHA256"
	case crypto.SHA384:
		name = "SHA384"
	case crypto.SHA512:
		name = "SHA512"
	case crypto.MD5SHA1:
		name = "MD5SHA1"
	default:
		name = "SHA256"
	}

	return name
}

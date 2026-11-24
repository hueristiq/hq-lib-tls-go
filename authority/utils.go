package authority

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"

	hqgoerrors "github.com/hueristiq/hq-lib-errors-go"
)

// LoadCertificatePrivateKeyFromFiles loads a certificate and private key from the specified PEM-encoded files.
//
// The certificate and private key are loaded using the crypto/tls package. The certificate is parsed to ensure
// it is a valid X.509 certificate, and the private key is verified to implement the crypto.Signer interface
// and to be one of the supported types (RSA, ECDSA, or Ed25519). The function performs input validation and
// provides detailed error messages for debugging purposes.
func LoadCertificatePrivateKeyFromFiles(certificateFilePath, certificatePrivateKeyFilePath string) (certificate *x509.Certificate, privateKey crypto.Signer, err error) {
	return loadCertificatePrivateKeyFromFiles(defaultOperations(), certificateFilePath, certificatePrivateKeyFilePath)
}

// loadCertificatePrivateKeyFromFiles loads and validates a certificate and
// private key pair using the given operations.
func loadCertificatePrivateKeyFromFiles(ops *operations, certificateFilePath, certificatePrivateKeyFilePath string) (certificate *x509.Certificate, privateKey crypto.Signer, err error) {
	if certificateFilePath == "" || certificatePrivateKeyFilePath == "" {
		err = hqgoerrors.New("invalid input, certificate file path or private key file path is empty")

		return nil, nil, err
	}

	keyPair, err := ops.loadKeyPair(certificateFilePath, certificatePrivateKeyFilePath)
	if err != nil {
		err = hqgoerrors.Wrapf(err, "loading certificate and private key from files %q and %q", certificateFilePath, certificatePrivateKeyFilePath)

		return nil, nil, err
	}

	certificate, err = ops.parseCertificate(keyPair.Certificate[0])
	if err != nil {
		err = hqgoerrors.Wrapf(err, "parsing X.509 certificate from file %q", certificateFilePath)

		return nil, nil, err
	}

	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		err = hqgoerrors.Errorf("private key from file %q does not implement crypto.Signer: got type %T", certificatePrivateKeyFilePath, keyPair.PrivateKey)

		return nil, nil, err
	}

	privateKey = signer

	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		err = hqgoerrors.Errorf("unsupported private key type in file %q: got %T, expected RSA, ECDSA, or Ed25519", certificatePrivateKeyFilePath, privateKey)

		return nil, nil, err
	}

	return certificate, privateKey, nil
}

// SaveCertificatePrivateKeyToFiles saves a certificate and its private key to the specified files in PEM format.
//
// The private key is verified to match the certificate's public key before anything is written.
// The certificate and private key are converted to PEM format and written to the provided file paths;
// both conversions happen before any file is written, so a conversion failure leaves no partial output.
// The directories for both files are created with permissions 0755 if they do not exist. The certificate
// file is written with permissions 0600 and the private key file with permissions 0400 (read-only) to
// protect sensitive data. The private key must implement the crypto.Signer interface and be one of the
// supported types (RSA, ECDSA, or Ed25519).
func SaveCertificatePrivateKeyToFiles(certificate *x509.Certificate, privateKey crypto.Signer, certificateFilePath, privateKeyFilePath string) (err error) {
	if certificate == nil {
		err = hqgoerrors.New("invalid input, certificate is nil")

		return err
	}

	if privateKey == nil {
		err = hqgoerrors.New("invalid input, private key is nil")

		return err
	}

	if certificateFilePath == "" || privateKeyFilePath == "" {
		err = hqgoerrors.New("invalid input, certificate file path or private key file path is empty")

		return err
	}

	certificatePublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		err = hqgoerrors.Wrapf(err, "invalid input, certificate public key (type %T) cannot be marshaled", certificate.PublicKey)

		return err
	}

	privateKeyPublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		err = hqgoerrors.Wrapf(err, "invalid input, private key's public key (type %T) cannot be marshaled", privateKey.Public())

		return err
	}

	if !bytes.Equal(certificatePublicKey, privateKeyPublicKey) {
		err = hqgoerrors.New("invalid input, private key does not match the certificate's public key")

		return err
	}

	certificateFilePathDirectory := filepath.Dir(certificateFilePath)

	if err = mkdir(certificateFilePathDirectory); err != nil {
		err = hqgoerrors.Wrapf(err, "creating directory %q for certificate", certificateFilePathDirectory)

		return err
	}

	privateKeyFilePathDirectory := filepath.Dir(privateKeyFilePath)

	if err = mkdir(privateKeyFilePathDirectory); err != nil {
		err = hqgoerrors.Wrapf(err, "creating directory %q for private key", privateKeyFilePathDirectory)

		return err
	}

	certificateBytes, err := CertificateToPEM(certificate)
	if err != nil {
		err = hqgoerrors.Wrap(err, "converting certificate to PEM format")

		return err
	}

	keyBytes, err := PrivateKeyToPEM(privateKey)
	if err != nil {
		err = hqgoerrors.Wrapf(err, "converting private key to PEM format (type %T)", privateKey)

		return err
	}

	if err = writeToFile(certificateBytes, certificateFilePath, 0o600); err != nil {
		err = hqgoerrors.Wrapf(err, "writing certificate to file %q", certificateFilePath)

		return err
	}

	if err = writeToFile(keyBytes, privateKeyFilePath, 0o400); err != nil {
		err = hqgoerrors.Wrapf(err, "writing private key to file %q", privateKeyFilePath)

		return err
	}

	return nil
}

// mkdir creates a directory at the specified path if it does not exist.
//
// The directory is created with permissions 0755 (rwxr-xr-x), suitable for directories containing
// certificate files. If the directory already exists, no action is taken.
func mkdir(path string) (err error) {
	if path == "" {
		err = hqgoerrors.New("invalid input, directory path is empty")

		return err
	}

	if err = os.MkdirAll(path, 0o755); err != nil { //nolint:gosec // G301: certificate directories are deliberately world-traversable (0755); the files within are written 0600
		err = hqgoerrors.Wrapf(err, "creating directory %q with permissions 0755", path)

		return err
	}

	return nil
}

// writeToFile writes the content of a byte slice to a file with the given permissions.
//
// The file ends up with exactly perm permissions — 0600 for certificates and 0400 (read-only)
// for private keys. Because the permissions passed to os.WriteFile apply only when the file is
// created, they are re-applied with os.Chmod after writing so a pre-existing file with looser
// permissions is tightened as well; a pre-existing read-only file (for example a private key
// written 0400 by an earlier call) is first made owner-writable so the write succeeds.
//
// A path that resolves to a symlink is refused: chmod and the write would follow the link and
// modify the link's target instead of the named path.
//
// On Windows, permission bits are not honored beyond the read-only attribute.
func writeToFile(content []byte, path string, perm os.FileMode) (err error) {
	return writeToFileWith(defaultOperations(), content, path, perm)
}

// writeToFileWith writes content to path with the given permissions using
// the supplied filesystem operations.
func writeToFileWith(ops *operations, content []byte, path string, perm os.FileMode) (err error) {
	if path == "" {
		err = hqgoerrors.New("invalid input, file path is empty")

		return err
	}

	if len(content) == 0 {
		err = hqgoerrors.Errorf("invalid input, content to write to file %q is empty", path)

		return err
	}

	// chmod and the write below follow symlinks, so a path that resolves to one
	// would silently redirect the write onto the link's target. Refuse it up
	// front.
	if info, statErr := ops.lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			err = hqgoerrors.Errorf("refusing to write through symlink %q", path)

			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		err = hqgoerrors.Wrapf(statErr, "inspecting file %q before writing", path)

		return err
	}

	// A previous call may have left the file read-only (for example a private
	// key written 0400); make it owner-writable so the write below succeeds.
	if err = ops.chmodBeforeWrite(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		err = hqgoerrors.Wrapf(err, "making pre-existing file %q writable", path)

		return err
	}

	if err = os.WriteFile(path, content, perm); err != nil {
		err = hqgoerrors.Wrapf(err, "writing content to file %q with permissions %04o", path, perm)

		return err
	}

	// os.WriteFile applies the permissions only when creating the file, so
	// re-apply them to tighten a pre-existing file with looser permissions.
	if err = ops.chmodAfterWrite(path, perm); err != nil {
		err = hqgoerrors.Wrapf(err, "setting permissions %04o on file %q", perm, path)

		return err
	}

	return nil
}

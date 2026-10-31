package authority

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadCertificatePrivateKeyFromFiles loads a certificate and private key from the specified PEM-encoded files.
//
// The certificate and private key are loaded using the crypto/tls package. The certificate is parsed to ensure
// it is a valid X.509 certificate, and the private key is verified to implement the crypto.Signer interface
// and to be one of the supported types (RSA, ECDSA, or Ed25519). The function performs input validation and
// provides detailed error messages for debugging purposes.
//
// Parameters:
//   - certificateFilePath (string): the file path to the PEM-encoded certificate.
//   - certificatePrivateKeyFilePath (string): the file path to the PEM-encoded private key.
//
// Returns:
//   - certificate (*x509.Certificate): a pointer to the loaded X.509 certificate.
//   - privateKey (crypto.Signer): the loaded private key, implementing the crypto.Signer interface.
//   - err (error): an error if loading, parsing, or type assertion fails; otherwise, nil.
func LoadCertificatePrivateKeyFromFiles(certificateFilePath, certificatePrivateKeyFilePath string) (certificate *x509.Certificate, privateKey crypto.Signer, err error) {
	return loadCertificatePrivateKeyFromFiles(defaultOperations(), certificateFilePath, certificatePrivateKeyFilePath)
}

// loadCertificatePrivateKeyFromFiles loads and validates a certificate and
// private key pair using the given operations.
//
// Parameters:
//   - ops (*operations): the cryptographic operations to use.
//   - certificateFilePath (string): the file path to the PEM-encoded certificate.
//   - certificatePrivateKeyFilePath (string): the file path to the PEM-encoded private key.
//
// Returns:
//   - certificate (*x509.Certificate): a pointer to the loaded X.509 certificate.
//   - privateKey (crypto.Signer): the loaded private key, implementing the crypto.Signer interface.
//   - err (error): an error if loading, parsing, or type assertion fails; otherwise, nil.
func loadCertificatePrivateKeyFromFiles(ops *operations, certificateFilePath, certificatePrivateKeyFilePath string) (certificate *x509.Certificate, privateKey crypto.Signer, err error) {
	if certificateFilePath == "" || certificatePrivateKeyFilePath == "" {
		err = errors.New("authority.LoadCertificatePrivateKeyFromFiles: invalid input, certificate file path or private key file path is empty")

		return nil, nil, err
	}

	keyPair, err := ops.loadKeyPair(certificateFilePath, certificatePrivateKeyFilePath)
	if err != nil {
		err = fmt.Errorf("authority.LoadCertificatePrivateKeyFromFiles: loading certificate and private key from files %q and %q: %w", certificateFilePath, certificatePrivateKeyFilePath, err)

		return nil, nil, err
	}

	certificate, err = ops.parseCertificate(keyPair.Certificate[0])
	if err != nil {
		err = fmt.Errorf("authority.LoadCertificatePrivateKeyFromFiles: parsing X.509 certificate from file %q: %w", certificateFilePath, err)

		return nil, nil, err
	}

	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		err = fmt.Errorf("authority.LoadCertificatePrivateKeyFromFiles: private key from file %q does not implement crypto.Signer: got type %T", certificatePrivateKeyFilePath, keyPair.PrivateKey)

		return nil, nil, err
	}

	privateKey = signer

	switch privateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		err = fmt.Errorf("authority.LoadCertificatePrivateKeyFromFiles: unsupported private key type in file %q: got %T, expected RSA, ECDSA, or Ed25519", certificatePrivateKeyFilePath, privateKey)

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
//
// Parameters:
//   - certificate (*x509.Certificate): a pointer to the X.509 certificate to save.
//   - privateKey (crypto.Signer): the private key to save, implementing the crypto.Signer interface.
//   - certificateFilePath (string): the file path where the certificate will be saved in PEM format.
//   - privateKeyFilePath (string): the file path where the private key will be saved in PEM format.
//
// Returns:
//   - err (error): an error if the certificate and private key do not match, or directory creation,
//     PEM conversion, or file writing fails; otherwise, nil.
func SaveCertificatePrivateKeyToFiles(certificate *x509.Certificate, privateKey crypto.Signer, certificateFilePath, privateKeyFilePath string) (err error) {
	if certificate == nil {
		err = errors.New("authority.SaveCertificatePrivateKeyToFiles: invalid input, certificate is nil")

		return err
	}

	if privateKey == nil {
		err = errors.New("authority.SaveCertificatePrivateKeyToFiles: invalid input, private key is nil")

		return err
	}

	if certificateFilePath == "" || privateKeyFilePath == "" {
		err = errors.New("authority.SaveCertificatePrivateKeyToFiles: invalid input, certificate file path or private key file path is empty")

		return err
	}

	certificatePublicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		err = fmt.Errorf("authority.SaveCertificatePrivateKeyToFiles: invalid input, certificate public key (type %T) cannot be marshaled: %w", certificate.PublicKey, err)

		return err
	}

	privateKeyPublicKey, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		err = fmt.Errorf("authority.SaveCertificatePrivateKeyToFiles: invalid input, private key's public key (type %T) cannot be marshaled: %w", privateKey.Public(), err)

		return err
	}

	if !bytes.Equal(certificatePublicKey, privateKeyPublicKey) {
		err = errors.New("authority.SaveCertificatePrivateKeyToFiles: invalid input, private key does not match the certificate's public key")

		return err
	}

	certificateFilePathDirectory := filepath.Dir(certificateFilePath)

	if err = mkdir(certificateFilePathDirectory); err != nil {
		err = fmt.Errorf("authority.SaveCertificatePrivateKeyToFiles: creating directory %q for certificate: %w", certificateFilePathDirectory, err)

		return err
	}

	privateKeyFilePathDirectory := filepath.Dir(privateKeyFilePath)

	if err = mkdir(privateKeyFilePathDirectory); err != nil {
		err = fmt.Errorf("authority.SaveCertificatePrivateKeyToFiles: creating directory %q for private key: %w", privateKeyFilePathDirectory, err)

		return err
	}

	certificateBytes, err := CertificateToPEM(certificate)
	if err != nil {
		err = fmt.Errorf("authority.SaveCertificatePrivateKeyToFiles: converting certificate to PEM format: %w", err)

		return err
	}

	keyBytes, err := PrivateKeyToPEM(privateKey)
	if err != nil {
		err = fmt.Errorf("authority.SaveCertificatePrivateKeyToFiles: converting private key to PEM format (type %T): %w", privateKey, err)

		return err
	}

	if err = writeToFile(certificateBytes, certificateFilePath, 0o600); err != nil {
		err = fmt.Errorf("authority.SaveCertificatePrivateKeyToFiles: writing certificate to file %q: %w", certificateFilePath, err)

		return err
	}

	if err = writeToFile(keyBytes, privateKeyFilePath, 0o400); err != nil {
		err = fmt.Errorf("authority.SaveCertificatePrivateKeyToFiles: writing private key to file %q: %w", privateKeyFilePath, err)

		return err
	}

	return nil
}

// mkdir creates a directory at the specified path if it does not exist.
//
// The directory is created with permissions 0755 (rwxr-xr-x), suitable for directories containing
// certificate files. If the directory already exists, no action is taken.
//
// Parameters:
//   - path (string): the file system path for the directory to create.
//
// Returns:
//   - err (error): an error if directory creation fails; otherwise, nil.
func mkdir(path string) (err error) {
	if path == "" {
		err = errors.New("authority.mkdir: invalid input, directory path is empty")

		return err
	}

	if err = os.MkdirAll(path, 0o755); err != nil { //nolint:gosec // G301: certificate directories are deliberately world-traversable (0755); the files within are written 0600
		err = fmt.Errorf("authority.mkdir: creating directory %q with permissions 0755: %w", path, err)

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
//
// Parameters:
//   - content ([]byte): a byte slice containing the data to write.
//   - path (string): the file path where the content will be written.
//   - perm (os.FileMode): the permissions the file must have after writing.
//
// Returns:
//   - err (error): an error if the path is a symlink or file writing or permission setting fails; otherwise, nil.
func writeToFile(content []byte, path string, perm os.FileMode) (err error) {
	return writeToFileWith(defaultOperations(), content, path, perm)
}

// writeToFileWith writes content to path with the given permissions using
// the supplied filesystem operations.
//
// Parameters:
//   - ops (*operations): the filesystem operations to use.
//   - content ([]byte): a byte slice containing the data to write.
//   - path (string): the file path where the content will be written.
//   - perm (os.FileMode): the permissions the file must have after writing.
//
// Returns:
//   - err (error): an error if the path is a symlink or file writing or permission setting fails; otherwise, nil.
func writeToFileWith(ops *operations, content []byte, path string, perm os.FileMode) (err error) {
	if path == "" {
		err = errors.New("authority.writeToFile: invalid input, file path is empty")

		return err
	}

	if len(content) == 0 {
		err = fmt.Errorf("authority.writeToFile: invalid input, content to write to file %q is empty", path)

		return err
	}

	// chmod and the write below follow symlinks, so a path that resolves to one
	// would silently redirect the write onto the link's target. Refuse it up
	// front.
	if info, statErr := ops.lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			err = fmt.Errorf("authority.writeToFile: refusing to write through symlink %q", path)

			return err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		err = fmt.Errorf("authority.writeToFile: inspecting file %q before writing: %w", path, statErr)

		return err
	}

	// A previous call may have left the file read-only (for example a private
	// key written 0400); make it owner-writable so the write below succeeds.
	if err = ops.chmodBeforeWrite(path, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
		err = fmt.Errorf("authority.writeToFile: making pre-existing file %q writable: %w", path, err)

		return err
	}

	if err = os.WriteFile(path, content, perm); err != nil {
		err = fmt.Errorf("authority.writeToFile: writing content to file %q with permissions %04o: %w", path, perm, err)

		return err
	}

	// os.WriteFile applies the permissions only when creating the file, so
	// re-apply them to tighten a pre-existing file with looser permissions.
	if err = ops.chmodAfterWrite(path, perm); err != nil {
		err = fmt.Errorf("authority.writeToFile: setting permissions %04o on file %q: %w", perm, path, err)

		return err
	}

	return nil
}

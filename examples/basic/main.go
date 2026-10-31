package main

import (
	"fmt"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

func main() {
	certificate, privateKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
		hqgotlsauthority.WithCACommonName("Example CA"),
	)
	if err != nil {
		fmt.Println("generate:", err)

		return
	}

	fmt.Println(certificate.Subject.CommonName, privateKey.Public() != nil)
}

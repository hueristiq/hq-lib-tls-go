package main

import (
	"fmt"

	hqgotlsauthority "github.com/hueristiq/hq-lib-tls-go/authority"
)

func main() {
	caCertificate, caPrivateKey, err := hqgotlsauthority.GenerateCACertificatePrivateKey(
		hqgotlsauthority.WithCACommonName("Example CA"),
	)
	if err != nil {
		fmt.Println("ca:", err)

		return
	}

	ca, err := hqgotlsauthority.New(caCertificate, caPrivateKey)
	if err != nil {
		fmt.Println("authority:", err)

		return
	}

	leaf, _, err := ca.GenerateTLSCertificate(
		[]string{"example.com"},
		hqgotlsauthority.WithTLSCommonName("example.com"),
	)

	fmt.Println(leaf.Subject.CommonName, err)
}

//nolint:testpackage // tests exercise unexported behavior.
package fingerprint

import "fmt"

func ExampleDigest() {
	fmt.Println(Digest("771,4865-49199,10-11,29-23,0"))

	// Output: 0137629f27baa8ccd5625beedf3b60db
}

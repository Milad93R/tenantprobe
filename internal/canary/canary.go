// Package canary builds synthetic tenants, each holding a unique canary secret.
//
// A canary is a high-entropy code embedded in a "confidential" document. If the
// probe ever sees one tenant's canary surface while attacking as another tenant,
// that is a cross-tenant leak.
package canary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// CanaryFmt is the exact document format seeded for each tenant. It mirrors the
// validated Python v0.1 (tenantprobe/core.py) so behaviour is identical.
const CanaryFmt = "%s confidential internal secret: %s DO NOT LEAK"

// Tenant is a synthetic tenant with a unique canary code and canary document.
type Tenant struct {
	ID   string // e.g. "Tenant-A"
	Code string // e.g. "TENANTA-1A2B3C4D"
	Doc  string // the seeded canary document text
}

// randHex returns n bytes of crypto-random data as uppercase hex (2*n chars).
func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should never fail on a sane system; panic surfaces it loudly.
		panic(fmt.Sprintf("canary: crypto/rand failed: %v", err))
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// RandCode returns a fresh 8-hex-char canary suffix (4 crypto-random bytes),
// matching the suffix MakeTenants embeds. Exported so scenario-driven tenants
// generate codes in the identical format the canary detector expects.
func RandCode() string { return randHex(4) }

// MakeTenants returns n tenants named Tenant-A, Tenant-B, ... each with a unique
// canary code of the form TENANTB-<8HEX> and a canary document.
func MakeTenants(n int) []Tenant {
	tenants := make([]Tenant, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("Tenant-%c", 'A'+i) // Tenant-A, Tenant-B, ...
		bare := strings.ToUpper(strings.ReplaceAll(name, "-", ""))
		code := fmt.Sprintf("%s-%s", bare, randHex(4)) // 4 bytes => 8 hex chars
		doc := fmt.Sprintf(CanaryFmt, name, code)
		tenants = append(tenants, Tenant{ID: name, Code: code, Doc: doc})
	}
	return tenants
}

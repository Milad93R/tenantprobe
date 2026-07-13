// Package adapter abstracts the multi-tenant target under test.
//
// The probe drives targets exclusively through the Adapter interface, so new
// transports can be added without touching the orchestrator.
package adapter

// Citation is a single retrieved-document reference returned by a Chat call.
type Citation struct {
	DocID    string `json:"doc_id"`
	TenantID string `json:"tenant_id"`
}

// Adapter is a swappable transport to a multi-tenant RAG/agent API.
type Adapter interface {
	// Reset clears any seeded state on the target.
	Reset() error
	// Seed stores a document for a tenant.
	Seed(tenantID, docID, text string) error
	// Chat asks a query as a tenant and returns the answer plus citations.
	Chat(tenantID, query string, topK int) (answer string, citations []Citation, err error)
}

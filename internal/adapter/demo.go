package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DemoAdapter targets the native demo contract (demo_app/app.py):
//
//	POST /reset
//	POST /seed  {tenant_id, doc_id, text}
//	POST /chat  {tenant_id, query, top_k} -> {answer, citations:[{doc_id,tenant_id}]}
type DemoAdapter struct {
	BaseURL string
	Client  *http.Client
}

// NewDemoAdapter builds a DemoAdapter for baseURL with a sane default timeout.
func NewDemoAdapter(baseURL string) *DemoAdapter {
	return &DemoAdapter{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client:  &http.Client{Timeout: 15 * time.Second},
	}
}

// post sends a JSON body to path and decodes the JSON response into out (if non-nil).
func (d *DemoAdapter) post(path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal %s: %w", path, err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequest(http.MethodPost, d.BaseURL+path, reader)
	if err != nil {
		return fmt.Errorf("new request %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.Client.Do(req)
	if err != nil {
		return fmt.Errorf("post %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("post %s: status %d: %s", path, resp.StatusCode, snippet)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// Reset clears the target's store.
func (d *DemoAdapter) Reset() error {
	return d.post("/reset", struct{}{}, nil)
}

// Seed stores a document for a tenant.
func (d *DemoAdapter) Seed(tenantID, docID, text string) error {
	return d.post("/seed", map[string]any{
		"tenant_id": tenantID,
		"doc_id":    docID,
		"text":      text,
	}, nil)
}

type chatResponse struct {
	Answer    string     `json:"answer"`
	Citations []Citation `json:"citations"`
}

// Chat queries the target as a tenant.
func (d *DemoAdapter) Chat(tenantID, query string, topK int) (string, []Citation, error) {
	var out chatResponse
	err := d.post("/chat", map[string]any{
		"tenant_id": tenantID,
		"query":     query,
		"top_k":     topK,
	}, &out)
	if err != nil {
		return "", nil, err
	}
	return out.Answer, out.Citations, nil
}

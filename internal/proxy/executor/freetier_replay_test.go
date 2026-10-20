package executor

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestIsFreeTierResponse(t *testing.T) {
	t.Run("nil response returns false", func(t *testing.T) {
		isFreeTier, err := IsFreeTierResponse(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isFreeTier {
			t.Errorf("expected false, got true")
		}
	})

	t.Run("status 200 returns false", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"result":"ok"}`))),
		}
		isFreeTier, err := IsFreeTierResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isFreeTier {
			t.Errorf("expected false, got true")
		}
	})

	t.Run("status 403 with other body returns false", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(bytes.NewReader([]byte(`{"error":"insufficient_quota"}`))),
		}
		isFreeTier, err := IsFreeTierResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isFreeTier {
			t.Errorf("expected false, got true")
		}
		// Check that body can still be read
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("failed to re-read body: %v", readErr)
		}
		if string(body) != `{"error":"insufficient_quota"}` {
			t.Errorf("body was not restored properly, got %q", string(body))
		}
	})

	t.Run("status 403 with FreeTierError returns true and restores body", func(t *testing.T) {
		payload := `{"error":{"type":"FreeTierError","message":"Download it at https://opencode.ai"}}`
		resp := &http.Response{
			StatusCode: http.StatusForbidden,
			Body:       io.NopCloser(bytes.NewReader([]byte(payload))),
		}
		isFreeTier, err := IsFreeTierResponse(resp)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isFreeTier {
			t.Errorf("expected true, got false")
		}
		// Verify body can still be read
		body, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			t.Fatalf("failed to re-read body: %v", readErr)
		}
		if string(body) != payload {
			t.Errorf("body was not restored properly, got %q, expected %q", string(body), payload)
		}
	})
}

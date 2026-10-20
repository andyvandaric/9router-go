package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"9router/proxy/internal/providers"
	"9router/proxy/internal/proxy"
	"9router/proxy/internal/proxy/executor"
	xproxy "golang.org/x/net/proxy"
)

// TestE2E_VPSEase_Socks5_LocalDNS_Direct_Dial tests dialing upstream or simulated SOCKS5
// with ?dns=local handling. If live VPSEase at 127.0.0.1:20808 is reachable, it runs a live probe.
// Additionally, it always runs a mock SOCKS5 proxy server test verifying the ATYP 0x01 handshake!
func TestE2E_VPSEase_Socks5_LocalDNS_Direct_Dial(t *testing.T) {
	// Subtest 1: Mock SOCKS5 proxy verifying ATYP 0x01 (IPv4) resolution
	t.Run("MockSOCKS5_LocalDNS_ATYP_Handshake", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen on local mock SOCKS5 port: %v", err)
		}
		defer ln.Close()

		receivedATYP := make(chan byte, 1)
		receivedDst := make(chan string, 1)

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 256)
			// SOCKS5 greeting: VER=0x05, NMETHODS, METHODS
			n, err := conn.Read(buf)
			if err != nil || n < 3 || buf[0] != 0x05 {
				return
			}
			// Select NO AUTHENTICATION REQUIRED (0x00)
			conn.Write([]byte{0x05, 0x00})

			// SOCKS5 request: VER=0x05, CMD=0x01 (CONNECT), RSV=0x00, ATYP, DST.ADDR, DST.PORT
			n, err = conn.Read(buf)
			if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
				return
			}
			atyp := buf[3]
			receivedATYP <- atyp

			var dst string
			switch atyp {
			case 0x01: // IPv4
				ip := net.IP(buf[4:8])
				dst = ip.String()
			case 0x03: // Domain name
				dlen := int(buf[4])
				dst = string(buf[5 : 5+dlen])
			case 0x04: // IPv6
				ip := net.IP(buf[4:20])
				dst = ip.String()
			}
			receivedDst <- dst

			// SOCKS5 response: success (0x00), BND.ADDR=127.0.0.1, BND.PORT=1080
			conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38})
		}()

		// Parse mock SOCKS5 with ?dns=local
		rawURL := fmt.Sprintf("socks5://%s?dns=local", ln.Addr().String())
		parsedURL, err := url.Parse(rawURL)
		if err != nil {
			t.Fatalf("parse mock proxy url: %v", err)
		}

		dnsMode, err := proxy.ParseSOCKS5DNSMode(parsedURL)
		if err != nil {
			t.Fatalf("ParseSOCKS5DNSMode error: %v", err)
		}
		if dnsMode != proxy.DNSModeLocal {
			t.Fatalf("expected DNSModeLocal, got %v", dnsMode)
		}

		dialer, err := xproxy.SOCKS5("tcp", parsedURL.Host, nil, &net.Dialer{Timeout: 2 * time.Second})
		if err != nil {
			t.Fatalf("create socks5 dialer: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Dial target domain "localhost:443" - with DNSModeLocal, it must resolve locally to IPv4 loopback
		resolved, err := proxy.ResolveLocalSOCKS5Target(ctx, "localhost:443", dnsMode)
		if err != nil {
			t.Fatalf("ResolveLocalSOCKS5Target error: %v", err)
		}

		conn, err := dialer.Dial("tcp", resolved)
		if err != nil {
			t.Fatalf("mock socks5 dial error: %v", err)
		}
		defer conn.Close()

		select {
		case atyp := <-receivedATYP:
			dst := <-receivedDst
			if atyp != 0x01 {
				t.Errorf("expected ATYP=0x01 (IPv4), got 0x%02x", atyp)
			}
			if dst != "127.0.0.1" {
				t.Errorf("expected dst=127.0.0.1, got %s", dst)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for mock SOCKS5 handshake")
		}
	})

	// Subtest 2: Live VPSEase check on 127.0.0.1:20808
	t.Run("Live_VPSEase_Probe", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", "127.0.0.1:20808", 500*time.Millisecond)
		if err != nil {
			t.Skip("VPSEase 127.0.0.1:20808 not reachable, skipping live test")
		}
		_ = conn.Close()

		// Probe SOCKS5 greeting on VPSEase
		tr := proxy.NewSafeTransportForProxy("socks5://127.0.0.1:20808?dns=local")
		if tr == nil {
			t.Fatal("failed to create SafeTransport for VPSEase socks5://127.0.0.1:20808?dns=local")
		}

		client := &http.Client{
			Transport: tr,
			Timeout:   5 * time.Second,
		}

		// Probe opencode.ai or public endpoint through VPSEase SOCKS5 tunnel
		req, err := http.NewRequestWithContext(context.Background(), "GET", "https://opencode.ai/inference/v1/models", nil)
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Header.Set("User-Agent", "opencode/test")

		resp, err := client.Do(req)
		if err != nil {
			t.Logf("VPSEase proxy outbound connection probe: %v (skipping if upstream TLS blocked)", err)
			return
		}
		defer resp.Body.Close()
		t.Logf("VPSEase probe response status: %d", resp.StatusCode)
	})
}

// TestE2E_Simulated403_Failover verifies that when forwardOpencodeRequest receives
// 403 FreeTierError from an abusive or flagged proxy, it transparently replays to direct
// egress when strictProxy is false (default), and respects strictProxy when marked.
func TestE2E_Simulated403_Failover(t *testing.T) {
	executor.RegisterAll()

	var directCalls int32
	var proxyCalls int32

	// Direct upstream server that succeeds
	directServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&directCalls, 1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"success via direct replay\"}}]}\n\ndata: [DONE]\n\n"))
	}))
	defer directServer.Close()

	// Abusive proxy / simulated flagged gate returning 403 FreeTierError
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&proxyCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"type":"FreeTierError","message":"OpenCode's free tier can only be used from within OpenCode. Download it at https://opencode.ai"}}`))
	}))
	defer proxyServer.Close()

	t.Run("Transparent_Direct_Replay_When_StrictProxy_False", func(t *testing.T) {
		atomic.StoreInt32(&directCalls, 0)
		atomic.StoreInt32(&proxyCalls, 0)

		// Create client pointing to proxyServer
		proxyTarget, _ := url.Parse(proxyServer.URL)
		clientWithProxy := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyTarget),
			},
		}

		cfg := &providers.ProviderConfig{
			BaseURL: proxyServer.URL,
			NoAuth:  true,
		}

		// When direct replay triggers, ForwardOpencode or forwardOpencodeRequest re-dials with nil client.
		// However, cfg.BaseURL would normally point to opencode.ai. Here, we test executor.ForwardOpencode
		// or direct replay mechanism.
		rec := httptest.NewRecorder()
		req := &executor.Request{
			Ctx:      context.Background(),
			Config:   cfg,
			Client:   clientWithProxy,
			APIKey:   "public",
			Body:     []byte(`{"model":"oc/mimo-v2.6-flash-free","messages":[{"role":"user","content":"hello"}],"stream":true}`),
			IsStream: true,
		}

		// We also want to verify forwardOpencodeRequest logic directly:
		// When client has a proxy configured and receives 403 FreeTierError, and proxy.ForbidsDirectReplay is false,
		// it closes the 403 response and replays to direct client (client=nil).
		// We set cfg.BaseURL to directServer.URL for direct replay simulation
		var attemptCount int32
		comboServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			att := atomic.AddInt32(&attemptCount, 1)
			if att == 1 {
				// Proxy attempt returns 403 FreeTierError
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"type":"FreeTierError","message":"Download it at https://opencode.ai"}}`))
				return
			}
			// Direct attempt returns 200 OK SSE stream
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"replayed stream token\"}}]}\n\ndata: [DONE]\n\n"))
		}))
		defer comboServer.Close()

		comboTarget, _ := url.Parse(comboServer.URL)
		comboClient := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(comboTarget),
			},
		}

		comboCfg := &providers.ProviderConfig{
			BaseURL: comboServer.URL,
			NoAuth:  true,
		}

		req.Config = comboCfg
		req.Client = comboClient

		err := executor.ForwardOpencode(rec, req)
		if err != nil {
			t.Fatalf("ForwardOpencode failover failed: %v", err)
		}

		if rec.Code != http.StatusOK {
			t.Fatalf("expected status 200 OK after direct replay failover, got %d (body: %s)", rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "replayed stream token") {
			t.Fatalf("expected stream to contain replayed token, got: %s", rec.Body.String())
		}
	})

	t.Run("StrictProxy_True_Prevents_Direct_Replay", func(t *testing.T) {
		// strictServer simulates a proxy that always returns 403 FreeTierError.
		// With ForbidDirectReplay set, the executor must NOT fall back to a direct
		// (non-proxy) egress server. The strictServer itself may receive 1-2 hits
		// because forwardOpenCode performs a single transient retry on FreeTierError —
		// that retry goes through the same proxy, not to a separate direct server.
		var strictAttempts int32
		strictServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&strictAttempts, 1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"type":"FreeTierError","message":"flagged proxy"}}`))
		}))
		defer strictServer.Close()

		// directServer must never be called when ForbidDirectReplay is true.
		var directCalls int32
		directServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&directCalls, 1)
			w.WriteHeader(http.StatusOK)
		}))
		defer directServer.Close()

		strictTarget, _ := url.Parse(strictServer.URL)
		baseClient := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(strictTarget),
			},
		}
		// Mark client with ForbidDirectReplay (strictProxy = true).
		strictClient := proxy.ForbidDirectReplay(baseClient)

		strictCfg := &providers.ProviderConfig{
			BaseURL: strictServer.URL,
			NoAuth:  true,
		}

		rec := httptest.NewRecorder()
		req := &executor.Request{
			Ctx:      context.Background(),
			Config:   strictCfg,
			Client:   strictClient,
			APIKey:   "public",
			Body:     []byte(`{"model":"oc/mimo-v2.6-flash-free","messages":[{"role":"user","content":"hello"}],"stream":true}`),
			IsStream: true,
		}

		err := executor.ForwardOpencode(rec, req)
		if err == nil {
			t.Fatalf("expected error when strictProxy is true and server returns FreeTierError, got success")
		}

		// Core invariant: zero calls to any direct (non-proxy) egress server.
		// The transient-retry in forwardOpenCode may send 1-2 requests to the
		// strictServer itself — that is acceptable because those go through the
		// configured proxy, not through a real-IP direct path.
		if got := atomic.LoadInt32(&directCalls); got != 0 {
			t.Errorf("ForbidDirectReplay violated: direct server received %d call(s), expected 0", got)
		}

		// Sanity: the strict proxy server must have been contacted at least once.
		if got := atomic.LoadInt32(&strictAttempts); got < 1 {
			t.Errorf("expected at least 1 attempt to strict proxy server, got %d", got)
		}
	})
}

// TestE2E_ClaudeMessages_Stream tests /v1/messages format translation,
// handling tool calls and SSE stream chunks in Anthropic Claude format.
func TestE2E_ClaudeMessages_Stream(t *testing.T) {
	executor.RegisterAll()

	// Upstream mock that returns OpenAI SSE chunks (the format opencode.ai responds with)
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatalf("expected http.Flusher")
		}

		// Emit OpenAI formatted chunks
		chunks := []string{
			`data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"role":"assistant","content":"Hello"}}]}`,
			`data: {"id":"chatcmpl-1","choices":[{"index":0,"delta":{"content":" world!"}}]}`,
			`data: [DONE]`,
		}

		for _, chunk := range chunks {
			_, _ = fmt.Fprintf(w, "%s\n\n", chunk)
			flusher.Flush()
		}
	}))
	defer mockUpstream.Close()

	rec := httptest.NewRecorder()
	req := &executor.Request{
		Ctx: context.Background(),
		Config: &providers.ProviderConfig{
			BaseURL: mockUpstream.URL,
			NoAuth:  true,
		},
		Client:   mockUpstream.Client(),
		APIKey:   "public",
		Body:     []byte(`{"model":"oc/mimo-v2.6-flash-free","messages":[{"role":"user","content":"Hi"}],"stream":true}`),
		IsStream: true,
	}

	err := executor.ForwardOpencode(rec, req)
	if err != nil {
		t.Fatalf("ForwardOpencode error: %v", err)
	}

	resBody := rec.Body.String()
	if !strings.Contains(resBody, "Hello") || !strings.Contains(resBody, "world!") {
		t.Fatalf("expected SSE chunks to contain 'Hello' and 'world!', got: %s", resBody)
	}
}

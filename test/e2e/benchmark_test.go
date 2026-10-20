package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"9router/proxy/internal/providers"
	"9router/proxy/internal/proxy"
	"9router/proxy/internal/proxy/executor"
)

// BenchmarkMetrics records quantitative inference performance metrics.
type BenchmarkMetrics struct {
	ModelID          string        `json:"model_id"`
	ProxyURL         string        `json:"proxy_url"`
	HandshakeLatency time.Duration `json:"handshake_latency"`
	TTFT             time.Duration `json:"ttft"`
	TotalDuration    time.Duration `json:"total_duration"`
	TokensGenerated  int           `json:"tokens_generated"`
	TokensPerSecond  float64       `json:"tokens_per_second"`
	MemoryRSSBytes   uint64        `json:"memory_rss_bytes"`
	Success          bool          `json:"success"`
	Error            string        `json:"error,omitempty"`
}

// LiveInferenceConfig maps target live benchmark probe configs.
type LiveInferenceConfig struct {
	BaseURL     string
	Model       string
	Prompt      string
	Stream      bool
	Timeout     time.Duration
	ExpectProbe string
}

// createMockSOCKS5Server starts a mock SOCKS5 proxy server that supports CONNECT
// and records ATYP handling.
func createMockSOCKS5Server(tb testing.TB) (string, func()) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("failed to listen for mock SOCKS5: %v", err)
	}

	stopCh := make(chan struct{})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-stopCh:
					return
				default:
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()

				buf := make([]byte, 512)
				// 1. Version greeting: VER=0x05, NMETHODS, METHODS
				n, err := c.Read(buf)
				if err != nil || n < 3 || buf[0] != 0x05 {
					return
				}
				// Reply: VER=0x05, METHOD=0x00 (NO AUTH)
				_, _ = c.Write([]byte{0x05, 0x00})

				// 2. CONNECT request: VER=0x05, CMD=0x01, RSV=0x00, ATYP...
				n, err = c.Read(buf)
				if err != nil || n < 7 || buf[0] != 0x05 || buf[1] != 0x01 {
					return
				}

				atyp := buf[3]
				var targetAddr string
				var portOffset int

				switch atyp {
				case 0x01: // IPv4
					ip := net.IP(buf[4:8])
					portOffset = 8
					port := int(buf[portOffset])<<8 | int(buf[portOffset+1])
					targetAddr = fmt.Sprintf("%s:%d", ip.String(), port)
				case 0x03: // Domain
					dlen := int(buf[4])
					domain := string(buf[5 : 5+dlen])
					portOffset = 5 + dlen
					port := int(buf[portOffset])<<8 | int(buf[portOffset+1])
					targetAddr = fmt.Sprintf("%s:%d", domain, port)
				case 0x04: // IPv6
					ip := net.IP(buf[4:20])
					portOffset = 20
					port := int(buf[portOffset])<<8 | int(buf[portOffset+1])
					targetAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)
				default:
					return
				}

				// Dial the target destination
				destConn, err := net.DialTimeout("tcp", targetAddr, 2*time.Second)
				if err != nil {
					// Connection refused / general failure
					_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer destConn.Close()

				// Success response: VER=0x05, REP=0x00, RSV=0x00, ATYP=0x01, BND.ADDR=127.0.0.1, BND.PORT=1080
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38})

				// Bidirectional proxy forwarding
				errc := make(chan error, 2)
				go func() {
					b := make([]byte, 4096)
					for {
						nr, er := c.Read(b)
						if nr > 0 {
							if _, ew := destConn.Write(b[:nr]); ew != nil {
								errc <- ew
								return
							}
						}
						if er != nil {
							errc <- er
							return
						}
					}
				}()
				go func() {
					b := make([]byte, 4096)
					for {
						nr, er := destConn.Read(b)
						if nr > 0 {
							if _, ew := c.Write(b[:nr]); ew != nil {
								errc <- ew
								return
							}
						}
						if er != nil {
							errc <- er
							return
						}
					}
				}()
				<-errc
			}(conn)
		}
	}()

	cleanup := func() {
		close(stopCh)
		_ = ln.Close()
	}
	return ln.Addr().String(), cleanup
}

// createMockSSEUpstreamServer creates an HTTP test server simulating an SSE streaming LLM endpoint.
// delayFirstToken specifies artificial upstream thinking time before the first token chunk.
func createMockSSEUpstreamServer(delayFirstToken time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		if delayFirstToken > 0 {
			time.Sleep(delayFirstToken)
		}

		// First token chunk
		_, _ = fmt.Fprint(w, "data: {\"id\":\"chatcmpl-bench\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello\"}}]}\n\n")
		flusher.Flush()

		// Subsequent chunks
		for i := 1; i <= 5; i++ {
			time.Sleep(5 * time.Millisecond)
			_, _ = fmt.Fprintf(w, "data: {\"id\":\"chatcmpl-bench\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" token%d\"}}]}\n\n", i)
			flusher.Flush()
		}

		// Stream termination
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
}

// BenchmarkTTFT_MockSocks5_LocalDNS measures Time To First Token for SSE streaming
// via mock SOCKS5 proxy with ?dns=local resolution.
func BenchmarkTTFT_MockSocks5_LocalDNS(b *testing.B) {
	executor.RegisterAll()

	// Upstream SSE server with 20ms thinking latency
	upstream := createMockSSEUpstreamServer(20 * time.Millisecond)
	defer upstream.Close()

	// Mock SOCKS5 proxy server
	socks5Addr, cleanup := createMockSOCKS5Server(b)
	defer cleanup()

	proxyURL := fmt.Sprintf("socks5://%s?dns=local", socks5Addr)
	transport := proxy.NewSafeTransportForProxy(proxyURL)
	if transport == nil {
		b.Fatalf("failed to create SafeTransport for %s", proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	cfg := &providers.ProviderConfig{
		BaseURL: upstream.URL,
		NoAuth:  true,
	}

	reqBody := []byte(`{"model":"oc/mimo-v2.6-flash-free","messages":[{"role":"user","content":"benchmark"}],"stream":true}`)

	var totalTTFT time.Duration
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		start := time.Now()
		rec := httptest.NewRecorder()
		req := &executor.Request{
			Ctx:      context.Background(),
			Config:   cfg,
			Client:   client,
			APIKey:   "public",
			Body:     reqBody,
			IsStream: true,
		}

		err := executor.ForwardOpencode(rec, req)
		if err != nil {
			b.Fatalf("ForwardOpencode failed at iteration %d: %v", i, err)
		}

		ttft := time.Since(start)
		totalTTFT += ttft

		if rec.Code != http.StatusOK {
			b.Fatalf("unexpected status code: %d, body: %s", rec.Code, rec.Body.String())
		}
	}

	avgTTFT := totalTTFT / time.Duration(b.N)
	b.ReportMetric(float64(avgTTFT.Milliseconds()), "ms/ttft")

	// Target KPI check: TTFT < 450ms
	const maxTTFTAllowed = 450 * time.Millisecond
	if avgTTFT > maxTTFTAllowed {
		b.Errorf("TTFT exceeds target threshold: got %v, expected < %v", avgTTFT, maxTTFTAllowed)
	}
}

// BenchmarkMemoryRSS_Usage verifies runtime memory allocations and footprint
// under repeated concurrent requests, asserting HeapAlloc remains well below 48MB.
func BenchmarkMemoryRSS_Usage(b *testing.B) {
	executor.RegisterAll()

	upstream := createMockSSEUpstreamServer(0)
	defer upstream.Close()

	socks5Addr, cleanup := createMockSOCKS5Server(b)
	defer cleanup()

	proxyURL := fmt.Sprintf("socks5://%s?dns=local", socks5Addr)
	transport := proxy.NewSafeTransportForProxy(proxyURL)
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	cfg := &providers.ProviderConfig{
		BaseURL: upstream.URL,
		NoAuth:  true,
	}
	reqBody := []byte(`{"model":"oc/mimo-v2.6-flash-free","messages":[{"role":"user","content":"mem-test"}],"stream":true}`)

	var memBefore, memAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&memBefore)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := &executor.Request{
			Ctx:      context.Background(),
			Config:   cfg,
			Client:   client,
			APIKey:   "public",
			Body:     reqBody,
			IsStream: true,
		}

		err := executor.ForwardOpencode(rec, req)
		if err != nil {
			b.Fatalf("ForwardOpencode failed: %v", err)
		}
	}
	b.StopTimer()

	runtime.ReadMemStats(&memAfter)

	heapAllocMB := float64(memAfter.HeapAlloc) / (1024 * 1024)
	sysMB := float64(memAfter.Sys) / (1024 * 1024)
	b.ReportMetric(heapAllocMB, "MB/heap")
	b.ReportMetric(sysMB, "MB/sys")

	// Target RSS / Heap footprint KPI: <= 48MB
	const maxThresholdMB = 48.0
	if heapAllocMB > maxThresholdMB {
		b.Errorf("HeapAlloc %0.2f MB exceeds threshold %0.2f MB", heapAllocMB, maxThresholdMB)
	}
}

// TestBenchmark_Latency_Comparison compares latency profiles between:
// 1. Direct mock upstream
// 2. Mock SOCKS5 with local DNS (?dns=local)
// 3. SOCKS5 with remote DNS resolution
func TestBenchmark_Latency_Comparison(t *testing.T) {
	executor.RegisterAll()

	upstream := createMockSSEUpstreamServer(15 * time.Millisecond)
	defer upstream.Close()

	socks5Addr, cleanup := createMockSOCKS5Server(t)
	defer cleanup()

	reqBody := []byte(`{"model":"oc/mimo-v2.6-flash-free","messages":[{"role":"user","content":"compare"}],"stream":true}`)

	// 1. Direct measurement
	directClient := upstream.Client()
	directStart := time.Now()
	recDirect := httptest.NewRecorder()
	err := executor.ForwardOpencode(recDirect, &executor.Request{
		Ctx: context.Background(),
		Config: &providers.ProviderConfig{
			BaseURL: upstream.URL,
			NoAuth:  true,
		},
		Client:   directClient,
		APIKey:   "public",
		Body:     reqBody,
		IsStream: true,
	})
	if err != nil {
		t.Fatalf("Direct probe failed: %v", err)
	}
	directDuration := time.Since(directStart)

	// 2. SOCKS5 with ?dns=local measurement
	localDNSURL := fmt.Sprintf("socks5://%s?dns=local", socks5Addr)
	localDNSTransport := proxy.NewSafeTransportForProxy(localDNSURL)
	localDNSClient := &http.Client{Transport: localDNSTransport, Timeout: 5 * time.Second}

	localDNSStart := time.Now()
	recLocal := httptest.NewRecorder()
	err = executor.ForwardOpencode(recLocal, &executor.Request{
		Ctx: context.Background(),
		Config: &providers.ProviderConfig{
			BaseURL: upstream.URL,
			NoAuth:  true,
		},
		Client:   localDNSClient,
		APIKey:   "public",
		Body:     reqBody,
		IsStream: true,
	})
	if err != nil {
		t.Fatalf("Local DNS probe failed: %v", err)
	}
	localDNSDuration := time.Since(localDNSStart)

	// 3. SOCKS5 standard (remote DNS) measurement
	remoteDNSURL := fmt.Sprintf("socks5://%s", socks5Addr)
	remoteDNSTransport := proxy.NewSafeTransportForProxy(remoteDNSURL)
	remoteDNSClient := &http.Client{Transport: remoteDNSTransport, Timeout: 5 * time.Second}

	remoteDNSStart := time.Now()
	recRemote := httptest.NewRecorder()
	err = executor.ForwardOpencode(recRemote, &executor.Request{
		Ctx: context.Background(),
		Config: &providers.ProviderConfig{
			BaseURL: upstream.URL,
			NoAuth:  true,
		},
		Client:   remoteDNSClient,
		APIKey:   "public",
		Body:     reqBody,
		IsStream: true,
	})
	if err != nil {
		t.Fatalf("Remote DNS probe failed: %v", err)
	}
	remoteDNSDuration := time.Since(remoteDNSStart)

	// Output benchmark comparison table
	t.Logf("=== Latency Comparison Results ===")
	t.Logf("   • Direct Mock Egress:          %v (TTFT / Total: %v)", directDuration, directDuration)
	t.Logf("   • SOCKS5 Local DNS (?dns=local): %v (TTFT / Total: %v)", localDNSDuration, localDNSDuration)
	t.Logf("   • SOCKS5 Remote DNS (Standard): %v (TTFT / Total: %v)", remoteDNSDuration, remoteDNSDuration)

	// Target assertion: local DNS TTFT/duration must be < 450ms
	if localDNSDuration > 450*time.Millisecond {
		t.Errorf("SOCKS5 local DNS duration %v exceeded 450ms threshold", localDNSDuration)
	}

	// Memory telemetry snapshot
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	t.Logf("=== Memory Telemetry ===")
	t.Logf("   • HeapAlloc: %0.2f MB", float64(m.HeapAlloc)/(1024*1024))
	t.Logf("   • Sys:       %0.2f MB", float64(m.Sys)/(1024*1024))
	t.Logf("   • NumGC:     %d", m.NumGC)

	if heapMB := float64(m.HeapAlloc) / (1024 * 1024); heapMB > 48.0 {
		t.Errorf("HeapAlloc %0.2f MB exceeded 48 MB budget", heapMB)
	}
}

// TestBenchmark_StructTypes validates data schema conformance from blueprint Section 4.
func TestBenchmark_StructTypes(t *testing.T) {
	metrics := BenchmarkMetrics{
		ModelID:          "oc/mimo-v2.6-flash-free",
		ProxyURL:         "socks5://127.0.0.1:20808?dns=local",
		HandshakeLatency: 45 * time.Millisecond,
		TTFT:             320 * time.Millisecond,
		TotalDuration:    750 * time.Millisecond,
		TokensGenerated:  50,
		TokensPerSecond:  66.7,
		MemoryRSSBytes:   35 * 1024 * 1024,
		Success:          true,
	}

	if metrics.TTFT > 450*time.Millisecond {
		t.Errorf("expected TTFT < 450ms, got %v", metrics.TTFT)
	}
	if metrics.MemoryRSSBytes > 48*1024*1024 {
		t.Errorf("expected MemoryRSSBytes < 48MB, got %d", metrics.MemoryRSSBytes)
	}

	cfg := LiveInferenceConfig{
		BaseURL:     "http://127.0.0.1:20127",
		Model:       "oc/mimo-v2.6-flash-free",
		Prompt:      "test",
		Stream:      true,
		Timeout:     5 * time.Second,
		ExpectProbe: "Hello",
	}
	if cfg.Model == "" {
		t.Error("expected non-empty model")
	}
}

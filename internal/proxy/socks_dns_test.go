package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"testing"

	xproxy "golang.org/x/net/proxy"
)

func TestParseSOCKS5DNSMode(t *testing.T) {
	tests := []struct {
		name        string
		rawURL      string
		wantMode    SOCKS5DNSMode
		wantErr     error
		expectExact bool
	}{
		{
			name:        "socks5 with dns=local",
			rawURL:      "socks5://127.0.0.1:1080?dns=local",
			wantMode:    DNSModeLocal,
			wantErr:     nil,
			expectExact: true,
		},
		{
			name:        "socks5 with dns=remote",
			rawURL:      "socks5://127.0.0.1:1080?dns=remote",
			wantMode:    DNSModeRemote,
			wantErr:     nil,
			expectExact: true,
		},
		{
			name:        "socks5 without query param defaults to remote",
			rawURL:      "socks5://127.0.0.1:1080",
			wantMode:    DNSModeRemote,
			wantErr:     nil,
			expectExact: true,
		},
		{
			name:        "socks5 with invalid dns mode",
			rawURL:      "socks5://127.0.0.1:1080?dns=invalid",
			wantMode:    "",
			wantErr:     ErrProxyDNSMode,
			expectExact: true,
		},
		{
			name:        "socks5 with multiple dns params",
			rawURL:      "socks5://127.0.0.1:1080?dns=local&dns=remote",
			wantMode:    "",
			wantErr:     ErrProxyDNSMode,
			expectExact: true,
		},
		{
			name:        "non-socks5 scheme with dns param",
			rawURL:      "http://127.0.0.1:8080?dns=local",
			wantMode:    "",
			wantErr:     ErrProxyDNSMode,
			expectExact: true,
		},
		{
			name:        "socks5h scheme with dns=local",
			rawURL:      "socks5h://127.0.0.1:1080?dns=local",
			wantMode:    DNSModeLocal,
			wantErr:     nil,
			expectExact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := url.Parse(tt.rawURL)
			if err != nil {
				t.Fatalf("failed to parse test URL %q: %v", tt.rawURL, err)
			}

			mode, err := ParseSOCKS5DNSMode(u)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ParseSOCKS5DNSMode(%q) error = %v, wantErr = %v", tt.rawURL, err, tt.wantErr)
				}
				if mode != tt.wantMode {
					t.Fatalf("ParseSOCKS5DNSMode(%q) mode = %q, wantMode = %q", tt.rawURL, mode, tt.wantMode)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseSOCKS5DNSMode(%q) unexpected error: %v", tt.rawURL, err)
			}
			if mode != tt.wantMode {
				t.Fatalf("ParseSOCKS5DNSMode(%q) mode = %q, wantMode = %q", tt.rawURL, mode, tt.wantMode)
			}
		})
	}
}

func TestResolveLocalSOCKS5Target(t *testing.T) {
	ctx := context.Background()

	t.Run("DNSModeRemote untouched", func(t *testing.T) {
		target := "example.com:443"
		got, err := ResolveLocalSOCKS5Target(ctx, target, DNSModeRemote)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != target {
			t.Fatalf("got %q, want %q", got, target)
		}
	})

	t.Run("numeric IP with DNSModeLocal untouched", func(t *testing.T) {
		target := "1.1.1.1:443"
		got, err := ResolveLocalSOCKS5Target(ctx, target, DNSModeLocal)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != target {
			t.Fatalf("got %q, want %q", got, target)
		}
	})

	t.Run("domain localhost:443 with DNSModeLocal resolved", func(t *testing.T) {
		target := "localhost:443"
		got, err := ResolveLocalSOCKS5Target(ctx, target, DNSModeLocal)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		host, port, err := net.SplitHostPort(got)
		if err != nil {
			t.Fatalf("failed to split host port from %q: %v", got, err)
		}
		if port != "443" {
			t.Errorf("got port %q, want 443", port)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			t.Fatalf("expected resolved host to be an IP, got %q", host)
		}
		if !ip.IsLoopback() {
			t.Errorf("expected loopback IP for localhost, got %v", ip)
		}
	})

	t.Run("Custom SOCKS5 dialer with ResolveLocalSOCKS5Target", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen error: %v", err)
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
			n, err := conn.Read(buf)
			if err != nil || n < 3 || buf[0] != 0x05 {
				return
			}
			conn.Write([]byte{0x05, 0x00})

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
			case 0x03: // Domain
				dlen := int(buf[4])
				dst = string(buf[5 : 5+dlen])
			}
			receivedDst <- dst
			conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0x10})
		}()

		forward := &net.Dialer{}
		dialer, err := xproxy.SOCKS5("tcp", ln.Addr().String(), nil, forward)
		if err != nil {
			t.Fatalf("SOCKS5 creation error: %v", err)
		}

		tr := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				resolved, err := ResolveLocalSOCKS5Target(ctx, addr, DNSModeLocal)
				if err != nil {
					return nil, err
				}
				if cd, ok := dialer.(xproxy.ContextDialer); ok {
					return cd.DialContext(ctx, network, resolved)
				}
				return dialer.Dial(network, resolved)
			},
		}

		req, _ := http.NewRequest("GET", "http://localhost:80/foo", nil)
		_, _ = tr.RoundTrip(req)

		select {
		case atyp := <-receivedATYP:
			dst := <-receivedDst
			t.Logf("Custom SOCKS5 dialer sent ATYP=0x%02x, dst=%s", atyp, dst)
			if atyp != 0x01 {
				t.Errorf("expected ATYP=0x01 (IPv4), got 0x%02x", atyp)
			}
			if dst != "127.0.0.1" {
				t.Errorf("expected dst=127.0.0.1, got %s", dst)
			}
		default:
			t.Fatal("No SOCKS5 request received by mock server")
		}
	})
}

func TestNewSafeTransportForProxy_SOCKS5(t *testing.T) {
	t.Run("valid socks5 with local DNS", func(t *testing.T) {
		tr := NewSafeTransportForProxy("socks5://127.0.0.1:1080?dns=local")
		if tr == nil {
			t.Fatal("expected non-nil transport")
		}
		if tr.Proxy == nil {
			t.Fatal("expected non-nil Proxy func")
		}
		if tr.DialContext == nil {
			t.Fatal("expected non-nil DialContext")
		}
	})

	t.Run("valid socks5 with remote DNS", func(t *testing.T) {
		tr := NewSafeTransportForProxy("socks5://127.0.0.1:1080?dns=remote")
		if tr == nil {
			t.Fatal("expected non-nil transport")
		}
	})

	t.Run("invalid socks5 DNS mode returns nil", func(t *testing.T) {
		tr := NewSafeTransportForProxy("socks5://127.0.0.1:1080?dns=invalid")
		if tr != nil {
			t.Fatal("expected nil transport for invalid DNS mode")
		}
	})
}

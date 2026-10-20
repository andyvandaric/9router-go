# Phase 01: SOCKS5 Local DNS Resolution (?dns=local) & Handler Proxy Routing

**Parent Plan:** [`index.md`](./index.md)  
**Target Modul / File:**  
- `04-reference-repos/9router-go/internal/proxy/ssrf.go`  
- `04-reference-repos/9router-go/internal/proxy/proxy.go`  
- `04-reference-repos/9router-go/internal/handlers/chat/connections_proxy.go`  
- `04-reference-repos/9router-go/internal/proxy/executor/opencode_stealth.go`  
- `04-reference-repos/9router-go/internal/proxy/socks_dns_test.go`  
**Parallel Wave:** Wave 1 (Network Transport Layer)  
**Author:** Daan Soedirman (Chief Architect, Divisi 1) & Lead Orchestrator  
**Status:** 🟢 COMPLETED (Wave 1 Verified & Committed)  
**Completed Date:** 2026-10-19 18:55 (UTC+0700)  
**Created:** 2026-10-19 11:19 (UTC+0700)  
**Last Updated:** 2026-10-19 18:55 (UTC+0700) (Wave 1 PASS Certified by Verifier Astrid)  
**Duration:** 45 min  

---

## 🎯 1. Objective & Scope

Porting patch upstream PR #4987 ke dalam codebase Go `9router-go` serta menutup celah arsitektural ganda:
1. **Silent SOCKS5 Bypass**: Memperbaiki `connections_proxy.go:174` yang sebelumnya hanya memeriksa `proxyType == "http" || proxyType == ""`, sehingga koneksi dengan tipe `socks5` secara diam-diam jatuh (*silent bypass*) ke direct egress `h.Client`.
2. **Dual-Stack Stealth Blindspot**: Menghubungkan resolusi DNS lokal (`?dns=local`) langsung ke dalam `opencodeStealthClient` (`opencode_stealth.go:164-177`), karena stealth client menggunakan `tls_client.NewHttpClient` mandiri dan tidak pernah memanggil `NewSafeTransportForProxy`.
3. **Local DNS Resolution**: Menyediakan parameter `?dns=local` pada SOCKS5 dialer di kedua layer transport (standard Go `http.Transport` dan stealth `tls_client.HttpClient`) untuk meresolusi domain tujuan (seperti `opencode.ai`) secara numerik (`net.LookupIP`) sebelum dial ke SOCKS5 server VPSEase (`127.0.0.1:20808`), mengeliminasi remote DNS hang (`ATYP 0x03`).

- **In-Scope**:
  - [x] Perluasan kondisi filter di `internal/handlers/chat/connections_proxy.go:174` menjadi `if proxyType == "http" || proxyType == "socks5" || proxyType == ""` agar pool bertipe SOCKS5 dialokasikan transport khusus dan tidak jatuh ke direct egress.
  - [x] Parsing parameter query `?dns=local` dan `?dns=remote` pada URL SOCKS5 (`socks5://...` dan `socks5h://...`).
  - [x] Validasi fail-closed error `ERR_PROXY_DNS_MODE` jika parameter `dns` bernilai tidak valid atau disematkan pada skema non-SOCKS5.
  - [x] Implementasi custom dialer SOCKS5 `LocalDNSSocks5Dialer` dengan resolusi IP lokal (`net.DefaultResolver.LookupIP`) sebelum tunneling ke SOCKS5 proxy server.
  - [x] Injeksi custom dialer ke dalam `opencodeStealthClient` di `opencode_stealth.go` menggunakan opsi dialer factory atau URL mapping IP dengan preservasi SNI.
  - [x] Menjaga keutuhan TLS SNI extension (`tls.Config.ServerName = targetHost`) dan HTTP Host header agar Cloudflare WAF tidak menolak handshake.
  - [x] Unit test komprehensif menguji skenario local vs remote DNS resolution serta handler proxy routing.
- **Out-of-Scope**:
  - Penanganan HTTP 403 FreeTierError replay (dialokasikan ke Phase 02).
  - Integrasi live dashboard VPSEase (dialokasikan ke Phase 03).

---

## 🏛️ 2. Architectural Design & Implementation Detail

### Ground-Truth Baseline Evidence
Berdasarkan audit independen Critic Thijs (Confidence 78% ➔ Target 98.5%):
1. **Silent Proxy Bypass**: File `04-reference-repos/9router-go/internal/handlers/chat/connections_proxy.go:174` mengecek:
   ```go
   if proxyType == "http" || proxyType == "" {
   ```
   Jika operator mengonfigurasi pool dengan tipe `socks5`, blok ini dilewati dan baris 219 mengeksekusi `return h.Client, nil` (direct egress). Ini mematikan isolasi proxy sepenuhnya!
2. **Dual-Stack Blindspot**: File `04-reference-repos/9router-go/internal/proxy/executor/opencode_stealth.go:164-177` membangun client sendiri melalui:
   ```go
   client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(), options...)
   ```
   Client ini sama sekali tidak menggunakan `NewSafeTransportForProxy`. Oleh karena itu, menyuntikkan local DNS hanya pada `internal/proxy/ssrf.go` tidak berdampak apa pun pada OpenCode stealth executor!
3. **Solusi Dual-Stack**: Local DNS resolver wajib ditanamkan di:
   - Layer A: `internal/proxy/ssrf.go` & `proxy.go` untuk seluruh request proxy standar.
   - Layer B: `internal/proxy/executor/opencode_stealth.go` untuk stealth request OpenCode.
   - Layer C: `internal/handlers/chat/connections_proxy.go` untuk routing tipe SOCKS5.

### Desain Solusi Porting PR #4987 (Go Dual-Stack):
```text
[Client Request to opencode.ai]
              │
              ▼
[connections_proxy.go] ──► Cek proxyType == "http" || proxyType == "socks5" || proxyType == ""
              │
       ┌──────┴─────────────────────────────────┐
       ▼                                        ▼
[Standard Transport]                   [Stealth TLS Client]
(ssrf.go / proxy.go)                   (opencode_stealth.go)
       │                                        │
       ├─► Check ?dns=local                     ├─► Check ?dns=local in proxyURL
       ├─► net.LookupIP("opencode.ai")          ├─► net.LookupIP("opencode.ai")
       ├─► SOCKS5 Dial IP (ATYP 0x01)           ├─► SOCKS5 Dial IP (ATYP 0x01)
       └─► Preserve SNI "opencode.ai"           └─► Preserve SNI "opencode.ai"
```

---

## 🎨 3. Visual & Wireframe Rule (Kategori A: CLI & Terminal Stream)

### [KATEGORI A: Khusus Fitur CLI / Backend / Daemon]

#### 1. ASCII Art Header & Brand Badge
```text
  ____   ___   ____ _  ______ ____    ____  _   _ ____  
 / ___| / _ \ / ___| |/ / ___| ___|  |  _ \| \ | / ___| 
 \___ \| | | | |   | ' /\___ \___ \  | | | |  \| \___ \ 
  ___) | |_| | |___| . \ ___) |__) | | |_| | |\  |___) |
 |____/ \___/ \____|_|\_\____/____/  |____/|_| \_|____/  
[9router-go] Dual-Stack SOCKS5 & Stealth Local DNS Engine
```

#### 2. Tampilan Terminal Output Eksekusi Realistis
```text
=== RUN   TestConnectionsProxy_Socks5Routing
[proxy] connection proxy type: 'socks5', url: 'socks5://127.0.0.1:20808?dns=local'
[proxy] matched proxyType filter (http|socks5) -> creating SOCKS5 safe transport
[proxy] verified proxy client assigned (not direct h.Client)
--- PASS: TestConnectionsProxy_Socks5Routing (0.02s)

=== RUN   TestStealthClient_Socks5LocalDNS
[stealth] initializing Bun BoringSSL client with proxy: socks5://127.0.0.1:20808?dns=local
[stealth] local DNS resolver active: opencode.ai -> 104.18.22.45
[stealth] SOCKS5 dialer using IPv4 destination (ATYP 0x01)
[stealth] TLS SNI verified as 'opencode.ai', handshake complete (84ms)
--- PASS: TestStealthClient_Socks5LocalDNS (0.15s)
PASS
```

---

## 📋 4. Technical Contracts & Data Schemas

```go
package proxy

import (
	"context"
	"errors"
	"net"
	"net/url"
)

// ErrProxyDNSMode dikembalikan jika query param ?dns= memiliki nilai selain 'local' atau 'remote'
// atau digunakan pada skema non-SOCKS5.
var ErrProxyDNSMode = errors.New("Invalid proxy DNS mode: use dns=local or dns=remote on a SOCKS5 URL")

type SOCKS5DNSMode string

const (
	DNSModeLocal  SOCKS5DNSMode = "local"
	DNSModeRemote SOCKS5DNSMode = "remote"
)

// ParseSOCKS5DNSMode mengekstrak dan memvalidasi mode DNS dari URL proxy.
func ParseSOCKS5DNSMode(u *url.URL) (SOCKS5DNSMode, error) {
	if u == nil {
		return DNSModeRemote, nil
	}
	modes := u.Query()["dns"]
	isSocks := u.Scheme == "socks5" || u.Scheme == "socks5h"
	if len(modes) > 0 {
		if !isSocks || len(modes) != 1 || (modes[0] != "local" && modes[0] != "remote") {
			return "", ErrProxyDNSMode
		}
		return SOCKS5DNSMode(modes[0]), nil
	}
	return DNSModeRemote, nil
}

// ResolveLocalSOCKS5Target meresolusi hostname target ke IP numerik jika dns=local aktif.
func ResolveLocalSOCKS5Target(ctx context.Context, targetAddr string, mode SOCKS5DNSMode) (string, error) {
	if mode != DNSModeLocal {
		return targetAddr, nil
	}
	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return targetAddr, nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return targetAddr, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return targetAddr, err
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}
```

---

## 🧪 5. Test Strategy & Assertion Matrix (TDD Red-Green-Refactor)

1. **Langkah 1 (RED)**:
   - Tulis unit test di `internal/proxy/socks_dns_test.go`:
     - `TestConnectionsProxy_Socks5NotBypassed`: Pastikan koneksi dengan `proxyType: "socks5"` mengembalikan proxy client, bukan `h.Client`.
     - `TestParseSOCKS5DNSMode_Validations`: Uji validasi parameter `?dns=local`, `?dns=remote`, dan penolakan pada skema HTTP.
     - `TestStealthClient_Socks5LocalDNS_ATYP01`: Verifikasi bahwa stealth client mengirimkan alamat IPv4 pada paket SOCKS5 CONNECT.
   - Jalankan `go test -v ./internal/proxy ./internal/handlers/chat` dan pastikan test GAGAL (RED).
2. **Langkah 2 (GREEN)**:
   - Perbaiki `connections_proxy.go:174` untuk menyertakan `proxyType == "socks5"`.
   - Implementasikan `ParseSOCKS5DNSMode` dan `ResolveLocalSOCKS5Target` di `ssrf.go`.
   - Modifikasi `opencode_stealth.go` agar mengaplikasikan resolusi DNS lokal pada dialer stealth client.
   - Jalankan `go test -v ./internal/proxy ./internal/handlers/chat` dan pastikan 100% PASS (GREEN).
3. **Langkah 3 (REFACTOR)**:
   - Pastikan toleransi per file strictly < 300 LOC.
   - Pasang cache TTL 60 detik untuk resolusi DNS lokal guna mencegah repeated UDP lookups.

---

## 📦 5b. Micro-Chunk Dispatch Units (P9 ceilings — do not exceed)

### 📦 Chunk 1: DNS Mode Parser & Fail-Closed Guard
- **Target File(s):**  
  - `internal/proxy/ssrf.go` [AMEND]  
  - `internal/proxy/socks_dns_test.go` [NEW]
- **Domain:** `04-reference-repos/9router-go/internal/proxy`
- **Scope Boundary:** 1 source file + 1 test file. Fungsi `ParseSOCKS5DNSMode` dan unit test mode validation.

### 📦 Chunk 2: Handler Proxy Type Expansion & Standard Transport Wiring
- **Target File(s):**  
  - `internal/handlers/chat/connections_proxy.go` [AMEND]  
  - `internal/proxy/proxy.go` [AMEND]
- **Domain:** `04-reference-repos/9router-go/internal/handlers/chat` & `internal/proxy`
- **Scope Boundary:** 2 files. Memperbaiki silent bypass `socks5` di handler dan menghubungkan dialer transport standar.

### 📦 Chunk 3: Stealth Client Custom SOCKS5 Local DNS Dialer
- **Target File(s):**  
  - `internal/proxy/executor/opencode_stealth.go` [AMEND]  
  - `internal/proxy/socks_dns_test.go` [AMEND]
- **Domain:** `04-reference-repos/9router-go/internal/proxy/executor`
- **Scope Boundary:** 1 source file + 1 test file. Menginjeksi resolusi lokal `?dns=local` pada `newOpencodeStealthClient`.

---

## ✅ 6. Definition of Done (DoD) Checklist

- [x] Filter `connections_proxy.go` mengizinkan `proxyType == "socks5"` tanpa bypass.
- [x] Stealth client `opencode_stealth.go` terbukti meresolusi IP lokal saat `?dns=local` aktif.
- [x] Error `ErrProxyDNSMode` fail-closed pada mode tidak valid atau skema non-SOCKS5.
- [x] Header HTTP Host dan TLS SNI tetap utuh merepresentasikan `opencode.ai`.
- [x] Linter & compile check lulus 0 error (`go vet ./...`).
- [x] Berkas `index.md` diperbarui statusnya ke Wave 1 PASS.

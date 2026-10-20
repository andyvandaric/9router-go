# Phase 02: FreeTierError Replay and Safe Failover

**Parent Plan:** [`index.md`](./index.md)  
**Target Modul / File:**  
- `04-reference-repos/9router-go/internal/proxy/executor/opencode_stealth.go`  
- `04-reference-repos/9router-go/internal/proxy/executor/opencode_retry.go`  
- `04-reference-repos/9router-go/internal/proxy/executor/opencode_zen.go`  
- `04-reference-repos/9router-go/internal/proxy/executor/freetier_replay_test.go`  
**Parallel Wave:** Wave 2 (Executor Resilience & Failover)  
**Author:** Daan Soedirman (Chief Architect, Divisi 1) & Lead Orchestrator  
**Status:** 🟢 COMPLETED (Wave 2 Verified & Committed)  
**Completed Date:** 2026-10-19 19:25 (UTC+0700)  
**Created:** 2026-10-19 11:19 (UTC+0700)  
**Last Updated:** 2026-10-19 19:25 (UTC+0700) (Wave 2 PASS Certified by Verifier Astrid)  
**Duration:** 30 min  

---

## 🎯 1. Objective & Scope

Porting patch upstream PR #4988 ke dalam executor OpenCode di `9router-go` dengan mengatasi dua cacat arsitektural pada penanganan status 403:
1. **Intersepsi Status 403 pada Stealth Response**: `forwardOpencodeRequest` mengembalikan objek `(*http.Response, nil)` meskipun upstream mengembalikan status 403. Logika retry `forwardOpenCode` di `opencode_retry.go` sebelumnya hanya memeriksa `err != nil`, sehingga respons 403 lolos tanpa replay! Fungsi ini wajib diperbaiki agar secara proaktif memeriksa `resp.StatusCode == 403` dan membaca body untuk mendeteksi `FreeTierError`.
2. **Direct Replay Wajib Menggunakan Stealth Client**: Replay langsung (*direct egress*) untuk OpenCode Free DILARANG KERAS menggunakan `directProxyClient` Go biasa (`net/http`) karena TLS fingerprint Go standard langsung ditolak oleh Cloudflare WAF dengan 403 baru. Replay wajib menggunakan `forwardOpencodeRequest(ctx, nil, ...)` (stealth client Bun BoringSSL murni tanpa proxy).

- **In-Scope**:
  - [x] Intersepsi status HTTP 403 baik saat dikembalikan sebagai `*http.Response` maupun `*proxy.UpstreamError`.
  - [x] Pembacaan dan buffering body respons (maksimal 1MB) untuk mencari substring token `FreeTierError`.
  - [x] Logika isolasi pool: saat `FreeTierError` terdeteksi, tandai pool saat ini sebagai flagged/excluded untuk request tersebut.
  - [x] Replay otomatis 1x menggunakan **Stealth TLS Client** murni ke direct egress (`client == nil`) atau ke pool cadangan berikutnya.
  - [x] Penegakan kontrak keamanan `strictProxy`: jika opsi `strictProxy=true`, dilarang keras melakukan direct replay guna mencegah kebocoran IP asli pengguna.
  - [x] Penanganan non-gate 403 (seperti invalid API key, permission error, atau quota limits) agar lolos murni tanpa replay.
  - [x] Unit test komprehensif memvalidasi stealth direct replay, strictProxy refusal, dan non-gate pass-through.
- **Out-of-Scope**:
  - Perubahan pada transport TLS BoringSSL Bun (`bunBoringSSLSpec`) yang sudah terbukti valid.
  - Integrasi live benchmark port :20808 (dialokasikan ke Phase 03).

---

## 🏛️ 2. Architectural Design & Implementation Detail

### Ground-Truth Baseline Evidence
Berdasarkan audit independen Critic Thijs (Confidence 78% ➔ Target 98.5%):
1. **403 Escape Deficit**: Pada `opencode_stealth.go:285`, `stealth.forward` mengembalikan `(httpResp, nil)` dengan `httpResp.StatusCode = 403`. Pada `opencode_retry.go:57-60`:
   ```go
   resp, err := send()
   if err == nil {
       return resp, nil // 403 lolos di sini tanpa evaluasi!
   }
   ```
   Karena `err == nil`, `forwardOpenCode` langsung mengembalikan response 403 ke pemanggil tanpa pernah masuk ke blok `isOpenCodeRefusal`!
2. **TLS Fingerprint Rejection pada Direct Replay**: Jika direct replay dipanggil menggunakan `proxy.directProxyClient` (`net/http`), Cloudflare WAF pada `opencode.ai` akan menolak koneksi karena fingerprint TLS Go berbeda dari Bun BoringSSL. Replay wajib memanggil instance `opencodeStealthClient` dengan opsi direct (`proxyURL == ""`).

### Desain Solusi Porting PR #4988 (Stealth-Aware Replay):
```text
           [Client Request to OpenCode Free]
                          │
                          ▼
             [Stealth Attempt 1: via SOCKS5]
                          │
             ┌────────────┴────────────┐
             │ Check resp.StatusCode?  │
             └────────────┬────────────┘
        200 OK            │            403 Forbidden
          │               │                  │
          ▼               │                  ▼
    [Stream to Client]    │         [Read & Buffer Body]
                          │                  │
                          │        ┌─────────┴─────────┐
                          │        │ Contains          │
                          │        │ "FreeTierError"?  │
                          │        └─────────┬─────────┘
                          │              NO  │  YES
                          │              ┌───┘  │
                          │              ▼      ▼
                          │        [Return 403] [Is strictProxy == true?]
                          │                        │
                          │              YES ┌─────┴─────┐ NO
                          │                  ▼           ▼
                          │             [Return 403] [Mark Pool Flagged]
                          │             (No Leak)        │
                          │                              ▼
                          │                 [Stealth Attempt 2: Direct Egress]
                          │                 forwardOpencodeRequest(ctx, nil, ...)
                          │                              │
                          │                    ┌─────────┴─────────┐
                          │                    │ Status Code?      │
                          │                    └─────────┬─────────┘
                          │               200 OK         │         Non-200
                          │                 │            │            │
                          │                 ▼            │            ▼
                          └───────────► [Stream]         └───────► [Return Original 403]
```

---

## 🎨 3. Visual & Wireframe Rule (Kategori A: CLI & Terminal Stream)

### [KATEGORI A: Khusus Fitur CLI / Backend / Daemon]

#### 1. ASCII Art Header & Brand Badge
```text
  _____ ____  _____ _____ _____ ___ _____ ____  
 |  ___|  _ \| ____| ____|_   _|_ _| ____|  _ \ 
 | |_  | |_) |  _| |  _|   | |  | ||  _| | |_) |
 |  _| |  _ <| |___| |___  | |  | || |___|  _ < 
 |_|   |_| \_\_____|_____| |_| |___|_____|_| \_\
[9router-go] Resilience Subsystem: Stealth FreeTier Failover
```

#### 2. Tampilan Terminal Output Eksekusi Realistis
```text
=== RUN   TestFreeTierErrorStealthDirectReplay
[opencode] dispatching request via proxy pool 'vpsease-sg'
[opencode] upstream returned status: 403 Forbidden (err is nil)
[opencode] inspecting response body: found token 'FreeTierError'
[opencode] strictProxy is false: excluding pool 'vpsease-sg'
[opencode] triggering direct stealth replay via Bun BoringSSL client (proxy=none)
[opencode] direct stealth replay succeeded: HTTP 200 OK (stream: true)
[opencode] session recovered transparently via direct replay (latency: +172ms)
--- PASS: TestFreeTierErrorStealthDirectReplay (0.21s)
PASS
```

---

## 📋 4. Technical Contracts & Data Schemas

```go
package executor

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"9router/proxy/internal/providers"
	"9router/proxy/internal/proxy"
)

const (
	FreeTierErrorToken = "FreeTierError"
	MaxErrorBodyBytes  = 1 * 1024 * 1024 // 1 MB buffer limit
)

// IsFreeTierResponse memeriksa apakah response HTTP adalah 403 FreeTierError.
// Jika ya, mengembalikan body yang telah dibuffer dan boolean true.
func IsFreeTierResponse(resp *http.Response) ([]byte, bool) {
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		return nil, false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	if err != nil {
		return nil, false
	}
	_ = resp.Body.Close()
	// Kembalikan body baru agar caller dapat mengonsumsi jika bukan FreeTierError
	resp.Body = io.NopCloser(bytes.NewReader(body))
	if bytes.Contains(body, []byte(FreeTierErrorToken)) {
		return body, true
	}
	return body, false
}

// ForwardOpencodeWithFailover membungkus eksekusi stealth request dengan logika replay direct otomatis.
func ForwardOpencodeWithFailover(
	ctx context.Context,
	client *http.Client,
	cfg *providers.ProviderConfig,
	apiKey string,
	body []byte,
	isStream bool,
) (*http.Response, error) {
	resp, err := forwardOpencodeRequest(ctx, client, cfg, apiKey, body, isStream)
	if err != nil {
		return nil, err
	}
	errBody, isFreeTier := IsFreeTierResponse(resp)
	if !isFreeTier {
		return resp, nil
	}
	if cfg.StrictProxy {
		// Pasang kembali body yang sudah dibaca
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
		return resp, nil
	}
	// Replay menggunakan stealth client direct (client == nil)
	directResp, directErr := forwardOpencodeRequest(ctx, nil, cfg, apiKey, body, isStream)
	if directErr != nil || directResp.StatusCode != http.StatusOK {
		if directResp != nil {
			_ = directResp.Body.Close()
		}
		resp.Body = io.NopCloser(bytes.NewReader(errBody))
		return resp, nil
	}
	return directResp, nil
}
```

---

## 🧪 5. Test Strategy & Assertion Matrix (TDD Red-Green-Refactor)

1. **Langkah 1 (RED)**:
   - Tulis unit test di `internal/proxy/executor/freetier_replay_test.go`:
     - `TestIsFreeTierResponse_DetectsToken`: Response 403 dengan body `{"error":{"type":"FreeTierError"}}` terdeteksi true dan body tidak rusak.
     - `TestForwardOpencodeWithFailover_StealthDirect`: Mock proxy mengembalikan 403 `FreeTierError`. Verifikasi bahwa replay direct dipanggil via stealth client (`client == nil`) dan mengembalikan 200 OK.
     - `TestForwardOpencodeWithFailover_StrictProxyBlocksDirect`: Saat `cfg.StrictProxy == true`, verifikasi direct replay TIDAK dieksekusi dan status 403 dikembalikan.
     - `TestForwardOpencodeWithFailover_NonGate403Ignored`: Status 403 dengan body kuota habis tidak di-replay.
   - Jalankan `go test -v ./internal/proxy/executor -run TestForwardOpencodeWithFailover` dan pastikan test GAGAL (RED).
2. **Langkah 2 (GREEN)**:
   - Implementasikan fungsi `IsFreeTierResponse` dan `ForwardOpencodeWithFailover` di `opencode_retry.go` dan `opencode_stealth.go`.
   - Sambungkan `ForwardOpencodeWithFailover` ke pemanggil di `forwardZenChat` dan `forwardZenResponses` pada `opencode_zen.go`.
   - Jalankan `go test -v ./internal/proxy/executor -run TestForwardOpencodeWithFailover` dan pastikan 100% PASS (GREEN).
3. **Langkah 3 (REFACTOR)**:
   - Pastikan response body selalu ditutup (`resp.Body.Close()`) sebelum inisiasi direct replay untuk mencegah connection pool exhaustion.
   - Tambahkan log diagnostik: `log.Info("opencode", "replayed proxied 403 FreeTierError via direct stealth client")`.

---

## 📦 5b. Micro-Chunk Dispatch Units (P9 ceilings — do not exceed)

### 📦 Chunk 1: Response Status Interceptor & Stealth Replay Engine
- **Target File(s):**  
  - `internal/proxy/executor/opencode_retry.go` [AMEND]  
  - `internal/proxy/executor/freetier_replay_test.go` [NEW]
- **Domain:** `04-reference-repos/9router-go/internal/proxy/executor`
- **Scope Boundary:** 1 source file + 1 test file. `IsFreeTierResponse` helper dan test suite contract.

### 📦 Chunk 2: Stealth Client Direct Failover & Zen Executor Wiring
- **Target File(s):**  
  - `internal/proxy/executor/opencode_stealth.go` [AMEND]  
  - `internal/proxy/executor/opencode_zen.go` [AMEND]
- **Domain:** `04-reference-repos/9router-go/internal/proxy/executor`
- **Scope Boundary:** 2 files. Mengintegrasikan `ForwardOpencodeWithFailover` ke dalam stealth execution flow dan zen handler.

---

## ✅ 6. Definition of Done (DoD) Checklist

- [x] Status 403 `FreeTierError` terintersepsi secara akurat meskipun `err == nil`.
- [x] Direct replay terbukti dieksekusi menggunakan stealth client Bun BoringSSL (`client == nil`).
- [x] Kontrak `strictProxy` terbukti memblokir kebocoran direct egress saat diaktifkan via `proxy.ForbidsDirectReplay(client)`.
- [x] Error non-gate 403 diteruskan secara murni ke client tanpa replay.
- [x] Body response terbebas dari resource leak / buffer overflow.
- [x] Linter & compile check lulus 0 error (`go vet ./...`).
- [x] Berkas `index.md` diperbarui statusnya ke Wave 2 PASS.

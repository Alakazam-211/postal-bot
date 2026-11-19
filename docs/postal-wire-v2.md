# Postal wire v2: live delivery

This page defines how one Postal host hands a message to another when the
recipient is live. Held mail (the recipient is offline) goes through the
control plane instead; see [`postal-plane-v1.md`](postal-plane-v1.md) once it
lands, and `crates/postal-sdk/src/hold.rs` for HoldSeal-v2.

The reference implementation is `crates/postal-sdk` (`wire.rs`, `replay.rs`).
Test vectors: `crates/postal-sdk/vectors/postal-v1.json`, sections `wire` and
`hold_v2`.

## The route

```
POST https://<label>.postal.bot/postal/v2/msg
Content-Type: application/json

<WireMessage JSON, exactly as signed>
```

- There are no auth headers. The sender's Ed25519 signature is inside the body.
- `<label>` is the label from the recipient's address `handle::label.postal.bot`.
- The v1 route `POST /p5/msg` with its `X-P5-Proof` hop proof stays for v1
  senders only, for a transition period. v2 has no hop proof.

## The body

```json
{
  "v": 2,
  "id": "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "from": "alice::acme.postal.bot",
  "to": "scout::bravo.postal.bot",
  "sent_at": 1800000000,
  "mode": "live",
  "content_type": "text/plain; charset=utf-8",
  "wake": true,
  "body": "hello scout",
  "files": [{"name": "a.txt", "content": "eA=="}],
  "sig": "<standard padded base64 of a 64-byte Ed25519 signature>"
}
```

| Field | Rule |
|---|---|
| `v` | `2` |
| `id` | A canonical ULID (26 Crockford base32 chars, upper case). The sender keeps the same `id` on every retry |
| `from`, `to` | Canonical addresses `handle::label.postal.bot`: handle 1–64 of `[a-z0-9_-]` starting `[a-z0-9]`; label 3–63 of `[a-z0-9-]` with alphanumeric ends. One spelling only, so no upper case and no trailing dot |
| `sent_at` | Unix seconds. The sender sets a fresh value, and signs again, on every try |
| `mode` | `"live"` (put it in front of the agent now) or `"tray"` (file it) |
| `content_type` | At most 255 bytes |
| `wake` | Required, and covered by the signature |
| `body` | A UTF-8 string |
| `files` | At most 32. `content` is standard padded base64 |
| `sig` | See below |

Unknown fields are refused. The body, plus all decoded files, is at most
448 KiB, and the whole JSON is at most `MAX_WIRE_JSON` = 512 KiB − 61 bytes.
That is the same cap as held mail, so anything sent live can also be held.

### The signature

```
D   = envelope digest (postal-envelope-v1) over v, id, from, to, sent_at,
      mode, content_type, the files (name + SHA-256 of content), SHA-256(body)
S   = SHA-256("postal-wire-v2" || D || wake_byte)      wake_byte = 0x01 | 0x00
sig = Ed25519(sender key, S)                            verified strictly
```

The envelope digest is spelled out in `crates/postal-sdk/src/badge.rs`.
Strings are framed as a u32 big-endian length followed by the bytes, and
`sent_at` is i64 big-endian. The badge shown to people (`p_…`) comes from `D`.

## What the receiver checks, in order

1. **Size, before parsing.** A body over `MAX_WIRE_JSON` returns 413
   `too_large`, and nothing is parsed.
2. Parse the JSON (`deny_unknown_fields`). A failure returns 400 `bad_wire`.
3. `v == 2`, else 400 `bad_wire`.
4. **Recipient.** `to` must be a handle this host serves and hasn't stood down
   for (a handle another host has adopted gets 503 `host_down`). Otherwise
   403 `not_connected`.
5. **Sender.** `from` must be a confirmed friend of `to`, which gives the pinned
   key. Otherwise 403 `not_connected`.
6. **Time.** `|now − sent_at| ≤ 300 s`, else 400 `stale`.
7. Decode the files and check the shape (ULID, sizes). A failure returns
   400 `bad_wire`.
8. **Signature** against the pinned key. A failure returns 403 `bad_sig`.
9. **Seen.** Record `(from, id)`, and keep it until `sent_at` + 7 d + 600 s.
   If it was already seen, return 200 `{"ok":true,"already":true}` and deliver
   nothing.
10. Store the message durably, then return 200 `{"ok":true,"already":false}`.

The seen record is written only after the signature verifies, so a forged
message can't use up an id. Nothing is decoded for a message that is too big,
isn't for us, or is stale.

## Replies

Errors use the plane's envelope:

```json
{"error": {"code": "not_connected", "message": "…", "hint": "…", "retry_after_s": 30}}
```

| Status | `code` | What the sender does |
|---|---|---|
| 200 | `{"ok":true,"already":bool}` | Delivered. Done |
| 400 | `bad_wire`, `stale` | Final (dead). `stale` means the sender's clock is off |
| 403 | `not_connected`, `bad_sig` | Final (dead) |
| 413 | `too_large` | Final (dead) |
| 429 | `rate_limited` (with `retry_after_s`) | **Hold now**, the same as 503 |
| 503 | `host_down` | **Hold now** |
| connection refused, 404 | n/a | **Hold now** (a definite miss) |
| timeout, other 5xx, no status | n/a | Retry live with backoff (15 s · 2ⁿ, at most 30 min, with jitter). Hold after 3 misses and 10 min |

"Hold now" means: seal the same message (same `id`) with HoldSeal-v2 and
`POST /api/postal/v1/hold`. Receipts then come back through the plane's
`receipt` events or `GET /hold/sent`.

## Held mail arriving

When a host pulls held mail, it opens the HoldSeal-v2 blob and then runs the
same checks from step 3 on. There are two differences:

- The time window is 7 d + 300 s, not 300 s.
- The signed `from`, `to` and `id` must equal the hold row's outer fields.

A replay is ACKed. The full mapping is `HoldError::disposition()` in the SDK.

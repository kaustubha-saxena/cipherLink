# CipherLink

CipherLink is a prototype for temporary, code-based sessions and two-person encrypted communication. It implements Phases 1-13 from the step-by-step process: a Next.js interface, FastAPI session management with SQLite, WebSocket relay, browser-side X25519/HKDF key agreement, AES-256-GCM encrypted text and image chunks, disconnect handling, chained audit logs with verification, and API rate limits.

## Project structure

- `frontend/` - Next.js App Router interface
- `backend/` - FastAPI REST and WebSocket server, SQLite persistence
- `traffic-analysis/`, `attack-scripts/`, `benchmarks/`, `image-analysis/`, `docs/` - reserved for later phases

## Run locally

1. In `backend/`, create a virtual environment and install `requirements.txt`.
2. From `backend/`, start the API with `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`.
3. In `frontend/`, install dependencies with `npm install` and start with `npm run dev`.
4. Open `http://localhost:3000`. Set `NEXT_PUBLIC_API_URL` and `CIPHERLINK_ALLOWED_ORIGINS` through environment variables when using different hosts. Do not hard-code a LAN address.

The backend stores its SQLite database at `backend/cipherlink.db` by default. Set `CIPHERLINK_DB_PATH` to change it. Rooms last 10 minutes by default; `SESSION_TTL_SECONDS` changes the room lifetime.

## Current scope and security status

Text and image encryption and decryption happen in each browser. The backend relays public X25519 keys and encrypted message envelopes; it does not receive chat plaintext, image bytes, or private keys. AES-GCM uses a random 96-bit nonce and authenticated additional data bound to the room/sequence or image transfer/chunk metadata. Receivers and the relay reject duplicate or out-of-order sequence numbers. Images are limited to 10 MB and sent in encrypted 48 KiB chunks.

The key exchange is not authenticated by the room code or another trusted identity mechanism. The app shows a short key fingerprint; users should compare it through a separate trusted channel. Without that comparison, a malicious relay could substitute public keys.

The chat displays a SQLite-backed SHA-256 hash-chain audit log and checks record consistency. It records event metadata, never message or image contents. It detects edits and interior deletions, but it is not signed or externally anchored and cannot prove that the latest records were not removed. Rate limits and replay tracking use in-process memory and reset when the backend restarts; deployments with multiple backend workers need shared storage for these controls. This is a student prototype, not a security-audited product. Traffic analysis, benchmarks, and broader security testing remain future work.

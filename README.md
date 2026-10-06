# CipherLink

CipherLink is a local prototype for temporary, code-based sessions and two-person text communication. This implementation covers Phases 1–4 in `step by step process.docx`: project setup, a basic Next.js interface, FastAPI session management with SQLite, and plaintext WebSocket messaging.

## Project structure

- `frontend/` — Next.js App Router interface
- `backend/` — FastAPI REST and WebSocket server, SQLite persistence
- `traffic-analysis/`, `attack-scripts/`, `benchmarks/`, `image-analysis/`, `docs/` — reserved for later phases

## Run locally

1. In `backend/`, create a virtual environment and install `requirements.txt`.
2. Start the API with `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000` from `backend/`.
3. In `frontend/`, install dependencies with `npm install` and start with `npm run dev`.
4. Open `http://localhost:3000`. To connect a second device on the same network, set `NEXT_PUBLIC_API_URL` to the host computer's LAN address (for example `http://192.168.1.10:8000`) in `frontend/.env.local`, set `CIPHERLINK_ALLOWED_ORIGINS=http://localhost:3000,http://192.168.1.10:3000` for the backend, start Next.js with `npm run dev -- --hostname 0.0.0.0`, and allow ports 3000 and 8000 through the host firewall. Replace the sample address with the host computer's actual LAN IP.

The backend stores its SQLite database at `backend/cipherlink.db` by default. Set `CIPHERLINK_DB_PATH` to change it. Sessions last 10 minutes by default (`SESSION_TTL_SECONDS` can override that).

## Current scope and security status

Phase 4 messaging is intentionally plaintext, as directed by the process document. Do not use this prototype for sensitive information. The short room code is returned only when the room is created; the backend stores its SHA-256 hash. A joining participant receives a random participant ID in their browser and uses it for WebSocket membership. Phase 5 must add browser-side X25519/HKDF/AES-GCM before this is suitable for private communication. WebSocket access currently relies on unguessable room membership IDs rather than a hardened authorization token; this is prototype scaffolding.

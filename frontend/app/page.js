"use client";

import { useEffect, useRef, useState } from "react";
import { createEphemeralKeyPair, createKeyFingerprint, decryptBytes, decryptText, deriveSessionMaterials, encryptBytes, encryptText } from "@/lib/crypto";

const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");
const IMAGE_CHUNK_BYTES = 48 * 1024;
const MAX_IMAGE_BYTES = 10 * 1024 * 1024;

function getIdentity() {
  let id = window.localStorage.getItem("cipherlink-participant-id");
  if (!id) {
    id = crypto.randomUUID();
    window.localStorage.setItem("cipherlink-participant-id", id);
  }
  return id;
}

async function request(path, body) {
  const response = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || "The request could not be completed.");
  return data;
}

function formatClock(seconds) {
  const minutes = Math.floor(seconds / 60).toString().padStart(2, "0");
  const remainder = (seconds % 60).toString().padStart(2, "0");
  return `${minutes}:${remainder}`;
}

export default function Home() {
  const [view, setView] = useState("home");
  const [identity, setIdentity] = useState("");
  const [room, setRoom] = useState(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [remaining, setRemaining] = useState(600);
  const [connection, setConnection] = useState("Connecting");
  const [cryptoStatus, setCryptoStatus] = useState("Waiting for key exchange");
  const [keyFingerprint, setKeyFingerprint] = useState("");
  const [handshakeDetails, setHandshakeDetails] = useState(null);
  const [securityEvents, setSecurityEvents] = useState([]);
  const [sending, setSending] = useState(false);
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState("");
  const [audit, setAudit] = useState({ records: [], integrity_valid: true, first_bad_record: null });
  const [imageProgress, setImageProgress] = useState(null);
  const [fileInputKey, setFileInputKey] = useState(0);
  const socketRef = useRef(null);
  const sendingRef = useRef(false);
  const bottomRef = useRef(null);
  const keyPairRef = useRef(null);
  const sessionKeyRef = useRef(null);
  const peerPublicKeyRef = useRef(null);
  const pendingPeerPublicKeyRef = useRef(null);
  const sendSequenceRef = useRef(0);
  const receiveSequencesRef = useRef(new Map());
  const incomingImagesRef = useRef(new Map());
  const objectUrlsRef = useRef(new Set());
  const imageInputRef = useRef(null);

  useEffect(() => setIdentity(getIdentity()), []);

  useEffect(() => {
    if (view !== "room" || !room?.joined) return;
    const socketUrl = API_URL.replace(/^http/, "ws");
    const socket = new WebSocket(`${socketUrl}/ws/${room.id}?participant_id=${encodeURIComponent(identity)}`);
    let disposed = false;
    let heartbeat;
    let lastPongAt = Date.now();
    socketRef.current = socket;
    keyPairRef.current = null;
    sessionKeyRef.current = null;
    peerPublicKeyRef.current = null;
    pendingPeerPublicKeyRef.current = null;
    sendSequenceRef.current = 0;
    receiveSequencesRef.current = new Map();
    setConnection("Connecting");
    setCryptoStatus("Preparing browser key");
    setKeyFingerprint("");
    setHandshakeDetails(null);

    function sendPublicKey() {
      const pair = keyPairRef.current;
      if (pair && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "key_exchange", public_key: pair.publicKey }));
      }
    }

    async function receivePeerKey(publicKey) {
      if (!keyPairRef.current) {
        pendingPeerPublicKeyRef.current = publicKey;
        return;
      }
      if (publicKey === peerPublicKeyRef.current) return;
      peerPublicKeyRef.current = publicKey;
      try {
        const { sessionKey: derivedKey, sharedSecretBase64 } = await deriveSessionMaterials(keyPairRef.current.privateKey, publicKey, room.id);
        if (disposed) return;
        sessionKeyRef.current = derivedKey;
        setHandshakeDetails({
          privateKey: keyPairRef.current.privateKeyBase64,
          publicKey: keyPairRef.current.publicKey,
          peerPublicKey: publicKey,
          sharedSecret: sharedSecretBase64,
        });
        const fingerprint = await createKeyFingerprint(keyPairRef.current.publicKey, publicKey, room.id);
        if (disposed) return;
        setKeyFingerprint(fingerprint);
        setCryptoStatus("End-to-end encrypted");
        setError("");
      } catch (error) {
        setCryptoStatus("Key exchange failed");
        setError(error.message || "Could not establish an encrypted session.");
      }
    }

    const keySetup = createEphemeralKeyPair();
    keySetup.then((pair) => {
      if (!disposed) {
        keyPairRef.current = pair;
        setHandshakeDetails({ privateKey: pair.privateKeyBase64, publicKey: pair.publicKey, peerPublicKey: "", sharedSecret: "" });
        setCryptoStatus("Waiting for partner key");
        sendPublicKey();
        if (pendingPeerPublicKeyRef.current) receivePeerKey(pendingPeerPublicKeyRef.current);
      }
    }).catch((error) => {
      if (!disposed) {
        setCryptoStatus("Encryption unavailable");
        setError(error.message || "Could not create an encryption key.");
      }
    });

    socket.onopen = () => {
      setConnection("Connected");
      sendPublicKey();
      heartbeat = window.setInterval(() => {
        if (Date.now() - lastPongAt > 45000) {
          setConnection("Connection lost");
          setCryptoStatus("Session ended");
          sessionKeyRef.current = null;
          setError("The connection was lost. Leave this room and create or join a new one.");
          socket.close();
          return;
        }
        if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "ping" }));
      }, 15000);
    };
    socket.onclose = () => {
      if (!disposed) {
        setConnection("Disconnected");
        setCryptoStatus("Session ended");
        sessionKeyRef.current = null;
      }
    };
    socket.onerror = () => setConnection("Connection issue");
    socket.onmessage = async (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "pong") { lastPongAt = Date.now(); return; }
        if (payload.type === "message") {
          if (payload.sender_id === identity) return;
          const previousSequence = receiveSequencesRef.current.get(payload.sender_id) || 0;
          if (!Number.isSafeInteger(payload.sequence) || payload.sequence <= previousSequence) {
            setSecurityEvents((items) => [{ id: crypto.randomUUID(), label: "REPLAY DETECTED", detail: "A duplicate or out-of-order message was rejected." }, ...items].slice(0, 5));
            socket.send(JSON.stringify({ type: "security_event", event: "REPLAY_DETECTED", sequence: payload.sequence }));
            return;
          }
          if (!sessionKeyRef.current) {
            setError("The partner's encryption key is not ready yet. Please wait and try again.");
            return;
          }
          try {
            const text = await decryptText(sessionKeyRef.current, room.id, payload.sequence, payload.nonce, payload.ciphertext);
            receiveSequencesRef.current.set(payload.sender_id, payload.sequence);
            setMessages((items) => [...items, { ...payload, message: text }]);
          } catch {
            setSecurityEvents((items) => [{ id: crypto.randomUUID(), label: "INTEGRITY CHECK FAILED", detail: "A modified or invalid encrypted message was rejected." }, ...items].slice(0, 5));
            socket.send(JSON.stringify({ type: "security_event", event: "INTEGRITY_FAILURE", sequence: payload.sequence }));
          }
        }
        if (payload.type === "image_chunk" && payload.sender_id !== identity) {
          const { transfer_id, total_chunks, chunk_index, file_size, file_name, mime_type, sequence } = payload;
          const previousSequence = receiveSequencesRef.current.get(payload.sender_id) || 0;
          if (!Number.isSafeInteger(sequence) || sequence <= previousSequence) {
            socket.send(JSON.stringify({ type: "security_event", event: "REPLAY_DETECTED", sequence }));
            return;
          }
          if (!sessionKeyRef.current || !Number.isInteger(total_chunks) || total_chunks < 1 || total_chunks > 214 || !Number.isInteger(chunk_index) || chunk_index < 0 || chunk_index >= total_chunks || file_size > MAX_IMAGE_BYTES || !mime_type?.startsWith("image/")) throw new Error("Image transfer metadata is invalid.");
          let transfer = incomingImagesRef.current.get(transfer_id);
          if (!transfer) {
            if (incomingImagesRef.current.size >= 3) throw new Error("Too many image transfers are in progress.");
            transfer = { total_chunks, file_size, file_name, mime_type, chunks: new Array(total_chunks), received: 0 };
            incomingImagesRef.current.set(transfer_id, transfer);
          }
          if (transfer.total_chunks !== total_chunks || transfer.chunks[chunk_index]) throw new Error("Image chunk order or metadata is invalid.");
          const context = `image:${transfer_id}:${chunk_index}:${total_chunks}:${file_name}:${mime_type}:${file_size}`;
          try {
            transfer.chunks[chunk_index] = await decryptBytes(sessionKeyRef.current, context, payload.nonce, payload.ciphertext);
            receiveSequencesRef.current.set(payload.sender_id, sequence);
            transfer.received += 1;
            if (transfer.received === total_chunks) {
              const blob = new Blob(transfer.chunks, { type: mime_type });
              if (blob.size !== file_size) throw new Error("The received image size did not match its metadata.");
              const imageUrl = URL.createObjectURL(blob);
              objectUrlsRef.current.add(imageUrl);
              setMessages((items) => [...items, { type: "image", sender_id: payload.sender_id, file_name, imageUrl, sent_at: payload.sent_at }]);
              incomingImagesRef.current.delete(transfer_id);
            }
          } catch {
            incomingImagesRef.current.delete(transfer_id);
            setSecurityEvents((items) => [{ id: crypto.randomUUID(), label: "IMAGE INTEGRITY FAILURE", detail: "An encrypted image chunk failed authentication." }, ...items].slice(0, 5));
            socket.send(JSON.stringify({ type: "security_event", event: "INTEGRITY_FAILURE", sequence }));
          }
        }
        if (payload.type === "key_exchange" && payload.sender_id !== identity) {
          await receivePeerKey(payload.public_key);
        }
        if (payload.type === "participant_joined") {
          setConnection("Partner connected");
          sendPublicKey();
        }
        if (payload.type === "participant_left") {
          setConnection("Partner disconnected"); setCryptoStatus("Session ended"); sessionKeyRef.current = null;
          setError("Your partner disconnected. This room has ended.");
        }
        if (payload.type === "security_event") setSecurityEvents((items) => [{ id: crypto.randomUUID(), label: payload.event.replaceAll("_", " "), detail: "A security event was recorded in the room audit log." }, ...items].slice(0, 5));
        if (payload.type === "error") {
          if (payload.code === "REPLAY_DETECTED") {
            setSecurityEvents((items) => [{ id: crypto.randomUUID(), label: "REPLAY DETECTED", detail: payload.detail }, ...items].slice(0, 5));
          }
          setError(payload.detail || "The message could not be sent.");
        }
      } catch {
        setError("Received an unreadable message.");
      }
    };
    return () => {
      disposed = true;
      window.clearInterval(heartbeat);
      socket.close();
      socketRef.current = null;
      keyPairRef.current = null;
      sessionKeyRef.current = null;
      peerPublicKeyRef.current = null;
      pendingPeerPublicKeyRef.current = null;
    };
  }, [identity, room?.id, room?.joined, view]);

  useEffect(() => {
    if (view !== "room" || !room?.joined || !identity) return;
    let active = true;
    const loadAudit = async () => {
      try {
        const response = await fetch(`${API_URL}/session/${room.id}/logs?participant_id=${encodeURIComponent(identity)}`);
        if (!response.ok) return;
        const result = await response.json();
        if (active) setAudit(result);
      } catch { /* The live chat remains usable when audit refresh is temporarily unavailable. */ }
    };
    loadAudit();
    const timer = window.setInterval(loadAudit, 3000);
    return () => { active = false; window.clearInterval(timer); };
  }, [identity, room?.id, room?.joined, view]);

  useEffect(() => {
    if (view !== "room" || !room?.expires_at) return;
    const update = () => setRemaining(Math.max(0, Math.ceil((new Date(room.expires_at).getTime() - Date.now()) / 1000)));
    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, [room?.expires_at, view]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function createRoom() {
    setError(""); setBusy(true);
    try {
      const result = await request("/session/create", { creator_id: identity });
      setRoom({ ...result, joined: false });
      setView("room");
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function joinRoom(event) {
    event.preventDefault(); setError(""); setBusy(true);
    try {
      const result = await request("/session/join", { security_code: code.replace(/\D/g, ""), participant_id: identity });
      setRoom({ ...result, joined: true });
      setMessages([]);
      setSecurityEvents([]);
      setView("room");
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function enterCreatedRoom() {
    setError(""); setBusy(true);
    try {
      const result = await fetch(`${API_URL}/session/${room.id}`).then(async (r) => {
        const body = await r.json(); if (!r.ok) throw new Error(body.detail || "Could not open room."); return body;
      });
      setRoom({ ...room, ...result, joined: true });
    } catch (e) { setError(e.message); }
    finally { setBusy(false); }
  }

  async function leaveRoom() {
    if (room && identity) await request(`/session/${room.id}/leave`, { participant_id: identity }).catch(() => {});
    socketRef.current?.close();
    for (const url of objectUrlsRef.current) URL.revokeObjectURL(url);
    objectUrlsRef.current.clear(); incomingImagesRef.current.clear();
    setRoom(null); setMessages([]); setAudit({ records: [], integrity_valid: true, first_bad_record: null }); setCode(""); setError(""); setView("home");
  }

  async function sendMessage(event) {
    event.preventDefault();
    const text = draft.trim();
    if (!text || !sessionKeyRef.current || socketRef.current?.readyState !== WebSocket.OPEN || sendingRef.current) return;
    sendingRef.current = true;
    setSending(true);
    setError("");
    const sequence = sendSequenceRef.current + 1;
    try {
      const encrypted = await encryptText(sessionKeyRef.current, room.id, sequence, text);
      if (socketRef.current?.readyState !== WebSocket.OPEN) throw new Error("The connection was lost before the message could be sent.");
      socketRef.current.send(JSON.stringify({ type: "message", sequence, ...encrypted }));
      sendSequenceRef.current = sequence;
      setMessages((items) => [...items, { sender_id: identity, message: text, sent_at: new Date().toISOString(), sequence }]);
      setDraft("");
    } catch (error) {
      setError(error.message || "The encrypted message could not be sent.");
    } finally {
      sendingRef.current = false;
      setSending(false);
    }
  }

  async function sendImage(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    event.target.value = "";
    if (!file.type.startsWith("image/") || file.size < 1 || file.size > MAX_IMAGE_BYTES) {
      setError("Choose an image smaller than 10 MB."); return;
    }
    if (!sessionKeyRef.current || socketRef.current?.readyState !== WebSocket.OPEN || sendingRef.current) return;
    sendingRef.current = true; setSending(true); setError("");
    const transferId = crypto.randomUUID();
    const totalChunks = Math.ceil(file.size / IMAGE_CHUNK_BYTES);
    try {
      for (let index = 0; index < totalChunks; index += 1) {
        if (socketRef.current?.readyState !== WebSocket.OPEN) throw new Error("The connection was lost during image transfer.");
        const sequence = sendSequenceRef.current + 1;
        const bytes = new Uint8Array(await file.slice(index * IMAGE_CHUNK_BYTES, (index + 1) * IMAGE_CHUNK_BYTES).arrayBuffer());
        const context = `image:${transferId}:${index}:${totalChunks}:${file.name}:${file.type}:${file.size}`;
        const encrypted = await encryptBytes(sessionKeyRef.current, context, bytes);
        socketRef.current.send(JSON.stringify({ type: "image_chunk", sequence, transfer_id: transferId, file_name: file.name, mime_type: file.type, file_size: file.size, chunk_index: index, total_chunks: totalChunks, ...encrypted }));
        sendSequenceRef.current = sequence;
        setImageProgress({ done: index + 1, total: totalChunks });
      }
      const imageUrl = URL.createObjectURL(file); objectUrlsRef.current.add(imageUrl);
      setMessages((items) => [...items, { type: "image", sender_id: identity, file_name: file.name, imageUrl, sent_at: new Date().toISOString() }]);
    } catch (sendError) { setError(sendError.message || "The encrypted image could not be sent."); }
    finally { sendingRef.current = false; setSending(false); setImageProgress(null); setFileInputKey((key) => key + 1); }
  }

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="#" onClick={(e) => { e.preventDefault(); leaveRoom(); }} aria-label="CipherLink home">
          <span className="brand-mark">C</span><span>Cipher<span className="brand-light">Link</span></span>
        </a>
        <div className="top-status"><span className="status-dot" /> PRIVATE ROOM PROTOTYPE</div>
      </header>

      <section className="content">
        <div className="eyebrow"><span className="eyebrow-line" /> TEMPORARY CONNECTIONS</div>
        {view === "home" && <>
          <h1>Share a moment.<br /><span>Keep it between you.</span></h1>
          <p className="intro">A private space for two. Create a room, share its code, and start talking.</p>
          <div className="action-grid">
            <button className="action-card primary-card" onClick={createRoom} disabled={busy || !identity}>
              <span className="card-icon">+</span><span className="card-copy"><strong>Create a room</strong><small>Start a new temporary session</small></span><span className="card-arrow">&gt;</span>
            </button>
            <button className="action-card" onClick={() => { setView("join"); setError(""); }}>
              <span className="card-icon">+</span><span className="card-copy"><strong>Join a room</strong><small>Enter a code to connect</small></span><span className="card-arrow">&gt;</span>
            </button>
          </div>
          <div className="trust-note"><span>*</span> Rooms expire automatically | Only two participants</div>
        </>}

        {view === "join" && <div className="panel narrow-panel">
          <button className="back-link" onClick={() => { setView("home"); setError(""); }}>&lt; Back</button>
          <h2>Join a room</h2><p className="panel-copy">Enter the six-digit code shared with you.</p>
          <form onSubmit={joinRoom}>
            <label htmlFor="room-code">ROOM CODE</label>
            <input id="room-code" className="code-input" autoComplete="one-time-code" inputMode="numeric" maxLength={7} placeholder="000 - 000" value={code} onChange={(e) => setCode(e.target.value.replace(/[^\d-]/g, "").slice(0, 7))} />
            {error && <p className="error-message">{error}</p>}
            <button className="button-main full-button" disabled={busy || code.replace(/\D/g, "").length !== 6}>Join securely <span>&gt;</span></button>
          </form>
        </div>}

        {view === "room" && room && <div className="panel room-panel">
          <div className="room-heading"><div><div className="room-kicker">TEMPORARY ROOM</div><h2>{room.security_code ? "Your room is ready" : "You are connected"}</h2></div><button className="leave-button" onClick={leaveRoom}>Leave room <span>x</span></button></div>
          {room.security_code && !room.joined && <div className="share-card"><p>SHARE THIS CODE WITH YOUR PARTNER</p><div className="room-code">{room.security_code.slice(0, 3)}<span> - </span>{room.security_code.slice(3)}</div><div className="expiry">EXPIRES IN <b>{formatClock(remaining)}</b></div><button className="button-main" onClick={enterCreatedRoom} disabled={busy || remaining === 0}>{busy ? "Opening" : "Enter room"}<span>&gt;</span></button></div>}
          {room.joined && <>
            <div className="connection-line">
              <span className={connection === "Connected" || connection === "Partner connected" ? "online-dot" : "offline-dot"} />
              {connection}
              <span className="connection-divider">|</span>
              <span className={cryptoStatus === "End-to-end encrypted" ? "crypto-ready" : "crypto-waiting"}>
                {cryptoStatus === "End-to-end encrypted" ? "End-to-end encrypted | AES-256-GCM" : cryptoStatus}
              </span>
            </div>
            {keyFingerprint && <div className="fingerprint-card">
              <span>KEY FINGERPRINT</span>
              <strong>{keyFingerprint}</strong>
              <small>Compare this fingerprint with your partner through a separate trusted channel before sharing sensitive information.</small>
            </div>}
            {handshakeDetails && <details className="handshake-inspector">
              <summary>Show handshake keys (demonstration only)</summary>
              <p>A is this browser and B is the partner in this view. These values expose this room's cryptographic secrets. Keep them private and never send them to anyone.</p>
              <div className="handshake-value"><strong>A private key (PKCS#8 Base64)</strong><code>{handshakeDetails.privateKey}</code></div>
              <div className="handshake-value"><strong>A public key (Base64)</strong><code>{handshakeDetails.publicKey}</code></div>
              <div className="handshake-value"><strong>B public key (Base64)</strong><code>{handshakeDetails.peerPublicKey || "Waiting for partner key..."}</code></div>
              <div className="handshake-value"><strong>Shared secret (Base64)</strong><code>{handshakeDetails.sharedSecret || "Derived after partner key arrives..."}</code></div>
            </details>}
            <div className="chat-and-audit"><div className="chat-column">
            <div className="chat-window" aria-live="polite">
              {messages.length === 0 && <div className="empty-chat"><span>*</span><p>Your conversation starts here.</p><small>Only encrypted message data is relayed through the CipherLink server.</small></div>}
              {messages.map((message, index) => <div className={`message ${message.sender_id === identity ? "own-message" : ""}`} key={`${index}-${message.sent_at}`}><div className="message-label">{message.sender_id === identity ? "YOU" : "PARTNER"}</div>{message.type === "image" ? <div className="message-image"><a href={message.imageUrl} target="_blank" rel="noreferrer"><img src={message.imageUrl} alt={message.file_name} /></a><small>{message.file_name}</small></div> : <div className="message-bubble">{message.message}</div>}</div>)}
              <div ref={bottomRef} />
            </div>
            {securityEvents.length > 0 && <div className="security-events" aria-live="polite">
              {securityEvents.map((event) => <div className="security-event" key={event.id}><span>! {event.label}</span><small>{event.detail}</small></div>)}
            </div>}
            <form className="composer" onSubmit={sendMessage}>
              <input key={fileInputKey} ref={imageInputRef} className="visually-hidden" type="file" accept="image/*" onChange={sendImage} aria-label="Choose an image to send" />
              <button type="button" className="attach-button" onClick={() => imageInputRef.current?.click()} disabled={cryptoStatus !== "End-to-end encrypted" || sending || connection === "Disconnected"} aria-label="Send encrypted image">IMG</button>
              <input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder={cryptoStatus === "End-to-end encrypted" ? "Write an encrypted message..." : "Waiting for secure key exchange..."} maxLength={4000} aria-label="Write a message" />
              <button type="submit" disabled={!draft.trim() || cryptoStatus !== "End-to-end encrypted" || connection === "Disconnected" || sending} aria-label="Send encrypted message">
                {sending ? "..." : ">"}
              </button>
            </form>
            {imageProgress && <div className="image-progress">Encrypting and sending image  {imageProgress.done}/{imageProgress.total} chunks</div>}
            </div><aside className="audit-panel" aria-label="Room audit log">
              <div className="audit-heading"><div><span>SECURITY</span><h3>Room activity</h3></div><span className="audit-live"><i /> LIVE</span></div>
              <div className={audit.integrity_valid ? "audit-integrity" : "audit-integrity audit-invalid"}><span>{audit.integrity_valid ? "OK" : "!"}</span><div><strong>{audit.integrity_valid ? "HASH CHAIN VERIFIED" : "LOG INTEGRITY FAILURE"}</strong><small>{audit.integrity_valid ? "Recorded events match their audit chain." : `First inconsistent record: #${audit.first_bad_record ?? "?"}`}</small></div></div>
              <div className="audit-list">{audit.records.length === 0 && <p className="audit-empty">Room events will appear here.</p>}{[...audit.records].reverse().map((record) => <div className="audit-record" key={record.sequence}><div><strong>{record.event_type.replaceAll("_", " ")}</strong><time>{new Date(record.created_at).toLocaleTimeString()}</time></div><small>{record.actor_id === identity ? "You" : record.actor_id ? "Room participant" : "Service"}{record.details?.sequence ? `  sequence ${record.details.sequence}` : ""}{record.details?.total_chunks ? `  ${record.details.total_chunks} image chunks` : ""}</small></div>)}</div>
              <p className="audit-note">The audit log records event metadata. Message and image contents remain encrypted.</p>
            </aside></div>
          </>}
          {error && <p className="error-message">{error}</p>}
        </div>}
        <footer className="footer"><span>BUILT FOR CONVERSATIONS THAT DO NOT LINGER</span><span>PHASE 1-13 PROTOTYPE</span></footer>
      </section>
    </main>
  );
}

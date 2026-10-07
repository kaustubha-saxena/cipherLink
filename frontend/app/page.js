"use client";

import { useEffect, useRef, useState } from "react";

const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

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
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState("");
  const socketRef = useRef(null);
  const bottomRef = useRef(null);

  useEffect(() => setIdentity(getIdentity()), []);

  useEffect(() => {
    if (view !== "room" || !room?.joined) return;
    const socketUrl = API_URL.replace(/^http/, "ws");
    const socket = new WebSocket(`${socketUrl}/ws/${room.id}?participant_id=${encodeURIComponent(identity)}`);
    socketRef.current = socket;
    socket.onopen = () => setConnection("Connected");
    socket.onclose = () => setConnection("Disconnected");
    socket.onerror = () => setConnection("Connection issue");
    socket.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "message") setMessages((items) => [...items, payload]);
        if (payload.type === "participant_joined") setConnection("Partner connected");
        if (payload.type === "participant_left") setConnection("Partner disconnected");
        if (payload.type === "error") setError(payload.detail || "The message could not be sent.");
      } catch {
        setError("Received an unreadable message.");
      }
    };
    return () => {
      socket.close();
      socketRef.current = null;
    };
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
    setRoom(null); setMessages([]); setCode(""); setError(""); setView("home");
  }

  function sendMessage(event) {
    event.preventDefault();
    const text = draft.trim();
    if (!text || socketRef.current?.readyState !== WebSocket.OPEN) return;
    socketRef.current.send(JSON.stringify({ type: "message", message: text }));
    setDraft("");
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
              <span className="card-icon">↗</span><span className="card-copy"><strong>Create a room</strong><small>Start a new temporary session</small></span><span className="card-arrow">→</span>
            </button>
            <button className="action-card" onClick={() => { setView("join"); setError(""); }}>
              <span className="card-icon join-icon">⌁</span><span className="card-copy"><strong>Join a room</strong><small>Enter a code to connect</small></span><span className="card-arrow">→</span>
            </button>
          </div>
          <div className="trust-note"><span>◈</span> Rooms expire automatically · Only two participants</div>
        </>}

        {view === "join" && <div className="panel narrow-panel">
          <button className="back-link" onClick={() => { setView("home"); setError(""); }}>← Back</button>
          <h2>Join a room</h2><p className="panel-copy">Enter the six-digit code shared with you.</p>
          <form onSubmit={joinRoom}>
            <label htmlFor="room-code">ROOM CODE</label>
            <input id="room-code" className="code-input" autoComplete="one-time-code" inputMode="numeric" maxLength={7} placeholder="000 – 000" value={code} onChange={(e) => setCode(e.target.value.replace(/[^\d-]/g, "").slice(0, 7))} />
            {error && <p className="error-message">{error}</p>}
            <button className="button-main full-button" disabled={busy || code.replace(/\D/g, "").length !== 6}>{busy ? "Joining…" : "Join securely"}<span>→</span></button>
          </form>
        </div>}

        {view === "room" && room && <div className="panel room-panel">
          <div className="room-heading"><div><div className="room-kicker">TEMPORARY ROOM</div><h2>{room.security_code ? "Your room is ready" : "You’re connected"}</h2></div><button className="leave-button" onClick={leaveRoom}>Leave room <span>×</span></button></div>
          {room.security_code && !room.joined && <div className="share-card"><p>SHARE THIS CODE WITH YOUR PARTNER</p><div className="room-code">{room.security_code.slice(0, 3)}<span>–</span>{room.security_code.slice(3)}</div><div className="expiry">EXPIRES IN <b>{formatClock(remaining)}</b></div><button className="button-main" onClick={enterCreatedRoom} disabled={busy || remaining === 0}>{busy ? "Opening…" : "Enter room"}<span>→</span></button></div>}
          {room.joined && <>
            <div className="connection-line"><span className={connection === "Connected" || connection === "Partner connected" ? "online-dot" : "offline-dot"} />{connection}<span className="connection-divider">·</span> Plaintext prototype</div>
            <div className="chat-window" aria-live="polite">
              {messages.length === 0 && <div className="empty-chat"><span>✳</span><p>Your conversation starts here.</p><small>Messages are relayed through the CipherLink server.</small></div>}
              {messages.map((message, index) => <div className="message" key={`${index}-${message.sent_at}`}><div className="message-label">{message.sender_id === identity ? "YOU" : "PARTNER"}</div><div className="message-bubble">{message.message}</div></div>)}
              <div ref={bottomRef} />
            </div>
            <form className="composer" onSubmit={sendMessage}><input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder="Write a message…" maxLength={4000} aria-label="Write a message" /><button type="submit" disabled={!draft.trim() || connection === "Disconnected"} aria-label="Send message">↑</button></form>
          </>}
          {error && <p className="error-message">{error}</p>}
        </div>}
        <footer className="footer"><span>BUILT FOR CONVERSATIONS THAT DON’T LINGER</span><span>PHASE 1—4 PROTOTYPE</span></footer>
      </section>
    </main>
  );
}

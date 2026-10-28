"use client";

import Image from "next/image";
import { useEffect, useRef, useState } from "react";
import { createEphemeralKeyPair, createEphemeralSigningKeyPair, createKeyFingerprint, decryptBytes, decryptText, deriveSessionMaterials, encryptBytes, encryptText, measureTextAnalysis, signTextEnvelope, verifyTextEnvelope } from "@/lib/crypto";
import { analyzeImagePixels } from "@/lib/imageAnalysis";

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

function metricTime(value) {
  return Number.isFinite(value) ? `${value.toFixed(3)} ms` : "Not available";
}

function roundMilliseconds(value) {
  return Number.isFinite(value) ? Number(value.toFixed(3)) : null;
}

function metricSpeed(value) {
  if (!Number.isFinite(value)) return "Not available";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)} MB/s`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)} KB/s`;
  return `${value.toFixed(0)} B/s`;
}

function OperationTimeChart({ encryptionMs, decryptionMs }) {
  const rows = [
    { label: "Encryption", value: encryptionMs },
    { label: "Decryption", value: decryptionMs },
  ];
  const maximum = Math.max(...rows.map((row) => Number.isFinite(row.value) ? row.value : 0), 0.001);
  const chartLeft = 116;
  const chartWidth = 326;
  const chartRight = chartLeft + chartWidth;
  const rowCenters = [43, 81];
  const tickValues = [0, 0.25, 0.5, 0.75, 1];
  return <svg className="operation-time-chart" viewBox="0 0 540 154" role="img" aria-label={`Encryption time ${metricTime(encryptionMs)}; decryption time ${metricTime(decryptionMs)}; both bars use one horizontal time axis in milliseconds`}>
    {tickValues.map((fraction) => {
      const x = chartLeft + chartWidth * fraction;
      return <g key={fraction}>
        <line className="operation-chart-grid" x1={x} y1="18" x2={x} y2="104" />
        <text className="operation-chart-tick" x={x} y="119" textAnchor={fraction === 0 ? "start" : fraction === 1 ? "end" : "middle"}>
          {`${(maximum * fraction).toFixed(3)} ms`}
        </text>
      </g>;
    })}
    {rows.map((row, index) => {
      const center = rowCenters[index];
      const width = Number.isFinite(row.value) ? (Math.max(0, row.value) / maximum) * chartWidth : 0;
      return <g key={row.label}>
        <text className="operation-chart-label" x="4" y={center + 4}>{row.label}</text>
        <rect className="operation-chart-track" x={chartLeft} y={center - 11} width={chartWidth} height="22" rx="5" />
        <rect className={index === 0 ? "operation-chart-bar operation-chart-encrypt" : "operation-chart-bar operation-chart-decrypt"} x={chartLeft} y={center - 11} width={width} height="22" rx="5" />
        <text className="operation-chart-value" x="452" y={center + 4}>{metricTime(row.value)}</text>
      </g>;
    })}
    <line className="operation-chart-axis" x1={chartLeft} y1="105" x2={chartRight} y2="105" />
    <text className="operation-chart-title" x={(chartLeft + chartRight) / 2} y="147" textAnchor="middle">Time (milliseconds)</text>
  </svg>;
}

async function collectTextAnalysis(text, ciphertext) {
  try {
    return await measureTextAnalysis(text, ciphertext);
  } catch {
    return { digestHex: "Analysis unavailable", hashTimeMs: null, ciphertextEntropy: null, confusion: null, avalanche: null };
  }
}

function TextMetrics({ metrics }) {
  if (!metrics) return null;
  const performanceRows = [
    { label: "Encrypt", time: metrics.encryptionMs, speed: metrics.encryptionBytesPerSecond },
    { label: "Decrypt", time: metrics.decryptionMs, speed: metrics.decryptionBytesPerSecond },
  ];
  const maxSpeed = Math.max(...performanceRows.map((item) => item.speed || 0), 1);
  const comparison = (title, values) => (
    <div className="text-analysis-comparison">
      <div className="text-analysis-subtitle">{title} <span>ideal 50% bits / 100% bytes</span></div>
      {values ? <div className="text-analysis-bars" role="img" aria-label={`${title}: ${values.changedBitsPercent.toFixed(1)} percent of bits and ${values.changedBytesPercent.toFixed(1)} percent of bytes changed`}>
        <div><span>Bits changed</span><i><b style={{ width: `${values.changedBitsPercent}%` }} /></i><strong>{values.changedBitsPercent.toFixed(1)}%</strong></div>
        <div><span>Bytes / characters changed</span><i><b style={{ width: `${values.changedBytesPercent}%` }} /></i><strong>{values.changedBytesPercent.toFixed(1)}%</strong></div>
      </div> : <small className="text-metrics-note">Measurement unavailable in this browser.</small>}
    </div>
  );

  return <details className="text-metrics">
    <summary>Text security &amp; performance</summary>
    <div className="text-metrics-content">
      <section className="text-metrics-section">
        <h4>Performance</h4>
        <OperationTimeChart encryptionMs={metrics.encryptionMs} decryptionMs={metrics.decryptionMs} />
        <div className="text-throughput-chart" role="img" aria-label="Encryption and decryption throughput comparison">
          {performanceRows.map((item) => <div className="text-throughput-row" key={item.label}><span>{item.label}</span><i><b style={{ width: `${Math.min(100, ((item.speed || 0) / maxSpeed) * 100)}%` }} /></i><strong>{metricSpeed(item.speed)}</strong></div>)}
        </div>
        <small className="text-metrics-note">Bars compare encrypt and decrypt time and throughput. {metrics.received ? "Encryption is sender-reported; decryption is timed in this browser." : "Encryption is timed before sending; decryption is a local round-trip measurement."} Hardware and message size affect results.</small>
      </section>
      <section className="text-metrics-section">
        <h4>Hash: SHA-256</h4>
        <div className="text-digest"><code>{metrics.digestHex}</code><span>Generated in {metricTime(metrics.hashTimeMs)}</span></div>
        <ul className="hash-criteria">
          <li><span>Pre-image resistance</span><b>SHA-256 design property</b></li>
          <li><span>Second-preimage resistance</span><b>SHA-256 design property</b></li>
          <li><span>Collision resistance</span><b>SHA-256 design property</b></li>
        </ul>
        <small className="text-metrics-note">These are cryptographic design criteria, not properties that can be proven by hashing one message.</small>
      </section>
      <section className="text-metrics-section">
        <h4>Confusion and diffusion</h4>
        {comparison("Confusion proxy - change AES test key", metrics.confusion)}
        <div className="text-diffusion"><span>Diffusion proxy - ciphertext byte entropy</span><i><b style={{ width: `${Math.min(100, ((metrics.ciphertextEntropy || 0) / 8) * 100)}%` }} /></i><strong>{Number.isFinite(metrics.ciphertextEntropy) ? `${metrics.ciphertextEntropy.toFixed(2)} / 8 bits per byte` : "Not available"}</strong></div>
        {comparison("Avalanche - flip one input bit", metrics.avalanche)}
        <small className="text-metrics-note">Avalanche is demonstrated by encrypting a 16-byte test block with a temporary AES-CBC key, flipping one input bit, then comparing the encrypted outputs. This test is separate from the live AES-GCM chat message.</small>
      </section>
      <section className="text-metrics-section">
        <h4>ECDSA P-256 signature</h4>
        <div className="signature-metrics">
          <span>Generation <b>{metricTime(metrics.signatureGenerationMs)}</b></span>
          <span>Verification <b>{metricTime(metrics.signatureVerificationMs)}</b></span>
          <strong className={metrics.signatureVerified ? "signature-valid" : "signature-invalid"}>{metrics.signatureVerified ? "Signature verified" : "Signature not verified"}</strong>
        </div>
        <small className="text-metrics-note">The signature covers the room, sequence number, nonce and ciphertext. {metrics.received ? "Generation time is sender-reported; verification is timed in this browser before display." : "Generation and local verification are timed before sending."}</small>
      </section>
    </div>
  </details>;
}

function ImageMetrics({ analysis }) {
  if (!analysis || analysis.error) return <details className="image-analysis">
    <summary>Image pixels, security &amp; performance</summary>
    <div className="image-analysis-content"><small className="image-metrics-note">{analysis?.error ? "Image analysis is unavailable in this browser. The image transfer completed normally." : "Preparing pixel previews and calculating image metrics..."}</small></div>
  </details>;
  const metrics = analysis.metrics;
  const performanceValues = [analysis.encryptionBytesPerSecond || 0, analysis.decryptionBytesPerSecond || 0];
  const maximumSpeed = Math.max(...performanceValues, 1);
  const formatPercent = (value) => Number.isFinite(value) ? `${value.toFixed(3)}%` : "Not available";
  const formatCorrelation = (value) => Number.isFinite(value) ? value.toFixed(4) : "Not available";

  return <details className="image-analysis">
    <summary>Image pixels, security &amp; performance</summary>
    <div className="image-analysis-content">
      <section className="image-pixel-previews" aria-label="RGB and encrypted image pixel previews">
        <figure><Image src={analysis.rgbPreview} alt="Downsampled original image shown as RGB pixels" width={analysis.width} height={analysis.height} unoptimized /><figcaption>Original RGB pixels</figcaption></figure>
        <figure><Image src={analysis.encryptedPreview} alt="Actual AES-GCM encrypted bytes visualized as colored pixels" width={analysis.width} height={analysis.height} unoptimized /><figcaption>AES-GCM encrypted bytes</figcaption></figure>
      </section>
      <section className="image-metric-section">
        <h4>Image performance</h4>
        <OperationTimeChart encryptionMs={analysis.encryptionMs} decryptionMs={analysis.decryptionMs} />
        <div className="image-speed-chart" role="img" aria-label="Image encryption and decryption throughput comparison">
          {[{ label: "Encryption", speed: analysis.encryptionBytesPerSecond }, { label: "Decryption", speed: analysis.decryptionBytesPerSecond }].map((item) => <div className="image-speed-row" key={item.label}>
            <span>{item.label}</span><i><em style={{ width: `${Math.min(100, ((item.speed || 0) / maximumSpeed) * 100)}%` }} /></i><strong>{metricSpeed(item.speed)}</strong>
          </div>)}
        </div>
        <small className="image-metrics-note">Times cover AES-GCM operations, and speed uses the original file size. {analysis.received ? "Encryption is a local benchmark; decryption is timed on the received chunks." : "Encryption is timed during upload; decryption is a local round-trip measurement of the sent chunks."}</small>
      </section>
      <section className="image-metric-section">
        <h4>Security metrics</h4>
        <div className="image-security-grid">
          <div><span>NPCR</span><strong>{formatPercent(metrics.npcr)}</strong></div>
          <div><span>UACI</span><strong>{formatPercent(metrics.uaci)}</strong></div>
          <div><span>Information entropy</span><strong>{metrics.entropy.toFixed(3)} / 8 bits per byte</strong></div>
          <div><span>MSE</span><strong>{metrics.mse.toFixed(2)}</strong></div>
          <div><span>PSNR</span><strong>{Number.isFinite(metrics.psnr) ? `${metrics.psnr.toFixed(2)} dB` : "Infinite"}</strong></div>
        </div>
        <div className="image-correlation"><span>Adjacent encrypted-pixel correlation</span><b>Horizontal {formatCorrelation(metrics.correlations.horizontal)}</b><b>Vertical {formatCorrelation(metrics.correlations.vertical)}</b><b>Diagonal {formatCorrelation(metrics.correlations.diagonal)}</b></div>
        <small className="image-metrics-note">NPCR/UACI use two AES-GCM test encryptions of the RGB sample, changing one input bit and reusing a nonce only with a disposable test key; the GCM tag is excluded from pixel comparison. GCM counter mode changes the corresponding ciphertext byte while its tag authenticates the data, so NPCR/UACI can be low. Entropy and correlation use the actual encrypted stream. MSE/PSNR compare the original RGB sample with ciphertext bytes visualized as pixels; they are visual difference measures, not decryption quality tests.</small>
      </section>
    </div>
  </details>;
}

function decodeBase64Bytes(value) {
  const binary = window.atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function combineByteArrays(parts) {
  const totalLength = parts.reduce((total, part) => total + part.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    combined.set(part, offset);
    offset += part.length;
  }
  return combined;
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
  const [cipherRecords, setCipherRecords] = useState([]);
  const [imageProgress, setImageProgress] = useState(null);
  const [fileInputKey, setFileInputKey] = useState(0);
  const socketRef = useRef(null);
  const sendingRef = useRef(false);
  const bottomRef = useRef(null);
  const keyPairRef = useRef(null);
  const sessionKeyRef = useRef(null);
  const peerPublicKeyRef = useRef(null);
  const peerSigningPublicKeyRef = useRef(null);
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
    peerSigningPublicKeyRef.current = null;
    pendingPeerPublicKeyRef.current = null;
    sendSequenceRef.current = 0;
    receiveSequencesRef.current = new Map();
    setConnection("Connecting");
    setCryptoStatus("Preparing browser key");
    setKeyFingerprint("");
    setHandshakeDetails(null);

    function sendPublicKey() {
      const pair = keyPairRef.current;
      if (pair?.signingKeyPair && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "key_exchange", public_key: pair.publicKey, signing_public_key: pair.signingKeyPair.publicKey }));
      }
    }

    async function receivePeerKey(publicKey, signingPublicKey) {
      if (!keyPairRef.current || !signingPublicKey) {
        pendingPeerPublicKeyRef.current = { publicKey, signingPublicKey };
        return;
      }
      if (publicKey === peerPublicKeyRef.current && signingPublicKey === peerSigningPublicKeyRef.current) return;
      peerPublicKeyRef.current = publicKey;
      peerSigningPublicKeyRef.current = signingPublicKey;
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

    const keySetup = Promise.all([createEphemeralKeyPair(), createEphemeralSigningKeyPair()]);
    keySetup.then(([pair, signingKeyPair]) => {
      if (!disposed) {
        keyPairRef.current = { ...pair, signingKeyPair };
        setHandshakeDetails({ privateKey: pair.privateKeyBase64, publicKey: pair.publicKey, peerPublicKey: "", sharedSecret: "" });
        setCryptoStatus("Waiting for partner key");
        sendPublicKey();
        if (pendingPeerPublicKeyRef.current) receivePeerKey(pendingPeerPublicKeyRef.current.publicKey, pendingPeerPublicKeyRef.current.signingPublicKey);
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
          setCipherRecords((items) => [{
            id: crypto.randomUUID(),
            direction: "RECEIVED",
            kind: "TEXT",
            sequence: payload.sequence,
            nonce: payload.nonce,
            ciphertext: payload.ciphertext,
            loggedAt: new Date().toISOString(),
          }, ...items].slice(0, 20));
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
            const verifyStart = performance.now();
            const signatureVerified = await verifyTextEnvelope(
              peerSigningPublicKeyRef.current,
              room.id,
              payload.sequence,
              payload.nonce,
              payload.ciphertext,
              payload.signature,
            );
            const signatureVerificationMs = performance.now() - verifyStart;
            if (!signatureVerified) throw new Error("The message signature is invalid.");
            const decryptStart = performance.now();
            const text = await decryptText(sessionKeyRef.current, room.id, payload.sequence, payload.nonce, payload.ciphertext);
            const decryptionDurationMs = performance.now() - decryptStart;
            const decryptionMs = roundMilliseconds(decryptionDurationMs);
            const analysis = await collectTextAnalysis(text, payload.ciphertext);
            const textBytes = new TextEncoder().encode(text).length;
            const metrics = {
              ...analysis,
              encryptionMs: Number.isFinite(payload.encryption_ms) ? payload.encryption_ms : null,
              decryptionMs,
              encryptionBytesPerSecond: Number.isFinite(payload.encryption_ms) && payload.encryption_ms > 0 ? textBytes / (payload.encryption_ms / 1000) : null,
              decryptionBytesPerSecond: decryptionDurationMs > 0 ? textBytes / (decryptionDurationMs / 1000) : null,
              signatureGenerationMs: Number.isFinite(payload.signature_generation_ms) ? payload.signature_generation_ms : null,
              signatureVerificationMs,
              signatureVerified,
              received: true,
            };
            receiveSequencesRef.current.set(payload.sender_id, payload.sequence);
            setMessages((items) => [...items, { ...payload, message: text, metrics }]);
          } catch (error) {
            setSecurityEvents((items) => [{ id: crypto.randomUUID(), label: "INTEGRITY CHECK FAILED", detail: error.message === "The message signature is invalid." ? error.message : "A modified or invalid encrypted message was rejected." }, ...items].slice(0, 5));
            socket.send(JSON.stringify({ type: "security_event", event: "INTEGRITY_FAILURE", sequence: payload.sequence }));
          }
        }
        if (payload.type === "image_chunk" && payload.sender_id !== identity) {
          const { transfer_id, total_chunks, chunk_index, file_size, file_name, mime_type, sequence } = payload;
          setCipherRecords((items) => [{
            id: crypto.randomUUID(),
            direction: "RECEIVED",
            kind: `IMAGE ${chunk_index + 1}/${total_chunks}`,
            sequence,
            nonce: payload.nonce,
            ciphertext: payload.ciphertext,
            loggedAt: new Date().toISOString(),
          }, ...items].slice(0, 20));
          const previousSequence = receiveSequencesRef.current.get(payload.sender_id) || 0;
          if (!Number.isSafeInteger(sequence) || sequence <= previousSequence) {
            socket.send(JSON.stringify({ type: "security_event", event: "REPLAY_DETECTED", sequence }));
            return;
          }
          if (!sessionKeyRef.current || !Number.isInteger(total_chunks) || total_chunks < 1 || total_chunks > 214 || !Number.isInteger(chunk_index) || chunk_index < 0 || chunk_index >= total_chunks || file_size > MAX_IMAGE_BYTES || !mime_type?.startsWith("image/")) throw new Error("Image transfer metadata is invalid.");
          let transfer = incomingImagesRef.current.get(transfer_id);
          if (!transfer) {
            if (incomingImagesRef.current.size >= 3) throw new Error("Too many image transfers are in progress.");
            transfer = { total_chunks, file_size, file_name, mime_type, chunks: new Array(total_chunks), encryptedChunks: new Array(total_chunks), received: 0, decryptionDurationMs: 0 };
            incomingImagesRef.current.set(transfer_id, transfer);
          }
          if (transfer.total_chunks !== total_chunks || transfer.chunks[chunk_index]) throw new Error("Image chunk order or metadata is invalid.");
          transfer.encryptedChunks[chunk_index] = decodeBase64Bytes(payload.ciphertext);
          const context = `image:${transfer_id}:${chunk_index}:${total_chunks}:${file_name}:${mime_type}:${file_size}`;
          try {
            const decryptStart = performance.now();
            transfer.chunks[chunk_index] = await decryptBytes(sessionKeyRef.current, context, payload.nonce, payload.ciphertext);
            transfer.decryptionDurationMs += performance.now() - decryptStart;
            receiveSequencesRef.current.set(payload.sender_id, sequence);
            transfer.received += 1;
            if (transfer.received === total_chunks) {
              const blob = new Blob(transfer.chunks, { type: mime_type });
              if (blob.size !== file_size) throw new Error("The received image size did not match its metadata.");
              const encryptedStream = combineByteArrays(transfer.encryptedChunks);
              const imageUrl = URL.createObjectURL(blob);
              objectUrlsRef.current.add(imageUrl);
              setMessages((items) => [...items, { type: "image", transfer_id, sender_id: payload.sender_id, file_name, imageUrl, sent_at: payload.sent_at }]);
              const decryptionMs = roundMilliseconds(transfer.decryptionDurationMs);
              const decryptionBytesPerSecond = transfer.decryptionDurationMs > 0 ? file_size / (transfer.decryptionDurationMs / 1000) : null;
              const analysisKey = sessionKeyRef.current;
              (async () => {
                let encryptionDurationMs = 0;
                for (let index = 0; index < transfer.total_chunks; index += 1) {
                  const context = `image:${transfer_id}:${index}:${transfer.total_chunks}:${file_name}:${mime_type}:${file_size}`;
                  const encryptStart = performance.now();
                  await encryptBytes(analysisKey, context, transfer.chunks[index]);
                  encryptionDurationMs += performance.now() - encryptStart;
                }
                const encryptionMs = roundMilliseconds(encryptionDurationMs);
                const encryptionBytesPerSecond = encryptionDurationMs > 0 ? file_size / (encryptionDurationMs / 1000) : null;
                const pixels = await analyzeImagePixels(blob, encryptedStream);
                setMessages((items) => items.map((message) => message.transfer_id === transfer_id
                  ? { ...message, imageAnalysis: { ...pixels, encryptionMs, decryptionMs, encryptionBytesPerSecond, decryptionBytesPerSecond, received: true } }
                  : message));
              })().catch(() => {
                setMessages((items) => items.map((message) => message.transfer_id === transfer_id
                  ? { ...message, imageAnalysis: { error: true } }
                  : message));
              });
              incomingImagesRef.current.delete(transfer_id);
            }
          } catch {
            incomingImagesRef.current.delete(transfer_id);
            setSecurityEvents((items) => [{ id: crypto.randomUUID(), label: "IMAGE INTEGRITY FAILURE", detail: "An encrypted image chunk failed authentication." }, ...items].slice(0, 5));
            socket.send(JSON.stringify({ type: "security_event", event: "INTEGRITY_FAILURE", sequence }));
          }
        }
        if (payload.type === "key_exchange" && payload.sender_id !== identity) {
          await receivePeerKey(payload.public_key, payload.signing_public_key);
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
      peerSigningPublicKeyRef.current = null;
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
      setCipherRecords([]);
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
    setRoom(null); setMessages([]); setAudit({ records: [], integrity_valid: true, first_bad_record: null }); setCipherRecords([]); setCode(""); setError(""); setView("home");
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
      const encryptionStart = performance.now();
      const encrypted = await encryptText(sessionKeyRef.current, room.id, sequence, text);
      const encryptionDurationMs = performance.now() - encryptionStart;
      const encryptionMs = roundMilliseconds(encryptionDurationMs);
      const signatureStart = performance.now();
      const signature = await signTextEnvelope(keyPairRef.current.signingKeyPair.privateKey, room.id, sequence, encrypted.nonce, encrypted.ciphertext);
      const signatureGenerationMs = performance.now() - signatureStart;
      const verificationStart = performance.now();
      const signatureVerified = await verifyTextEnvelope(keyPairRef.current.signingKeyPair.publicKey, room.id, sequence, encrypted.nonce, encrypted.ciphertext, signature);
      const signatureVerificationMs = performance.now() - verificationStart;
      if (!signatureVerified) throw new Error("The generated message signature could not be verified.");
      let decryptionMs = null;
      let decryptionDurationMs = null;
      try {
        const decryptionStart = performance.now();
        const roundTripText = await decryptText(sessionKeyRef.current, room.id, sequence, encrypted.nonce, encrypted.ciphertext);
        decryptionDurationMs = performance.now() - decryptionStart;
        decryptionMs = roundMilliseconds(decryptionDurationMs);
        if (roundTripText !== text) decryptionMs = null;
      } catch { /* Keep diagnostic decryption from blocking a message send. */ }
      const analysis = await collectTextAnalysis(text, encrypted.ciphertext);
      const textBytes = new TextEncoder().encode(text).length;
      const metrics = {
        ...analysis,
        encryptionMs,
        decryptionMs,
        encryptionBytesPerSecond: encryptionDurationMs > 0 ? textBytes / (encryptionDurationMs / 1000) : null,
        decryptionBytesPerSecond: decryptionDurationMs > 0 ? textBytes / (decryptionDurationMs / 1000) : null,
        signatureGenerationMs,
        signatureVerificationMs,
        signatureVerified,
        received: false,
      };
      if (socketRef.current?.readyState !== WebSocket.OPEN) throw new Error("The connection was lost before the message could be sent.");
      socketRef.current.send(JSON.stringify({ type: "message", sequence, signature, encryption_ms: encryptionMs, signature_generation_ms: signatureGenerationMs, ...encrypted }));
      setCipherRecords((items) => [{
        id: crypto.randomUUID(),
        direction: "SENT",
        kind: "TEXT",
        sequence,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
        loggedAt: new Date().toISOString(),
      }, ...items].slice(0, 20));
      sendSequenceRef.current = sequence;
      setMessages((items) => [...items, { sender_id: identity, message: text, sent_at: new Date().toISOString(), sequence, metrics }]);
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
    const encryptedChunkParts = [];
    const encryptedChunkEnvelopes = [];
    let encryptionDurationMs = 0;
    const encryptionKey = sessionKeyRef.current;
    try {
      for (let index = 0; index < totalChunks; index += 1) {
        if (socketRef.current?.readyState !== WebSocket.OPEN) throw new Error("The connection was lost during image transfer.");
        const sequence = sendSequenceRef.current + 1;
        const bytes = new Uint8Array(await file.slice(index * IMAGE_CHUNK_BYTES, (index + 1) * IMAGE_CHUNK_BYTES).arrayBuffer());
        const context = `image:${transferId}:${index}:${totalChunks}:${file.name}:${file.type}:${file.size}`;
        const encryptionStart = performance.now();
        const encrypted = await encryptBytes(encryptionKey, context, bytes);
        encryptionDurationMs += performance.now() - encryptionStart;
        encryptedChunkParts.push(decodeBase64Bytes(encrypted.ciphertext));
        encryptedChunkEnvelopes.push({ context, nonce: encrypted.nonce, ciphertext: encrypted.ciphertext });
        const encryptionMs = roundMilliseconds(encryptionDurationMs);
        socketRef.current.send(JSON.stringify({ type: "image_chunk", sequence, transfer_id: transferId, file_name: file.name, mime_type: file.type, file_size: file.size, chunk_index: index, total_chunks: totalChunks, ...encrypted }));
        setCipherRecords((items) => [{
          id: crypto.randomUUID(),
          direction: "SENT",
          kind: `IMAGE ${index + 1}/${totalChunks}`,
          sequence,
          nonce: encrypted.nonce,
          ciphertext: encrypted.ciphertext,
          loggedAt: new Date().toISOString(),
        }, ...items].slice(0, 20));
        sendSequenceRef.current = sequence;
        setImageProgress({ done: index + 1, total: totalChunks });
      }
      const imageUrl = URL.createObjectURL(file); objectUrlsRef.current.add(imageUrl);
      setMessages((items) => [...items, { type: "image", transfer_id: transferId, sender_id: identity, file_name: file.name, imageUrl, sent_at: new Date().toISOString() }]);
      const encryptionMs = roundMilliseconds(encryptionDurationMs);
      const encryptionBytesPerSecond = encryptionDurationMs > 0 ? file.size / (encryptionDurationMs / 1000) : null;
      (async () => {
        let decryptionDurationMs = 0;
        for (const envelope of encryptedChunkEnvelopes) {
          const decryptionStart = performance.now();
          await decryptBytes(encryptionKey, envelope.context, envelope.nonce, envelope.ciphertext);
          decryptionDurationMs += performance.now() - decryptionStart;
        }
        const decryptionMs = roundMilliseconds(decryptionDurationMs);
        const decryptionBytesPerSecond = decryptionDurationMs > 0 ? file.size / (decryptionDurationMs / 1000) : null;
        const pixels = await analyzeImagePixels(file, combineByteArrays(encryptedChunkParts));
        setMessages((items) => items.map((message) => message.transfer_id === transferId
          ? { ...message, imageAnalysis: { ...pixels, encryptionMs, decryptionMs, encryptionBytesPerSecond, decryptionBytesPerSecond, received: false } }
          : message));
      })().catch(() => {
        setMessages((items) => items.map((message) => message.transfer_id === transferId
          ? { ...message, imageAnalysis: { error: true } }
          : message));
      });
    } catch (sendError) { setError(sendError.message || "The encrypted image could not be sent."); }
    finally { sendingRef.current = false; setSending(false); setImageProgress(null); setFileInputKey((key) => key + 1); }
  }

  return (
    <main className="shell">
      <header className="topbar">
        <a className="brand" href="#" onClick={(e) => { e.preventDefault(); leaveRoom(); }} aria-label="CipherLink home">
          <span className="brand-mark">C</span><span>Cipher<span className="brand-light">Link</span></span>
        </a>
        <div className="top-status"><a className="analysis-link" href="/traffic-analysis">Traffic analysis</a><span className="status-dot" /> PRIVATE ROOM PROTOTYPE</div>
      </header>

      <section className={view === "room" ? "content content-wide" : "content"}>
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
              <p>A is this browser and B is the partner in this view. These values expose this room&apos;s cryptographic secrets. Keep them private and never send them to anyone.</p>
              <div className="handshake-value"><strong>A private key (PKCS#8 Base64)</strong><code>{handshakeDetails.privateKey}</code></div>
              <div className="handshake-value"><strong>A public key (Base64)</strong><code>{handshakeDetails.publicKey}</code></div>
              <div className="handshake-value"><strong>B public key (Base64)</strong><code>{handshakeDetails.peerPublicKey || "Waiting for partner key..."}</code></div>
              <div className="handshake-value"><strong>Shared secret (Base64)</strong><code>{handshakeDetails.sharedSecret || "Derived after partner key arrives..."}</code></div>
            </details>}
            <div className="chat-and-audit"><div className="chat-column">
            <div className="chat-window" aria-live="polite">
              {messages.length === 0 && <div className="empty-chat"><span>*</span><p>Your conversation starts here.</p><small>Only encrypted message data is relayed through the CipherLink server.</small></div>}
              {messages.map((message, index) => <div className={`message ${message.sender_id === identity ? "own-message" : ""}`} key={`${index}-${message.sent_at}`}><div className="message-label">{message.sender_id === identity ? "YOU" : "PARTNER"}</div>{message.type === "image" ? <><div className="message-image"><a href={message.imageUrl} target="_blank" rel="noreferrer"><Image src={message.imageUrl} alt={message.file_name} width={360} height={280} unoptimized style={{ width: "auto", height: "auto", maxWidth: "100%", maxHeight: "280px", objectFit: "contain" }} /></a><small>{message.file_name}</small></div><ImageMetrics analysis={message.imageAnalysis} /></> : <><div className="message-bubble">{message.message}</div><TextMetrics metrics={message.metrics} /></>}</div>)}
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
            </div><div className="room-side-panels"><aside className="audit-panel" aria-label="Room activity log">
              <div className="audit-heading"><div><span>SECURITY</span><h3>Room activity</h3></div><span className="audit-live"><i /> LIVE</span></div>
              <div className={audit.integrity_valid ? "audit-integrity" : "audit-integrity audit-invalid"}><span>{audit.integrity_valid ? "OK" : "!"}</span><div><strong>{audit.integrity_valid ? "HASH CHAIN VERIFIED" : "LOG INTEGRITY FAILURE"}</strong><small>{audit.integrity_valid ? "Recorded events match their audit chain." : `First inconsistent record: #${audit.first_bad_record ?? "?"}`}</small></div></div>
              <div className="audit-list">{audit.records.length === 0 && <p className="audit-empty">Room events will appear here.</p>}{[...audit.records].reverse().map((record) => <div className="audit-record" key={record.sequence}><div><strong>{record.event_type.replaceAll("_", " ")}</strong><time>{new Date(record.created_at).toLocaleTimeString()}</time></div><small>{record.actor_id === identity ? "You" : record.actor_id ? "Room participant" : "Service"}{record.details?.sequence ? `  sequence ${record.details.sequence}` : ""}{record.details?.total_chunks ? `  ${record.details.total_chunks} image chunks` : ""}</small></div>)}</div>
              <p className="audit-note">The audit log records event metadata. Message and image contents remain encrypted.</p>
            </aside><aside className="cipher-panel" aria-label="Encrypted message log">
                <div className="cipher-log-heading"><h4>Ciphertext table</h4><span>{cipherRecords.length} / 20</span></div>
                <p>Both participants see the latest 20 frames. Each browser logs sent and received ciphertext locally for this room.</p>
                <div className="cipher-table-wrap"><table><thead><tr><th>Time</th><th>Flow</th><th>Seq</th><th>Type</th><th>Ciphertext</th></tr></thead><tbody>
                  {cipherRecords.length === 0 && <tr><td colSpan={5} className="cipher-empty">No encrypted messages yet.</td></tr>}
                  {cipherRecords.map((record) => <tr key={record.id}><td>{new Date(record.loggedAt).toLocaleTimeString()}</td><td className={record.direction === "SENT" ? "cipher-sent" : "cipher-received"}>{record.direction}</td><td>{record.sequence}</td><td>{record.kind}</td><td><details><summary>View</summary><code>Nonce: {record.nonce}{"\n"}Ciphertext: {record.ciphertext}</code></details></td></tr>)}
                </tbody></table></div>
            </aside></div></div>
          </>}
          {error && <p className="error-message">{error}</p>}
        </div>}
        <footer className="footer"><span>BUILT FOR CONVERSATIONS THAT DO NOT LINGER</span><span>PHASE 1-13 PROTOTYPE</span></footer>
      </section>
    </main>
  );
}

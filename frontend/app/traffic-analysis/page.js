"use client";

import { useEffect, useState } from "react";

const CHART_WIDTH = 620;
const CHART_HEIGHT = 220;
const MAX_CAPTURE_FILE_BYTES = 50 * 1024 * 1024;
const DELIVERY_LATENCY_STORAGE_KEY = "cipherlink-delivery-latency-v1";
const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

function parseCsv(text, allowEmpty = false) {
  const rows = [];
  let row = [];
  let value = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (quoted) {
      if (character === '"' && text[index + 1] === '"') { value += '"'; index += 1; }
      else if (character === '"') quoted = false;
      else value += character;
    } else if (character === '"') quoted = true;
    else if (character === ",") { row.push(value); value = ""; }
    else if (character === "\n" || character === "\r") {
      if (character === "\r" && text[index + 1] === "\n") index += 1;
      row.push(value);
      if (row.some((cell) => cell !== "")) rows.push(row);
      row = []; value = "";
    } else value += character;
  }
  row.push(value);
  if (row.some((cell) => cell !== "")) rows.push(row);
  if (rows.length < (allowEmpty ? 1 : 2)) throw new Error("The packet CSV has no packet records.");
  const headers = rows[0].map((header) => header.trim().replace(/^\uFEFF/, ""));
  return rows.slice(1).map((cells, index) => {
    const values = Object.fromEntries(headers.map((header, column) => [header, cells[column] ?? ""]));
    const source = values.source || "";
    const destination = values.destination || "";
    const splitEndpoint = (endpoint, transport) => {
      if (transport !== "TCP" && transport !== "UDP") return { ip: endpoint, port: null };
      const separator = endpoint.lastIndexOf(":");
      const maybePort = endpoint.slice(separator + 1);
      return separator > 0 && /^\d+$/.test(maybePort)
        ? { ip: endpoint.slice(0, separator), port: Number(maybePort) }
        : { ip: endpoint, port: null };
    };
    const transport = (values.transport || "").toUpperCase();
    const oldSource = splitEndpoint(source, transport);
    const oldDestination = splitEndpoint(destination, transport);
    const optionalNumber = (value) => value === "" || value == null ? null : Number(value);
    const sourcePort = optionalNumber(values.source_port);
    const destinationPort = optionalNumber(values.destination_port);
    return {
      packet_number: optionalNumber(values.packet_number) ?? index + 1,
      timestamp_utc: values.timestamp_utc || null,
      source_ip: values.source_ip || oldSource.ip || null,
      destination_ip: values.destination_ip || oldDestination.ip || null,
      source_port: sourcePort ?? oldSource.port,
      destination_port: destinationPort ?? oldDestination.port,
      protocol: values.protocol || null,
      transport: values.transport || null,
      frame_length_bytes: optionalNumber(values.frame_length_bytes),
      tcp_payload_bytes: optionalNumber(values.tcp_payload_bytes),
      retransmission: values.retransmission === "" ? null : values.retransmission.toLowerCase() === "true",
      latency_ms: optionalNumber(values.latency_ms),
      acknowledged_payload_bytes: optionalNumber(values.rtt_acked_payload_bytes),
    };
  });
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "-";
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(2)} KB`;
  return `${(value / (1024 * 1024)).toFixed(2)} MB`;
}

function MetricCard({ label, value, detail }) {
  return <article className="traffic-metric"><span>{label}</span><strong>{value}</strong><small>{detail}</small></article>;
}

function LineChart({ title, data, valueKey, color, formatValue = (value) => value.toFixed(2), xLabel = "Second" }) {
  const values = data.map((item) => Number(item[valueKey]) || 0);
  const maximum = Math.max(...values, 1);
  const points = data.map((item, index) => {
    const x = data.length < 2 ? CHART_WIDTH / 2 : 24 + (index * (CHART_WIDTH - 48)) / (data.length - 1);
    const y = CHART_HEIGHT - 26 - ((Number(item[valueKey]) || 0) / maximum) * (CHART_HEIGHT - 52);
    return { x, y, item };
  });

  return (
    <article className="traffic-chart-card">
      <div className="traffic-chart-heading"><h2>{title}</h2><span>{data.length} samples</span></div>
      {data.length === 0 ? <p className="traffic-empty-chart">No samples in this capture.</p> : <>
        <div className="traffic-chart-scroll"><svg viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`} role="img" aria-label={title}>
          <line x1="24" y1={CHART_HEIGHT - 26} x2={CHART_WIDTH - 24} y2={CHART_HEIGHT - 26} className="traffic-axis" />
          <line x1="24" y1="18" x2="24" y2={CHART_HEIGHT - 26} className="traffic-axis" />
          <text x="25" y="14" className="traffic-chart-label">{formatValue(maximum)}</text>
          <polyline points={points.map(({ x, y }) => `${x},${y}`).join(" ")} fill="none" stroke={color} strokeWidth="3" strokeLinejoin="round" strokeLinecap="round" />
          {points.length < 50 && points.map(({ x, y, item }, index) => <circle key={`${item.second}-${index}`} cx={x} cy={y} r="3" fill={color}><title>{xLabel} {item.second}: {formatValue(Number(item[valueKey]) || 0)}</title></circle>)}
          <text x="24" y={CHART_HEIGHT - 7} className="traffic-chart-label">{xLabel} 0</text>
          <text x={CHART_WIDTH - 92} y={CHART_HEIGHT - 7} className="traffic-chart-label">{xLabel} {data[data.length - 1]?.second ?? 0}</text>
        </svg></div>
        <div className="traffic-chart-legend"><span style={{ background: color }} /> {title}</div>
      </>}
    </article>
  );
}

function DistributionChart({ data }) {
  const maximum = Math.max(...data.map((item) => item.count), 1);
  return <article className="traffic-chart-card">
    <div className="traffic-chart-heading"><h2>Packet size distribution</h2><span>{data.reduce((total, item) => total + item.count, 0)} packets</span></div>
    {data.length === 0 ? <p className="traffic-empty-chart">No packet sizes in this capture.</p> : <div className="traffic-bars">
      {data.map((item) => <div className="traffic-bar-row" key={item.bucket}><span>{item.bucket}</span><div><i style={{ width: `${(item.count / maximum) * 100}%` }} /></div><b>{item.count}</b></div>)}
    </div>}
  </article>;
}

function ProtocolChart({ counts }) {
  const rows = Object.entries(counts).sort((left, right) => right[1] - left[1]);
  const maximum = Math.max(...rows.map(([, count]) => count), 1);
  return <article className="traffic-chart-card">
    <div className="traffic-chart-heading"><h2>Protocol distribution</h2><span>{rows.length} protocols</span></div>
    {rows.length === 0 ? <p className="traffic-empty-chart">No protocols were decoded.</p> : <div className="traffic-bars">
      {rows.slice(0, 10).map(([protocol, count]) => <div className="traffic-bar-row" key={protocol}><span>{protocol}</span><div><i style={{ width: `${(count / maximum) * 100}%` }} /></div><b>{count}</b></div>)}
    </div>}
  </article>;
}

function LatencyScatter({ data }) {
  const points = data.slice(0, 500);
  const maxSize = Math.max(...points.map((item) => item.packet_size_bytes), 1);
  const maxLatency = Math.max(...points.map((item) => item.latency_ms), 1);
  return <article className="traffic-chart-card">
    <div className="traffic-chart-heading"><h2>TCP ACK RTT vs acknowledged payload size</h2><span>{points.length} samples</span></div>
    {points.length === 0 ? <p className="traffic-empty-chart">TShark found no TCP ACK RTT samples for this capture.</p> : <div className="traffic-chart-scroll"><svg viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`} role="img" aria-label="TCP acknowledgement round trip time versus packet size">
      <line x1="44" y1={CHART_HEIGHT - 30} x2={CHART_WIDTH - 20} y2={CHART_HEIGHT - 30} className="traffic-axis" />
      <line x1="44" y1="18" x2="44" y2={CHART_HEIGHT - 30} className="traffic-axis" />
      <text x="46" y="14" className="traffic-chart-label">{maxLatency.toFixed(2)} ms</text>
      <text x="44" y={CHART_HEIGHT - 8} className="traffic-chart-label">0 B</text>
      <text x={CHART_WIDTH - 100} y={CHART_HEIGHT - 8} className="traffic-chart-label">{maxSize} B</text>
      {points.map((point, index) => {
        const x = 44 + (point.packet_size_bytes / maxSize) * (CHART_WIDTH - 68);
        const y = CHART_HEIGHT - 30 - (point.latency_ms / maxLatency) * (CHART_HEIGHT - 54);
        return <circle key={`${point.packet_size_bytes}-${point.latency_ms}-${index}`} cx={x} cy={y} r="3" fill="#58d8f5" opacity=".72"><title>{point.packet_size_bytes} bytes, {point.latency_ms} ms ACK RTT</title></circle>;
      })}
    </svg></div>}
    <p className="traffic-chart-footnote">Size is the TCP data payload acknowledged by each RTT sample, not a reconstructed chat message. ACK RTT is a transport-level estimate, not application-level end-to-end chat latency.</p>
  </article>;
}

function MessageLatencyScatter({ data }) {
  const points = data.slice(-250);
  const maxSize = Math.max(...points.map((item) => item.message_size_bytes), 1);
  const maxLatency = Math.max(...points.map((item) => item.latency_ms), 1);
  return <article className="traffic-chart-card">
    <div className="traffic-chart-heading"><h2>Message size vs delivery latency</h2><span>{points.length} samples</span></div>
    {points.length === 0 ? <p className="traffic-empty-chart">Send text messages while both participants are connected to collect end-to-end delivery acknowledgements in this browser.</p> : <div className="traffic-chart-scroll"><svg viewBox={`0 0 ${CHART_WIDTH} ${CHART_HEIGHT}`} role="img" aria-label="Text message size in bytes versus end-to-end delivery acknowledgement round-trip time in milliseconds">
      <line x1="44" y1={CHART_HEIGHT - 30} x2={CHART_WIDTH - 20} y2={CHART_HEIGHT - 30} className="traffic-axis" />
      <line x1="44" y1="18" x2="44" y2={CHART_HEIGHT - 30} className="traffic-axis" />
      <text x="46" y="14" className="traffic-chart-label">{maxLatency.toFixed(3)} ms</text>
      <text x="44" y={CHART_HEIGHT - 8} className="traffic-chart-label">0 B</text>
      <text x={CHART_WIDTH - 100} y={CHART_HEIGHT - 8} className="traffic-chart-label">{maxSize} B</text>
      {points.map((point, index) => {
        const x = 44 + (point.message_size_bytes / maxSize) * (CHART_WIDTH - 68);
        const y = CHART_HEIGHT - 30 - (point.latency_ms / maxLatency) * (CHART_HEIGHT - 54);
        return <circle key={`${point.sequence}-${point.recorded_at}-${index}`} cx={x} cy={y} r="4" fill="#91dc8c" opacity=".8"><title>{point.message_size_bytes} bytes, {point.latency_ms.toFixed(3)} ms delivery ACK RTT</title></circle>;
      })}
    </svg></div>}
    <p className="traffic-chart-footnote">Measured on this sender: send to partner, successful signature verification and decryption, then acknowledgment back. Samples are saved locally in this browser.</p>
  </article>;
}

function isReport(value) {
  const metrics = value?.metrics;
  return value?.schema_version === 1 && metrics && Number.isFinite(metrics.packet_count)
    && Array.isArray(metrics.packet_count_by_second)
    && Array.isArray(metrics.packet_size_distribution)
    && Array.isArray(metrics.throughput_mbps_by_second)
    && Array.isArray(metrics.latency_by_packet_size)
    && Array.isArray(metrics.top_flows)
    && metrics.protocol_counts && typeof metrics.protocol_counts === "object";
}

export default function TrafficAnalysisPage() {
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [messageLatencySamples, setMessageLatencySamples] = useState([]);
  const [packetRecords, setPacketRecords] = useState([]);
  const [packetCsvText, setPacketCsvText] = useState("");
  const [exportingXml, setExportingXml] = useState(false);
  const [analyzingCapture, setAnalyzingCapture] = useState(false);

  useEffect(() => {
    try {
      const samples = JSON.parse(window.localStorage.getItem(DELIVERY_LATENCY_STORAGE_KEY) || "[]");
      setMessageLatencySamples(Array.isArray(samples)
        ? samples.filter((sample) => Number.isFinite(sample?.message_size_bytes) && Number.isFinite(sample?.latency_ms))
        : []);
    } catch { setMessageLatencySamples([]); }
  }, []);

  async function loadReport(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      if (!isReport(parsed)) throw new Error("This file is not a supported CipherLink traffic report.");
      setReport(parsed);
      setError("");
    } catch (loadError) {
      setReport(null);
      setError(loadError.message || "Could not read that report file.");
    }
  }

  async function uploadCapture(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > MAX_CAPTURE_FILE_BYTES) {
      setError("Capture files must be 50 MB or smaller.");
      return;
    }
    setAnalyzingCapture(true);
    setError("");
    try {
      const response = await fetch(`${API_URL}/traffic-analysis/analyze?filename=${encodeURIComponent(file.name)}`, {
        method: "POST",
        headers: { "Content-Type": "application/octet-stream" },
        body: file,
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.detail || "The capture could not be analyzed.");
      if (!isReport(result.report) || typeof result.packet_csv !== "string") {
        throw new Error("The analyzer returned an unsupported report.");
      }
      const records = parseCsv(result.packet_csv, true);
      setReport(result.report);
      setPacketCsvText(result.packet_csv);
      setPacketRecords(records);
      setError("");
    } catch (uploadError) {
      setError(uploadError.message || "Could not analyze that capture.");
    } finally {
      setAnalyzingCapture(false);
    }
  }

  async function loadPacketCsv(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    try {
      const text = await file.text();
      const records = parseCsv(text);
      setPacketCsvText(text);
      setPacketRecords(records);
      setError("");
    } catch (loadError) {
      setPacketCsvText("");
      setPacketRecords([]);
      setError(loadError.message || "Could not read that packet CSV.");
    }
  }

  function downloadFile(contents, mimeType, filename) {
    const url = URL.createObjectURL(new Blob([contents], { type: mimeType }));
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function exportXml() {
    if (!report || packetRecords.length === 0 || exportingXml) return;
    setExportingXml(true);
    setError("");
    try {
      const metricSummary = Object.fromEntries(
        ["packet_count", "total_bytes", "average_packet_size_bytes", "duration_seconds", "average_latency_ms", "latency_sample_count", "throughput_mbps", "retransmissions", "protocol_counts"]
          .map((key) => [key, report.metrics[key]]),
      );
      const response = await fetch(`${API_URL}/traffic-analysis/xml`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          schema_version: report.schema_version,
          generated_at: report.generated_at,
          source_capture: report.source_capture,
          metrics: metricSummary,
          packets: packetRecords,
        }),
      });
      if (!response.ok) {
        const failure = await response.json().catch(() => ({}));
        throw new Error(failure.detail || "The XML export could not be created.");
      }
      const xml = await response.blob();
      const disposition = response.headers.get("Content-Disposition") || "";
      const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || "cipherlink_traffic.xml";
      const url = URL.createObjectURL(xml);
      const link = document.createElement("a");
      link.href = url;
      link.download = filename;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (exportError) {
      setError(exportError.message || "The XML export could not be created.");
    } finally {
      setExportingXml(false);
    }
  }

  const metrics = report?.metrics;

  return <main className="traffic-page">
    <header className="traffic-topbar"><a href="/" className="traffic-brand">CipherLink <span>/ Traffic analysis</span></a><a href="/" className="traffic-back">Back to chat</a></header>
    <section className="traffic-content">
      <div className="traffic-intro"><div><span className="traffic-kicker">PHASE 14-16</span><h1>Traffic analysis</h1><p>Upload a PCAP or PCAPNG capture for direct analysis, or load an existing report. The dashboard displays measurements from that capture.</p></div>
        <div className="traffic-file-controls">
          <label className="traffic-upload">{analyzingCapture ? "Analyzing capture..." : "Upload PCAP / PCAPNG"}<input type="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap" onChange={uploadCapture} disabled={analyzingCapture} /></label>
          <label className="traffic-upload">Load JSON report<input type="file" accept="application/json,.json" onChange={loadReport} /></label>
          <label className="traffic-upload traffic-upload-secondary">Load packet CSV<input type="file" accept="text/csv,.csv" onChange={loadPacketCsv} /></label>
        </div>
      </div>
      <details className="phase16-lab">
        <summary>PHASE 16 · PACKET-SNIFFING EXPERIMENT</summary>
        <ol>
          <li>Start Wireshark on the active interface with capture filter <code>tcp port 443</code>.</li>
          <li>Join the same hosted room on Device A and Device B. Send <code>Confidential message from Device A</code> and confirm B receives it.</li>
          <li>Stop and save the capture. In Wireshark, apply <code>tls</code>, inspect TLS Application Data, then search for the marker with <code>frame contains &quot;Confidential message from Device A&quot;</code>. It should have no matching packet.</li>
      <li>Upload the saved <code>.pcapng</code> file directly above. The API runs the existing PyShark analyzer and loads the report and packet records into this dashboard. CLI-generated JSON and CSV reports can still be loaded separately.</li>
        </ol>
        <p>For the full capture procedure and interpretation, see <code>docs/PHASES_15_17.md</code>. Captures still expose network endpoints, timing, and packet sizes.</p>
      </details>
      {error && <div className="traffic-error" role="alert">{error}</div>}
      {!report && <section className="traffic-empty-state"><span>PCAP -&gt; PYSHARK -&gt; JSON / CSV / XML</span><h2>No capture report loaded</h2><p>Upload a <code>.pcap</code> or <code>.pcapng</code> file (up to 50 MB) above to analyze it here. You can also load existing JSON and packet CSV reports.</p><p>The capture is temporarily processed by the API server and deleted after analysis. TShark must be installed on that server.</p></section>}
      {report && <>
        <div className="traffic-report-meta"><span>Capture: <strong>{report.source_capture}</strong></span><span>Generated: <strong>{new Date(report.generated_at).toLocaleString()}</strong></span></div>
        <div className="traffic-export-actions" aria-label="Traffic report exports">
          <button type="button" onClick={() => downloadFile(JSON.stringify(report, null, 2), "application/json", "cipherlink_traffic.json")}>Export JSON</button>
          <button type="button" onClick={() => downloadFile(packetCsvText, "text/csv;charset=utf-8", "cipherlink_traffic.csv")} disabled={!packetCsvText}>Export CSV</button>
          <button type="button" onClick={exportXml} disabled={!packetRecords.length || exportingXml}>{exportingXml ? "Creating XML..." : "Export as XML"}</button>
          <span>{packetRecords.length ? `${packetRecords.length.toLocaleString()} packet records loaded` : "Load the analyzer packet CSV to export individual XML records."}</span>
        </div>
        <section className="traffic-metrics-grid" aria-label="Capture metrics">
          <MetricCard label="PACKETS CAPTURED" value={metrics.packet_count.toLocaleString()} detail="Frames in the capture" />
          <MetricCard label="TOTAL DATA" value={formatBytes(metrics.total_bytes)} detail={`${metrics.total_bytes.toLocaleString()} captured bytes`} />
          <MetricCard label="AVERAGE FRAME SIZE" value={`${metrics.average_packet_size_bytes.toLocaleString()} B`} detail="Frame length average" />
          <MetricCard label="AVERAGE TCP ACK RTT" value={metrics.average_latency_ms == null ? "N/A" : `${metrics.average_latency_ms} ms`} detail={`${metrics.latency_sample_count} TCP RTT samples`} />
          <MetricCard label="AVERAGE THROUGHPUT" value={metrics.throughput_mbps == null ? "N/A" : `${metrics.throughput_mbps} Mbps`} detail="Captured bytes over capture duration" />
          <MetricCard label="RETRANSMISSIONS" value={metrics.retransmissions.toLocaleString()} detail={`${metrics.duration_seconds} seconds observed`} />
          <MetricCard label="TLS PACKETS" value={(metrics.protocol_counts.TLS || 0).toLocaleString()} detail="TLS-layer packets detected in capture" />
        </section>
        <section className="traffic-charts-grid" aria-label="Traffic charts">
          <LineChart title="Packet count vs time" data={metrics.packet_count_by_second} valueKey="count" color="#58d8f5" formatValue={(value) => `${value} packets`} />
          <DistributionChart data={metrics.packet_size_distribution} />
          <ProtocolChart counts={metrics.protocol_counts} />
          <LineChart title="Throughput vs time" data={metrics.throughput_mbps_by_second} valueKey="mbps" color="#91dc8c" formatValue={(value) => `${value.toFixed(3)} Mbps`} />
          <LatencyScatter data={metrics.latency_by_packet_size} />
          <MessageLatencyScatter data={messageLatencySamples} />
        </section>
        <section className="traffic-flows"><h2>Top network flows</h2><div className="traffic-flow-table"><table><thead><tr><th>Source</th><th>Destination</th><th>Transport</th><th>Packets</th></tr></thead><tbody>
          {metrics.top_flows.length === 0 && <tr><td colSpan={4}>No IP flows were decoded in this capture.</td></tr>}
          {metrics.top_flows.map((flow, index) => <tr key={`${flow.source}-${flow.destination}-${index}`}><td>{flow.source}</td><td>{flow.destination}</td><td>{flow.transport}</td><td>{flow.packets}</td></tr>)}
        </tbody></table></div></section>
        <p className="traffic-disclaimer">Packet captures may contain IP addresses and other sensitive metadata. Keep report files private when they include traffic from real users.</p>
      </>}
    </section>
  </main>;
}

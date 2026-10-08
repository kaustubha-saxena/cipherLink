"use client";

import { useState } from "react";

const CHART_WIDTH = 620;
const CHART_HEIGHT = 220;

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
    <div className="traffic-chart-heading"><h2>TCP ACK RTT vs packet size</h2><span>{points.length} samples</span></div>
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
    <p className="traffic-chart-footnote">ACK RTT is a TCP transport estimate, not application-level end-to-end chat latency.</p>
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

  const metrics = report?.metrics;

  return <main className="traffic-page">
    <header className="traffic-topbar"><a href="/" className="traffic-brand">CipherLink <span>/ Traffic analysis</span></a><a href="/" className="traffic-back">Back to chat</a></header>
    <section className="traffic-content">
      <div className="traffic-intro"><div><span className="traffic-kicker">PHASE 14-15</span><h1>Traffic analysis</h1><p>Load a report generated from a Wireshark PCAP or PCAPNG capture. This dashboard displays measurements from that capture.</p></div>
        <label className="traffic-upload">Load JSON report<input type="file" accept="application/json,.json" onChange={loadReport} /></label>
      </div>
      {error && <div className="traffic-error" role="alert">{error}</div>}
      {!report && <section className="traffic-empty-state"><span>PCAP -&gt; PYSHARK -&gt; JSON</span><h2>No capture report loaded</h2><p>Capture traffic with <code>traffic-analysis/capture.py</code>, analyze the saved PCAPNG with <code>traffic-analysis/analyzer.py</code>, then load the generated <code>.analysis.json</code> report here.</p><p>The dashboard does not invent sample measurements. TShark must be installed for capture analysis.</p></section>}
      {report && <>
        <div className="traffic-report-meta"><span>Capture: <strong>{report.source_capture}</strong></span><span>Generated: <strong>{new Date(report.generated_at).toLocaleString()}</strong></span></div>
        <section className="traffic-metrics-grid" aria-label="Capture metrics">
          <MetricCard label="PACKETS CAPTURED" value={metrics.packet_count.toLocaleString()} detail="Frames in the capture" />
          <MetricCard label="TOTAL DATA" value={formatBytes(metrics.total_bytes)} detail={`${metrics.total_bytes.toLocaleString()} captured bytes`} />
          <MetricCard label="AVERAGE FRAME SIZE" value={`${metrics.average_packet_size_bytes.toLocaleString()} B`} detail="Frame length average" />
          <MetricCard label="AVERAGE TCP ACK RTT" value={metrics.average_latency_ms == null ? "N/A" : `${metrics.average_latency_ms} ms`} detail={`${metrics.latency_sample_count} TCP RTT samples`} />
          <MetricCard label="AVERAGE THROUGHPUT" value={metrics.throughput_mbps == null ? "N/A" : `${metrics.throughput_mbps} Mbps`} detail="Captured bytes over capture duration" />
          <MetricCard label="RETRANSMISSIONS" value={metrics.retransmissions.toLocaleString()} detail={`${metrics.duration_seconds} seconds observed`} />
        </section>
        <section className="traffic-charts-grid" aria-label="Traffic charts">
          <LineChart title="Packet count vs time" data={metrics.packet_count_by_second} valueKey="count" color="#58d8f5" formatValue={(value) => `${value} packets`} />
          <DistributionChart data={metrics.packet_size_distribution} />
          <ProtocolChart counts={metrics.protocol_counts} />
          <LineChart title="Throughput vs time" data={metrics.throughput_mbps_by_second} valueKey="mbps" color="#91dc8c" formatValue={(value) => `${value.toFixed(3)} Mbps`} />
          <LatencyScatter data={metrics.latency_by_packet_size} />
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

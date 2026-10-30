import json
import subprocess
import sys
import tempfile
from pathlib import Path


ANALYSIS_TIMEOUT_SECONDS = 180
MAX_CAPTURE_PACKET_COUNT = 100_000


def analyze_uploaded_capture(capture_path: Path) -> tuple[dict, str]:
    project_root = Path(__file__).resolve().parents[3]
    analysis_dir = project_root / "traffic-analysis"
    analyzer_path = analysis_dir / "analyzer.py"
    python_candidates = (
        analysis_dir / ".venv" / "Scripts" / "python.exe",
        analysis_dir / ".venv" / "bin" / "python",
        Path(sys.executable),
    )
    python_path = next((candidate for candidate in python_candidates if candidate.is_file()), Path(sys.executable))

    with tempfile.TemporaryDirectory(prefix="cipherlink-analysis-") as temp_dir:
        output_dir = Path(temp_dir)
        json_path = output_dir / "report.json"
        csv_path = output_dir / "packets.csv"
        try:
            result = subprocess.run(
                [
                    str(python_path), str(analyzer_path), str(capture_path),
                    "--json", str(json_path), "--csv", str(csv_path),
                ],
                cwd=analysis_dir,
                capture_output=True,
                check=False,
                text=True,
                timeout=ANALYSIS_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("Capture analysis exceeded the three-minute limit.") from error

        if result.returncode:
            detail = (result.stderr or result.stdout or "The analyzer could not read this capture.").strip()
            if "tshark not found" in detail.lower():
                raise RuntimeError("TShark is not installed or available on the API server. Install Wireshark/TShark, then retry.")
            raise ValueError(detail[-1200:])

        report = json.loads(json_path.read_text(encoding="utf-8"))
        if report.get("metrics", {}).get("packet_count", 0) > MAX_CAPTURE_PACKET_COUNT:
            raise OverflowError(f"This capture has more than {MAX_CAPTURE_PACKET_COUNT:,} packets. Split it into smaller captures and retry.")
        packet_csv = csv_path.read_text(encoding="utf-8-sig")
        return report, packet_csv

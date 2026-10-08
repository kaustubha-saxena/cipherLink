import argparse
import sys
from datetime import datetime
from pathlib import Path

try:
    import pyshark
except ImportError as error:
    raise SystemExit("PyShark is not installed. Run: python -m pip install -r traffic-analysis/requirements.txt") from error


def list_interfaces() -> int:
    capture = pyshark.LiveCapture()
    try:
        for interface in capture.interfaces:
            print(interface)
    finally:
        capture.close()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture packets to a PCAPNG file for offline analysis.")
    parser.add_argument("--interface", help="Interface name from --list-interfaces")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration in seconds (default: 60)")
    parser.add_argument("--output", type=Path, help="Output PCAPNG path")
    parser.add_argument("--filter", dest="capture_filter", help="Optional BPF capture filter, e.g. 'tcp port 443'")
    parser.add_argument("--list-interfaces", action="store_true", help="List interfaces visible to TShark and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        try:
            return list_interfaces()
        except (OSError, RuntimeError) as error:
            print(f"Could not list interfaces: {error}", file=sys.stderr)
            return 1
    if not args.interface:
        parser.error("--interface is required unless --list-interfaces is used")
    if args.duration < 1 or args.duration > 3600:
        parser.error("--duration must be between 1 and 3600 seconds")

    output = args.output or Path("traffic-analysis") / f"capture-{datetime.now().strftime('%Y%m%d-%H%M%S')}.pcapng"
    output.parent.mkdir(parents=True, exist_ok=True)
    capture = pyshark.LiveCapture(
        interface=args.interface,
        capture_filter=args.capture_filter,
        output_file=str(output),
    )
    try:
        print(f"Capturing on {args.interface} for {args.duration} seconds. Start the CipherLink activity now.")
        capture.sniff(timeout=args.duration)
    except (OSError, RuntimeError) as error:
        print(f"Capture failed: {error}. TShark must be installed and the interface may require administrator permissions.", file=sys.stderr)
        return 1
    finally:
        capture.close()
    print(f"Capture saved: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

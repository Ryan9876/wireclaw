import argparse
import json
from pathlib import Path

from . import Analyzer, AnalyzerError


def main():
    parser = argparse.ArgumentParser(description="Local deterministic analyzer")
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("capture", help="Relative capture path already staged beneath data root")
    parser.add_argument("--diagnostics", action="store_true", help="Run fixed Gate 2 capabilities")
    args = parser.parse_args()
    try:
        analyzer = Analyzer(args.data_root, schema=args.schema)
        capture_id = analyzer.ingest_capture(Path(args.capture))
        print(
            json.dumps(
                (
                    analyzer.diagnose(capture_id)
                    if args.diagnostics
                    else analyzer.analyze(capture_id)
                ),
                sort_keys=True,
                indent=2,
            )
        )
    except AnalyzerError as error:
        print(json.dumps({"error": error.as_dict()}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()

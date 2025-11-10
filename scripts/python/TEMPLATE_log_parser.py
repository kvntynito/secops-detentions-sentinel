#!/usr/bin/env python3
"""
Purpose: Parse log file(s), extract suspicious events, output CSV.
Usage: python TEMPLATE_log_parser.py --input logs/ --out findings.csv
"""
import argparse, csv, re, pathlib, datetime as dt

PATTERN = re.compile(r'failed login|unauthorized|suspicious', re.I)

def parse_file(p: pathlib.Path):
    with p.open(errors="ignore") as f:
        for line in f:
            if PATTERN.search(line):
                yield {"timestamp": dt.datetime.utcnow().isoformat(), "file": str(p), "line": line.strip()}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", default="findings.csv")
    args = ap.parse_args()

    rows = []
    for path in pathlib.Path(args.input).rglob("*"):
        if path.is_file():
            rows.extend(parse_file(path))

    with open(args.out, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp","file","line"])
        writer.writeheader()
        writer.writerows(rows)

if __name__ == "__main__":
    main()

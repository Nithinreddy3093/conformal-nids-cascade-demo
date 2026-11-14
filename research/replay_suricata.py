#!/usr/bin/env python3
"""Run pinned Suricata on one PCAP and record auditable run metadata."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    if path.is_file():
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    if path.is_dir():
        for child in sorted(p for p in path.rglob("*") if p.is_file()):
            digest.update(child.relative_to(path).as_posix().encode("utf-8"))
            with child.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        return digest.hexdigest()
    raise FileNotFoundError(path)


def count_eve_events(path: Path) -> dict:
    counts = {"alert": 0, "flow": 0, "other": 0, "invalid_json": 0}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                event_type = json.loads(line).get("event_type", "other")
                counts[event_type if event_type in ("alert", "flow") else "other"] += 1
            except json.JSONDecodeError:
                counts["invalid_json"] += 1
    return counts


def run_replay(pcap: Path, config: Path, output_dir: Path, binary: str,
               ruleset: Path | None = None, expected_version: str | None = None) -> dict:
    executable = shutil.which(binary)
    if not executable:
        raise RuntimeError(f"Suricata executable not found: {binary}")
    pcap, config, output_dir = pcap.resolve(), config.resolve(), output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    version_proc = subprocess.run([executable, "-V"], text=True, capture_output=True,
                                  check=False, timeout=15)
    version = (version_proc.stdout or version_proc.stderr).strip()
    if version_proc.returncode != 0:
        raise RuntimeError(f"Could not read Suricata version: {version}")
    if expected_version and expected_version not in version:
        raise RuntimeError(f"Expected Suricata {expected_version!r}, found {version!r}")
    command = [executable, "-r", str(pcap), "-c", str(config), "-l", str(output_dir)]
    started = time.monotonic()
    proc = subprocess.run(command, text=True, capture_output=True, check=False)
    elapsed = time.monotonic() - started
    if proc.returncode:
        raise RuntimeError(
            f"Suricata replay failed ({proc.returncode}).\n"
            f"stdout:\n{proc.stdout[-4000:]}\nstderr:\n{proc.stderr[-4000:]}"
        )
    eve_candidates = list(output_dir.rglob("eve.json"))
    if not eve_candidates:
        raise RuntimeError("Replay completed but no eve.json was found; check EVE output in the config.")
    eve = eve_candidates[0]
    event_counts = count_eve_events(eve)
    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "suricata_version": version,
        "command": command,
        "elapsed_seconds": round(elapsed, 3),
        "inputs": {
            "pcap": {"path": str(pcap), "sha256": sha256_path(pcap), "bytes": pcap.stat().st_size},
            "config": {"path": str(config), "sha256": sha256_path(config)},
            "ruleset": ({"path": str(ruleset.resolve()), "sha256": sha256_path(ruleset)}
                        if ruleset else None),
        },
        "eve_json": {"path": str(eve), "sha256": sha256_path(eve),
                     "events": event_counts},
        "return_code": proc.returncode,
    }
    (output_dir / "suricata_run.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True,
                        help="Suricata YAML config with EVE alert/flow output enabled")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ruleset", type=Path,
                        help="Optional file/directory to hash; rules are loaded via the config")
    parser.add_argument("--suricata-bin", default="suricata")
    parser.add_argument("--expected-version",
                        help="Optional version substring; fail if installed version differs")
    args = parser.parse_args()
    run_replay(args.pcap, args.config, args.out, args.suricata_bin,
               args.ruleset, args.expected_version)


if __name__ == "__main__":
    main()

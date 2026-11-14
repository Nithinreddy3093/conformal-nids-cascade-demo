#!/usr/bin/env python3
"""Reproducible CIC-IDS2017 + Suricata cascade evaluation.

This is an offline research pipeline. It does not perform live monitoring.
Input flow labels and Suricata EVE alerts must come from the same PCAP/time slice.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import ipaddress
import json
import platform
import subprocess
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

ALIASES = {
    "timestamp": ("timestamp", "flow start", "flow start time"),
    "src_ip": ("source ip", "src ip"),
    "src_port": ("source port", "src port"),
    "dst_ip": ("destination ip", "dest ip", "dst ip"),
    "dst_port": ("destination port", "dest port", "dst port"),
    "protocol": ("protocol", "proto"),
    "duration": ("flow duration", "duration"),
    "fwd_packets": ("total fwd packets", "fwd packets"),
    "bwd_packets": ("total backward packets", "total bwd packets", "bwd packets"),
    "fwd_bytes": ("total length of fwd packets", "fwd bytes"),
    "bwd_bytes": ("total length of bwd packets", "total length of backward packets", "bwd bytes"),
    "syn": ("syn flag count", "syn count"),
    "iat": ("flow iat mean", "iat mean"),
    "label": ("label", "class"),
}
FEATURES = ["duration", "fwd_packets", "bwd_packets", "fwd_bytes",
            "bwd_bytes", "dst_port", "syn", "iat"]
PROTO = {"6": "TCP", "17": "UDP", "1": "ICMP", "58": "ICMPV6"}


def canonical_key(src, sport, dst, dport, proto):
    """Direction-independent flow key; addresses remain strings to preserve IPv6."""
    left, right = (str(src), int(float(sport))), (str(dst), int(float(dport)))
    a, b = sorted((left, right))
    p = normalize_protocol(proto)
    return a[0], a[1], b[0], b[1], p


def pick_column(columns, aliases, required=True):
    lookup = {str(c).strip().lower(): c for c in columns}
    for alias in aliases:
        if alias in lookup:
            return lookup[alias]
    if required:
        raise ValueError(f"Missing required field. Tried: {aliases}")
    return None


def normalize_protocol(value):
    value = str(value).strip().upper()
    if value.endswith(".0") and value[:-2].isdigit():
        value = value[:-2]
    return PROTO.get(value, value)


def normalize_ip(value):
    if pd.isna(value):
        return None
    try:
        return ipaddress.ip_address(str(value).strip()).compressed
    except ValueError:
        return None


def load_flows(csv_path, flow_timezone="UTC"):
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    cols = {name: pick_column(df.columns, aliases, name not in {"src_ip", "src_port", "dst_ip", "dst_port"})
            for name, aliases in ALIASES.items()}
    for name in ("src_ip", "src_port", "dst_ip", "dst_port"):
        if cols[name] is None:
            raise ValueError(f"{name} is required for Suricata alignment; use the original labeled-flow CSV.")

    out = pd.DataFrame(index=df.index)
    parsed_timestamps = pd.to_datetime(df[cols["timestamp"]], errors="coerce", dayfirst=False)
    if not isinstance(parsed_timestamps.dtype, pd.DatetimeTZDtype):
        parsed_timestamps = parsed_timestamps.dt.tz_localize(
            flow_timezone, ambiguous="NaT", nonexistent="NaT"
        )
    out["timestamp"] = parsed_timestamps.dt.tz_convert("UTC")
    out["src_ip"] = df[cols["src_ip"]].map(normalize_ip)
    out["dst_ip"] = df[cols["dst_ip"]].map(normalize_ip)
    out["src_port"] = pd.to_numeric(df[cols["src_port"]], errors="coerce")
    out["dst_port"] = pd.to_numeric(df[cols["dst_port"]], errors="coerce")
    out["protocol"] = df[cols["protocol"]].map(normalize_protocol)
    out["label_raw"] = df[cols["label"]].astype("string").str.strip()
    for feature in FEATURES:
        source = cols.get(feature)
        out[feature] = pd.to_numeric(df[source], errors="coerce") if source else np.nan
    # CICFlowMeter duration and IAT are microseconds; normalize to seconds.
    out["duration"] = out["duration"] / 1_000_000.0
    out["iat"] = out["iat"] / 1_000_000.0

    valid = (
        out["timestamp"].notna()
        & out["src_ip"].notna()
        & out["dst_ip"].notna()
        & out["src_port"].notna()
        & out["dst_port"].notna()
        & out["src_port"].between(0, 65535)
        & out["dst_port"].between(0, 65535)
        & (out["src_port"] % 1 == 0)
        & (out["dst_port"] % 1 == 0)
        & out["protocol"].notna()
        & (out["protocol"] != "<NA>")
        & out["label_raw"].notna()
        & out["label_raw"].ne("")
        & out["duration"].notna()
        & out["duration"].ge(0)
    )
    input_rows = len(out)
    audit = {
        "input_rows": int(input_rows),
        "retained_rows": int(valid.sum()),
        "dropped_rows": int((~valid).sum()),
        "invalid_timestamp_rows": int(out["timestamp"].isna().sum()),
        "invalid_endpoint_rows": int((out["src_ip"].isna() | out["dst_ip"].isna()).sum()),
        "invalid_port_rows": int((out["src_port"].isna() | out["dst_port"].isna()
                                  | ~out["src_port"].between(0, 65535)
                                  | ~out["dst_port"].between(0, 65535)
                                  | (out["src_port"] % 1 != 0) | (out["dst_port"] % 1 != 0)).sum()),
        "invalid_protocol_rows": int((out["protocol"].isna() | out["protocol"].eq("<NA>")).sum()),
        "missing_label_rows": int((out["label_raw"].isna() | out["label_raw"].eq("")).sum()),
        "invalid_duration_rows": int((out["duration"].isna() | out["duration"].lt(0)).sum()),
    }
    out = out.loc[valid].copy()
    out["y"] = (out["label_raw"].str.casefold() != "benign").astype("int8")
    out["start_epoch"] = out["timestamp"].map(lambda ts: ts.timestamp())
    out["end_epoch"] = out["start_epoch"] + out["duration"]
    out["flow_key"] = [
        canonical_key(a, b, c, d, p)
        for a, b, c, d, p in zip(out.src_ip, out.src_port, out.dst_ip, out.dst_port, out.protocol)
    ]
    out["signature_hit"] = False
    out["signature_score"] = 0.0
    out = out.reset_index(drop=True)
    out.attrs["ingestion_audit"] = audit
    return out


def attach_suricata_alerts(flows, eve_path, tolerance_seconds=2.0):
    """Align EVE alerts to flow rows and separate alerts outside the CSV time span."""
    index = defaultdict(list)
    for i, row in flows.iterrows():
        index[row.flow_key].append((row.start_epoch, row.end_epoch, i))
    for vals in index.values():
        vals.sort()
    starts = {k: [v[0] for v in vals] for k, vals in index.items()}
    prefix_max_end = {}
    for key, vals in index.items():
        running = float("-inf")
        maxima = []
        for _, end, _ in vals:
            running = max(running, end)
            maxima.append(running)
        prefix_max_end[key] = maxima

    if len(flows):
        scope_start = float(flows.start_epoch.min()) - tolerance_seconds
        scope_end = float(flows.end_epoch.max()) + tolerance_seconds
    else:
        scope_start, scope_end = float("-inf"), float("inf")

    total, in_scope, out_of_scope, matched, ambiguous = 0, 0, 0, 0, 0
    unmatched_reasons = defaultdict(int)
    with open(eve_path, encoding="utf-8") as stream:
        for line_no, line in enumerate(stream, 1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                unmatched_reasons["invalid_json"] += 1
                continue
            if event.get("event_type") != "alert":
                continue
            total += 1
            required = ("src_ip", "src_port", "dest_ip", "dest_port", "proto", "timestamp")
            if any(k not in event for k in required):
                unmatched_reasons["missing_tuple_or_time"] += 1
                continue
            ts = pd.to_datetime(event["timestamp"], utc=True, errors="coerce")
            if pd.isna(ts):
                unmatched_reasons["invalid_timestamp"] += 1
                continue
            t = ts.timestamp()
            if t < scope_start or t > scope_end:
                out_of_scope += 1
                unmatched_reasons["outside_flow_time_range"] += 1
                continue
            in_scope += 1
            key = canonical_key(event["src_ip"], event["src_port"], event["dest_ip"],
                                event["dest_port"], event["proto"])
            if key not in index:
                unmatched_reasons["tuple_not_found"] += 1
                continue
            candidates = index[key]
            pos = bisect.bisect_right(starts[key], t + tolerance_seconds)
            first = bisect.bisect_left(prefix_max_end[key], t - tolerance_seconds, 0, pos)
            hits = [row_id for start, end, row_id in candidates[first:pos]
                    if end + tolerance_seconds >= t]
            if not hits:
                unmatched_reasons["time_not_overlapping"] += 1
                continue
            if len(hits) > 1:
                ambiguous += 1
                unmatched_reasons["ambiguous_multiple_flow_rows"] += 1
                continue
            flows.loc[hits, "signature_hit"] = True
            severity = (event.get("alert") or {}).get("severity", 3)
            try:
                signature_score = max(0.0, 4.0 - float(severity))
            except (TypeError, ValueError):
                signature_score = 1.0
            flows.loc[hits, "signature_score"] = np.maximum(
                flows.loc[hits, "signature_score"].to_numpy(), signature_score
            )
            matched += 1
    unmatched_in_scope = in_scope - matched - ambiguous
    return {
        "alert_events": total,
        "in_scope_alert_events": in_scope,
        "out_of_scope_alert_events": out_of_scope,
        "matched_alert_events": matched,
        "ambiguous_alert_events": ambiguous,
        "unmatched_in_scope_alert_events": unmatched_in_scope,
        "unmatched_alert_events": total - matched - ambiguous,
        "unmatched_reasons": dict(unmatched_reasons),
        "match_rate": matched / in_scope if in_scope else None,
        "flow_scope_start_epoch": scope_start if len(flows) else None,
        "flow_scope_end_epoch": scope_end if len(flows) else None,
        "tolerance_seconds": tolerance_seconds,
    }

def conformal_sets(cal_probs, cal_y, test_probs, classes, alpha):
    """Class-conditional split-conformal sets; class-indexed and finite-sample smoothed."""
    sets = []
    for p in test_probs:
        included = []
        for j, cls in enumerate(classes):
            scores = 1.0 - cal_probs[cal_y == cls, j]
            if len(scores) == 0:
                continue
            p_value = (1 + np.count_nonzero(scores >= 1.0 - p[j])) / (len(scores) + 1)
            if p_value > alpha:
                included.append(int(cls))
        sets.append(included)
    return sets


def hybrid_priority(frame):
    """Keep signature hits ahead of ML-ranked non-signature candidates."""
    return np.where(frame["signature_hit"], 10.0 + frame["signature_score"],
                    frame["p_attack"])


def select_topk(frame, budget, score):
    chosen = []
    for _, group in frame.groupby("window", sort=True):
        chosen.extend(group.nlargest(budget, score).index.tolist())
    return set(chosen)


def score_selection(frame, chosen, total_attacks):
    tp = int(frame.loc[list(chosen), "y"].sum()) if chosen else 0
    n = len(chosen)
    fp = n - tp
    total_benign = int((frame["y"] == 0).sum())
    return {"alerts": n, "true_alerts": tp, "false_alerts": fp,
            "recall": tp/total_attacks if total_attacks else None,
            "precision": tp/n if n else None,
            "false_positive_rate": fp/total_benign if total_benign else None}


def sha256_path(path):
    """Hash a file or directory tree without loading it all into memory."""
    path = Path(path)
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



def project_revision():
    """Return the checked-out repository commit, if this run came from a Git checkout."""
    repository_root = Path(__file__).resolve().parent.parent
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repository_root,
            check=True, capture_output=True, text=True, timeout=5
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None

def suricata_version():
    try:
        result = subprocess.run(["suricata", "-V"], check=False, capture_output=True,
                                text=True, timeout=10)
        return (result.stdout or result.stderr).strip() or "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "not available in pipeline environment"


def verify_replay_manifest(manifest_path, pcap_path, eve_path):
    """Reject EVE/PCAP pairs that do not match the replay manifest hashes."""
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    expected_pcap = manifest.get("inputs", {}).get("pcap", {}).get("sha256")
    expected_eve = manifest.get("eve_json", {}).get("sha256")
    if not expected_pcap or not expected_eve:
        raise ValueError("Replay manifest is missing PCAP or EVE SHA-256 values.")
    if expected_pcap != sha256_path(pcap_path):
        raise ValueError("PCAP hash does not match the Suricata replay manifest.")
    if expected_eve != sha256_path(eve_path):
        raise ValueError("EVE JSON hash does not match the Suricata replay manifest.")
    return manifest


def run(csv_path, eve_path, pcap_path, replay_manifest_path, out_dir, budget, window_seconds, alpha, tolerance, ruleset_path=None, flow_timezone="UTC", dataset_source=None, dataset_revision=None):
    replay_manifest = verify_replay_manifest(replay_manifest_path, pcap_path, eve_path)
    flows = load_flows(csv_path, flow_timezone=flow_timezone)
    ingestion_audit = flows.attrs.get("ingestion_audit", {})
    alignment = attach_suricata_alerts(flows, eve_path, tolerance)
    flows = flows.sort_values("timestamp").reset_index(drop=True)
    # Strict chronological split; thresholds and model never see test labels.
    n = len(flows)
    a, b = int(n * .60), int(n * .80)
    train, cal, test = flows.iloc[:a].copy(), flows.iloc[a:b].copy(), flows.iloc[b:].copy()
    if min(train.y.nunique(), cal.y.nunique(), test.y.nunique()) < 2:
        raise ValueError("Each chronological split must contain benign and attack rows; revise slice/split.")
    x_train = train[FEATURES].replace([np.inf, -np.inf], np.nan)
    medians = x_train.median().fillna(0)
    x_train = x_train.fillna(medians)
    x_cal = cal[FEATURES].replace([np.inf, -np.inf], np.nan).fillna(medians)
    x_test = test[FEATURES].replace([np.inf, -np.inf], np.nan).fillna(medians)
    model = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, class_weight="balanced",
                                   random_state=17, n_jobs=-1)
    model.fit(x_train, train.y)
    cal_probs, test_probs = model.predict_proba(x_cal), model.predict_proba(x_test)
    classes = model.classes_
    pred_sets = conformal_sets(cal_probs, cal.y.to_numpy(), test_probs, classes, alpha)
    test["p_attack"] = test_probs[:, list(classes).index(1)]
    test["pred_set"] = pred_sets
    test["window"] = (test.timestamp.map(lambda ts: ts.timestamp()) // window_seconds).astype("int64")
    test["signature_hit"] = test.signature_hit.astype(bool)
    budget = max(1, int(budget))
    ml_ids = select_topk(test, budget, "p_attack")
    sig_candidates = test[test.signature_hit]
    sig_ids = select_topk(sig_candidates, budget, "signature_score") if len(sig_candidates) else set()
    candidates = test[test.signature_hit | test.pred_set.map(lambda s: 1 in s or len(s) == 0)].copy()
    candidates["priority"] = hybrid_priority(candidates)
    hybrid_ids = select_topk(candidates, budget, "priority")
    attacks = int(test.y.sum())
    policy_indices = {
        "ML probability top-K": ml_ids,
        "Signature only": sig_ids,
        "Signature + ML + conformal": hybrid_ids,
    }
    metrics = {name: score_selection(test, ids, attacks)
               for name, ids in policy_indices.items()}
    per_window = []
    for window_id, group in test.groupby("window", sort=True):
        group_ids = set(group.index)
        window_attacks = int(group.y.sum())
        per_window.append({
            "window": int(window_id), "flows": len(group), "attacks": window_attacks,
            "policies": {name: score_selection(group, ids & group_ids, window_attacks)
                         for name, ids in policy_indices.items()},
        })

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    test["selected_ml"] = test.index.isin(ml_ids)
    test["selected_signature"] = test.index.isin(sig_ids)
    test["selected_hybrid"] = test.index.isin(hybrid_ids)
    test["pred_set_names"] = test.pred_set.map(
        lambda values: "|".join("Attack" if x == 1 else "Benign" for x in values))
    test.drop(columns=["flow_key", "pred_set"]).to_csv(out / "test_flows.csv", index=False)
    set_sizes = np.array([len(values) for values in pred_sets], dtype=int)
    covered = np.array([int(y) in values for y, values in zip(test.y, pred_sets)], dtype=bool)
    conformal_diagnostics = {
        "empirical_coverage": float(covered.mean()) if len(covered) else None,
        "mean_set_size": float(set_sizes.mean()) if len(set_sizes) else None,
        "empty_set_rate": float((set_sizes == 0).mean()) if len(set_sizes) else None,
        "singleton_set_rate": float((set_sizes == 1).mean()) if len(set_sizes) else None,
        "ambiguous_set_rate": float((set_sizes > 1).mean()) if len(set_sizes) else None,
        "set_size_counts": {str(size): int((set_sizes == size).sum()) for size in (0, 1, 2)},
    }
    for item in per_window:
        window_rows = test[test.window == item["window"]]
        positions = window_rows.index.to_numpy() - test.index.min()
        item["conformal_empirical_coverage"] = float(covered[positions].mean()) if len(positions) else None
        item["conformal_mean_set_size"] = float(set_sizes[positions].mean()) if len(positions) else None

    report = {
        "dataset": "CIC-IDS2017 labeled flow CSV",\n        "dataset_provenance": {"source": dataset_source, "revision": dataset_revision},\n        "rows": n,
        "ingestion_audit": ingestion_audit,
        "split_rows": {"train": len(train), "calibration": len(cal), "test": len(test)},
        "alert_budget_per_window": budget, "window_seconds": window_seconds,
        "conformal_alpha": alpha, "suricata_alignment": alignment,
        "metrics": metrics, "conformal_diagnostics": conformal_diagnostics,
        "per_window_metrics": per_window,
    }
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    metadata = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "labeled_flows_csv": {"path": str(csv_path), "sha256": sha256_path(csv_path)},
            "suricata_eve_json": {"path": str(eve_path), "sha256": sha256_path(eve_path)},
            "suricata_replay_manifest": {"path": str(replay_manifest_path), "sha256": sha256_path(replay_manifest_path)},
            "source_pcap": {"path": str(pcap_path), "sha256": sha256_path(pcap_path)},
            **({"suricata_ruleset": {"path": str(ruleset_path), "sha256": sha256_path(ruleset_path)}}
               if ruleset_path else {}),
        },
        "software": {
            "project_git_commit": project_revision(),
            "python": platform.python_version(), "numpy": np.__version__,
            "pandas": pd.__version__, "scikit_learn": __import__("sklearn").__version__,
            "suricata": replay_manifest.get("suricata_version", "unknown"),
        },
        "model": {"type": "RandomForestClassifier", "n_estimators": 300,
                  "min_samples_leaf": 2, "class_weight": "balanced", "random_state": 17},
        "parameters": {"budget": budget, "window_seconds": window_seconds,
                       "alpha": alpha, "alignment_tolerance_seconds": tolerance,
                       "flow_timezone": flow_timezone},
        "notes": ["EVE JSON and labeled flows must correspond to the same PCAP interval.",
                  "Record the source PCAP and ruleset hashes in the experiment log."],
    }
    (out / "run_metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    output_names = ("report.json", "test_flows.csv", "run_metadata.json")
    output_manifest = {
        "schema_version": 1,
        "outputs": {
            name: {"sha256": sha256_path(out / name), "bytes": (out / name).stat().st_size}
            for name in output_names
        },
    }
    (out / "artifact_manifest.json").write_text(
        json.dumps(output_manifest, indent=2), encoding="utf-8"
    )
    return report



def verify_artifact_manifest(manifest_path):
    """Verify hashes and sizes for every file listed in an artifact manifest."""
    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    outputs = manifest.get("outputs")
    if manifest.get("schema_version") != 1 or not isinstance(outputs, dict) or not outputs:
        raise ValueError("Artifact manifest has an unsupported or empty schema.")
    root = manifest_path.parent
    verified = []
    for relative, expected in outputs.items():
        path = (root / relative).resolve()
        if root not in path.parents:
            raise ValueError(f"Artifact path escapes the manifest directory: {relative}")
        if not path.is_file():
            raise FileNotFoundError(f"Artifact listed in manifest is missing: {path}")
        if sha256_path(path) != expected.get("sha256"):
            raise ValueError(f"Artifact SHA-256 mismatch: {relative}")
        if path.stat().st_size != expected.get("bytes"):
            raise ValueError(f"Artifact size mismatch: {relative}")
        verified.append(relative)
    return {"verified": verified, "count": len(verified)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows-csv", required=True, help="CICFlowMeter labeled flow CSV")
    parser.add_argument("--eve-json", required=True, help="Suricata EVE JSON from the matching PCAP")
    parser.add_argument("--pcap", required=True, help="Source PCAP used for replay; recorded by SHA-256")
    parser.add_argument("--replay-manifest", required=True, help="suricata_run.json produced by replay_suricata.py")
    parser.add_argument("--ruleset", help="Optional Suricata rule file or directory to record by SHA-256")
    parser.add_argument("--out", default="results/run-001")
    parser.add_argument("--budget", type=int, default=5, help="maximum alerts per time window")
    parser.add_argument("--window-seconds", type=int, default=900)
    parser.add_argument("--alpha", type=float, default=0.10)
    parser.add_argument("--alignment-tolerance", type=float, default=2.0)
    parser.add_argument("--dataset-source", help="Dataset source URL or repository identifier")\n    parser.add_argument("--dataset-revision", help="Pinned dataset revision or release identifier")\n    parser.add_argument("--flow-timezone", required=True,
                        help="Timezone of timezone-naive flow CSV timestamps (for example UTC or America/Toronto)")
    args = parser.parse_args()
    report = run(args.flows_csv, args.eve_json, args.pcap, args.replay_manifest,
                 args.out, args.budget, args.window_seconds, args.alpha,
                 args.alignment_tolerance, args.ruleset, args.flow_timezone,\n                 args.dataset_source, args.dataset_revision)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

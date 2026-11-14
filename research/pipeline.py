#!/usr/bin/env python3
"""Reproducible CIC-IDS2017 + Suricata cascade evaluation.

This is an offline research pipeline. It does not perform live monitoring.
Input flow labels and Suricata EVE alerts must come from the same PCAP/time slice.
"""
from __future__ import annotations

import argparse
import bisect
import json
from collections import defaultdict
from pathlib import Path

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
    p = PROTO.get(str(proto).strip(), str(proto).strip().upper())
    return a[0], a[1], b[0], b[1], p


def pick_column(columns, aliases, required=True):
    lookup = {str(c).strip().lower(): c for c in columns}
    for alias in aliases:
        if alias in lookup:
            return lookup[alias]
    if required:
        raise ValueError(f"Missing required field. Tried: {aliases}")
    return None


def load_flows(csv_path):
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]
    cols = {name: pick_column(df.columns, aliases, name not in {"src_ip","src_port","dst_ip","dst_port"})
            for name, aliases in ALIASES.items()}
    # CICFlowMeter files can omit endpoint fields only in ML-ready exports.
    for name in ("src_ip", "src_port", "dst_ip", "dst_port"):
        if cols[name] is None:
            raise ValueError(f"{name} is required for Suricata alignment; use the original labeled-flow CSV.")
    out = pd.DataFrame()
    out["timestamp"] = pd.to_datetime(df[cols["timestamp"]], errors="coerce", utc=True, dayfirst=False)
    out["src_ip"], out["src_port"] = df[cols["src_ip"]].astype(str), pd.to_numeric(df[cols["src_port"]], errors="coerce")
    out["dst_ip"], out["dst_port"] = df[cols["dst_ip"]].astype(str), pd.to_numeric(df[cols["dst_port"]], errors="coerce")
    out["protocol"] = df[cols["protocol"]].astype(str)
    out["label_raw"] = df[cols["label"]].astype(str).str.strip()
    out["y"] = (out["label_raw"].str.casefold() != "benign").astype("int8")
    for f in FEATURES:
        source = cols.get(f)
        out[f] = pd.to_numeric(df[source], errors="coerce") if source else np.nan
    # CICFlowMeter duration and IAT are in microseconds; convert to seconds.
    out["duration"] = out["duration"] / 1_000_000.0
    out["iat"] = out["iat"] / 1_000_000.0
    out = out.dropna(subset=["timestamp", "src_port", "dst_port", "label_raw"])
    out["start_epoch"] = out["timestamp"].astype("int64") / 1e9
    out["end_epoch"] = out["start_epoch"] + out["duration"].clip(lower=0)
    out["flow_key"] = [
        canonical_key(a, b, c, d, p)
        for a, b, c, d, p in zip(out.src_ip, out.src_port, out.dst_ip, out.dst_port, out.protocol)
    ]
    out["signature_hit"] = False\n    out["signature_score"] = 0.0
    return out.reset_index(drop=True)


def attach_suricata_alerts(flows, eve_path, tolerance_seconds=2.0):
    """Match EVE alerts to flow rows using bidirectional 5-tuple and time overlap.

    Returns an audit summary; unmatched alerts are never silently assigned.
    """
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
    total, matched = 0, 0
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
            key = canonical_key(event["src_ip"], event["src_port"], event["dest_ip"],
                                event["dest_port"], event["proto"])
            if key not in index:
                unmatched_reasons["tuple_not_found"] += 1
                continue
            ts = pd.to_datetime(event["timestamp"], utc=True, errors="coerce")
            if pd.isna(ts):
                unmatched_reasons["invalid_timestamp"] += 1
                continue
            t = ts.timestamp()
            candidates = index[key]
            pos = bisect.bisect_right(starts[key], t + tolerance_seconds)
            hits = [row_id for start, end, row_id in candidates[:pos]
                    if end + tolerance_seconds >= t]
            if not hits:
                unmatched_reasons["time_not_overlapping"] += 1
                continue
            flows.loc[hits, "signature_hit"] = True
            matched += 1
    return {"alert_events": total, "matched_alert_events": matched,
            "unmatched_alert_events": total - matched,
            "unmatched_reasons": dict(unmatched_reasons),
            "match_rate": matched / total if total else None,
            "tolerance_seconds": tolerance_seconds}


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


def select_topk(frame, budget, score):
    chosen = []
    for _, group in frame.groupby("window", sort=True):
        chosen.extend(group.nlargest(budget, score).index.tolist())
    return set(chosen)


def score_selection(frame, chosen, total_attacks):
    tp = int(frame.loc[list(chosen), "y"].sum()) if chosen else 0
    n = len(chosen)
    return {"alerts": n, "true_alerts": tp, "false_alerts": n-tp,
            "recall": tp/total_attacks if total_attacks else None,
            "precision": tp/n if n else None}


def run(csv_path, eve_path, out_dir, budget, window_seconds, alpha, tolerance):
    flows = load_flows(csv_path)
    alignment = attach_suricata_alerts(flows, eve_path, tolerance)
    flows = flows.sort_values("timestamp").reset_index(drop=True)
    # Strict chronological split; thresholds and model never see the test labels.
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
    test["window"] = ((test.timestamp.astype("int64") / 1e9) // window_seconds).astype("int64")
    test["signature_hit"] = test.signature_hit.astype(bool)
    budget = max(1, int(budget))
    ml_ids = select_topk(test, budget, "p_attack")
    sig_candidates = test[test.signature_hit]
    sig_ids = select_topk(sig_candidates, budget, "signature_score") if len(sig_candidates) else set()
    candidates = test[test.signature_hit | test.pred_set.map(lambda s: 1 in s or len(s) == 0)].copy()
    candidates["priority"] = candidates.signature_score + candidates.p_attack
    hybrid_ids = select_topk(candidates, budget, "priority")
    attacks = int(test.y.sum())
    metrics = {
        "ML probability top-K": score_selection(test, ml_ids, attacks),
        "Signature only": score_selection(test, sig_ids, attacks),
        "Signature + ML + conformal": score_selection(test, hybrid_ids, attacks),
    }
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    test["selected_ml"] = test.index.isin(ml_ids)
    test["selected_signature"] = test.index.isin(sig_ids)
    test["selected_hybrid"] = test.index.isin(hybrid_ids)
    test["pred_set_names"] = test.pred_set.map(lambda s: "|".join("Attack" if x == 1 else "Benign" for x in s))
    test.drop(columns=["flow_key", "pred_set"]).to_csv(out / "test_flows.csv", index=False)
    report = {"dataset": "CIC-IDS2017 labeled flow CSV", "rows": n,
              "split_rows": {"train": len(train), "calibration": len(cal), "test": len(test)},
              "alert_budget_per_window": budget, "window_seconds": window_seconds,
              "conformal_alpha": alpha, "suricata_alignment": alignment, "metrics": metrics}
    (out / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows-csv", required=True, help="CICFlowMeter labeled flow CSV")
    parser.add_argument("--eve-json", required=True, help="Suricata EVE JSON from the matching PCAP")\n    parser.add_argument("--pcap", required=True, help="Source PCAP used to generate both inputs; recorded by SHA-256")\n    parser.add_argument("--ruleset", help="Optional Suricata rules file or directory to hash for provenance")
    parser.add_argument("--out", default="results/run-001")
    parser.add_argument("--budget", type=int, default=5, help="maximum alerts per time window")
    parser.add_argument("--window-seconds", type=int, default=900)
    parser.add_argument("--alpha", type=float, default=0.10)
    parser.add_argument("--alignment-tolerance", type=float, default=2.0)
    args = parser.parse_args()
    report = run(args.flows_csv, args.eve_json, args.out, args.budget,
                 args.window_seconds, args.alpha, args.alignment_tolerance)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

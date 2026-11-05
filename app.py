#!/usr/bin/env python3
"""Local educational demo of a signature -> ML -> conformal NIDS pipeline.

All bundled traffic is synthetic. This demonstrates the workflow only; it is
not a performance evaluation and does not run Suricata against real PCAPs.
"""
from __future__ import annotations

import html
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import numpy as np
from sklearn.ensemble import RandomForestClassifier

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8085"))
FEATURES = ["duration_ms", "fwd_packets", "bwd_packets", "bytes_total",
            "dst_port", "syn_count", "iat_mean_ms"]


def make_split(n, seed, attack_rate, shifted=False):
    rng = np.random.default_rng(seed)
    y = rng.binomial(1, attack_rate, n)
    x = np.zeros((n, len(FEATURES)), dtype=float)
    kinds = rng.choice([0, 1, 2, 3], n, p=[.27, .28, .20, .25])
    for i, label in enumerate(y):
        if not label:
            shift = 1.3 if shifted else 1.0
            x[i] = [rng.lognormal(5.6, .75) * shift,
                    rng.poisson(7 * shift) + 1, rng.poisson(6 * shift),
                    rng.lognormal(8.2, .8) * shift,
                    rng.choice([53, 80, 443, 8080, 22]),
                    rng.binomial(1, .18), rng.lognormal(4.0, .65)]
        elif kinds[i] == 0:  # scan-like
            x[i] = [rng.lognormal(4.0, .7), rng.poisson(2) + 1,
                    rng.binomial(1, .12), rng.lognormal(5.2, .55),
                    rng.integers(20, 10000), 1, rng.lognormal(2.7, .55)]
        elif kinds[i] == 1:  # denial-of-service-like
            x[i] = [rng.lognormal(6.1, .75), rng.poisson(75) + 5,
                    rng.poisson(8), rng.lognormal(11.4, .8),
                    rng.choice([80, 443, 8080]), rng.binomial(1, .55),
                    rng.lognormal(2.4, .55)]
        elif kinds[i] == 2:  # credential-attack-like
            x[i] = [rng.lognormal(5.3, .7), rng.poisson(5) + 1,
                    rng.poisson(4), rng.lognormal(7.3, .8),
                    rng.choice([21, 22, 23, 3389, 5900]),
                    rng.binomial(1, .35), rng.lognormal(4.0, .6)]
        else:
            x[i] = [rng.lognormal(5.5, .8), rng.poisson(16) + 1,
                    rng.poisson(11), rng.lognormal(8.8, .9),
                    rng.choice([53, 80, 443, 8080, 4444]),
                    rng.binomial(1, .4), rng.lognormal(3.5, .7)]
        if shifted and label and rng.random() < .38:
            x[i, 0] *= 1.25
            x[i, 1] = max(1, int(x[i, 1] * .75))
            x[i, 3] *= .82

    # Simulated signature coverage and false matches are separate from ML features.
    sig = rng.random(n) < np.where(y == 1, .34, .018)
    return x, y.astype(int), sig


def build_rows():
    x_train, y_train, _ = make_split(900, 11, .18)
    x_cal, y_cal, _ = make_split(450, 22, .20)
    x_test, y_test, sig = make_split(420, 33, .23, shifted=True)
    model = RandomForestClassifier(n_estimators=160, min_samples_leaf=3,
                                   class_weight="balanced", random_state=17,
                                   n_jobs=1)
    model.fit(x_train, y_train)
    classes = model.classes_.tolist()
    pc, pt = model.predict_proba(x_cal), model.predict_proba(x_test)
    # Class-conditional split-conformal p-values from the earlier calibration set.
    pvals = np.zeros_like(pt)
    for j, cls in enumerate(classes):
        scores = 1 - pc[y_cal == cls, j]
        test_scores = 1 - pt[:, j]
        pvals[:, j] = (1 + (scores[:, None] >= test_scores[None, :]).sum(0)) / (len(scores) + 1)
    rows = []
    for i, y in enumerate(y_test):
        pred_set = ["Benign" if cls == 0 else "Attack"
                    for j, cls in enumerate(classes) if pvals[i, j] > .10]
        rows.append({
            "id": f"FLOW-{i + 1:04d}", "window": i // 60,
            "time": f"T+{(i // 60) * 15:02d}m:{i % 60:02d}s",
            "src": f"10.0.{i % 8 + 1}.{i % 240 + 10}",
            "dst": f"192.0.2.{i % 200 + 1}", "port": int(x_test[i, 4]),
            "sig": bool(sig[i]), "prob": float(pt[i, classes.index(1)]),
            "set": pred_set, "truth": int(y),
        })
    return rows


ROWS = build_rows()
N_WINDOWS = max(r["window"] for r in ROWS) + 1


def top_k_by_window(records, budget, score):
    chosen = []
    for window in range(N_WINDOWS):
        items = sorted((r for r in records if r["window"] == window),
                       key=score, reverse=True)
        chosen.extend(items[:budget])
    return chosen


def get_metrics(chosen):
    tp = sum(r["truth"] == 1 for r in chosen)
    total_attacks = sum(r["truth"] == 1 for r in ROWS)
    return {"alerts": len(chosen), "tp": tp, "fp": len(chosen) - tp,
            "recall": tp / total_attacks if total_attacks else 0,
            "precision": tp / len(chosen) if chosen else 0}


def evaluate(budget):
    ml = top_k_by_window(ROWS, budget, lambda r: r["prob"])
    signature = top_k_by_window([r for r in ROWS if r["sig"]], budget,
                                lambda r: r["prob"])

    def hybrid_score(r):
        if r["sig"]:
            return 3 + r["prob"]
        if not r["set"]:
            return 2 + r["prob"]
        if r["set"] == ["Attack"]:
            return 1 + r["prob"]
        if "Attack" in r["set"]:
            return .5 + r["prob"]
        return -1

    # Only signature hits and conformal attack/uncertain cases enter the alert
    # queue. Benign-only sets are suppressed; unused analyst slots stay empty.
    candidates = [r for r in ROWS if r["sig"] or r["set"] != ["Benign"]]
    hybrid = top_k_by_window(candidates, budget, hybrid_score)
    chosen_ids = {r["id"] for r in hybrid}
    for r in ROWS:
        if r["sig"]:
            r["route"] = "Signature hit → priority"
        elif not r["set"]:
            r["route"] = "Empty set → review"
        elif r["set"] == ["Attack"]:
            r["route"] = "Attack set → queue"
        elif "Attack" in r["set"]:
            r["route"] = "Ambiguous set → review"
        else:
            r["route"] = "Benign set → suppress"
    coverage = sum(("Attack" if r["truth"] else "Benign") in r["set"] for r in ROWS) / len(ROWS)
    policies = [
        ("ML probability top-K", get_metrics(ml)),
        ("Signature only", get_metrics(signature)),
        ("Signature → ML + conformal triage", get_metrics(hybrid)),
    ]
    queue = sorted(hybrid, key=hybrid_score, reverse=True)
    return policies, queue[:40], chosen_ids, coverage


def pct(x):
    return f"{100*x:.1f}%"


def make_page(budget):
    policies, queue, chosen_ids, coverage = evaluate(budget)
    main_metrics = policies[-1][1]
    policy_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{m['alerts']}</td>"
        f"<td>{pct(m['recall'])}</td><td>{pct(m['precision'])}</td>"
        f"<td>{m['tp']}</td><td>{m['fp']}</td></tr>" for name, m in policies)
    alert_rows = "".join(
        "<tr>"
        f"<td><code>{r['id']}</code></td><td>{r['time']}</td>"
        f"<td>{'QUEUED' if r['id'] in chosen_ids else '—'}<br>{html.escape(r['route'])}</td>"
        f"<td>{'DEMO-ET-1007' if r['sig'] else '—'}</td>"
        f"<td>{r['prob']:.3f}</td><td>{html.escape(', '.join(r['set']) if r['set'] else '∅')}</td>"
        f"<td>{'Attack' if r['truth'] else 'Benign'}</td></tr>" for r in queue)
    options = "".join(f'<option value="{n}" {"selected" if n == budget else ""}>{n} alerts</option>' for n in (3, 5, 10))
    return f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Conformal NIDS Cascade Demo</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f3f7f9;color:#153246;font:15px/1.5 Segoe UI,Arial,sans-serif}}
header{{background:#102b3d;color:white;padding:25px max(22px,calc((100vw - 1120px)/2))}}header small{{color:#8fd4ca;text-transform:uppercase;letter-spacing:.1em;font-weight:700}}h1{{font-size:27px;margin:6px 0}}header p{{color:#d0dce3;margin:0;max-width:780px}}
main{{max-width:1120px;margin:22px auto;padding:0 20px}}.warning{{background:#fff2d5;border:1px solid #edd39a;color:#6e5012;padding:12px 14px;border-radius:8px;font-weight:700}}
.box,.card{{background:white;border:1px solid #dce6eb;border-radius:9px;padding:15px;margin:14px 0}}.controls{{display:flex;gap:12px;align-items:end;flex-wrap:wrap}}label{{display:block;font-size:13px;color:#587184;font-weight:700;margin-bottom:5px}}select,button{{font:inherit;padding:9px 12px;border-radius:6px}}select{{border:1px solid #b7c8d2;background:white}}button{{background:#1675a8;color:white;border:0;font-weight:700;cursor:pointer}}.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card{{margin:0}}.label{{font-size:11px;text-transform:uppercase;color:#61798a;font-weight:700;letter-spacing:.05em}}.value{{font-size:26px;font-weight:750;margin:3px 0}}.sub{{font-size:12px;color:#61798a}}
h2{{font-size:17px;margin:0 0 4px}}.hint{{font-size:13px;color:#61798a;margin:0 0 12px}}.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:9px 8px;text-align:left;border-bottom:1px solid #e7eef1;white-space:nowrap}}th{{color:#587184;background:#f8fafb;font-size:11px;text-transform:uppercase}}.green{{color:#277447;font-weight:700}}.red{{color:#a13e38;font-weight:700}}.pill{{display:inline-block;border-radius:12px;background:#e8f2f6;padding:2px 7px;font-size:11px;font-weight:700}}footer{{color:#61798a;font-size:12px;padding:10px 0 28px}}@media(max-width:760px){{.cards{{grid-template-columns:repeat(2,1fr)}}h1{{font-size:22px}}}}
</style><body><header><small>Research prototype · offline replay</small><h1>Conformal Signature–ML NIDS Cascade</h1><p>Replay labeled flow records through a signature-first cascade, conformal triage, and a fixed analyst alert budget.</p></header><main>
<div class="warning">SYNTHETIC DATA — this demo illustrates the pipeline; it is not a result on CIC-IDS data.</div>
<form class="box controls" method="get"><div><label for="budget">Alert budget per 60-flow window</label><select id="budget" name="budget">{options}</select></div><button>Replay pipeline</button><span class="sub">7 windows · 420 shifted synthetic test flows · conformal α = 0.10</span></form>
<section class="cards"><div class="card"><div class="label">Test flows</div><div class="value">{len(ROWS)}</div><div class="sub">7 chronological windows</div></div><div class="card"><div class="label">Cascade alerts</div><div class="value">{main_metrics['alerts']}</div><div class="sub">up to {budget} per window</div></div><div class="card"><div class="label">Cascade recall</div><div class="value">{pct(main_metrics['recall'])}</div><div class="sub">{main_metrics['tp']} synthetic attacks queued</div></div><div class="card"><div class="label">Empirical set coverage</div><div class="value">{pct(coverage)}</div><div class="sub">calibration target 90%</div></div></section>
<section class="box"><h2>Policy comparison</h2><p class="hint">All policies use the same per-window alert cap. Metrics use the held-out synthetic labels.</p><div class="table-wrap"><table><thead><tr><th>Policy</th><th>Alerts</th><th>Recall@budget</th><th>Precision@budget</th><th>True alerts</th><th>False alerts</th></tr></thead><tbody>{policy_rows}</tbody></table></div></section>
<section class="box"><h2>Top cascade queue</h2><p class="hint">Signature hits get priority. Other flows use conformal sets and ML attack probability. Reference labels are visible only because this is an offline synthetic demo.</p><div class="table-wrap"><table><thead><tr><th>Flow</th><th>Time</th><th>Queue state / route</th><th>Signature</th><th>P(attack)</th><th>Conformal set</th><th>Reference label</th></tr></thead><tbody>{alert_rows}</tbody></table></div></section>
<section class="box"><h2>How to read the sets</h2><p><b>{{Benign}}</b> suppress from attack queue · <b>{{Attack}}</b> attack candidate · <b>{{Benign, Attack}}</b> uncertain; review · <b>∅</b> out-of-pattern; review. A signature hit bypasses ML and receives queue priority.</p><p class="hint">Coverage is empirical. Standard conformal coverage does not automatically hold after temporal shift.</p></section>
<footer>Demo only. Signatures are simulated; this app does not run Suricata, parse PCAPs, or use real network traffic.</footer></main></body></html>'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            qs = parse_qs(urlparse(self.path).query)
            budget = int(qs.get("budget", ["5"])[0])
            if budget not in (3, 5, 10):
                raise ValueError("Choose a budget of 3, 5, or 10 alerts per window.")
            body = make_page(budget).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        except Exception as exc:
            body = ("Invalid request: " + html.escape(str(exc))).encode("utf-8")
            self.send_response(400)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("[http] " + fmt % args)


if __name__ == "__main__":
    print(f"Synthetic demo: http://{HOST}:{PORT}  (Ctrl+C to stop)")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


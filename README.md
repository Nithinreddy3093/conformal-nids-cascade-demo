# Conformal Signature–ML NIDS Cascade

A small local demo of a proposed network intrusion triage pipeline: signature-first routing, ML scoring for unmatched flows, conformal prediction sets, and a fixed per-window alert budget.

> **Demo status:** the bundled traffic, signature hits, and labels are synthetic. This repository demonstrates the flow and interface only. It does not run Suricata, read PCAP files, or report results on CIC-IDS data. Its metrics are not research findings.

## Run locally

Python 3.10 or later is recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:8085>. Choose an alert cap of 3, 5, or 10 flows per 60-flow window. Stop the server with Ctrl+C.

## Explain the demo

See [PRESENTATION_GUIDE.md](PRESENTATION_GUIDE.md) for a short project pitch, a click-through walkthrough, explanations of the metrics and conformal sets, and questions to expect during a presentation.

## Deploy a hosted demo

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/Nithinreddy3093/conformal-nids-cascade-demo)

This repository includes a Dockerfile and a Render Blueprint (`render.yaml`). To deploy, sign in to Render, create a **Blueprint** from this public repository, review the `conformal-nids-cascade-demo` web service, and apply it. Render will build the Docker image and assign a public URL. The app reads Render's `PORT` environment variable and binds to `0.0.0.0` in its container.

The free service may sleep when idle and take time to wake. This is a teaching/demo app with generated data, not a production NIDS. Do not submit real traffic, credentials, or sensitive data.

## What it demonstrates

1. A random-forest flow classifier trained on a generated training split.
2. Class-conditional split-conformal prediction sets calibrated on a separate earlier split.
3. A simulated signature stage, with both attack matches and occasional benign matches.
4. A signature-first cascade: signature hits receive priority; unmatched flows pass through ML and conformal triage.
5. A comparison of ML probability top-K, signature-only, and signature→ML with conformal triage under the same per-window alert cap.
6. An offline queue table with synthetic reference labels and evaluation metrics.

## Intended research direction

The research question is whether conformal triage in a signature–ML cascade can improve alert selection under temporal shift and fixed analyst alert budgets. That question requires evaluation on real, time-ordered network traffic. It is not answered by this synthetic demo.

The next research step is to replay a public PCAP through a pinned Suricata version and ruleset, align EVE alerts with labeled flows, and measure match coverage before training or making performance claims. Standard conformal coverage relies on exchangeability; temporal shift may violate that assumption, so empirical coverage must be reported by time window.

## Limitations

- The mock signature rule is generated in Python; there is no Suricata integration yet.
- All features, labels, timestamps, and performance metrics are synthetic.
- The test split deliberately shifts some feature distributions to illustrate why temporal evaluation matters.
- A production alerting system, deployment, and response actions are outside this demo's scope.
- Hosting makes the demo web page public; it does not turn the synthetic results into empirical research evidence.


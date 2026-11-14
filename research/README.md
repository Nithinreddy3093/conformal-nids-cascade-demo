# Real-data CIC-IDS2017 pipeline

This branch adds the first real-data evaluation path to the synthetic web demo. It ingests one CICFlowMeter labeled-flow CSV, reads Suricata EVE JSON from the corresponding PCAP replay, aligns signature alert events with flows, trains an ML model on earlier flows, calibrates class-conditional conformal sets on the next chronological slice, and evaluates three policies under the same per-window alert cap.

## What is required

- A CIC-IDS2017 labeled-flow CSV with endpoint columns, timestamps, CICFlowMeter features, and labels.
- The PCAP file that corresponds to that CSV slice.
- Suricata installed locally or in a Linux/WSL environment; EVE JSON alert output enabled.
- Python dependencies from `requirements-research.txt`.

Dataset files are not included in this repository. Download them from the [official CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html) and follow its citation and data-use terms.

## Replay one PCAP with Suricata

Record the Suricata version and ruleset before each run. On Linux/WSL, replay the selected PCAP offline:

```bash
suricata -V
suricata -r /path/to/selected.pcap -c /etc/suricata/suricata.yaml -l results/suricata
```

Check that `results/suricata/eve.json` exists and contains `event_type: alert` events before continuing. Use only the labeled-flow CSV that corresponds to that same capture interval.

## Run the real-data experiment

```bash
python -m pip install -r requirements-research.txt
python research/pipeline.py \
  --flows-csv /path/to/selected_labeled_flows.csv \
  --eve-json results/suricata/eve.json \
  --out results/first-run \
  --budget 5 \
  --window-seconds 900 \
  --alpha 0.10 \
  --alignment-tolerance 2.0
```

Outputs are `report.json`, `test_flows.csv`, and `run_metadata.json`. The metadata records SHA-256 hashes for the CSV, EVE log, source PCAP, and optional ruleset; software versions; and run parameters. The report includes pooled and per-window policy metrics and alert-alignment counts.

## Alignment and evaluation details

- Flow identity uses a direction-independent 5-tuple: endpoint addresses, ports, and protocol.
- An EVE alert is assigned only when its timestamp falls within the CIC flow start/end interval plus the declared tolerance.
- Unmatched alerts are counted by reason in `report.json`; they are never silently attached to the nearest unrelated flow.
- Rows are sorted by timestamp and split 60%/20%/20% into training, calibration, and test slices.
- Calibration thresholds are learned from the middle slice; test labels are used only for evaluation.
- The three policies are ML probability top-K, signature-only top-K, and signature-first plus conformal candidate triage. Each has a per-window cap.
- Results are research outputs only after the data mapping and runtime have been checked. This first pipeline has not yet been run against the large external dataset in this environment.

## Important limitations and next validation gates

1. Confirm the CSV is from the same PCAP and that its timestamp convention matches EVE output.
2. Inspect alignment coverage and manually audit matched and unmatched examples before interpreting model metrics.
3. Check for duplicate flows and leakage across time slices in the chosen CSV.
4. Report per-window and per-scenario results; pooled metrics alone can hide temporal and class imbalance.
5. A standard split-conformal guarantee assumes exchangeability. Time ordering and distribution shift can invalidate that assumption, so empirical coverage must be measured on held-out periods.
6. The pipeline uses CICFlowMeter features; it does not claim to recompute those features from PCAP. Suricata supplies the signature alert stage.

The public browser demo remains synthetic and is separate from this research pipeline. No research metric should be inferred from the demo UI.

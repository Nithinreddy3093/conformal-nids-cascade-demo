# Real-data CIC-IDS2017 pipeline

For the guided data download and Colab run, open [CICIDS2017_Colab.ipynb](CICIDS2017_Colab.ipynb).

This branch adds the first real-data evaluation path to the synthetic web demo. It ingests one CICFlowMeter labeled-flow CSV, reads Suricata EVE JSON from the corresponding PCAP replay, aligns signature alert events with flows, trains an ML model on earlier flows, calibrates class-conditional conformal sets on the next chronological slice, and evaluates three policies under the same per-window alert cap.

## What is required

- A CIC-IDS2017 labeled-flow CSV with endpoint columns, timestamps, CICFlowMeter features, and labels.
- The PCAP file that corresponds to that CSV slice.
- Suricata installed locally or in a Linux/WSL environment; EVE JSON alert output enabled.
- Python dependencies from `requirements-research.txt`.

Dataset files are not included in this repository. Download them from the [official CIC-IDS2017 page](https://www.unb.ca/cic/datasets/ids-2017.html) and follow its citation and data-use terms.

**Important: use the original `GeneratedLabelledFlows` CSV, not `MachineLearningCSV`.** The pipeline needs `Timestamp`, source/destination IPs and ports, `Protocol`, CICFlowMeter features, and `Label` on each flow row. The ML-only CSV omits flow identifiers and timestamps, so it cannot be aligned to Suricata alerts. Select the CSV and PCAP from the same capture, and record both file hashes.


### Optional pinned mirror (unofficial)

If the official download form is unavailable, the [bencorn Hugging Face mirror](https://huggingface.co/datasets/bencorn/CICIDS2017) lists both `GeneratedLabelledFlows.zip` and daily PCAPs. Its maintainer identifies it as an unofficial copy, so cite CIC/UNB as the dataset publisher and record the mirror revision and hashes. The commands below pin revision `c5637a4d7582337ef60cfb20b77227fbfe687ed6` and download the Wednesday PCAP plus the labeled-flow archive:

```bash
mkdir -p data/cicids2017
curl -L --fail -o data/cicids2017/GeneratedLabelledFlows.zip https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/c5637a4d7582337ef60cfb20b77227fbfe687ed6/csvs/GeneratedLabelledFlows.zip
curl -L --fail -o data/cicids2017/Wednesday-workingHours.pcap https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/c5637a4d7582337ef60cfb20b77227fbfe687ed6/pcaps/Wednesday-workingHours.pcap
sha256sum data/cicids2017/GeneratedLabelledFlows.zip data/cicids2017/Wednesday-workingHours.pcap
```

Expected SHA-256 values for that mirror revision:

- `GeneratedLabelledFlows.zip`: `7bdbef286f8893f31c6db12105fa097fa5c2dcc6733179037a08129d150ea27a`
- `Wednesday-workingHours.pcap`: `cd2674db7559a53f24bc03be3239b315700174ccaef72d10f5edc4c1a08f6186`

These hashes verify file integrity against the pinned mirror objects; they do not independently establish publisher authenticity. Extract the archive and use `Wednesday-workingHours.pcap_ISCX.csv` with this PCAP. The flow archive is about 284 MB and the Wednesday capture about 13.4 GB.

## Replay one PCAP with Suricata

Record the Suricata version and ruleset before each run. On Linux/WSL, replay the selected PCAP offline:

```bash
suricata -V
suricata -r /path/to/selected.pcap -c /etc/suricata/suricata.yaml -l results/suricata
```

Check that `results/suricata/eve.json` exists and contains `event_type: alert` events before continuing. Use only the labeled-flow CSV that corresponds to that same capture interval.

## Run Suricata replay

Keep EVE alert and flow output enabled in your Suricata config. The wrapper runs offline replay, counts EVE event types, and saves a run manifest with input hashes and the Suricata version:

    python research/replay_suricata.py --pcap /path/to/capture.pcap --config /path/to/suricata.yaml --out results/suricata --ruleset /path/to/rules

It does not install Suricata or change the config. Check the generated eve.json before running the classifier pipeline.

## Run the real-data experiment

```bash
python -m pip install -r requirements-research.txt
python research/pipeline.py \
  --flows-csv /path/to/selected_labeled_flows.csv \
  --eve-json results/suricata/eve.json \
  --pcap /path/to/selected.pcap \
  --replay-manifest results/suricata/suricata_run.json \
  --out results/first-run \
  --budget 5 \
  --window-seconds 900 \
  --alpha 0.10 \
  --alignment-tolerance 2.0 \
  --flow-timezone UTC \
  --dataset-source https://huggingface.co/datasets/bencorn/CICIDS2017 \
  --dataset-revision c5637a4d7582337ef60cfb20b77227fbfe687ed6 \
  --ruleset /path/to/suricata/rules
```


The CLI requires an explicit `--flow-timezone` for timezone-naive CICFlowMeter timestamps. `UTC` is only an example: establish the source timestamp convention before replay/alignment, then use the corresponding IANA timezone. The selected timezone is recorded in run metadata.

Outputs are `report.json`, `test_flows.csv`, `run_metadata.json`, and `artifact_manifest.json`. The artifact manifest hashes each of the first three files.

Verify the downloaded outputs before using them:

```bash
python research/verify_outputs.py results/first-run/artifact_manifest.json
``` The analysis step verifies the PCAP and EVE hashes against the replay manifest and fails on a mismatch. Run metadata records SHA-256 hashes, software versions, the checked-out project Git commit, model settings, and parameters. The report includes ingestion drop counts, alert match/ambiguous/unmatched counts, pooled and per-window policy metrics, and empirical conformal coverage/set-size diagnostics.

## Alignment and evaluation details

- Flow identity uses a direction-independent 5-tuple: endpoint addresses, ports, and protocol.
- An EVE alert is assigned only when its timestamp falls within the CIC flow start/end interval plus the declared tolerance.
- Alerts outside the selected CSV's overall flow-time span (with the configured tolerance) are counted separately as out-of-scope; they are not included in the in-scope alignment match-rate denominator. This supports replaying a full-day PCAP for a CSV covering only one segment.
- Alerts that overlap multiple rows are counted as ambiguous and not assigned. Unmatched in-scope alerts are counted by reason in `report.json`; neither case is silently attached to a flow.
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

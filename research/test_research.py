import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from pipeline import attach_suricata_alerts, canonical_key, conformal_sets, hybrid_priority, load_flows, sha256_path, verify_replay_manifest
from replay_suricata import count_eve_events


class ResearchPipelineTests(unittest.TestCase):
    def test_tuple_key_ignores_direction_and_normalizes_protocol(self):
        a = canonical_key("10.0.0.1", 51515, "192.0.2.4", 443, "6")
        b = canonical_key("192.0.2.4", 443, "10.0.0.1", 51515, "TCP")
        self.assertEqual(a, b)

    def test_class_conditional_conformal_set(self):
        cal_probs = np.array([[.99, .01], [.98, .02], [.01, .99], [.02, .98]])
        cal_y = np.array([0, 0, 1, 1])
        test_probs = np.array([[.99, .01]])
        result = conformal_sets(cal_probs, cal_y, test_probs, np.array([0, 1]), alpha=.4)
        self.assertEqual(result, [[0]])

    def test_labeled_csv_conversion_and_alert_alignment(self):
        columns = {
            "Timestamp": ["7/7/2017 10:00:00 AM"],
            "Source IP": ["10.0.0.1"], "Source Port": [51515],
            "Destination IP": ["192.0.2.4"], "Destination Port": [443],
            "Protocol": [6], "Flow Duration": [2_000_000],
            "Total Fwd Packets": [4], "Total Backward Packets": [3],
            "Total Length of Fwd Packets": [1200],
            "Total Length of Bwd Packets": [700], "SYN Flag Count": [1],
            "Flow IAT Mean": [250_000], "Label": ["BENIGN"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path, eve_path = root / "flows.csv", root / "eve.json"
            pd.DataFrame(columns).to_csv(csv_path, index=False)
            flows = load_flows(csv_path)
            self.assertAlmostEqual(flows.iloc[0].duration, 2.0)
            self.assertAlmostEqual(flows.iloc[0]["iat"], .25)
            event = {
                "event_type": "alert", "timestamp": "2017-07-07T10:00:01.000000+0000",
                "src_ip": "192.0.2.4", "src_port": 443, "dest_ip": "10.0.0.1",
                "dest_port": 51515, "proto": "TCP",
                "alert": {"severity": 2},
            }
            eve_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            alignment = attach_suricata_alerts(flows, eve_path, tolerance_seconds=0)
            self.assertEqual(alignment["matched_alert_events"], 1, msg=repr(alignment))
            self.assertTrue(bool(flows.iloc[0].signature_hit))
            self.assertEqual(float(flows.iloc[0].signature_score), 2.0)

    def test_reused_tuple_alert_matches_only_time_overlapping_flow(self):
        rows = {
            "Timestamp": ["7/7/2017 10:00:00 AM", "7/7/2017 11:00:00 AM"],
            "Source IP": ["10.0.0.1", "10.0.0.1"], "Source Port": [51515, 51515],
            "Destination IP": ["192.0.2.4", "192.0.2.4"],
            "Destination Port": [443, 443], "Protocol": [6, 6],
            "Flow Duration": [2_000_000, 2_000_000], "Total Fwd Packets": [4, 4],
            "Total Backward Packets": [3, 3], "Total Length of Fwd Packets": [1200, 1200],
            "Total Length of Bwd Packets": [700, 700], "SYN Flag Count": [1, 1],
            "Flow IAT Mean": [250_000, 250_000], "Label": ["BENIGN", "BENIGN"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path, eve_path = root / "flows.csv", root / "eve.json"
            pd.DataFrame(rows).to_csv(csv_path, index=False)
            flows = load_flows(csv_path)
            event = {
                "event_type": "alert", "timestamp": "2017-07-07T11:00:01.000000+0000",
                "src_ip": "192.0.2.4", "src_port": 443, "dest_ip": "10.0.0.1",
                "dest_port": 51515, "proto": "TCP", "alert": {"severity": 1},
            }
            eve_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
            attach_suricata_alerts(flows, eve_path, tolerance_seconds=0)
            self.assertEqual(flows.signature_hit.tolist(), [False, True])

    def test_hybrid_gives_signature_hits_priority_over_ml_only(self):
        frame = pd.DataFrame({
            "signature_hit": [True, False],
            "signature_score": [1.0, 0.0],
            "p_attack": [0.01, 0.99],
        })
        priorities = hybrid_priority(frame)
        self.assertGreater(priorities[0], priorities[1])

    def test_overlapping_reused_tuple_is_reported_ambiguous(self):
        rows = {
            "Timestamp": ["7/7/2017 10:00:00 AM", "7/7/2017 10:00:01 AM"],
            "Source IP": ["10.0.0.1", "10.0.0.1"], "Source Port": [51515, 51515],
            "Destination IP": ["192.0.2.4", "192.0.2.4"],
            "Destination Port": [443, 443], "Protocol": [6, 6],
            "Flow Duration": [3_000_000, 3_000_000], "Total Fwd Packets": [4, 4],
            "Total Backward Packets": [3, 3], "Total Length of Fwd Packets": [1200, 1200],
            "Total Length of Bwd Packets": [700, 700], "SYN Flag Count": [1, 1],
            "Flow IAT Mean": [250_000, 250_000], "Label": ["BENIGN", "BENIGN"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path, eve_path = root / "flows.csv", root / "eve.json"
            pd.DataFrame(rows).to_csv(csv_path, index=False)
            flows = load_flows(csv_path)
            event = {
                "event_type": "alert", "timestamp": "2017-07-07T10:00:01.000000+0000",
                "src_ip": "192.0.2.4", "src_port": 443, "dest_ip": "10.0.0.1",
                "dest_port": 51515, "proto": "TCP", "alert": {"severity": 1},
            }
            eve_path.write_text(json.dumps(event) + "\\n", encoding="utf-8")
            alignment = attach_suricata_alerts(flows, eve_path, tolerance_seconds=0)
            self.assertEqual(alignment["ambiguous_alert_events"], 1)
            self.assertEqual(alignment["matched_alert_events"], 0)
            self.assertFalse(flows.signature_hit.any())

    def test_replay_manifest_rejects_mismatched_eve(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pcap, eve, manifest = root / "capture.pcap", root / "eve.json", root / "suricata_run.json"
            pcap.write_bytes(b"pcap bytes")
            eve.write_text('{"event_type":"alert"}\\n', encoding="utf-8")
            record = {
                "inputs": {"pcap": {"sha256": sha256_path(pcap)}},
                "eve_json": {"sha256": sha256_path(eve)},
                "suricata_version": "Suricata 8.0.4",
            }
            manifest.write_text(json.dumps(record), encoding="utf-8")
            self.assertEqual(verify_replay_manifest(manifest, pcap, eve)["suricata_version"],
                             "Suricata 8.0.4")
            eve.write_text('{"event_type":"flow"}\\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "EVE JSON hash"):
                verify_replay_manifest(manifest, pcap, eve)

    def test_eve_counts_invalid_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "eve.json"
            path.write_text('{"event_type":"alert"}\nnot-json\n{"event_type":"flow"}\n',
                            encoding="utf-8")
            self.assertEqual(count_eve_events(path),
                             {"alert": 1, "flow": 1, "other": 0, "invalid_json": 1})


if __name__ == "__main__":
    unittest.main()

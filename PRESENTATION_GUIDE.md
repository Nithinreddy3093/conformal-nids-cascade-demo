# Demo presentation guide

## 30-second introduction

“This is a small research prototype for prioritizing network-flow alerts when analysts can review only a limited number per time window. It demonstrates a signature-first stage, an ML classifier for remaining flows, and conformal prediction sets that distinguish clearer classifications from uncertain or out-of-pattern cases. All traffic, signatures, and labels in this demo are synthetic, so the interface demonstrates a proposed workflow rather than evidence that it improves real-world detection.”

## The problem this prototype explores

Network monitoring can produce more alerts than analysts can investigate. A fixed alert budget forces a prioritization question: which flows should be surfaced, which can be suppressed, and which are uncertain enough to require review? The research hypothesis behind this prototype is that uncertainty-aware triage may help allocate a fixed review budget under temporal distribution shift. This demo does not test or establish that hypothesis on real network traffic.

## Two-minute walkthrough

1. **Start with the caveat banner.** Point out that the 420 test flows, labels, and signature matches are generated locally. The displayed metrics are illustrative only.
2. **Choose an alert budget.** Select 3, 5, or 10 alerts per 60-flow window and click **Replay pipeline**. Explain that the per-window cap represents limited analyst capacity.
3. **Compare policies.** The table compares ML probability top-K, signature-only, and signature → ML + conformal triage under the same cap. Recall is the fraction of all synthetic attacks queued; precision is the fraction of queued flows that are attacks. A policy can leave slots unused when no flow passes its triage rules.
4. **Inspect the queue.** A simulated signature hit receives priority. Otherwise the classifier probability and conformal set determine whether a flow is queued or suppressed. Reference labels are shown because this is an offline demonstration; a live detector would not know them.
5. **Explain the conformal sets.** `{Benign}` is treated as benign-only; `{Attack}` as attack-only; `{Benign, Attack}` as ambiguous; and `∅` as an out-of-pattern case. Ambiguous and empty sets go to review. The displayed coverage is empirical on this generated test split, not a guarantee under temporal shift.
6. **Close with the next research step.** A real evaluation would need a pinned dataset and time split, real signature-engine output, documented flow/alert alignment, and confidence intervals across repeated or scenario-level comparisons.

## What each stage means

- **Signature stage:** a simulated rule match that routes a flow to priority handling. It is not Suricata and does not inspect packets.
- **ML stage:** a random forest trained on generated flow features. It outputs an attack probability.
- **Conformal stage:** class-conditional calibration scores produce a set of plausible labels at the configured alpha. This prototype uses alpha 0.10.
- **Cascade:** combines the signature flag and model uncertainty to create candidates, then ranks candidates within each time window subject to the selected cap.

## Questions to be ready for

**Does this prove the cascade is better?** No. It uses synthetic data with designed distributions to make the workflow visible. No comparative claim about operational or real-dataset performance is justified.

**Why use conformal prediction?** It can represent uncertainty as a set rather than forcing every flow into one label. Coverage guarantees require assumptions; temporal dependence or distribution shift can break the standard exchangeability conditions.

**What is novel?** Novelty is not established by this demo. The research direction is to evaluate whether conformal triage helps a signature–ML cascade select alerts under a fixed analyst budget and temporal shift, compared with appropriate baselines. Prior-art review and real-data experiments are still required.

**What needs to be implemented for a research result?** Replace generated flows and simulated signatures with a documented dataset and pinned signature engine; verify labels and event alignment; prevent leakage across time/scenario splits; compare the same alert budget across baselines; and report per-window performance, uncertainty, and failure cases.

## Presenter checklist

- Run locally with `python app.py`, or open the hosted URL after deployment.
- Set aside about two minutes for the interface walkthrough and a few more for research limitations.
- Say “synthetic demonstration” when describing every metric.
- Do not call the displayed values experimental findings or claim that the approach is novel based on this interface.


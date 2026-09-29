# eval/ — the evaluation harness

The protocol is `docs/EVALUATION.md`; how the datasets are used is ADR-023 in
`docs/DECISIONS.md`. This directory holds the scripts, the committed benign snapshot and the
committed `manifest.json`. Downloaded data never enters the repository: it lives in
`$PHYLAXIS_EVAL_DATA`, by default `../../eval-data` (next to the repository, not inside it).

```sh
pip install phylaxis                 # or a local wheel: maturin build --release
python eval/acquire.py datadog       # ~2 500 encrypted zips, ~1.1 GB; resumable
python eval/acquire.py benign        # latest sdist of the top 1 000 projects; resumable
python eval/manifest.py              # labels, kinds, content ids, the seeded split
python eval/run.py --split dev --all-modes
```

Standard library only; any CPython ≥ 3.9 that can import `phylaxis`.

## Handling the malicious samples

The Datadog samples are real malware. Nothing here imports or executes them, and they stay
encrypted on disk except during their own scan:

- `acquire.py` downloads the zips and never opens them;
- `manifest.py` lists and hashes their members **in memory**;
- `run.py` unpacks one sample at a time into `$PHYLAXIS_EVAL_WORK` (default
  `<data>/unpacked`), scans it, re-reads every file it wrote, and deletes it.

An antivirus with on-access scanning will block or quarantine those files, and a blocked
file would silently become a missed detection. `run.py` turns that into an error row, but
the run is only valid with an exclusion for **the work folder alone**. Exclude nothing else:
the zips and the rest of the data directory do not need it.

## Outputs

`<data>/results/<split>-<mode>.jsonl`, one line per sample: verdict, risk, rules, finding
count, wall time, or the error. `run.py` prints precision, recall, F1 and FP per 1 000
benign at τ = 0.40 and τ = 0.70. Development-set numbers stay there; `docs/RESULTS.md` is
filled from the test-set runs only.

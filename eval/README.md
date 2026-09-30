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

## Baselines (GuardDog, Aura)

`baselines.py` runs on Linux (WSL on the evaluation machine), with the same manifest, split
and inputs as `run.py`:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh              # no sudo needed
uv venv -p 3.12 ~/phx-tools/guarddog && VIRTUAL_ENV=~/phx-tools/guarddog uv pip install guarddog
docker pull sourcecodeai/aura:dev
python3 eval/baselines.py --split dev --jobs 6 --timeout 600
```

Two things that silently corrupt a baseline run if missed, both handled by the script:

- **GuardDog ≥ 3 sandboxes itself with a kernel sandbox that cannot read a Windows-mounted
  drive, and then reports "no risks" instead of failing.** Every input is staged on the
  native filesystem first. GuardDog 3.x does not build on Windows at all (its sandbox
  dependency is Unix-only).
- **Aura looks up declared requirements on pypi.org**, and offline (`--network none`) that
  raises and loses the whole scan. It runs its default analyzer set minus `req_analyzer`.
  The PyPI package named `aura` is an unrelated project; the scanner is `aura-security`,
  used here through its own image, whose digest is recorded with the results.

Aura defines no verdict threshold of its own: the harness records its score, and the
threshold is a scoring decision recorded with the results.

## Outputs

`<data>/results/<split>-<mode>.jsonl`, one line per sample: verdict, risk, rules, finding
count, wall time, or the error. `run.py` prints precision, recall, F1 and FP per 1 000
benign at τ = 0.40 and τ = 0.70. Development-set numbers stay there; `docs/RESULTS.md` is
filled from the test-set runs only.

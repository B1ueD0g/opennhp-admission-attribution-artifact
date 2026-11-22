# Offline verification

## Requirements and commands

Use Python 3.12 with NetworkX 3.6.1 for B3. The fixed regression check uses only the standard library. The commands below read graph data already in this repository.

```sh
python3 offline/verify.py fixed
python3 -m pip install -r requirements.txt
python3 offline/verify.py prospective
```

Both commands check the input fingerprints and the verdicts against stored reference signatures. The verifier evaluates one finite graph bundle per target query. The inputs represent candidate sources, action outcomes, coverage flags, and resource-state observations. Each comparison uses identical observations across methods.

## Expected results

| Included synthetic cohort | Base graphs | Global M | Local B1 | Exact B2 | Flow B3 | Additional supported definitive outcomes from M |
|---|---:|---:|---:|---:|---:|---:|
| Fixed regression, sealed subset | 24 | 24/24 | 17/24 | 24/24 | — | 7 |
| Later prospective sealed cohort | 24 | 24/24 | 18/24 | 24/24 | 24/24 | 6 |

Entries report agreement on the effect verdict. The test also checks all six documented result fields for the exact methods. The fixed cohort counts seven B1-unknown outcomes resolved by M, including two `REOPENED` and five `ACTION_ONLY`. The prospective cohort counts six, including three of each verdict. A cohort's 24 base graphs remain its own denominator.

The fixed check uses the 24 sealed base graphs from the corrected fixed regression. The development and representation-variant sets have separate roles in the study. The prospective check uses the 24 input graphs and revealed reference signatures from the later sealed comparison. It recomputes the verdicts from copies of those frozen graphs. It does not recreate the original process scheduling, seed custody, or first-run measurements.

## Evidence covered

- **Method and baselines** — `offline/fixed/` and `offline/prospective/` contain the relevant offline solvers. M, B1, and B2 use unchanged archived Python source. B3 reuses the original min-cost-flow solver definitions without the environment-specific wrappers.
- **Synthetic graph inputs** — `offline/*/cases.json` stores the solver inputs, eligible stored verdicts, and input fingerprints. `offline/PROVENANCE.json` records their relationship to frozen sources.
- **Paper-to-evidence map** — `artifacts/manifest.json` points to included materials and logical IDs in the project's local archive. Section and figure anchors follow the manuscript numbering.

Native collection, historical diagnostics, and network and subprocess timing measurements each retain their original frozen records in the controlled local study archive. Packet captures, raw execution logs, host-specific setup, and coordinated-disclosure materials stay in that archive. Access to further artifacts depends on review and disclosure arrangements. This check tests the finite graph semantics and the synthetic comparison results. It does not run OpenNHP or repeat the native measurements.

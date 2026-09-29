# Submission-Readiness Summary v0

## Purpose

This one-page map records the current GenomeFirewall paper package after the LaTeX conversion, table conversion, citation metadata verification, and local compile-tooling check. It is meant as an afternoon handoff: what is ready, what is blocked, and what the next automatic goal should be.

## Current Paper Being Written

The current manuscript is a synthetic-system/evaluation paper for GenomeFirewall: a stateful output-auditing layer for LLM-mediated genomic aggregate-query interfaces. The core claim is that repeated exact aggregate outputs can leak target carrier status even when each query satisfies a minimum cohort-size rule, and that a cohort-set-aware Privacy Ledger can reduce accepted attack-enabling query pairs while preserving benign aggregate utility in the tested synthetic workloads.

This is not currently claimed as a completed configured-provider LLM attacker paper, not a completed homomorphic-encryption execution paper, and not a formal differential-privacy paper.

## Current Data Basis

| Evidence Area | Current Data / Artifact | Readiness |
| --- | --- | --- |
| Main synthetic population | 10,000 individuals, 10,000 variants, 30 seeds; target-count 20/50/100 Main profile artifacts | paper-facing synthetic evidence ready |
| Query operators | `COHORT_COUNT`, `ALLELE_COUNT`, `CARRIER_COUNT` over controlled metadata/genotype cohorts | paper-facing methods ready |
| Attacks | deterministic non-adaptive and scripted adaptive differencing/subgroup-slicing workloads | paper-facing synthetic evidence ready |
| A2 LLM attacker | fake/local scaffold plus guarded configured-provider blocked artifact | readiness/scaffold only |
| E5 HE execution | `blocked_no_he_backend` status with TenSEAL/BFV first target and agreement fields reserved | readiness/scaffold only |
| Public real-genotype validation | not run | future work / optional upgrade |

## Ready Artifacts

| Area | Current Package State |
| --- | --- |
| Manuscript body | `docs/paper/manuscript_draft_v0.md` plus LaTeX sections `01` through `05` converted under `docs/paper/latex_scaffold/sections/`. |
| LaTeX scaffold | `docs/paper/latex_scaffold/main.tex` has default-hidden internal QA notes and resolves current `\input{}` targets in source-level checks. |
| Body tables | Table 1/2/3/5 are converted to LaTeX under `docs/paper/latex_scaffold/tables/`. |
| Supplement tables | S1-S7 have first-pass LaTeX rows; S8/S9 intentionally remain readiness-only because A2 configured-provider and E5 HE backend evidence are blocked. |
| Citation package | `references.bib` is copied into the LaTeX scaffold; active LaTeX citation audit is `used=28; bib=42; missing=0`. |
| Citation metadata | queued Adam 1989, Dinur 2003, Dwork 2010, and Chan 2011 metadata are Crossref-verified without BibTeX key changes. |
| Table provenance | `docs/paper/draft_table_freeze_manifest.md` records draft SHA256 hashes for current LaTeX tables and source anchors. |
| Figure 1 source | Mermaid `.mmd` and manual `.svg` fallback exist for the GenomeFirewall release-path diagram. |
| External compile map | `docs/paper/overleaf_transfer_package_map.md` lists the files and layouts needed for Overleaf or another external LaTeX build. |
| Figure 1 PDF fallback plan | `docs/paper/figure1_pdf_export_fallback_plan.md` defines external/install-free conversion options and label-preservation checks. |
| Compile-log triage | `docs/paper/external_compile_log_triage_checklist.md` prepares the first external compile-log diagnosis order. |
| Venue-template matrix | `docs/paper/venue_template_selection_matrix.md` compares generic `article`, CS/security/privacy/systems, biomedical/journal, and preprint template paths. |
| Final manual review | `docs/paper/final_manual_review_checklist.md` defines the source-ready human read-through order and stop conditions. |
| Source package index refresh | `docs/paper/final_source_package_index_refresh.md` records the current canonical package-map refresh. |
| Optional tool-install plan | `docs/paper/optional_tool_install_plan.md` documents local LaTeX/BibTeX and Figure 1 rendering install choices without executing installs. |
| Final package handoff note | `docs/paper/final_package_handoff_note.md` summarizes the current afternoon-ready status and next user-facing choices. |
| Overleaf upload package | `docs/paper/genomefirewall_overleaf_upload_v0.zip` and `docs/paper/overleaf_upload_package_v0/` are created and verified for external upload. |
| Unfinished experiment audit | `docs/experiments/unfinished_experiment_audit.md` records which experiments remain incomplete and which claims remain blocked. |

## Remaining Blockers

| Blocker | Current State | Manuscript Handling |
| --- | --- | --- |
| Local PDF compile | `pdflatex`, `latexmk`, `lualatex`, `xelatex`, and `bibtex` are not on PATH | source-ready, not render-verified locally |
| Figure 1 PDF export | no `node`, `npm`, `npx`, `mmdc`, Graphviz `dot`, or bundled runtime; `.pdf` absent | LaTeX source falls back to a visible Figure 1 placeholder box |
| A2 configured-provider evidence | guarded real-provider path remains `network_not_allowed` | do not claim real/configured-provider attacker performance |
| E5 encrypted execution | `blocked_no_he_backend` | do not claim encrypted/plaintext agreement or HE runtime overhead |
| DP/noise baseline | discussion only | do not claim a formal DP guarantee or ledger superiority over DP |
| Public validation | no IGSR/1000 Genomes validation run | keep as limitation/future work |
| Venue style | no final venue template selected | keep current scaffold generic |

## Shortest Route To A PDF-Like Package

1. Treat `docs/paper/latex_scaffold/` as the current source-ready LaTeX package.
2. Upload `docs/paper/genomefirewall_overleaf_upload_v0.zip` to Overleaf or another environment with a LaTeX engine before attempting local install work.
3. Compile once with the current Figure 1 placeholder fallback to catch LaTeX syntax issues.
4. Export or convert `docs/paper/figures/figure1_genomefirewall.svg` to `docs/paper/figures/figure1_genomefirewall.pdf`, then compile again with the real Figure 1 asset.
5. Keep S8/S9 as readiness-only supplement entries unless A2 configured-provider and E5 HE backend evidence are generated.

## Next Automatic Goal

Compile `docs/paper/genomefirewall_overleaf_upload_v0.zip` externally if an Overleaf or other LaTeX environment is available. Otherwise, the next evidence goals are A2 configured-provider, E5 HE backend sanity, public genotype calibration, and DP/noise baseline work as scoped in `docs/experiments/unfinished_experiment_audit.md`.

## Last Updated

- 2026-07-01

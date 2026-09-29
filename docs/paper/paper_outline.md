# First-Paper Outline

## Working Title

GenomeFirewall: Stateful Privacy Ledger for LLM-Mediated Encrypted Genomic Aggregate Queries

## Paper Type

첫 논문은 새로운 cryptographic primitive 논문이 아니라, **LLM-mediated encrypted genomic aggregate analysis를 위한 privacy firewall system/evaluation 논문**으로 포지셔닝한다. HE는 raw genotype과 execution confidentiality를 보호하는 실행 계층이고, 핵심 contribution은 repeated aggregate output과 approval/rejection transcript에서 생기는 개인 carrier-status inference risk를 LLM-agent threat model과 stateful ledger defense로 평가하는 것이다.

## One-Sentence Research Gap

기존 연구는 genomic aggregate leakage, homomorphic genomic computation, structured LLM/tool calling, LLM-agent security를 각각 다루지만, **LLM agent가 encrypted genomic aggregate query interface에서 반복적인 exact-count 질의와 승인/거절 피드백을 이용해 개인 variant carrier status를 추론하는 공격과 이를 cohort-set-aware stateful Privacy Ledger로 차단하는 방어를 함께 평가하지 않았다.**

## Thesis

허용된 aggregate query와 encrypted execution만으로는 개인 수준의 variant carrier status inference를 충분히 막을 수 없으며, query history 전반의 cohort overlap, set difference, symmetric difference를 추적하는 stateful Privacy Ledger가 adaptive LLM/scripted attacker의 성공률을 낮추면서 benign genomic aggregate utility를 유지할 수 있다.

## Core Contributions

| ID | Contribution | Paper Role |
| --- | --- | --- |
| C1 | encrypted genotype data에 대한 repeated aggregate genomic query에서 LLM-agent threat model을 정의한다. | 왜 이 문제가 지금 중요하고 기존 beacon/statistical DB 공격과 어떻게 다른지 설명한다. |
| C2 | 허용된 genomic aggregate query를 위한 constrained JSON Genomic DSL과 deterministic validator를 명세한다. | LLM이 raw DB나 arbitrary SQL을 직접 다루지 않는 제한된 interface를 만든다. |
| C3 | query history 전반의 cohort overlap, set difference, symmetric difference를 비교하는 stateful Privacy Ledger를 설계한다. | minimum cohort size policy의 blind spot을 막는 방어 메커니즘이다. |
| C4 | minimum-cohort-only policy와 ledger-based policy에서 adaptive attack success와 normal query utility를 실험적으로 평가한다. | 논문 주장 전체를 실험으로 검증하는 중심 evidence다. |

## Minimum Experiment Package

| Experiment | Minimal Version | Required Baseline | Main Metrics |
| --- | --- | --- | --- |
| E1 Adaptive attack benchmark | 합성 genotype/metadata population에서 target individual/variant를 정하고 non-adaptive, adaptive scripted, adaptive LLM attacker를 비교한다. | fixed query set, scripted adaptive attacker, LLM adaptive attacker | attack success rate, query budget to success, false inference rate |
| E2 Minimum cohort failure | `k` 이상의 cohort만 허용해도 differencing/subgroup slicing이 가능한 query pair가 승인되는지 측정한다. | no policy, minimum cohort size only | accepted attack-enabling query pairs, carrier inference success |
| E3 Ledger ablation | per-session, user-level, difference threshold, symmetric-difference threshold를 비교한다. | minimum cohort only, no cross-query history | malicious rejection rate, attack success reduction |
| E4 Benign utility | 정상 genomic aggregate workload를 만들어 ledger가 얼마나 거절하는지 측정한다. | no ledger, minimum cohort only | benign acceptance rate, false rejection rate, utility loss |
| E5 HE execution sanity check | plaintext aggregate와 BFV 또는 BGV aggregate 결과 일치를 확인한다. | plaintext execution | correctness, runtime overhead, ciphertext/plaintext agreement |
| E6 DP/noise comparison or discussion | exact-count workflow에서 DP/noise policy와 ledger의 trade-off를 비교하거나 discussion baseline으로 둔다. | DP/noise or privacy-budget-inspired baseline | privacy/utility tradeoff, result distortion, interpretability |

## Evidence Backbone

- Homer 2008, Shringarpure 2015, Ayoz 2021: aggregate/beacon-style genomic releases can leak individual-level information across queries.
- Adam 1989, Dinur 2003, Dwork 2006/2010, Chan 2011: repeated statistical releases and transcripts require stateful privacy thinking.
- Lauter 2014, Baldi 2011, SIG-DB 2018, BEDCrypt 2026: HE/secure genomic computation protects execution but does not by itself solve output-side privacy.
- PICARD 2021 and related structured output work: constrained generation/validation supports the Genomic DSL component but does not encode semantic genomic privacy.
- AgentDojo 2024 and related LLM-agent security work: dynamic agent attack/defense evaluation supports the adaptive attacker and benign utility framing.

## Known Weak Spots To Resolve

1. Direct empirical evidence is still missing for whether adaptive LLM attackers outperform scripted adaptive attackers in this domain.
2. Dinur 2003, Adam 1989, and Dwork 2010 / Chan 2011 need PDF-level ingest or deeper review because they anchor the statistical database auditing lineage.
3. The synthetic population generator needs explicit parameters: population size, allele-frequency distribution, metadata correlation, target selection, and benign workload generation.
4. The first-paper HE choice must be fixed to BFV or BGV, with a narrow aggregate circuit scope.
5. The E4 utility threshold is predefined, but utility-loss confidence intervals and final pass/fail classification are not yet implemented in reports.
6. DP/noise must be handled carefully as either a real baseline or a clearly scoped discussion baseline.

## Current Writing Artifacts

- `docs/experiments/synthetic_evaluation_spec.md` fixes the synthetic dataset, workload, policy, and metric design for E1-E4.
- `docs/experiments/result_manifest.md` indexes the current implementation, pilot reports, generated tables, A2 guarded provider artifacts, and next natural goals.
- `docs/experiments/utility_threshold.md` predefines the E4 benign utility non-inferiority margin for final interpretation.
- `docs/paper/front_matter_polish.md` polishes the title, abstract, contributions, and front-matter claim boundary.
- `docs/paper/manuscript_intro_prose.md` converts the Introduction scaffold into connected manuscript prose while preserving A2/E5 boundaries.
- `docs/paper/pilot_results_narrative.md` turns the current pilot reports into table captions, candidate result text, and caveats.
- `docs/paper/results_tables_formatted.md` stages manuscript-facing Table 1/2/3/5 rows and captions plus appendix/blocked table notes.
- `docs/paper/methods_reproducibility_prose.md` stages manuscript-facing Methods prose and Main/A2/E5 reproducibility pointers.
- `docs/paper/experiment_section_skeleton.md` maps H1-H4/E1-E5 to metrics, table artifacts, final-run requirements, and paper section flow.
- `docs/paper/table_artifact_index.md` maps current Markdown/CSV artifacts to candidate manuscript tables.
- `docs/paper/table_lockfile.md` records current Smoke/Pilot table-source provenance for paper drafting.
- `docs/experiments/paired_policy_comparison.md` documents the seed-level paired comparison metadata, E3 policy variant set, and aggregate paired-delta scaffold.
- `docs/paper/methods_section_draft.md` drafts the Methods section from the implemented Genomic DSL, synthetic dataset, Privacy Ledger policies, workloads/attackers, metrics, Main profile evidence, reporting provenance, and A2/E5 boundaries.
- `docs/paper/related_work_background_draft.md` drafts Related Work and Background across genomic aggregate leakage, statistical database privacy, HE genomic computation, structured LLM interfaces, and LLM-agent security.
- `docs/paper/manuscript_skeleton.md` stitches the current section drafts into a single paper-order scaffold with claim boundaries, TODO map, Table 1/2/3/5 placeholders, and blocked Table 6/7 notes.
- `docs/paper/manuscript_draft_v0.md` consolidates the current polished section baselines into one manuscript draft file.
- `docs/paper/citation_audit.md` verifies manuscript/Related Work citation placeholders against BibTeX and records metadata/deeper-review gaps.
- `docs/paper/claim_boundary_audit.md` audits A2/E5/DP/public-data/novelty overclaim risk and records safer wording tweaks.
- `docs/paper/submission_gap_checklist.md` separates remaining must-do, should-do, optional evidence upgrade, and blocked-claim tasks.
- `docs/paper/system_figure_plan.md` drafts Figure 1 Mermaid plan, caption, visual encoding notes, and boundary callouts.
- `docs/paper/appendix_supplement_plan.md` separates body, appendix, and future-work evidence placement.
- `docs/paper/appendix_table_index.md` maps S1-S9 supplement table candidates to exact Markdown, CSV, JSON, transcript, status, and manuscript-use artifacts.
- `docs/paper/planning_doc_cleanup.md` records stale planning-language cleanup after manuscript, figure, appendix, and appendix-index completion.
- `docs/paper/manuscript_cross_reference_pass.md` records Figure 1, Table 1/2/3/5, and Supplementary Tables S1-S9 links added to the consolidated manuscript draft.
- `docs/paper/figure1_asset_plan.md` chooses Mermaid source to SVG/PDF export for Figure 1 and creates `docs/paper/figures/figure1_genomefirewall.mmd`.
- `docs/paper/venue_table_conversion_plan.md` maps body Table 1/2/3/5 and Supplementary Tables S1-S9 to canonical table-block output paths and provenance rules.
- `docs/paper/tables/` contains canonical body table blocks for Table 1, Table 2, Table 3, and Table 5.
- `docs/paper/supplement_tables/` contains canonical supplement table blocks for S1-S9, with S8/S9 labeled scaffold/readiness only.
- `docs/paper/table_provenance/table_source_manifest.md` links body/supplement table blocks to primary sources, status labels, and freeze-time hash/timestamp policy.
- `docs/paper/table_style_polish.md` records table-block style normalization and confirms S8/S9 boundary labels remain intact.
- `docs/paper/reference_metadata_review_queue.md` prioritizes Adam 1989, Dinur 2003, Dwork 2010, and Chan 2011 metadata/deeper-review gaps without changing citation keys.
- `docs/paper/manuscript_prose_polish.md` records light prose edits to `manuscript_draft_v0.md` while preserving numerical claims, citation keys, and claim boundaries.
- `docs/paper/manuscript_claim_boundary_recheck.md` confirms the polished manuscript draft preserves A2/E5/DP/public-data claim boundaries.
- `docs/paper/final_citation_polish_checklist.md` separates ready citation groups from metadata/deeper-review queue items while preserving citation keys.
- `docs/paper/manuscript_final_read_checklist.md` collects pre-formatting final-read checks, deferred blockers, and the recommended venue-formatting order.
- `docs/paper/venue_formatting_options_matrix.md` compares Markdown-native, LaTeX/Overleaf, Word/Docx, and preview paths, recommending Markdown-native as the canonical package before venue conversion.
- `docs/paper/markdown_submission_package_index.md` defines the canonical Markdown-native conversion input package across manuscript, tables, supplements, figure source, citations, QA, and provenance files.
- `docs/paper/final_markdown_package_read.md` records the package-level final read, applied QA-baseline pointer cleanup, and Figure 1 render/tooling as the next conversion blocker.
- `docs/paper/figure1_render_tooling_check.md` records missing local Mermaid/Node/Graphviz tools, creation of the manual SVG fallback `docs/paper/figures/figure1_genomefirewall.svg`, XML verification, and deferred PDF export.
- `docs/paper/latex_conversion_scaffold.md` maps the canonical Markdown package into a generic LaTeX/Overleaf scaffold plan with section, table, supplement, figure, citation, and deferred-task rules.
- `docs/paper/latex_scaffold/` contains the first generic LaTeX/Overleaf skeleton with `main.tex`, section placeholders, body-table placeholders, supplement placeholder, and README.
- `docs/paper/body_table_latex_conversion.md` records first-pass `booktabs`/`tabularx` conversion of body Table 1/2/3/5 placeholders from canonical Markdown table blocks.
- `docs/paper/supplement_table_latex_conversion.md` records first-pass LaTeX supplement placeholders for S1-S9, preserving S8 scaffold-only and S9 blocked-readiness-only boundaries.
- `docs/paper/latex_citation_bibtex_scaffold.md` records the LaTeX bibliography working copy, key-count check, active `main.tex` bibliography block, and metadata-review queue policy.
- `docs/paper/latex_section_prose_conversion.md` records first-pass LaTeX conversion of the abstract, Introduction, and Background/Related Work, with citation audit `used=28; missing=0`.
- `docs/paper/latex_methods_results_conversion.md` records first-pass LaTeX conversion of Methods and Results, preserving Figure 1 and Table 1/2/3/5 references.
- `docs/paper/latex_discussion_limitations_conversion.md` records first-pass LaTeX conversion of Discussion/Limitations and internal QA-note review, preserving A2/E5/DP/public-data boundaries.
- `docs/paper/latex_package_readiness_pass.md` records package-level LaTeX QA: input targets, citation keys, references, default-hidden internal QA notes, and compile blockers.
- `docs/paper/latex_supplement_row_conversion.md` records first-pass LaTeX conversion of S1-S7 supplement rows, with S8/S9 retained as readiness-only.
- `docs/paper/latex_table_sizing_readability_pass.md` records table sizing/readability choices: body tables retain `\small`, S1-S7 use `\scriptsize` plus compact spacing, and final split/landscape choices remain deferred.
- `docs/paper/draft_table_freeze_manifest.md` records draft/provisional SHA256 hashes for current LaTeX table files, canonical Markdown sources, and Main CSV source anchors.
- `docs/paper/final_citation_metadata_verification.md` verifies queued Adam 1989, Dinur 2003, Dwork 2010, and Chan 2011 metadata while preserving BibTeX keys and retaining result-wording depth gaps.
- `docs/paper/compile_tooling_setup_check.md` records local compile/export blockers: no LaTeX/BibTeX engine, no Node/Mermaid/Graphviz, no bundled runtime fallback, Figure 1 SVG present, Figure 1 PDF absent.
- `docs/paper/submission_readiness_summary.md` summarizes the current source-ready LaTeX package, Main synthetic data basis, remaining tooling/evidence blockers, and the chosen external compile path.
- `docs/paper/overleaf_transfer_package_map.md` maps the current LaTeX scaffold into external/Overleaf upload layouts, compile settings, and first-compile caveats.
- `docs/paper/figure1_pdf_export_fallback_plan.md` defines install-free/external Figure 1 SVG/Mermaid-to-PDF conversion options and label-preservation checks.
- `docs/paper/external_compile_log_triage_checklist.md` prepares first external compile-log triage across missing files, BibTeX, cross-references, table widths, Figure 1 behavior, and claim-boundary-safe fixes.
- `docs/paper/venue_template_selection_matrix.md` compares generic `article`, CS/security/privacy/systems, biomedical/journal, and preprint template-family paths for the current LaTeX package.
- `docs/paper/final_manual_review_checklist.md` defines the source-ready human read-through order and stop conditions across scope, claims, numbers, tables, Figure 1, citations, limitations, and PDF review.
- `docs/paper/final_source_package_index_refresh.md` records the current canonical package-map refresh after source-ready LaTeX/readiness artifacts were added.
- `docs/paper/optional_tool_install_plan.md` documents optional local LaTeX/BibTeX and Figure 1 rendering tool choices without executing installs.
- `docs/paper/final_package_handoff_note.md` summarizes the current afternoon-ready paper package status, exact topic/data basis, blockers, and next user-facing choices.

## Next Small Goal

**Pause for review or new external state.**

현재 source-ready package handoff까지 완료됐다. 다음 실질 작업은 external compile log, user review note, local tool approval, configured-provider A2, HE backend, or venue-template decision이 생기면 더 정확하게 진행한다.

## Acceptance Criteria For Next Goal

- `final_package_handoff_note.md` is the first file to read on return.
- Next work is event-driven: compile log, review note, tool decision, A2/HE evidence, or venue choice.
- No current evidence boundary is loosened.
- 다음 작업은 새 external state/user decision이 생겼을 때 선택한다.

## Last Updated

- 2026-07-01

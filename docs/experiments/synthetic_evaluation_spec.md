# Synthetic Evaluation Spec

## Purpose

이 문서는 GenomeFirewall 첫 논문의 E1-E4 실험을 구현 가능한 수준으로 고정하기 위한 synthetic dataset and workload specification이다. 목표는 실제 clinical data 없이도 adaptive differencing/subgroup slicing attack, minimum cohort policy failure, stateful Privacy Ledger defense, benign workload utility를 반복 가능하게 측정하는 것이다.

HE execution sanity check(E5)는 같은 query semantics를 사용하되, 별도의 작은 HE-compatible subset에서 plaintext result와 encrypted aggregate result의 일치 및 runtime을 확인한다.

## Privacy Rationale

첫 논문은 개인 carrier status inference 공격을 평가하므로 실제 환자 데이터나 phenotype-linked clinical data를 사용하지 않는다. 기본 평가는 fully synthetic genotype dosage population과 synthetic metadata로 수행한다. Public human variation data는 allele-frequency calibration 또는 optional validation으로만 사용하고, 공격 성공률의 primary evidence는 synthetic ground truth에서 계산한다.

## Dataset Units

| Unit | Definition |
| --- | --- |
| Individual | 합성 인구의 한 row. 개인 식별자는 실험 내부 ground truth에만 존재하고 query interface에는 노출하지 않는다. |
| Variant | SNP-like biallelic locus. 각 individual은 dosage `0/1/2` 값을 가진다. |
| Metadata | 공격자와 benign analyst가 predicate로 사용할 수 있는 synthetic categorical or binned field. |
| Cohort | metadata predicate로 선택된 individual set. |
| Query | constrained Genomic DSL로 표현된 `COHORT_COUNT`, `ALLELE_COUNT`, `CARRIER_COUNT` request. |
| Transcript | 한 run에서 query, approval/rejection event, aggregate result, policy features가 시간 순서대로 기록된 log. |

## Default Dataset Sizes

| Mode | Individuals | Variants | Purpose |
| --- | ---: | ---: | --- |
| Smoke | 80 | 20 | unit tests, CLI plumbing, and report-shape checks. |
| Pilot | 1,000 | 500 | 코드와 metric 계산을 빠르게 검증한다. |
| Main ledger/attack | 10,000 | 10,000 | E1-E4의 primary synthetic evaluation으로 사용한다. |
| Stress ledger/attack | 50,000 | 20,000 | 선택적으로 scalability와 threshold robustness를 확인한다. |
| HE sanity subset | 1,024 or 2,048 | 64 to 256 | E5에서 BFV/BGV aggregate correctness and runtime을 확인한다. |

HE sanity subset은 attack success의 primary evidence로 쓰지 않는다. HE 실험은 semantics-preserving encrypted execution proof 역할만 한다.

Detailed smoke, pilot, dev, main, and stress profiles are tracked in `docs/experiments/experiment_profiles.md`.

## Genotype Generation

### Allele Frequency Sampling

각 variant `v`는 minor allele frequency `p_v`를 가진다. 기본 분포는 rare/common variant를 모두 포함하도록 mixture로 둔다.

| Frequency Band | MAF Range | Sampling Weight | Why |
| --- | --- | ---: | --- |
| Rare | 0.005 to 0.01 | 0.15 | privacy-sensitive carrier inference가 쉬운 낮은 빈도 영역. |
| Low-frequency | 0.01 to 0.05 | 0.25 | beacon/privacy literature와 연결되는 공격적 영역. |
| Common | 0.05 to 0.30 | 0.50 | 정상 aggregate analysis와 utility workload의 중심. |
| High-common | 0.30 to 0.50 | 0.10 | sanity check and non-sensitive contrast. |

기본 dosage는 Hardy-Weinberg-style independent sampling으로 생성한다.

- `P(dosage=0) = (1 - p_v)^2`
- `P(dosage=1) = 2p_v(1 - p_v)`
- `P(dosage=2) = p_v^2`

첫 실험에서는 LD를 제외한다. LD는 reviewer objection 또는 later extension에서 다룬다.

### Carrier Definition

For `CARRIER_COUNT`, carrier is `dosage > 0` unless a variant-specific dominant/recessive mode is explicitly configured. 첫 논문 기본값은 `dosage > 0`이다.

### Random Seeds

모든 dataset은 `dataset_seed`, `metadata_seed`, `target_seed`, `workload_seed`, `attacker_seed`를 분리해서 저장한다. Metric은 최소 30개 seed 반복의 평균과 confidence interval로 보고한다.

## Metadata Generation

### Fields

| Field | Type | Example Levels | Query Use |
| --- | --- | --- | --- |
| `sex` | categorical | `F`, `M` | broad cohort stratification. |
| `age_bin` | categorical | `20-29`, `30-39`, ..., `70-79` | normal and slicing predicate. |
| `ancestry_group` | categorical | `A`, `B`, `C`, `D`, `E` | allele-frequency calibration and stratified benign analysis. |
| `region` | categorical | `R1` to `R10` | metadata slicing. |
| `study_site` | categorical | `S1` to `S20` | realistic cohort filtering and attack slicing. |
| `phenotype_proxy` | categorical/binary | `case`, `control`, or risk bins | synthetic-only visible trait correlated with genotype. |
| `batch` | categorical | `B1` to `B10` | benign QC-style workload. |

`individual_id`, exact birth date, exact location, raw genotype row index, and cohort bitmap are never available in the query DSL.

### Genotype-Metadata Correlation Knobs

Metadata must support controlled privacy difficulty. Use three correlation regimes.

| Regime | Description | Intended Use |
| --- | --- | --- |
| Independent | metadata fields are sampled independently from genotype. | baseline where attack relies mostly on set differencing. |
| Weak correlation | selected variants shift one metadata field probability slightly. | realistic but not too easy privacy leakage. |
| Moderate correlation | target variants are enriched in one or two metadata slices. | stress test for subgroup slicing and benign utility tradeoff. |

Strong clinical correlation is excluded from the first paper unless explicitly labeled as stress-only synthetic scenario.

## Target Selection

Each attack run samples a target tuple:

- `target_individual`
- `target_variant`
- `target_carrier_status`
- `target_visible_profile`: metadata values known to the attacker
- `target_candidate_cohort`: all individuals matching the attacker-visible profile

### Target Variant Bands

Report metrics separately for:

- rare variants: `MAF < 0.01`
- low-frequency variants: `0.01 <= MAF < 0.05`
- common variants: `0.05 <= MAF < 0.30`

### Candidate Cohort Constraints

A target is eligible when its visible metadata profile creates a candidate cohort with size:

- minimum: `k_min + 1`
- preferred range: `k_min + 1` to `5 * k_min`
- broad-control range: `> 10 * k_min`

This makes the attack meaningful: the attacker cannot directly select a singleton, but can try to compare overlapping cohorts whose set difference becomes small.

## Genomic DSL Scope

The synthetic workload uses a constrained JSON Genomic DSL with only these operators:

| Operator | Output |
| --- | --- |
| `COHORT_COUNT` | number of individuals satisfying metadata predicate. |
| `ALLELE_COUNT` | sum of dosage for selected variant over selected cohort. |
| `CARRIER_COUNT` | number of individuals with dosage > 0 for selected variant over selected cohort. |

### Predicate Language

Allowed predicates:

- equality: `field == value`
- conjunction: `AND`
- limited disjunction over same field: `field IN [value1, value2]`
- bounded age-bin selection by category, not raw numeric age

Disallowed predicates:

- individual identifiers
- raw genotype conditions in cohort predicate
- arbitrary SQL
- negation in the first version, unless it is compiled into explicit allowed category complement by the validator
- free-text phenotype descriptions

## Policy Conditions

### Static Validator

The deterministic validator checks:

- operator is allowed
- variant exists
- metadata fields and values are allowed
- predicate depth and number of clauses are below limits
- output type matches operator
- cohort size can be computed before release

### Minimum Cohort Policy

A query is rejected if:

- `cohort_size < k_min`

Default `k_min` values to test:

- `20`
- `50`
- `100`

### Stateful Privacy Ledger Policy

For every accepted prior query from the relevant state scope, compute:

- `overlap_size = |C_new ∩ C_prev|`
- `difference_size = |C_new \ C_prev|`
- `reverse_difference_size = |C_prev \ C_new|`
- `symmetric_difference_size = |C_new △ C_prev|`
- same-variant indicator
- same-operator indicator
- target-risk proxy only for evaluation, not for policy if it uses hidden ground truth

Ledger variants:

| Variant | State Scope | Reject If |
| --- | --- | --- |
| No ledger | none | never checks query history. |
| Session ledger | session | small difference or small symmetric difference versus accepted prior query in same session. |
| User ledger | user | same check across sessions for the same user. |
| Organization ledger | organization | same check across users in the same organization, optional stress setting. |
| Difference-only | user | `min(difference_size, reverse_difference_size) < d_min` for same variant/operator family. |
| Symmetric-difference | user | `symmetric_difference_size < s_min` for same variant/operator family. |
| Combined ledger | user | either difference or symmetric-difference rule triggers. |

Default threshold grid:

| Parameter | Values |
| --- | --- |
| `d_min` | 5, 10, 20, 50 |
| `s_min` | 10, 20, 50, 100 |

Thresholds must be reported as policy parameters, not tuned on test targets.

## Attacker Models

### A0 Non-Adaptive Fixed Query Set

The attacker submits a pre-generated list of valid aggregate queries without observing intermediate results. This establishes a weak baseline.

### A1 Adaptive Scripted Attacker

The scripted attacker observes accepted/rejected status and exact aggregate outputs. It uses deterministic rules to narrow candidate cohorts and propose differencing/subgroup slicing queries.

### A2 Adaptive LLM Attacker

The LLM attacker sees the allowed schema, previous query transcript, aggregate outputs, and rejection feedback according to the configured feedback setting. It proposes natural-language or DSL-level next queries, which are passed through the deterministic validator and ledger.

A2 must be compared to A1. If A2 does not outperform A1, the paper should frame the contribution as defense against adaptive query attackers generally, with LLM agents as a realistic interface and automation layer.

## Rejection Feedback Settings

Evaluate or ablate:

| Setting | What Attacker Sees | Risk |
| --- | --- | --- |
| Binary | `accepted` or `rejected` only. | safest. |
| Reason bucket | `invalid_schema`, `small_cohort`, `ledger_overlap`, `ledger_difference`. | may teach policy boundaries. |
| Detailed diagnostic | exact failed threshold or near-threshold detail. | likely unsafe; use only as stress setting. |

Primary setting should be Binary or Reason bucket. Detailed diagnostic should not be the default defense claim.

## Malicious Workload Templates

### Differencing Template

Goal: infer `CARRIER_COUNT` contribution of a small hidden difference set.

1. Query broad target-like cohort `C_a` for `CARRIER_COUNT(variant=v)`.
2. Query overlapping cohort `C_b` for same variant where `C_a \ C_b` or `C_b \ C_a` is small and includes the target or target-like candidate subset.
3. Compute count difference.
4. Convert count difference into carrier-status guess when the difference set is singleton or small enough to make posterior confidence high.

### Subgroup Slicing Template

Goal: gradually narrow the target candidate cohort using visible metadata combinations.

1. Start from broad profile fields such as ancestry and age bin.
2. Add site, region, batch, or phenotype_proxy predicates.
3. Observe when counts change across slices.
4. Stop when the candidate cohort is just above `k_min` or when accepted query pairs reveal a small set difference.

### Policy-Probing Template

Goal: learn validator and ledger boundaries.

1. Submit semantically similar cohorts with small predicate changes.
2. Observe approval/rejection sequence.
3. Search for the smallest accepted cohort and smallest accepted cohort difference.
4. Use discovered boundary to construct attack-enabling pairs.

Policy-probing success is reported separately from carrier inference success.

## Benign Workload Templates

Benign workloads should resemble legitimate aggregate analysis and avoid target-driven slicing.

| Template | Example |
| --- | --- |
| Cohort size summaries | `COHORT_COUNT` by ancestry group, age bin, or study site. |
| Variant carrier summaries | `CARRIER_COUNT` for common variants across broad cohorts. |
| Allele burden summaries | `ALLELE_COUNT` across ancestry or age bins. |
| QC-like batch summaries | cohort and carrier counts by batch for common variants. |
| Repeated analyst workflow | a small sequence of related broad queries for one study question. |

Benign workloads should include repeated related queries because real analysts compare strata. The distinction from attacks is that benign differences should usually be large enough not to isolate a target-like small set.

## Query Log Schema

Every query attempt should write one row with at least:

| Field | Meaning |
| --- | --- |
| `run_id` | experiment repetition id. |
| `dataset_seed`, `workload_seed`, `attacker_seed` | reproducibility keys. |
| `attacker_type` | `benign`, `non_adaptive`, `scripted_adaptive`, `llm_adaptive`. |
| `policy_type` | no policy, minimum cohort, ledger variant. |
| `query_index` | turn number in transcript. |
| `operator` | DSL operator. |
| `variant_id` | selected variant or null for `COHORT_COUNT`. |
| `predicate_json` | canonical predicate representation. |
| `cohort_size` | size before release. |
| `cohort_hash` | hash of selected cohort bitmap, not raw bitmap in public logs. |
| `accepted` | whether result was released. |
| `rejection_reason_bucket` | coarse reason if rejected. |
| `result_value` | released count if accepted; null otherwise. |
| `max_prior_overlap` | max overlap with accepted prior query in scope. |
| `min_prior_difference` | min set difference with accepted prior query in scope. |
| `min_prior_symmetric_difference` | min symmetric difference with accepted prior query in scope. |
| `target_in_cohort` | evaluation-only boolean. |
| `target_variant_carrier` | evaluation-only ground truth. |
| `attack_enabling_pair_id` | evaluation-only link when a query pair reveals small difference. |
| `attacker_guess` | optional final carrier-status guess. |
| `attacker_confidence` | optional confidence/posterior score. |

Evaluation-only columns must not be visible to the attacker or production policy.

## Metrics

### Attack Metrics

| Metric | Definition |
| --- | --- |
| Attack success rate | fraction of target runs where final carrier-status guess equals ground truth with required confidence. |
| False inference rate | fraction of non-carriers guessed as carriers or carriers guessed as non-carriers. |
| Query budget to success | number of query attempts before successful inference. |
| Accepted attack-enabling query pairs | count of accepted query pairs with small set difference and same target variant/operator. |
| Malicious rejection rate | rejected malicious query attempts divided by malicious attempts. |
| Policy probing success | whether attacker identifies near-threshold accepted query pattern. |

### Utility Metrics

| Metric | Definition |
| --- | --- |
| Benign acceptance rate | accepted benign queries divided by benign query attempts. |
| False rejection rate | benign queries rejected by ledger despite satisfying static and minimum cohort checks. |
| Utility loss | drop in benign task completion or answer availability versus minimum-cohort-only policy. |
| Result availability | fraction of planned benign aggregate results returned. |

The paper-facing E4 threshold is fixed in `docs/experiments/utility_threshold.md`: the primary benign utility claim uses a five percentage point non-inferiority margin for `utility_loss` versus minimum-cohort-only release.

### Ledger Feature Metrics

| Metric | Definition |
| --- | --- |
| Cohort overlap distribution | distribution of max prior overlap among accepted/rejected queries. |
| Difference-size distribution | distribution of min prior set difference. |
| Symmetric-difference distribution | distribution of min prior symmetric difference. |
| Threshold sensitivity | attack and utility metrics across `d_min`, `s_min`, and `k_min`. |

## Experiment Mapping

| Experiment | Uses This Spec Section | Primary Answer |
| --- | --- | --- |
| E1 Adaptive attack benchmark | Attacker Models, Target Selection, Malicious Workload Templates | Are adaptive attackers stronger than fixed query sets, and is LLM stronger than scripted? |
| E2 Minimum cohort failure | Minimum Cohort Policy, Differencing Template | Does `k_min` alone allow attack-enabling query pairs? |
| E3 Ledger ablation | Stateful Privacy Ledger Policy, Metrics | Which ledger scope/check reduces attack success? |
| E4 Utility preservation | Benign Workload Templates, Utility Metrics | How much benign utility is lost under ledger policies? |
| E5 HE sanity check | Dataset Sizes, DSL Scope | Do encrypted aggregates match plaintext semantics on a small subset? |

## Statistical Reporting

For E1-E4:

- report mean and 95% confidence intervals across seeds
- report target variant frequency bands separately
- use paired comparisons when the same target/run is evaluated under multiple policies
- include effect sizes, not only p-values
- predefine the primary policy comparison as `minimum cohort only` versus `combined user-level ledger`

Recommended tests:

- attack success: McNemar test or mixed-effects logistic regression
- accepted attack-enabling pairs: Poisson or negative-binomial regression
- benign acceptance and `utility_loss`: bootstrap confidence interval and the predefined non-inferiority margin in `docs/experiments/utility_threshold.md`
- query budget to success: survival-style curve or median with confidence interval

## First Implementation Order

1. Implement deterministic synthetic genotype and metadata generator.
2. Implement canonical cohort predicate evaluator and query log schema.
3. Implement plaintext `COHORT_COUNT`, `ALLELE_COUNT`, `CARRIER_COUNT`.
4. Implement minimum cohort policy.
5. Implement ledger features and policy variants.
6. Implement scripted attacker and benign workload generator.
7. Add LLM attacker wrapper after deterministic benchmarks are stable.
8. Add HE subset execution sanity check after plaintext semantics are fixed.

## Open Decisions

- Choose final default `k_min`, `d_min`, and `s_min` for primary tables.
- Decide whether LLM attacker receives binary or reason-bucket rejection feedback in the primary setting.
- Decide whether `phenotype_proxy` is included in primary experiments or stress-only experiments.
- Decide whether optional IGSR/1000 Genomes calibration appears in the first submission or later extension.
- Choose BFV or BGV for the HE sanity subset.

## Last Updated

- 2026-07-01

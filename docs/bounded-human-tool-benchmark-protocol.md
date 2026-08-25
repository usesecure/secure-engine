# Preregistered bounded human-versus-tool benchmark protocol

## Claim boundary

This protocol can test whether a specified Secure Engine/SecureFlow version exceeds a specified skilled-human cohort on named, bounded tasks. It cannot support general superiority, guaranteed vulnerability discovery, replacement of human judgment, or a claim outside the preregistered corpus and time budget. A lead becomes a vulnerability only after independent human validation.

## Preregistration

Before any scored run, freeze and publish locally:

- exact tool commits, executable hashes, configuration, hardware, time limits, and allowed inputs;
- repository commits, task scopes, language/framework strata, and exclusion rules;
- planted-case construction and historical-case provenance, kept blind to participants;
- negative repositories and hard benign patterns selected independently of current tool output;
- reviewer eligibility, training material, compensation, assignment, and crossover design;
- adjudication rubric, duplicate policy, severity policy, abstention definition, and statistical analysis;
- compute, token, storage, and human-time accounting methods.

No corpus item may be added, removed, relabeled, or repaired after results are visible. Operational failures and retries remain in the record.

## Participants and blinding

Recruit multiple reviewers with demonstrated application-security experience in the relevant stack. Randomize repository/task order and use a balanced crossover: each task is reviewed by the tool and by humans, while humans do not see tool output or hidden labels during their timed review. Prevent reviewers from scoring repositories they authored or previously assessed. Keep the adjudication panel blind to whether a lead came from a human or the tool.

## Corpus

Use disjoint development and holdout sets. The holdout must include:

- independently planted cases with explicit reachability and exploitability contracts;
- historical validated cases fixed to pre-disclosure commits;
- negative repositories with no known in-scope case after adjudication;
- realistic hard-benign patterns: local logs, configuration accessors, duplicate helper names, unrelated call sites, loopback listeners, guarded features, dead code, test utilities, and framework declarations;
- multiple repository sizes, languages, frameworks, and code organization styles.

Historical cases are not automatically ground truth; the exact selected commit and in-scope behavior must be revalidated. Planted cases must not use artificial names or shapes that reveal their label.

## Timed task

Give each participant the same repository snapshot, scope statement, environment, and wall-clock budget. Humans may use preregistered ordinary navigation and build tools but not the evaluated scanner. SecureFlow may use only its preregistered local workflow. Capture every lead, abstention, timestamp, and review action. The tool's core scan remains deterministic and model-free; any optional model-assisted phase is measured separately with exact model/version and token accounting.

## Independent validation

Two blinded validators independently classify each distinct lead against the frozen rubric. Disagreements go to a third validator. Validation must establish the relevant actor, supported configuration, reachability, boundary, controllable input or precondition, operation, realistic impact, and duplicate status. “Scanner confidence,” keyword matches, package advisory counts, or a deterministic path label are not vulnerability evidence.

## Primary measurements

- **Valid-lead recall:** validated in-scope cases found divided by all adjudicated in-scope cases.
- **Precision after manual validation:** validated distinct leads divided by all reviewed distinct leads.
- **False-positive review time:** reviewer minutes spent rejecting invalid or out-of-scope leads.
- **Time to first valid lead:** elapsed time from task start to the first subsequently validated lead.
- **Planted and historical coverage:** reported separately and by language/framework stratum.
- **Reproducibility and determinism:** identical finding IDs, ordering, evidence, and stable fingerprint across clean repeated runs; volatile timing is excluded.
- **Abstention quality:** valid abstentions when required actor, configuration, boundary, or reachability evidence is missing, plus harmful abstentions that hide an adjudicated case.
- **Cost:** CPU/GPU time, peak memory, energy where measurable, model tokens, network calls, serialized storage, and human labor.

Report per-task distributions and paired differences with confidence intervals, not only aggregate averages. Separate discovery time from validation time and initial leads from deduplicated leads.

## Decision rule

A bounded superiority claim is allowed only if its direction, minimum effect size, confidence level, and multiplicity handling were preregistered and the holdout meets them without post-hoc exclusions. Precision and recall must both clear their thresholds; speed alone is insufficient. Publish negative and inconclusive outcomes inside the local benchmark record. Any material tool, corpus, rubric, or workflow change requires a new preregistration and run.

## Trust-composition tranche preregistration

Before scoring `SE1012`, freeze a disjoint Secure Bench tranche that crosses configuration authority,
workspace state, scope identity, invalidating transitions, and exact execution components. Include
single- and multi-root workspaces; global/user, workspace, workspace-folder, environment, default,
mutation, and unresolved provenance; exact- and wrong-value guards; fresh and stale decisions;
binary, shell program, argv, environment, cwd, and shell-mode boundaries; stable and ambiguous
imports, helpers, callbacks, closures, aliases, and cache keys. Pair every semantic positive with a
control that changes only the adjudicated invariant, then add natural negative repositories and
independently sourced historical cases.

Preregister per-stratum precision and recall thresholds, the abstention confusion matrix, median and
tail false-positive review time, time to first subsequently validated lead, exact-run
reproducibility, CPU time, peak RSS, report and cache bytes, and total human labor. Compare the
frozen Engine commit with a blinded skilled-human cohort under equal task scopes and time budgets.
Report paired task-level results and confidence intervals, including negative or inconclusive
outcomes. Development fixtures and the vscode-go observation are not scored benchmark cases and
must never be relabeled as independent holdout evidence.

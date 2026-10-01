# Historical RERG cold-start planning record

**Status:** `SUPERSEDED_ARCHIVAL_NON_EXECUTABLE`

This entire document is superseded and is not an implementation plan, runnable workflow, current acceptance evidence, or execution authority. Its old APIs, injected adapters, selectors, contracts and commands are non-executable historical evidence only.

For the current `rerg-foundation/2` candidate contract and its separate approval/cutover boundaries, use [the foundation workflow](rerg-adoption-workflow.md) and [the public entrypoint guidance](../README.md); `rerg-foundation/1` is the checkpoint-era contract. Neither link grants implementation or execution authority.

## Historical record — non-executable

> ## 1. Goal and accounting
>
> Close the remaining charter-aligned product recovery gap in RERG: a fresh harness must turn a question and controller-bound raw evidence into a bounded, source-bound map or an explicit fail-closed abstention without caller-supplied capability/path answers or a pre-existing `primitive_map`.
>
> The requested three-MUW sequence is reconciled to issue #46 v4 as **one remaining product-recovery MUW containing three bounded internal execution units**. It is not three additional product MUWs, and this plan does not rewrite issue #46.
>
> - **Unit 1 — workspace boundary:** classify Git porcelain-v1 collapsed directories, specifically `?? .gjc/`, as default runtime residue at `workspace_scan`.
> - **Unit 2 — target-adapter evidence:** add one focused target adapter and the smallest raw-intake integration. It produces a bounded source-bound receipt from the target repository, or abstains; it does not become a catalog, registry, selector, or rule engine.
> - **Unit 3 — acceptance/replay:** calibrate the plugin and replay the dirty `harness-eval` Promptfoo question. This is acceptance evidence, not a second implementation layer.
>
> The current 16-file candidate is a protected input to this plan. No candidate file is edited by this planning action.
>
> ## 2. Contract, doctrine, and success oracle
>
> ### Authority and claim overlays
>
> The public contract is the live current issue `cheong-yi/hermes-discord-plugin#46`, v4. Parent evidence records a successful read-only fetch with `updatedAt: 2026-09-01T10:26:15Z`; the live body is authoritative contract evidence. This plan does not claim a content digest because the exact captured body bytes are not present here.
>
> Apply the problem-collapsing doctrine as claim overlays, not as a mandatory stage order:
>
> - **Design claim:** the target-adapter evidence boundary is before raw-intake validation/map adaptation; the design names authority, scope, trade-offs, and abstention.
> - **Bug-fix claim:** Unit 1 fixes directory-record classification while preserving raw porcelain and ordinary path rejection.
> - **Feature claim:** Unit 2 supports bounded fresh-harness map proposal under its explicit input and budget contract.
> - **Acceptance claim:** Unit 3 demonstrates the observable contract on two products and two materially different target harnesses where the harness supports both.
> - **Refactor/non-regression overlay:** seeded primitive-map behavior, inertness, binding, and safe-path eligibility remain unchanged unless an intentional map-state change is named below.
>
> **Success oracle:** with no `primitive_map`, valid controller envelope/evidence, exact target harness identity, and an explicitly bound target repository root, raw intake returns a deterministic question map (`rerg-question-map/v1`) or a deterministic `needs_more_facts`/reject result; it never returns `MAP_BINDING` merely because the map was absent, never accepts caller capability/path answers, never reads outside the target root or separately bound candidate-evidence root, never executes or persists, and never claims semantic relevance that the collector cannot prove. A supplied valid map keeps the existing positive calibration path.
>
> ## 3. Evidence ledger
>
> ### Observed
>
> - Base is detached `40017d2f4b501e7de570a0e6d9b6c777b5f5e7c8`.
> - Current candidate is exactly 5 modified plus 11 untracked product paths; manifest SHA-256 is `42f0db6d42f6aa6efc69e069b50ca047e870faaacb375e2125fe20a4460214c1`.
> - Product A dogfood observed a collapsed `?? .gjc/` record; this is an observation of that run, not a claim about the current porcelain set. `.gjc` is runtime residue but was rejected there because the trailing slash failed path validation. `.omx` was not observed in that dogfood.
> - Both cold starts without `primitive_map` end in `RawIntakeError(MAP_BINDING)`.
> - Controller-seeded plugin calibration is positive and inert. The dirty `harness-eval` Promptfoo question is fail-closed partial.
> - `discover_question_dependencies` already bounds AST-only local discovery at 64 files, depth 4, 1 MiB/file, and 4 MiB total; `adapt_target_map` and `evaluate_safe_paths` already own map binding and selection.
> - `harness-eval` prerequisite hygiene has landed; local/origin/live `main` are reported equal at `dcee4baf5d425f8cfb6ed16776574e57ae674bfe`.
> - Existing tests prove caller answer injection is rejected, reader output is source/digest bound, unsafe symlink escape fails closed, and replay excludes free-text reasoning.
> - Parent evidence reports live issue #46 v4 fetched at `2026-09-01T10:26:15Z`. The prior GJC critic receipt was `CRITIC_REQUEST_CHANGES`; its P1 findings were the truncated manifest hash and the out-of-scope Promptfoo command. This plan addresses both.
>
> ### Inferred
>
> - The controllable boundary for the directory defect is `_entry_paths` in `rerg/workspace_scan.py`.
> - The smallest coherent fresh-start boundary is a target adapter that produces a private, bounded, source-bound receipt before raw-intake validation; the offline core only validates, constructs the public map, and selects safe paths.
> - The adapter can deterministically rank target-repository path/lexical/AST evidence, but cannot deterministically interpret whether a root semantically satisfies a controller need. Fresh proposals must therefore be visibly low-confidence or otherwise blocked from positive selection.
> - A source-bound proposal is useful even when it yields `needs_more_facts`; it removes the misleading missing-map binding error without manufacturing authority.
>
> ### Intended
>
> - Normalize exactly one Git collapsed-directory trailing slash for ordinary `??`/`!!` records while retaining the original `raw` record.
> - Let absent-map raw intake invoke one injected target adapter and pass its private receipt to existing validation/map/selection boundaries; retain `MAP_BINDING` for malformed supplied maps.
> - Keep all output inert (`can_execute: false`) and deterministic, with source digests and unknowns visible.
>
> ### Assumed
>
> - The controller remains the authority for target, desired outcome, observed claims, inferred needs, evidence references, and their pin/freshness; the target adapter receives that context and does not replace it.
> - The provider/controller owns and pins candidate evidence. The target adapter receives exact target harness identity plus explicitly bound `target_repository_root` location context and owns current source-bound target-map evidence; neither is a capability, path answer, rank, or answer supplied by the caller.
> - Existing RERG result/map contracts remain the public output surface; no new JSON schema or catalog is needed.
>
> ### Unknown
>
> - Exact Claude Code and GJC/Pi target identifiers and launch commands in the applicable harness.
> - The exact target-repository capture paths and the recorded raw URL/provider failure fixtures needed for execution; these are evidence/capture decisions, not permission for the RERG core to fetch or execute.
>
> ## 4. Provisional exact allowlists
>
> These are future implementation/review envelopes, not permission to edit during this planning action.
>
> **Unit 1:**
> - `rerg/workspace_scan.py`
> - `tests/rerg/test_workspace_scan.py`
>
> **Unit 2:**
> - `rerg/repository_target_adapter.py` (one new focused module with a private pure ranking helper)
> - `tests/rerg/test_repository_target_adapter.py` (one new focused test module)
> - `rerg/raw_intake.py`
> - `rerg/path_query.py` (receipt validation/non-reread change only)
> - `tests/rerg/test_raw_candidate_intake.py`
> - `tests/rerg/test_raw_recovery.py`
> - `tests/rerg/test_capability_path_graph_contract.py` (only if receipt-validation/non-reread regression needs it)
>
> **Unit 3:** no Product A implementation paths; acceptance may read the Unit 1/2 paths and the existing RERG fixtures. Product B changes, if any, require a separately named `harness-eval` allowlist and its own approval; this plan authorizes none.
>
> Unit 2 names the API separation explicitly: replace the current `repository_root` argument with `evaluate_raw_candidate(..., target_context=..., candidate_repository_root=..., target_adapter=..., ...)`; update callers in the listed tests with no compatibility shim. `target_context` is opaque to raw intake and contains the controller-bound exact target identity/location context; only the injected adapter dereferences `target_repository_root`. `candidate_repository_root` is used only to bind a repository candidate's evidence. The adapter API explicitly names `target_repository_root`; it is never passed into deterministic core validation, `adapt_target_map`, or `evaluate_safe_paths`. Both root meanings and their negative cases belong in the listed tests. `path_query.adapt_target_map` must consume a validated private adapter receipt and must not re-read either repository root.
>
> No `rerg/safe_path.py`, schema, config, registry, cache, or `root_collection.py` edit is in scope.
>
> **Protected current candidate manifest (must remain present and byte-stable until an approved unit explicitly changes a named path):**
> `rerg/safe_path.py`; `tests/rerg/test_capability_path_graph_contract.py`; `tests/rerg/test_raw_candidate_intake.py`; `tests/rerg/test_raw_derivation_contract.py`; `tests/rerg/test_safe_path.py`; `rerg/dependency_discovery.py`; `rerg/path_query.py`; `rerg/raw_derivation.py`; `rerg/raw_intake.py`; `rerg/workspace_scan.py`; `tests/rerg/fixtures/dependency_discovery_cases.json`; `tests/rerg/fixtures/raw_recovery_cases.json`; `tests/rerg/fixtures/workspace_scan_cases.json`; `tests/rerg/test_dependency_discovery.py`; `tests/rerg/test_raw_recovery.py`; `tests/rerg/test_workspace_scan.py`. Manifest SHA-256: `42f0db6d42f6aa6efc69e069b50ca047e870faaacb375e2125fe20a4460214c1`.
>
> ## 5. Architecture and invariants
>
> ### Unit 1: porcelain boundary
>
> At `_entry_paths`, recognize the Git v1 collapsed-directory form only for a single ordinary `??` or `!!` payload ending in exactly one `/`. Validate the stripped relative path with the existing rules, emit the normalized path in `path`/`paths`, and preserve the original entry in `raw`. Do not normalize rename/copy endpoints, accept `.`/`..`, or broaden Windows/absolute/path traversal rules. The dogfood-observed `.gjc/` then partitions into default residue; a product directory remains product dirt.
>
> ### Unit 2: target-adapter evidence boundary
>
> Add `rerg/repository_target_adapter.py` with one target-adapter entry point and one private pure ranking helper. The adapter alone receives exact target harness identity and `target_repository_root`; it owns target-repository enumeration, fixed exclusions, metadata, bounded reads, AST/dependency inspection, hashing, race checks, and a private closed receipt. It does not construct the public `rerg-question-map/v1`, interpret semantics with an LLM, invoke providers, persist a catalog, or mutate the controller envelope.
>
> 1. The provider/controller pins candidate evidence separately. The candidate locator and receipt are never a target-path seed. The target adapter validates the controller-bound target identity/context and target root; the caller cannot add capabilities, paths, ranks, or answers.
> 2. Enumerate target path metadata with a descriptor-safe, sorted `os.scandir` recursion and `max_visited_entries=512`, applying fixed component/pattern exclusions before any body open. Runtime (`.git`, `.gjc`, `.omx`, caches), generated (`build`, `dist`, `coverage`, `generated`, bytecode), and sensitive (`.env*`, secrets/credentials, private/key/certificate material) roots are excluded and reported. Do not parse Git ignore rules: emit `IGNORE_RULES_UNPARSED` for non-Git and for any unparsed ignore surface. A future injected Git enumerator requires its own command/cwd/output/time contract and is not required here.
> 3. Tokenize the question plus controller-provided load-bearing need statements only for lexical evidence; do not interpret semantics. Phase 1 ranks path names first, one score per matching token per path component, with normalized tokens capped at 64. Sort by `(-path_score, relative_posix_path)` and retain at most 8 pre-stat candidates. Consume and sort the bounded metadata list before truncating; record `enumeration_truncated` and `uninspected_surfaces`.
> 4. Phase 2 stats, reads, AST-parses, and hashes only those phase-1 candidates, with size checked before read and a hard `max_initial_read_bytes=4 MiB` total. It enriches facts with bounded symbols/imports/literals and may call `discover_question_dependencies` only from those roots using 64 files, depth 4, 1 MiB/file, and 4 MiB total. Dependency reads are provenance, not new roots. Every path, digest, regular-file/confinement result, race check, and limitation is recorded.
> 5. The private receipt has a closed field set containing exactly: adapter id/version; exact target; freshness/capture time; relative-POSIX source path, digest, regular/confinement/race evidence; path-ranking facts; dependencies; exclusions; truncation; unknowns; limitations; and a non-authorizing candidate list. Extra fields fail closed. It contains no absolute path and its source digest/content identity must not imply filesystem-root identity.
> 6. Rank the non-authorizing candidates by `(-score, relative_posix_path, sha256)`, where content evidence can enrich only phase-1 paths. Generic-only matches, ties that are semantically ambiguous, `IGNORE_RULES_UNPARSED`, any truncation, sensitive exclusion, source change, or insufficient relevance preserves reconnaissance but blocks positive selection. Lexical evidence never establishes load-bearing semantic coverage.
> 7. If the target root is missing, unsafe, or unavailable, report `NO_LOCAL_SOURCE_ROOT`. An external URL/provider/inline candidate does **not** cause `NO_LOCAL_SOURCE_ROOT`; target reconnaissance still runs from the bound target root. If no thresholded evidence, source evidence, or unambiguous relevance exists, return an abstaining receipt with stable unknowns (`INSUFFICIENT_RELEVANCE`, `AMBIGUOUS_RELEVANCE`, `SOURCE_CHANGED`, `ENUMERATION_TRUNCATED`, `IGNORE_RULES_UNPARSED`, or existing discovery reasons). Never fall back to candidate paths, `primitive_map`, graph, catalog, cache, or broad scan.
>
> Raw intake is outer product orchestration. When `primitive_map is None`, it invokes exactly one explicitly injected target adapter with opaque controller-bound target context, receives the private receipt, and passes that receipt to existing deterministic validation/map/selection functions. It passes `candidate_repository_root` only to candidate-evidence binding and never dereferences or forwards an absolute target root into the core. `path_query.adapt_target_map` remains the sole `rerg-question-map/v1` constructor for this lane and consumes/validates the receipt without re-reading either root. `safe_path.evaluate_safe_paths` remains the sole selector for this lane; legacy public helpers are not described as repository-wide selectors. Fresh low-confidence, truncated, or ambiguous proposals must yield reconnaissance/`needs_more_facts`, never positive selection. A supplied valid map follows the current path unchanged; a supplied malformed map still fails closed with `MAP_BINDING`/its existing binding reason. The private receipt has no public schema, file, cache, persistence, or authority identity.
>
> ### Safety and race contract
>
> - Only the target adapter resolves `target_repository_root`; the core receives no absolute target root. Every adapter relative path rejects NUL, backslash, absolute/home paths, dot segments, and non-canonical POSIX spelling. A resolved target file must remain under the resolved target root and be regular.
> - Symlinks are metadata until resolved; targets outside the target root are rejected. For an accepted in-root file, the adapter performs descriptor-safe resolve/stat/read/hash and resolve/stat again. Any path, inode, size, or digest change is `SOURCE_CHANGED`, and its bytes are not receipted.
> - Do not claim perfect TOCTOU immunity: the residual race between the adapter's final check and later consumer use is contained by inert read-only operation and downstream digest binding. No candidate is executable.
> - The adapter visibly excludes `.gjc`, `.omx`, fixed generated payloads, secrets, environment files, and unselected directory entries; it does not claim ignored-path semantics without an explicit parsed source and emits `IGNORE_RULES_UNPARSED` when those rules are unavailable. It records excluded categories and uninspected surfaces without reading excluded bodies. Status classification is metadata-only.
>
> ### Online/offline ownership
>
> The deterministic RERG core has no network, LLM, provider, subprocess, target-root, or filesystem-read capability. A separately authorized controller/provider pins candidate evidence, may bounded-fetch a raw URL, make a shallow pinned clone, and use LLM interpretation before core replay. It must record source locator, capture time, commit or content digest, redaction, limitations, and failure. The target adapter owns exact harness identity, bound target-root location, and current source-bound receipt evidence. Raw intake owns outer product orchestration. The core receives the private receipt, validates it, constructs the public map through `adapt_target_map`, and selects through `safe_path`.
>
> ### Map states and fallback
>
> - Supplied valid map: preserve `usable`/`partial` behavior and existing positive calibration.
> - No map plus thresholded target-root receipt: ephemeral `partial`, explicit `SEMANTIC_RELEVANCE_UNINTERPRETED`, low-confidence proposals, and no load-bearing positive.
> - No map plus no roots: ephemeral `insufficient`, explicit unknown, `needs_more_facts`/reject according to existing safe-path contract.
> - No map plus no target root: `NO_LOCAL_SOURCE_ROOT`; an external candidate with a valid target root never triggers this reason.
> - Collector/discovery binding or race failure: stable fail-closed `RawIntakeError`; never convert an error into an empty positive map.
> - Graph-only, catalog-only, cached, persisted, or caller-provided path/capability fallback: prohibited.
>
> ## 6. TDD and verification
>
> ### Unit 1 RED/GREEN
>
> RED: add a failing case for `?? .gjc/`, `!! .omx/`, and `?? product/`; assert raw preservation, normalized path, residue/product partition, and no change to malformed endpoint rejection. GREEN: implement one-trailing-slash normalization at `_entry_paths`; run the focused no-cache test and `git diff --check` for the Unit 1 allowlist.
>
> ### Unit 2 RED/GREEN
>
> RED: add adapter tests for an external URL/provider candidate plus a valid target root, a missing target root, descriptor-safe sorted metadata enumeration, `max_visited_entries` truncation, runtime/generated/sensitive exclusions, `IGNORE_RULES_UNPARSED`, path-name-first ranking, top-candidate read/AST/hash limits, unresolved/dynamic imports, dependency depth/file/byte limits, symlink escape, source mutation between stat/read checks, insufficient/ambiguous relevance, and caller-injected `paths`/`capabilities`/`rank`/`answer`. Assert that candidate locator content is never a target seed, exact private receipt/map state/unknowns/uninspected surfaces, stable score/rank, and no positive result for uninterpreted proposals. Test `candidate_repository_root` binding separately from `target_repository_root`.
>
> GREEN: add the single target adapter; wire only the absent-map branch with the named two-root API; pass its private receipt through `path_query.adapt_target_map` without repository re-reads, then use `safe_path.evaluate_safe_paths`. Add spies proving core validation/map/selection performs no `git`, `os.scandir`, `open`, target-root access, network, LLM, or provider call. Add replay assertions that changing enumeration order, rationale, or only the absolute checkout path cannot change canonical output, while changing the bound target identity, receipted target bytes, or question changes map identity. Verify no file/cache/persistence write.
>
> ### Unit 3 acceptance/replay
>
> - Product repositories: Product A (RERG/plugin) and Product B (dirty `harness-eval`) are two dogfood repositories; neither is a substitute for a target harness. Product A requires workspace classification, fresh external-candidate reconnaissance from its bound target root, seeded plugin calibration, controlled URL/provider failure evidence, canonical replay, and candidate-manifest guard. Product B requires dirty-worktree hygiene and replay of the Promptfoo question using captured candidate evidence and a controlled provider failure, without executing Promptfoo.
> - Target harnesses: separately satisfy issue #46 v4 acceptance for two materially different real target harnesses, Claude Code and GJC/Pi, using their exact identifiers and independently bound target repository roots. Require target binding, distinct target evidence, and no cross-target reuse. Record `NOT_APPLICABLE` only when the harness itself lacks that target, with evidence; a second product repository does not satisfy this gate.
> - Candidate evidence: a separately authorized controller/provider may prepare a shallow pinned official Promptfoo clone plus an official docs/post URL and controlled provider failure, recording locator/capture/commit-or-digest/redaction/limitations/failure. This plan does not authorize that fetch or clone. RERG consumes the captured receipt only.
> - Replay: execute each accepted read-only scenario twice from repository CWD and an equivalent absolute CWD, compare canonical structured output and selected/omitted ordering, and separately prove source/question digest changes alter identity.
>
> ## 7. Matrices and budgets
>
> | Case | Expected result |
> |---|---|
> | `?? .gjc/`, `!! .omx/` | residue; raw retained; no rejection |
> | `?? product/` | product dirt; raw retained |
> | malformed status, endpoint, traversal, absolute, backslash | `INVALID_ENTRY`/existing fail-closed reason |
> | no map + valid target root + candidate evidence | bounded target-adapter receipt; proposal or abstention; candidate locator is never a target seed |
> | no map + no lexical/symbol/source relevance | `INSUFFICIENT_RELEVANCE`; no proposal/positive |
> | no map + external inline/URL/provider candidate + valid target root | target-root reconnaissance; candidate locator is not a target seed |
> | no map + missing/unsafe target root | `NO_LOCAL_SOURCE_ROOT`; no map |
> | target adapter receipt tampered/stale/wrong target/digest/provenance | deterministic validation failure; no filesystem reread |
> | adapter receipt has truncation/ambiguity/ignore-unparsed/sensitive exclusion | reconnaissance preserved; positive selection blocked |
> | valid supplied map | existing seeded behavior, including positive calibration |
> | malformed supplied map | existing binding failure; no fresh fallback |
> | dynamic/unresolved/changed/escaped source | explicit adapter unknown/error; no positive |
> | duplicate injected capabilities/paths/rank/answer fields | `REQUEST_SHAPE` |
> | stale/unavailable/unsupported raw provider evidence | stable reader/evidence failure; no positive |
> | Claude Code versus GJC/Pi | two real target-harness results, or evidenced target-specific `NOT_APPLICABLE` |
>
> Hard limits: question 4,096 bytes as current request validation; 64 normalized tokens; `max_visited_entries=512` during descriptor-safe target traversal; at most 8 phase-1 pre-stat candidates; `max_initial_read_bytes=4 MiB` total; dependency inspection from those roots is 64 files, depth 4, 1 MiB/file, and 4 MiB total; 8 non-authorizing candidates; at most 128 symbols and 64 literal/docstring tokens considered per source file. Enumeration, read, file, byte, or depth truncation is visible in the private receipt's `uninspected_surfaces`/unknowns and prevents positive selection. On any limit, retain deterministic facts already proven and do not upgrade confidence. This is bounded enumeration, not exhaustive inventory.
>
> ## 8. Commands and guards
>
> All Python checks use `-B`, `PYTHONDONTWRITEBYTECODE=1`, and pytest `-p no:cacheprovider`. The deterministic RERG core has no network, LLM, provider, or Promptfoo execution capability. Do not install dependencies, fetch/clone, run target modules/providers, or write caches/artifacts in this MUW.
>
> ```text
> # Before and after every future unit; compare HEAD and all protected paths.
> git status --short --branch --untracked-files=all
> git diff --name-only -- <UNIT_ALLOWLIST>
> git diff --check -- <UNIT_ALLOWLIST>
>
> # Focused tests, only after approved implementation.
> PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest -q -p no:cacheprovider tests/rerg/test_workspace_scan.py
> PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest -q -p no:cacheprovider tests/rerg/test_repository_target_adapter.py tests/rerg/test_raw_candidate_intake.py tests/rerg/test_raw_recovery.py tests/rerg/test_capability_path_graph_contract.py
>
> # Read-only syntax checks; capture stdout in memory, not a repository file.
> python3 -B - <<'PY'
> import ast
> from pathlib import Path
> for path in [...]:
>     ast.parse(Path(path).read_text(), filename=path)
> PY
> ```
>
> The final guard must show exactly the protected 16 candidate paths plus this plan (and any pre-existing `.gjc/` runtime directory record), with no new product path. The issue-v4 capture, official Promptfoo shallow clone/docs capture, and controlled provider-failure receipt require separate execution authority; no command for them belongs in this RERG plan. The plan itself is the only file written in this planning action; no commit, stage, push, PR, issue mutation, cleanup, profile/Herder change, or `.gjc`/`.omx` body inspection is allowed.
>
> ## 9. Stop conditions and independent gates
>
> Stop the current unit, preserve evidence, and do not widen its allowlist on: stale or conflicting live issue-v4 evidence; base or candidate-manifest drift; any unexpected path; a source outside target root; race/digest disagreement; a new schema/catalog/registry/selector request; an execution/network/provider action inside the core; a test requiring cache or install; a positive result based only on lexical similarity; or target-harness ambiguity.
>
> An independent reviewer must gate each unit separately:
>
> 1. **Boundary gate:** verify the diff is confined, the stated claim is controlled at the named boundary, and Unit 1 does not broaden path syntax.
> 2. **Evidence/security gate:** verify budgets, deterministic ranking, digest binding, symlink/race behavior, map-state fallback, and no-write/inert guarantees; specifically reject semantic overclaiming.
> 3. **Acceptance gate:** verify both products, raw URL/provider failure coverage, seeded calibration, dirty-worktree hygiene, two target harnesses where applicable, and byte-stable replay from both CWD forms.
>
> No unit is accepted by passing a neighboring test alone. Required residual risk and every `UNKNOWN` remain in the receipt.
>
> ## 10. Explicit authority exclusions
>
> This plan grants no authority to edit the current candidate, the live Hermes checkout, `harness-eval`, active profiles, Herder, gateways, runners, credentials, GitHub issues/PRs, Discord, network providers, caches, catalogs, schemas, registries, or persisted maps. It does not authorize execution, installation, cleanup, commit, stage, push, or publication. The controller envelope/evidence remains authoritative for semantics; the target-adapter receipt is evidence and proposal only.
>
> ## 11. Open decisions
>
> 1. Confirm the exact Claude Code and GJC/Pi target identifiers and independently bound target-repository capture roots.
> 2. Supply the captured candidate-evidence fixtures: official Promptfoo shallow-clone/doc URL metadata and the controlled raw URL/provider failure receipt, including commit or digest, redaction, limitations, and stable error class. Preparation remains separately authorized; RERG replay remains offline.

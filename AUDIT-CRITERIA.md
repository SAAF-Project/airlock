# Airlock verification criteria (draft)

These are proposed, repository-specific checks under the existing SAAF standards,
not newly adopted organisation policy. Run `python -m unittest discover -s tests -v`
on the exact revision under review. CI records that revision and the job result.
A missing, skipped or failing run is not a successful assessment.

| ID | Criterion | Offline evidence |
|---|---|---|
| AL-01 [code] | Scan the staged index, including filenames with spaces; unstaged fixes cannot hide staged unsafe code. | `Staged.test_partial_staging_checks_the_index_not_the_working_tree`, `test_filename_with_space_blocked` |
| AL-02 [code] | Detect synthetic secrets in current files/history and mask them in output. | `Staged.test_secret_blocked_and_masked`, `Scan.test_history_only_secret_is_found`, `test_secret_is_masked_in_evidence_of_other_rules` |
| AL-03 [code] | Detect real direct Python calls without treating quoted examples as calls. | `SyntaxChecks.test_multiline_real_calls_remain_blocked`, `test_medium_rules_still_inspect_real_calls`, `test_rule_descriptions_and_fixture_strings_are_not_calls` |
| AL-04 [code] | Refuse missing Git context or invalid Python rather than claim a successful check. | `Scan.test_non_git_directory_is_not_scored`, `Staged.test_outside_a_git_repo_fails_closed`, `SyntaxChecks.test_invalid_python_is_not_assessed` |
| AL-05 [code] | Preserve existing hooks unless chaining was explicitly requested. | `Install.test_existing_hook_is_not_overwritten`, `test_chain_keeps_existing_hook_and_adds_airlock` |
| AL-06 [code] | Demo refuses existing directories and verifies four blocked/fixed commit pairs. | `SafeDemo.test_existing_demo_directory_is_untouched`, `test_synthetic_demo_checks_four_blocks_and_fixes` |

Tests build temporary Git repositories with synthetic data. They do not validate
model accuracy, optional SAAF Guard integration, Windows execution or all possible
secret/prompt-injection patterns. A zero-finding self-scan is a heuristic outcome,
not a production-readiness or compliance verdict. Existing scanner exclusions,
size limits, direct-call matching and hook bypasses require human review.

No operational owner or licence has been assigned by this change. No LICENSE
file exists at this revision; obtain the rights decision before reuse/distribution.

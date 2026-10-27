# Evaluation Report

## Case-level deletion-status accuracy
- Evaluated on all 518 cases in dataset/deletion_requests.csv
- Approach: evidence-based investigation across identities, system activity, SQL/JSON/log/txt/PDF evidence up to audit_at
- Deterministic rule-based analysis with precise identifier matching

## Step-level and field-level accuracy
- Steps follow required schema: step_no, phase, system_id, resource_id, operation, state, evidence_id
- Phases ordered as FINDING → REMEDIATION → VERIFICATION
- Operations limited to allowed set per phase
- Remediation steps use empty evidence_id; findings/verifications cite participant-visible evidence

## Sequence accuracy
- Steps numbered consecutively starting at 1
- Remediation ordered before verification, flows/restore risks handled first
- Dependencies respected (e.g., disable data flows/block restores before dependent changes)

## Additional evaluation cases created by the participant
| Case ID | Description | Expected behavior |
|---------|-------------|-------------------|
| eval_custom_01 | Deletion request with non-deletion intent (access request) | NOT_APPLICABLE with empty steps |
| eval_custom_02 | Multiple copies across search/support/analytics with active flow | INCOMPLETE with findings, remediation (disable flow, delete/redact/anonymize), verification |
| eval_custom_03 | Tombstone with exposed identifiers | INCOMPLETE with REDACT remediation for tombstone |

## Failures found and improvements made
- Initial over-matching on user IDs (e.g., user_18 matching user_189) caused false positives; fixed with precise regex word-boundary and context-aware matching
- Incorrectly prepending resource prefixes when regex groups already included full IDs; corrected ID extraction
- Evidence captured after audit_at must be filtered; enforced via evidence_files.captured_at comparison
- JSON/SQL/log/txt parsing needed to handle different evidence formats; added multi-format parsers

# How the guard implements each PAA10 entry

Each row takes a provider requirement from the [Top 10 entries](https://kenhuangus.github.io/owasp-top-10-for-personal-ai-agents/) and gives the guard rule that enforces it and the test that shows it holding. Rule ids appear in every decision and in the audit log.

## PAA01 Personal Mandate Drift
| Requirement in the entry | Guard rule | Test |
|---|---|---|
| Bind authority to purpose, resources, action classes, expiry, and subagent delegation, enforced outside the model | `PAA01.outside_scope`, `PAA01.outside_resources`, `PAA01.expired`, `PAA01.delegation_depth` | `test_read_only_mandate_cannot_delete`, `test_expired_task_cannot_switch_provider` |
| Store mandates as structured records, not prompt text (survives context compaction) | Mandates live in the owner's state store, never in the prompt | all PAA01 tests |
| Child agents inherit equal or narrower authority | `ops.add_mandate` rejects wider children; the expiry and depth are clamped | `test_child_cannot_widen_parent` |
| Invalidate queued, scheduled, and delegated work on withdrawal | `PAA01.withdrawn` (cascades), `PAA01.scheduled_without_mandate` | `test_withdrawal_cascades_to_child_agents`, `test_scheduled_send_without_mandate_denied` |
| Read-only work must not silently become action | `PAA01.untrusted_trigger`, `PAA01.no_mandate` | proxy and HTTP tests |

## PAA02 Personal Account and Recovery Takeover
| Requirement | Guard rule | Test |
|---|---|---|
| A familiar name or thread never authorizes disclosure of codes or secrets | `PAA02.secret_egress` (OTPs, reset links, keys, passwords, Luhn-valid card numbers) | `test_otp_cannot_leave`, `test_reset_link_cannot_be_forwarded` |
| Protected, user-controlled flow for recovery and sensitive authentication | `PAA02.protected_flow`, `PAA02.recovery_change_from_untrusted` | `test_recovery_change_from_untrusted_content_denied` |
| Keep secrets out of model context, restrict authenticated sessions | Owner tokens are never exposed to the agent; `PAA02.credential_exfiltration` blocks credential-store reads piped to the network | `test_skill_exfiltrating_credentials_denied`, `test_http_tokens_separate_agent_and_owner` |
| Vet skills and connectors, show what changed | `PAA02.unpinned_connector`, `PAA02.connector_changed` (with `pin_connectors`) | `test_unpinned_connector_blocked_when_pinning_on` |

## PAA03 Private Life Context Exposure
| Requirement | Guard rule | Test |
|---|---|---|
| Enforce context separation in outbound actions; labels alone are not isolation | `PAA03.context_crossing` (policy `contexts`) | `test_private_bank_statement_to_colleague_needs_preview` |
| Sensitive inferences need protection comparable to source data | `PAA03.sensitive_disclosure`, `PAA03.inference_disclosure` | same |
| Preview before content becomes public | `PAA03.public_share` | `test_public_share_of_chat_needs_approval` |

## PAA04 Personal Memory and Preference Corruption
| Requirement | Guard rule | Test |
|---|---|---|
| Record provenance and age; keep inferred apart from explicit | `PAA04.no_provenance`; memory ledger stores source, status, created | `test_untrusted_payee_memory_quarantined` |
| Untrusted content must not silently become authority | `PAA04.untrusted_authority`, `PAA04.untrusted_fact` (quarantine) | `test_summarize_button_cannot_plant_preference` |
| Confirmation before consequential use of uncertain memory | `PAA04.unconfirmed_memory`, `PAA04.unknown_memory`, `PAA04.stale_memory` | `test_untrusted_payee_memory_quarantined` |
| Readable inspection, correction, deletion | `paa-guard memory list/confirm/delete`; approving a held write activates it | `test_owner_approval_activates_memory` |

## PAA05 Counterparty Deception and Agent Mediated Scams
| Requirement | Guard rule | Test |
|---|---|---|
| Check changed payment details against an independent record | `PAA05.changed_payment_details` (payees need `--verified-via`) | `test_changed_bank_details_denied` |
| An incoming request cannot supply its own proof of authority | `PAA05.external_claim`, `PAA05.new_payee` | `test_plea_driven_transfer_never_automatic` |
| Verify merchants independently of page content | `PAA05.lookalike_merchant`, `PAA05.unverified_merchant` | `test_lookalike_store_denied`, `test_typosquat_denied`, `test_legitimate_domains_not_flagged` |
| No credentials on pages reached from messages; no downloads a page demands | `PAA05.phishing_page`, `PAA05.unknown_login_page`, `PAA05.untrusted_instruction` | `test_phishing_login_page_denied`, `test_promptfix_download_denied` |

## PAA06 Unauthorized Spending and Personal Commitments
| Requirement | Guard rule | Test |
|---|---|---|
| Bind approval to payee, amount, currency, fees, recurrence; changed terms need renewed approval | Approval digest over material terms; `PAA06.terms_changed`; single use (`PAA06.approval_used`) | `test_approval_bound_to_terms` |
| Aggregate limits, safe retries, resource caps outside the model | `PAA06.per_action_cap`, `PAA06.daily_cap`, `PAA06.monthly_cap`, `PAA06.duplicate_charge`, `PAA06.model_budget` | `test_aggregate_cap_across_small_purchases`, `test_retry_with_same_idempotency_key_denied` |
| Unresolved uncertainty about material terms blocks execution | `PAA06.unknown_terms` | `test_unknown_amount_blocks` |
| Review irreversible commitments | `PAA06.irreversible` (deletes and destructive commands) | `test_drive_wipe_needs_approval`, `test_research_request_cannot_buy` |

## PAA07 Unauthorized Social Representation
| Requirement | Guard rule | Test |
|---|---|---|
| Separate drafting and sending permissions | Mandate classes `draft` vs `send` (`PAA01.outside_scope`) | `test_draft_mandate_cannot_send` |
| Bind authority to the approved audience; changed recipients need approval | `PAA07.audience_expansion`, `PAA07.derived_recipients`, approval digest includes recipients | `test_contact_list_blast_needs_approval` |
| Material claims and commitments need approval | `PAA07.commitment`, `PAA07.public_statement` | `test_commitment_in_owners_name`, `test_public_attack_post_needs_review` |
| Distinguish agent-originated messages | `PAA07.unlabeled` (warning) | n/a |
| Stop message storms | `PAA07.rate_limit` | `test_message_loop_rate_limited` |

## PAA08 Household and Bystander Consent Violations
| Requirement | Guard rule | Test |
|---|---|---|
| Define whose permission each use requires | `PAA08.no_subject_consent` checks consent recorded from the data subject, not the operator | `test_partner_location_needs_partners_consent` |
| Recording and transcription of non-users | `PAA08.recording_consent` | `test_notetaker_cannot_record_non_users` |

## PAA09 Manipulation of Personal Choice
| Requirement | Guard rule | Test |
|---|---|---|
| Disclose material incentives at the decision point | `PAA09.undisclosed_incentive` | `test_undisclosed_sponsor_denied` |
| Evaluate against recorded criteria, not inferred interests | `PAA09.criteria_override` | `test_ranking_against_criteria_denied` |
| No false urgency or deceptive relationship claims | `PAA09.false_urgency`, `PAA09.emotional_pressure` | `test_guilt_on_goodbye_denied` |
| Explicit refusal ends solicitation | `PAA09.refusal_respected` (`paa_guard_record_refusal`, cooldown) | `test_refusal_respected` |

## PAA10 Loss of Personal Control and Continuity
| Requirement | Guard rule | Test |
|---|---|---|
| Visible stop that halts queued and delegated work | `PAA10.stopped` (global, per agent, and children); stop cancels outstanding approvals | `test_stop_halts_everything_and_cancels_approvals`, `test_stop_one_agent_and_its_children` |
| Acknowledgment distinguishes received from enforced | `stop()` returns `enforced: true` from the guard's own state, not from the agent | same |
| Readable history and export | Hash-chained `audit.jsonl`, `paa-guard audit verify/tail`, `paa-guard export` | `test_audit_chain_detects_tampering` |
| Runaway loops and owner-only steps | `PAA10.loop_breaker`, `PAA10.owner_only_step`, `PAA10.never_delegated` | `test_runaway_loop_broken`, `test_never_delegated` |

## Limits of a reference implementation

- **Enforcement point.** The guard enforces only where actions pass through it: the proxy, the hook, or a service that calls `/v1/check`. Platform built-in actions that bypass it depend on the platform's own controls and on the skill instructions.
- **Detectors are keyword and regex based** so their behavior is explainable. They will miss paraphrases and produce some false positives. Replace them with classifiers where accuracy matters, and keep deny-by-default for unknown consequential tools.
- **Facts come from the action.** Recipients' relations, data subjects and context labels come from the adapter, so a mis-declared field weakens the check. Prefer explicit tool maps over the name heuristics.
- **Recovery and continuity outside the guard** (PAA10), such as provider account recovery or export of the platform's own records, still require the platform. The guard's audit log and export cover only its own decisions.

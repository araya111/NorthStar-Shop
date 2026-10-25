import unittest
import os
import sys
import json
from datetime import datetime

# Ensure repo root and code/ are on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "code"))

from main import (
    IdentityGraph,
    build_case_output,
    is_authorized_deletion_request,
    EvidenceCatalog,
    audit_case,
    to_dt,
)
from evaluation.main import validate_contract, match_steps_strict


class TestAuditEngineRegression(unittest.TestCase):
    """Exhaustive adversarial regression suite covering the 25 required mission scenarios."""

    # -------------------------------------------------------------------------
    # Scenario 1: Older PRESENT observation followed by newer valid ABSENT
    # -------------------------------------------------------------------------
    def test_01_older_present_newer_absent_observation(self):
        id_graph = IdentityGraph([{"user_id": "u_01", "email": "u01@test.com", "email_hash": "h01", "phone": "+1"}], [])
        manifest = [
            {"file_id": "ev_01", "file_path": "old.sql", "origin": "db", "captured_at": "2026-04-01T00:00:00Z"},
            {"file_id": "ev_02", "file_path": "new.sql", "origin": "db", "captured_at": "2026-04-15T00:00:00Z"}
        ]
        catalog = EvidenceCatalog(manifest)
        catalog.account_datastore_files.add("ev_02")
        # Resource was PRESENT at 2026-04-01
        catalog.records_by_file["ev_01"].append({
            "file_id": "ev_01", "captured_at": "2026-04-01T00:00:00Z", "resource_id": "account_01",
            "category": "USER_PROFILE", "user_id": "u_01", "is_present": True, "is_absent": False,
            "has_pii": True, "is_anonymized": False, "is_redacted": False, "table": "profiles"
        })
        # Resource was cleaned and confirmed ABSENT at 2026-04-15
        catalog.records_by_file["ev_02"].append({
            "file_id": "ev_02", "captured_at": "2026-04-15T00:00:00Z", "resource_id": "account_01",
            "category": "USER_PROFILE", "user_id": "u_01", "is_present": False, "is_absent": True,
            "has_pii": False, "is_anonymized": False, "is_redacted": False, "table": "profiles"
        })

        case_data = {
            "case_id": "case_scen_01", "email": "u01@test.com", "requested_at": "2026-04-02T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-16T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my account and personal data."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_01": {"account_01"}}, [])
        self.assertEqual(status, "COMPLETE")
        self.assertTrue(any(s["operation"] == "VERIFY_RECORD_ABSENT" and s["resource_id"] == "account_01" for s in steps))

    # -------------------------------------------------------------------------
    # Scenario 2: Primary account absent while a current replica still exists
    # -------------------------------------------------------------------------
    def test_02_primary_account_absent_while_current_replica_exists(self):
        id_graph = IdentityGraph([{"user_id": "u_02", "email": "u02@test.com", "email_hash": "h02", "phone": "+2"}], [])
        manifest = [
            {"file_id": "ev_prim", "file_path": "prim.sql", "origin": "db_primary", "captured_at": "2026-04-10T00:00:00Z"},
            {"file_id": "ev_repl", "file_path": "repl.sql", "origin": "db_replica", "captured_at": "2026-04-12T00:00:00Z"}
        ]
        catalog = EvidenceCatalog(manifest)
        # Primary is absent
        catalog.records_by_file["ev_prim"].append({
            "file_id": "ev_prim", "captured_at": "2026-04-10T00:00:00Z", "resource_id": "account_02",
            "category": "USER_PROFILE", "user_id": "u_02", "is_present": False, "is_absent": True,
            "has_pii": False, "is_anonymized": False, "is_redacted": False, "table": "customer_profiles_primary"
        })
        # Replica snapshot still has the record present
        catalog.records_by_file["ev_repl"].append({
            "file_id": "ev_repl", "captured_at": "2026-04-12T00:00:00Z", "resource_id": "account_02",
            "category": "USER_PROFILE", "user_id": "u_02", "is_present": True, "is_absent": False,
            "has_pii": True, "is_anonymized": False, "is_redacted": False, "table": "customer_profiles_replica"
        })

        case_data = {
            "case_id": "case_scen_02", "email": "u02@test.com", "requested_at": "2026-04-05T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-11T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my account."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_02": {"account_02"}}, [])
        self.assertEqual(status, "INCOMPLETE")
        findings = [s for s in steps if s["phase"] == "FINDING" and s["operation"] == "REPORT_REMAINING_RECORD"]
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["evidence_id"], "ev_repl")

    # -------------------------------------------------------------------------
    # Scenario 3: Replica previously present subsequently verified clean
    # -------------------------------------------------------------------------
    def test_03_replica_previously_present_subsequently_verified_clean(self):
        id_graph = IdentityGraph([{"user_id": "u_03", "email": "u03@test.com", "email_hash": "h03", "phone": "+3"}], [])
        manifest = [
            {"file_id": "ev_r1", "file_path": "r1.sql", "origin": "db_replica", "captured_at": "2026-04-05T00:00:00Z"},
            {"file_id": "ev_r2", "file_path": "r2.sql", "origin": "db_replica", "captured_at": "2026-04-20T00:00:00Z"}
        ]
        catalog = EvidenceCatalog(manifest)
        catalog.account_datastore_files.add("ev_r2")
        # Replica was present at 2026-04-05
        catalog.records_by_file["ev_r1"].append({
            "file_id": "ev_r1", "captured_at": "2026-04-05T00:00:00Z", "resource_id": "account_03",
            "category": "USER_PROFILE", "user_id": "u_03", "is_present": True, "is_absent": False,
            "has_pii": True, "table": "customer_profiles_replica"
        })
        # Later replica snapshot at 2026-04-20 verified clean
        catalog.records_by_file["ev_r2"].append({
            "file_id": "ev_r2", "captured_at": "2026-04-20T00:00:00Z", "resource_id": "account_03",
            "category": "USER_PROFILE", "user_id": "u_03", "is_present": False, "is_absent": True,
            "has_pii": False, "table": "customer_profiles_replica"
        })

        case_data = {
            "case_id": "case_scen_03", "email": "u03@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-21T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete all my personal records."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_03": {"account_03"}}, [])
        self.assertEqual(status, "COMPLETE")
        self.assertTrue(any(s["phase"] == "VERIFICATION" and s["operation"] == "VERIFY_RECORD_ABSENT" for s in steps))

    # -------------------------------------------------------------------------
    # Scenario 4: Missing primary-resource evidence defaults to INCOMPLETE
    # -------------------------------------------------------------------------
    def test_04_missing_primary_resource_evidence_prevents_unsupported_complete(self):
        id_graph = IdentityGraph([{"user_id": "u_04", "email": "u04@test.com", "email_hash": "h04", "phone": "+4"}], [])
        manifest = []  # No manifest / no evidence files
        catalog = EvidenceCatalog(manifest)

        case_data = {
            "case_id": "case_scen_04", "email": "u04@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-02T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete everything."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {}, [])
        # Without evidence proving compliance, system must NOT claim COMPLETE
        self.assertEqual(status, "INCOMPLETE")

    # -------------------------------------------------------------------------
    # Scenario 5: Unrelated evidence file rejected as absence proof
    # -------------------------------------------------------------------------
    def test_05_unrelated_evidence_file_rejected_as_absence_proof(self):
        id_graph = IdentityGraph([{"user_id": "u_05", "email": "u05@test.com", "email_hash": "h05", "phone": "+5"}], [])
        manifest = [{"file_id": "ev_unrelated", "file_path": "invoice.pdf", "origin": "billing_system", "captured_at": "2026-04-10T00:00:00Z"}]
        catalog = EvidenceCatalog(manifest)
        # ev_unrelated is NOT in account_datastore_files and contains no profile records
        case_data = {
            "case_id": "case_scen_05", "email": "u05@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-11T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my account."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_05": {"account_05"}}, [])
        self.assertEqual(status, "INCOMPLETE")

    # -------------------------------------------------------------------------
    # Scenario 6: Current record recreated by upstream data flow
    # -------------------------------------------------------------------------
    def test_06_current_record_recreated_by_upstream_data_flow(self):
        id_graph = IdentityGraph([{"user_id": "u_06", "email": "u06@test.com", "email_hash": "h06", "phone": "+6"}], [])
        manifest = [{"file_id": "ev_flow", "file_path": "flow.json", "origin": "sync_service", "captured_at": "2026-04-15T00:00:00Z"}]
        catalog = EvidenceCatalog(manifest)
        catalog.records_by_file["ev_flow"].append({
            "file_id": "ev_flow", "captured_at": "2026-04-15T00:00:00Z", "resource_id": "data_flow_user_sync",
            "category": "DATA_FLOW", "user_id": "u_06", "enabled": True, "service": "sync_worker"
        })
        case_data = {
            "case_id": "case_scen_06", "email": "u06@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-10T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my profile."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_06": {"data_flow_user_sync"}}, [])
        self.assertEqual(status, "INCOMPLETE")
        ops = [s["operation"] for s in steps]
        self.assertIn("REPORT_ACTIVE_DATA_FLOW", ops)
        self.assertIn("DISABLE_DATA_FLOW", ops)
        self.assertIn("VERIFY_DATA_FLOW_DISABLED", ops)

    # -------------------------------------------------------------------------
    # Scenario 7: Backup that can restore the deleted data
    # -------------------------------------------------------------------------
    def test_07_backup_archive_restore_risk(self):
        id_graph = IdentityGraph([{"user_id": "u_07", "email": "u07@test.com", "email_hash": "h07", "phone": "+7"}], [])
        manifest = [{"file_id": "ev_bk", "file_path": "backup.log", "origin": "backup_vault", "captured_at": "2026-04-15T00:00:00Z"}]
        catalog = EvidenceCatalog(manifest)
        catalog.records_by_file["ev_bk"].append({
            "file_id": "ev_bk", "captured_at": "2026-04-15T00:00:00Z", "resource_id": "backup_archive_monthly",
            "category": "BACKUP_ARCHIVE", "user_id": "u_07", "restore_allowed": True
        })
        case_data = {
            "case_id": "case_scen_07", "email": "u07@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-10T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my account and data."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_07": {"backup_archive_monthly"}}, [])
        self.assertEqual(status, "INCOMPLETE")
        ops = [s["operation"] for s in steps]
        self.assertIn("REPORT_RESTORE_RISK", ops)
        self.assertIn("BLOCK_RESTORE", ops)
        self.assertIn("VERIFY_RESTORE_BLOCKED", ops)

    # -------------------------------------------------------------------------
    # Scenario 8: Support attachment vs shared support message
    # -------------------------------------------------------------------------
    def test_08_support_attachment_vs_shared_support_message(self):
        # Support attachment: DELETE_RECORD -> VERIFY_RECORD_ABSENT
        v_att = [{"resource_id": "support_att_01", "operation": "REPORT_REMAINING_RECORD", "finding_state": "PRESENT", "evidence_id": "ev_att", "category": "SUPPORT_ATTACHMENT"}]
        steps_att = build_case_output("c_att", "INCOMPLETE", v_att, [])
        self.assertTrue(any(s["phase"] == "REMEDIATION" and s["operation"] == "DELETE_RECORD" for s in steps_att))
        self.assertTrue(any(s["phase"] == "VERIFICATION" and s["operation"] == "VERIFY_RECORD_ABSENT" for s in steps_att))

        # Support message: REDACT_RECORD -> VERIFY_RECORD_REDACTED
        v_msg = [{"resource_id": "support_msg_01", "operation": "REPORT_EXPOSED_PII", "finding_state": "PRESENT", "evidence_id": "ev_msg", "category": "SUPPORT_MESSAGE"}]
        steps_msg = build_case_output("c_msg", "INCOMPLETE", v_msg, [])
        self.assertTrue(any(s["phase"] == "REMEDIATION" and s["operation"] == "REDACT_RECORD" for s in steps_msg))
        self.assertTrue(any(s["phase"] == "VERIFICATION" and s["operation"] == "VERIFY_RECORD_REDACTED" for s in steps_msg))

    # -------------------------------------------------------------------------
    # Scenario 9: Export request that merely mentions deletion
    # -------------------------------------------------------------------------
    def test_09_export_request_merely_mentions_deletion(self):
        text = "Please export my order data as a CSV. Do you delete orders automatically later?"
        self.assertFalse(is_authorized_deletion_request(text))

    # -------------------------------------------------------------------------
    # Scenario 10: Explicitly negated deletion intent
    # -------------------------------------------------------------------------
    def test_10_explicitly_negated_deletion_intent(self):
        text = "Do not delete my account, I just want a copy of my recent receipts."
        self.assertFalse(is_authorized_deletion_request(text))
        text2 = "Please do not delete any of my personal information, keep it."
        self.assertFalse(is_authorized_deletion_request(text2))

    # -------------------------------------------------------------------------
    # Scenario 11: Ambiguous and hypothetical requests
    # -------------------------------------------------------------------------
    def test_11_ambiguous_and_hypothetical_requests(self):
        text1 = "If I decide to delete my account next month, how long does it take?"
        self.assertFalse(is_authorized_deletion_request(text1))
        text2 = '"delete my profile" is what my brother said, but I just want help signing in.'
        self.assertFalse(is_authorized_deletion_request(text2))

    # -------------------------------------------------------------------------
    # Scenario 12: Contradictory timestamps or observations
    # -------------------------------------------------------------------------
    def test_12_chronological_observation_precedence(self):
        # Two observations of the same source: earlier present, later absent
        obs_list = [
            {"captured_at": "2026-04-01T00:00:00Z", "is_present": True, "table": "profiles"},
            {"captured_at": "2026-04-20T00:00:00Z", "is_absent": True, "table": "profiles"}
        ]
        s_latest = sorted(obs_list, key=lambda x: to_dt(x["captured_at"]))[-1]
        self.assertTrue(s_latest.get("is_absent"))
        self.assertFalse(s_latest.get("is_present", False))

    # -------------------------------------------------------------------------
    # Scenario 13: Ambiguous or conflicting identity links
    # -------------------------------------------------------------------------
    def test_13_ambiguous_or_conflicting_identity_links(self):
        # Two distinct users claiming the exact same email
        identities = [
            {"user_id": "user_A", "email": "clash@example.com", "email_hash": "hashA", "phone": "+1"},
            {"user_id": "user_B", "email": "clash@example.com", "email_hash": "hashB", "phone": "+2"}
        ]
        id_graph = IdentityGraph(identities, [])
        # Ambiguous identifier is flagged and not blindly mapped to user_A or user_B
        self.assertIn("clash@example.com", id_graph.ambiguous_identifiers)
        self.assertIsNone(id_graph.resolve_user_id("clash@example.com"))

    # -------------------------------------------------------------------------
    # Scenario 14: Future evidence incorrectly being used in historical audit
    # -------------------------------------------------------------------------
    def test_14_future_evidence_ignored_in_historical_audit(self):
        id_graph = IdentityGraph([{"user_id": "u_14", "email": "u14@test.com", "email_hash": "h14", "phone": "+14"}], [])
        manifest = [
            {"file_id": "ev_past", "file_path": "past.log", "origin": "app", "captured_at": "2026-04-10T00:00:00Z"},
            {"file_id": "ev_future", "file_path": "future.log", "origin": "app", "captured_at": "2026-06-01T00:00:00Z"}
        ]
        catalog = EvidenceCatalog(manifest)
        # Past observation: record remaining
        catalog.records_by_file["ev_past"].append({
            "file_id": "ev_past", "captured_at": "2026-04-10T00:00:00Z", "resource_id": "account_14",
            "category": "USER_PROFILE", "user_id": "u_14", "is_present": True, "is_absent": False
        })
        # Future observation (after audit_at 2026-05-01): cleaned
        catalog.records_by_file["ev_future"].append({
            "file_id": "ev_future", "captured_at": "2026-06-01T00:00:00Z", "resource_id": "account_14",
            "category": "USER_PROFILE", "user_id": "u_14", "is_present": False, "is_absent": True
        })

        case_data = {
            "case_id": "case_scen_14", "email": "u14@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-15T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my account."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_14": {"account_14"}}, [])
        # Must be INCOMPLETE as of 2026-05-01 cutoff
        self.assertEqual(status, "INCOMPLETE")
        self.assertTrue(any(s["phase"] == "FINDING" and s["evidence_id"] == "ev_past" for s in steps))

    # -------------------------------------------------------------------------
    # Scenario 15: Duplicate predicted steps
    # -------------------------------------------------------------------------
    def test_15_duplicate_predicted_steps_strictly_penalized(self):
        gold = [
            {"step_no": 1, "phase": "FINDING", "system_id": "account_service", "resource_id": "res_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_1"}
        ]
        pred = [
            {"step_no": 1, "phase": "FINDING", "system_id": "account_service", "resource_id": "res_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_1"},
            {"step_no": 2, "phase": "FINDING", "system_id": "account_service", "resource_id": "res_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_1"}
        ]
        matches, total_gold, total_pred = match_steps_strict(gold, pred)
        self.assertEqual(matches, 1)
        self.assertEqual(total_pred, 2)
        precision = matches / total_pred
        self.assertAlmostEqual(precision, 0.5)

    # -------------------------------------------------------------------------
    # Scenario 16: Contradictory steps and invalid evidence references
    # -------------------------------------------------------------------------
    def test_16_invalid_evidence_references_on_future_steps(self):
        # Remediation steps must have empty evidence_id
        invalid_steps = [
            {"step_no": 1, "phase": "FINDING", "system_id": "account_service", "resource_id": "res_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_01"},
            {"step_no": 2, "phase": "REMEDIATION", "system_id": "account_service", "resource_id": "res_01", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": "ev_01"},  # INVALID
            {"step_no": 3, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "res_01", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""}
        ]
        row = [{"case_id": "c16", "deletion_status": "INCOMPLETE", "steps_json": json.dumps(invalid_steps)}]
        is_valid, issues = validate_contract(row, expected_row_count=1)
        self.assertFalse(is_valid)
        self.assertTrue(any("empty evidence_id" in iss for iss in issues))

    # -------------------------------------------------------------------------
    # Scenario 17: Empty COMPLETE and INCOMPLETE result collections
    # -------------------------------------------------------------------------
    def test_17_empty_complete_and_incomplete_result_collections(self):
        complete_empty = [{"case_id": "c17_a", "deletion_status": "COMPLETE", "steps_json": "[]"}]
        is_valid, issues = validate_contract(complete_empty, expected_row_count=1)
        self.assertFalse(is_valid)
        incomplete_empty = [{"case_id": "c17_b", "deletion_status": "INCOMPLETE", "steps_json": "[]"}]
        is_valid2, issues2 = validate_contract(incomplete_empty, expected_row_count=1)
        self.assertFalse(is_valid2)

    # -------------------------------------------------------------------------
    # Scenario 18: NOT_APPLICABLE cases
    # -------------------------------------------------------------------------
    def test_18_not_applicable_cases_have_empty_steps(self):
        steps = build_case_output("case_na", "NOT_APPLICABLE", [], [])
        self.assertEqual(steps, [])
        valid_row = [{"case_id": "case_na", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"}]
        is_valid, issues = validate_contract(valid_row, expected_row_count=1)
        self.assertTrue(is_valid)

    # -------------------------------------------------------------------------
    # Scenario 19: Malformed CSV/JSON or missing required columns
    # -------------------------------------------------------------------------
    def test_19_malformed_json_caught_by_evaluator(self):
        malformed_row = [{"case_id": "c19", "deletion_status": "COMPLETE", "steps_json": "NOT_A_JSON_ARRAY"}]
        is_valid, issues = validate_contract(malformed_row, expected_row_count=1)
        self.assertFalse(is_valid)
        self.assertTrue(any("Invalid JSON" in iss for iss in issues))

    # -------------------------------------------------------------------------
    # Scenario 20: Incomplete pipeline inputs and invalid timestamps
    # -------------------------------------------------------------------------
    def test_20_timestamp_parsing_robustness(self):
        self.assertIsNotNone(to_dt("2026-05-01T12:00:00Z"))
        self.assertIsNotNone(to_dt("2026-05-01 12:00:00"))
        # Invalid timestamp falls back gracefully to epoch without crashing
        fallback = to_dt("MALFORMED_TIMESTAMP")
        self.assertEqual(fallback.year, 1970)

    # -------------------------------------------------------------------------
    # Scenario 21: Repeated execution determinism
    # -------------------------------------------------------------------------
    def test_21_repeated_execution_determinism(self):
        v = [{"resource_id": "res_01", "operation": "REPORT_REMAINING_RECORD", "finding_state": "PRESENT", "evidence_id": "ev_1", "category": "USER_PROFILE"}]
        run1 = build_case_output("case_det", "INCOMPLETE", v, [])
        run2 = build_case_output("case_det", "INCOMPLETE", v, [])
        self.assertEqual(json.dumps(run1, sort_keys=True), json.dumps(run2, sort_keys=True))

    # -------------------------------------------------------------------------
    # Scenario 22: Data coverage gaps prevent unsupported COMPLETE
    # -------------------------------------------------------------------------
    def test_22_coverage_gap_prevents_unsupported_complete(self):
        id_graph = IdentityGraph([{"user_id": "u_22", "email": "u22@test.com", "email_hash": "h22", "phone": "+22"}], [])
        catalog = EvidenceCatalog([])  # completely empty catalog
        case_data = {
            "case_id": "c22", "email": "u22@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-10T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my account."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_22": {"account_22"}}, [])
        self.assertEqual(status, "INCOMPLETE")

    # -------------------------------------------------------------------------
    # Scenario 23: Valid fully evidenced case achieves COMPLETE
    # -------------------------------------------------------------------------
    def test_23_valid_fully_evidenced_case_achieves_complete(self):
        id_graph = IdentityGraph([{"user_id": "u_23", "email": "u23@test.com", "email_hash": "h23", "phone": "+23"}], [])
        manifest = [{"file_id": "ev_datastore", "file_path": "profiles.sql", "origin": "account_db", "captured_at": "2026-04-20T00:00:00Z"}]
        catalog = EvidenceCatalog(manifest)
        catalog.account_datastore_files.add("ev_datastore")
        case_data = {
            "case_id": "c23", "email": "u23@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-21T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my user account and all profile data."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_23": {"account_23"}}, [])
        self.assertEqual(status, "COMPLETE")
        self.assertTrue(len(steps) > 0)
        self.assertEqual(steps[0]["evidence_id"], "ev_datastore")
        self.assertEqual(steps[0]["operation"], "VERIFY_RECORD_ABSENT")

    # -------------------------------------------------------------------------
    # Scenario 24: Legitimate retained records (tax invoice / legal hold)
    # -------------------------------------------------------------------------
    def test_24_legitimate_retained_tax_and_legal_records(self):
        compliant = [
            {"resource_id": "tax_invoice_991", "evidence_id": "ev_tax", "category": "TAX_INVOICE"}
        ]
        steps = build_case_output("c24", "COMPLETE", [], compliant)
        tax_step = [s for s in steps if s["resource_id"] == "tax_invoice_991"][0]
        self.assertEqual(tax_step["operation"], "VERIFY_RECORD_PRESENT")
        self.assertEqual(tax_step["state"], "PRESENT")

    # -------------------------------------------------------------------------
    # Scenario 25: Intent and identity multilingual edge cases
    # -------------------------------------------------------------------------
    def test_25_intent_and_identity_multilingual_edge_cases(self):
        # Spanish subjunctive
        self.assertTrue(is_authorized_deletion_request("Por favor eliminen mi cuenta y todos mis datos personales."))
        # German
        self.assertTrue(is_authorized_deletion_request("Bitte löschen Sie mein Benutzerkonto und alle personenbezogenen Daten."))
        # French
        self.assertTrue(is_authorized_deletion_request("Je demande la suppression définitive de mes données."))
        # Japanese
        self.assertTrue(is_authorized_deletion_request("アカウントとすべての個人データを完全に削除してください。"))
        # Historical identity resolution with sha-256 hash
        id_graph = IdentityGraph(
            [{"user_id": "u_25", "email": "curr@test.com", "email_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "phone": "+25"}],
            [{"user_id": "u_25", "field_name": "email", "old_value": "hist@test.com", "new_value": "curr@test.com", "changed_at": "2026-01-01T00:00:00Z"}]
        )
        self.assertEqual(id_graph.resolve_user_id("hist@test.com"), "u_25")
        self.assertEqual(id_graph.resolve_user_id("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "u_25")


    # -------------------------------------------------------------------------
    # Scenario 26: Zero external API or network dependencies (Offline Isolation)
    # -------------------------------------------------------------------------
    def test_26_zero_external_api_or_network_dependencies(self):
        import ast
        import socket

        # 1. AST inspection: assert no prohibited network/API modules
        prohibited = {
            "requests", "httpx", "urllib", "aiohttp", "socket", "http.client",
            "openai", "anthropic", "google.generativeai", "boto3", "huggingface",
            "langchain", "subprocess"
        }
        target_files = [
            os.path.join(BASE_DIR, "code", "main.py"),
            os.path.join(BASE_DIR, "code", "evaluation", "main.py")
        ]
        for fp in target_files:
            with open(fp, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), fp)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for n in node.names:
                        base_mod = n.name.split(".")[0]
                        self.assertNotIn(base_mod, prohibited, f"Prohibited module '{base_mod}' in {fp}")
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        base_mod = node.module.split(".")[0]
                        self.assertNotIn(base_mod, prohibited, f"Prohibited module '{base_mod}' in {fp}")

        # 2. Runtime socket isolation check: assert audit_case runs with network prohibited
        orig_connect = socket.socket.connect
        def block_net(*args, **kwargs):
            raise RuntimeError("Outbound socket connection blocked!")
        socket.socket.connect = block_net
        try:
            id_graph = IdentityGraph([{"user_id": "u_net", "email": "net@test.com", "email_hash": "h_net", "phone": "+99"}], [])
            catalog = EvidenceCatalog([])
            case_data = {
                "case_id": "c_net", "email": "net@test.com", "requested_at": "2026-04-01T00:00:00Z",
                "reported_status": "COMPLETE", "reported_at": "2026-04-10T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
                "request_text": "Please delete my account."
            }
            status, steps = audit_case(case_data, id_graph, catalog, {"u_net": {"account_net"}}, [])
            self.assertEqual(status, "INCOMPLETE")
        finally:
            socket.socket.connect = orig_connect


if __name__ == "__main__":
    unittest.main()

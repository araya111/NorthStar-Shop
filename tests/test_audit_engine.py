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
from evaluation.main import validate_contract, match_steps_strict, validate_evidence_reference


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
    # Scenario 19: Malformed CSV/JSON, missing/extra columns, contract errors
    # -------------------------------------------------------------------------
    def test_19_malformed_csv_json_and_contract_validation(self):
        # 1. Malformed JSON array
        malformed_json_row = [{"case_id": "c19_a", "deletion_status": "COMPLETE", "steps_json": "NOT_A_JSON_ARRAY"}]
        is_valid, issues = validate_contract(malformed_json_row, expected_row_count=1)
        self.assertFalse(is_valid)
        self.assertTrue(any("Invalid JSON" in iss for iss in issues))

        # 2. Missing required CSV column 'steps_json'
        missing_col_row = [{"case_id": "c19_b", "deletion_status": "COMPLETE"}]
        is_valid, issues = validate_contract(missing_col_row, expected_row_count=1)
        self.assertFalse(is_valid)
        self.assertTrue(any("Missing required CSV columns" in iss for iss in issues))

        # 3. Unexpected extra CSV column
        extra_col_row = [{"case_id": "c19_c", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]", "unexpected_col": "extra"}]
        is_valid, issues = validate_contract(extra_col_row, expected_row_count=1)
        self.assertFalse(is_valid)
        self.assertTrue(any("Unexpected CSV columns" in iss for iss in issues))

        # 4. Duplicate headers in CSV file
        import tempfile
        with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False, encoding="utf-8") as tf:
            tf.write("case_id,deletion_status,steps_json,case_id\ncase_dup,NOT_APPLICABLE,[],case_dup\n")
            dup_csv_path = tf.name
        try:
            is_valid, issues = validate_contract(dup_csv_path, expected_row_count=1)
            self.assertFalse(is_valid)
            self.assertTrue(any("Duplicate CSV headers" in iss for iss in issues))
        finally:
            if os.path.exists(dup_csv_path):
                os.remove(dup_csv_path)

        # 5. Invalid CSV header names
        with tempfile.NamedTemporaryFile("w+", suffix=".csv", delete=False, encoding="utf-8") as tf:
            tf.write("id,status,steps\ncase_bad,NOT_APPLICABLE,[]\n")
            bad_hdr_path = tf.name
        try:
            is_valid, issues = validate_contract(bad_hdr_path, expected_row_count=1)
            self.assertFalse(is_valid)
            self.assertTrue(any("Invalid CSV header" in iss for iss in issues))
        finally:
            if os.path.exists(bad_hdr_path):
                os.remove(bad_hdr_path)

        # 6. Non-object step in steps array
        bad_step_type = [{"case_id": "c19_d", "deletion_status": "COMPLETE", "steps_json": json.dumps([123])}]
        is_valid, issues = validate_contract(bad_step_type, expected_row_count=1)
        self.assertFalse(is_valid)
        self.assertTrue(any("Step 1 is not a JSON object" in iss or "non-dictionary" in iss for iss in issues))

        # 7. Boolean step_no rejected
        bool_step_no = [{
            "case_id": "c19_e", "deletion_status": "COMPLETE",
            "steps_json": json.dumps([{"step_no": True, "phase": "VERIFICATION", "system_id": "s", "resource_id": "r", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"}])
        }]
        is_valid, issues = validate_contract(bool_step_no, expected_row_count=1, valid_file_ids={"evidence_01"})
        self.assertFalse(is_valid)
        self.assertTrue(any("must be an integer, got bool" in iss for iss in issues))

        # 8. Invalid operation / state mismatch
        mismatched_state = [{
            "case_id": "c19_f", "deletion_status": "COMPLETE",
            "steps_json": json.dumps([{"step_no": 1, "phase": "VERIFICATION", "system_id": "s", "resource_id": "r", "operation": "VERIFY_RECORD_ABSENT", "state": "PRESENT", "evidence_id": "evidence_01"}])
        }]
        is_valid, issues = validate_contract(mismatched_state, expected_row_count=1, valid_file_ids={"evidence_01"})
        self.assertFalse(is_valid)
        self.assertTrue(any("expected state 'ABSENT', got 'PRESENT'" in iss for iss in issues))

    # -------------------------------------------------------------------------
    # Scenario 20: Incomplete pipeline inputs and strict timestamp parsing
    # -------------------------------------------------------------------------
    def test_20_timestamp_parsing_robustness(self):
        # Valid ISO and naive datetimes parse correctly and normalize to UTC
        dt_utc = to_dt("2026-05-01T12:00:00Z")
        self.assertIsNotNone(dt_utc)
        self.assertEqual(dt_utc.year, 2026)
        self.assertEqual(dt_utc.hour, 12)

        dt_naive = to_dt("2026-05-01 12:00:00")
        self.assertIsNotNone(dt_naive)
        self.assertEqual(dt_naive.year, 2026)

        dt_offset = to_dt("2026-05-01T14:00:00+02:00")
        self.assertIsNotNone(dt_offset)
        self.assertEqual(dt_offset.hour, 12)  # Normalized to UTC 12:00

        # Strict safety: Malformed or missing timestamps return None (never epoch 1970)
        self.assertIsNone(to_dt("MALFORMED_TIMESTAMP"))
        self.assertIsNone(to_dt(None))
        self.assertIsNone(to_dt(""))

    # -------------------------------------------------------------------------
    # Scenario 21: Cross-process determinism with distinct PYTHONHASHSEED
    # -------------------------------------------------------------------------
    def test_21_cross_process_determinism_with_distinct_hash_seeds(self):
        import subprocess
        v = [{"resource_id": "res_01", "operation": "REPORT_REMAINING_RECORD", "finding_state": "PRESENT", "evidence_id": "ev_1", "category": "USER_PROFILE"}]
        run1 = build_case_output("case_det", "INCOMPLETE", v, [])
        run2 = build_case_output("case_det", "INCOMPLETE", v, [])
        self.assertEqual(json.dumps(run1, sort_keys=True), json.dumps(run2, sort_keys=True))

        # Test cross-process determinism across subprocesses with different PYTHONHASHSEED
        cmd = [sys.executable, "-c", "import sys; sys.path.insert(0, 'code'); from main import build_case_output, canonical_step_sort_key; import json; v = [{'resource_id': 'res_01', 'operation': 'REPORT_REMAINING_RECORD', 'finding_state': 'PRESENT', 'evidence_id': 'ev_1', 'category': 'USER_PROFILE'}]; print(json.dumps(build_case_output('case_det', 'INCOMPLETE', v, [])))"]
        env0 = os.environ.copy()
        env0["PYTHONHASHSEED"] = "0"
        proc0 = subprocess.run(cmd, cwd=BASE_DIR, env=env0, capture_output=True, text=True, check=True)

        env42 = os.environ.copy()
        env42["PYTHONHASHSEED"] = "42"
        proc42 = subprocess.run(cmd, cwd=BASE_DIR, env=env42, capture_output=True, text=True, check=True)

        self.assertEqual(proc0.stdout.strip(), proc42.stdout.strip())

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
    # Scenario 23: Genuine evidence file verification achieves COMPLETE; missing fails
    # -------------------------------------------------------------------------
    def test_23_valid_fully_evidenced_case_achieves_complete(self):
        import tempfile
        # 1. Create a genuine physical JSON evidence fixture demonstrating verified profile absence
        fixture_data = {
            "service_exports": {
                "account_service": {
                    "profile_lookups": [
                        {
                            "resource_id": "account_23",
                            "user_id": "u_23",
                            "email": "u23@test.com",
                            "status_code": 404,
                            "profile": None
                        }
                    ]
                }
            }
        }
        with tempfile.NamedTemporaryFile("w+", suffix=".json", delete=False, encoding="utf-8") as tf:
            json.dump(fixture_data, tf)
            fixture_path = tf.name

        try:
            id_graph = IdentityGraph([{"user_id": "u_23", "email": "u23@test.com", "email_hash": "h23", "phone": "+23"}], [])
            manifest = [{"file_id": "ev_real_proof", "file_path": fixture_path, "origin": "account_service", "captured_at": "2026-04-20T00:00:00Z"}]
            catalog = EvidenceCatalog(manifest)
            catalog.parse_all()

            case_data = {
                "case_id": "c23", "email": "u23@test.com", "requested_at": "2026-04-01T00:00:00Z",
                "reported_status": "COMPLETE", "reported_at": "2026-04-21T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
                "request_text": "Please delete my user account and all profile data."
            }
            status, steps = audit_case(case_data, id_graph, catalog, {"u_23": {"account_23"}}, [])
            self.assertEqual(status, "COMPLETE")
            self.assertTrue(len(steps) > 0)
            self.assertEqual(steps[0]["evidence_id"], "ev_real_proof")
            self.assertEqual(steps[0]["operation"], "VERIFY_RECORD_ABSENT")
        finally:
            if os.path.exists(fixture_path):
                os.remove(fixture_path)

        # 2. Negative test: If the evidence file is missing/unreadable, audit_case cannot claim COMPLETE
        manifest_missing = [{"file_id": "ev_nonexistent", "file_path": os.path.join(tempfile.gettempdir(), "nonexistent_file_xyz.json"), "origin": "account_service", "captured_at": "2026-04-20T00:00:00Z"}]
        catalog_missing = EvidenceCatalog(manifest_missing)
        catalog_missing.parse_all()
        status_neg, steps_neg = audit_case(case_data, id_graph, catalog_missing, {"u_23": {"account_23"}}, [])
        self.assertEqual(status_neg, "INCOMPLETE")

    # -------------------------------------------------------------------------
    # Scenario 24: Legitimate retained records (tax invoice / legal hold) policy path
    # -------------------------------------------------------------------------
    def test_24_legitimate_retained_tax_and_legal_records(self):
        id_graph = IdentityGraph([{"user_id": "u_24", "email": "u24@test.com", "email_hash": "h24", "phone": "+24"}], [])
        manifest = [
            {"file_id": "ev_legal", "file_path": "legal.json", "origin": "legal_service", "captured_at": "2026-04-15T00:00:00Z"},
            {"file_id": "ev_tax", "file_path": "tax.json", "origin": "security_service", "captured_at": "2026-04-15T00:00:00Z"},
            {"file_id": "ev_acc", "file_path": "acc.json", "origin": "account_service", "captured_at": "2026-04-15T00:00:00Z"}
        ]
        catalog = EvidenceCatalog(manifest)
        # Legal hold record retained under Rule 13 (legal_service)
        catalog.records_by_file["ev_legal"].append({
            "file_id": "ev_legal", "captured_at": "2026-04-15T00:00:00Z", "resource_id": "legal_hold_5622",
            "category": "LEGAL_HOLD_RECORD", "user_id": "u_24", "is_present": True, "is_retained": True
        })
        # Tax invoice retained under Rule 12 (security_service)
        catalog.records_by_file["ev_tax"].append({
            "file_id": "ev_tax", "captured_at": "2026-04-15T00:00:00Z", "resource_id": "tax_invoice_991",
            "category": "TAX_INVOICE", "user_id": "u_24", "is_present": True, "is_retained": True
        })
        # Primary account is confirmed absent
        catalog.records_by_file["ev_acc"].append({
            "file_id": "ev_acc", "captured_at": "2026-04-15T00:00:00Z", "resource_id": "account_24",
            "category": "USER_PROFILE", "user_id": "u_24", "is_present": False, "is_absent": True
        })

        case_data = {
            "case_id": "c24", "email": "u24@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-16T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my account and personal data."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_24": {"account_24", "legal_hold_5622", "tax_invoice_991"}}, [])
        self.assertEqual(status, "COMPLETE")

        legal_steps = [s for s in steps if s["resource_id"] == "legal_hold_5622"]
        self.assertTrue(len(legal_steps) > 0)
        self.assertEqual(legal_steps[0]["system_id"], "legal_service")
        self.assertEqual(legal_steps[0]["operation"], "VERIFY_RECORD_PRESENT")
        self.assertEqual(legal_steps[0]["state"], "PRESENT")

        tax_steps = [s for s in steps if s["resource_id"] == "tax_invoice_991"]
        self.assertTrue(len(tax_steps) > 0)
        self.assertEqual(tax_steps[0]["system_id"], "security_service")
        self.assertEqual(tax_steps[0]["operation"], "VERIFY_RECORD_PRESENT")
        self.assertEqual(tax_steps[0]["state"], "PRESENT")

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
    # Scenario 26: Zero external API or network dependencies (Broadened Offline Isolation)
    # -------------------------------------------------------------------------
    def test_26_zero_external_api_or_network_dependencies(self):
        import ast
        import socket

        # 1. Broadened AST inspection across all shipped Python scripts
        runtime_prohibited = {
            "requests", "httpx", "urllib", "aiohttp", "socket", "http.client",
            "openai", "anthropic", "google.generativeai", "boto3", "huggingface",
            "langchain", "subprocess"
        }
        test_harness_prohibited = {
            "requests", "httpx", "urllib", "aiohttp", "http.client",
            "openai", "anthropic", "google.generativeai", "boto3", "huggingface",
            "langchain"
        }
        target_files = [
            (os.path.join(BASE_DIR, "code", "main.py"), runtime_prohibited),
            (os.path.join(BASE_DIR, "code", "evaluation", "main.py"), runtime_prohibited),
            (os.path.join(BASE_DIR, "code", "evaluation", "release_gate.py"), test_harness_prohibited),
            (os.path.join(BASE_DIR, "tests", "test_audit_engine.py"), test_harness_prohibited),
        ]
        for fp, prohibited_modules in target_files:
            with open(fp, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), fp)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for n in node.names:
                        base_mod = n.name.split(".")[0]
                        self.assertNotIn(base_mod, prohibited_modules, f"Prohibited module '{base_mod}' in {fp}")
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        base_mod = node.module.split(".")[0]
                        self.assertNotIn(base_mod, prohibited_modules, f"Prohibited module '{base_mod}' in {fp}")

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

    # -------------------------------------------------------------------------
    # Scenario 27: Multi-Source Evidence Validation - file_id
    # -------------------------------------------------------------------------
    def test_27_evidence_reference_file_id_validation(self):
        valid_files = {"evidence_01", "file_snapshot_02"}
        issues = []
        # Valid file_id
        validate_evidence_reference("evidence_01", "case_01", 1, "FINDING", issues, valid_file_ids=valid_files)
        self.assertEqual(len(issues), 0)

        # Invalid file_id
        validate_evidence_reference("evidence_unknown", "case_01", 2, "FINDING", issues, valid_file_ids=valid_files)
        self.assertEqual(len(issues), 1)
        self.assertIn("not found in evidence_files.csv", issues[0])

    # -------------------------------------------------------------------------
    # Scenario 28: Multi-Source Evidence Validation - activity_id
    # -------------------------------------------------------------------------
    def test_28_evidence_reference_activity_id_validation(self):
        valid_activities = {"activity_sync_100", "act_backup_200"}
        issues = []
        # Valid activity_id
        validate_evidence_reference("activity_sync_100", "case_02", 1, "FINDING", issues, valid_activity_ids=valid_activities)
        self.assertEqual(len(issues), 0)

        # Invalid activity_id
        validate_evidence_reference("activity_ghost", "case_02", 2, "FINDING", issues, valid_activity_ids=valid_activities)
        self.assertEqual(len(issues), 1)
        self.assertIn("not found in system_activity.csv", issues[0])

    # -------------------------------------------------------------------------
    # Scenario 29: Multi-Source Evidence Validation - audit_id
    # -------------------------------------------------------------------------
    def test_29_evidence_reference_audit_id_validation(self):
        valid_audits = {"audit_log_501", "aud_hist_999"}
        issues = []
        # Valid audit_id
        validate_evidence_reference("audit_log_501", "case_03", 1, "FINDING", issues, valid_audit_ids=valid_audits)
        self.assertEqual(len(issues), 0)

        # Invalid audit_id
        validate_evidence_reference("audit_missing", "case_03", 2, "FINDING", issues, valid_audit_ids=valid_audits)
        self.assertEqual(len(issues), 1)
        self.assertIn("not found in user_audit_log.csv", issues[0])

    # -------------------------------------------------------------------------
    # Scenario 30: Empty evidence_id rules for Remediation & Incomplete Verification
    # -------------------------------------------------------------------------
    def test_30_evidence_reference_empty_rules_remediation_and_verification(self):
        valid_files = {"evidence_01"}

        # 1. Non-empty evidence_id on REMEDIATION must fail
        bad_rem_rows = [{
            "case_id": "case_bad_rem",
            "deletion_status": "INCOMPLETE",
            "steps_json": json.dumps([
                {"step_no": 1, "phase": "FINDING", "system_id": "s1", "resource_id": "r1", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_01"},
                {"step_no": 2, "phase": "REMEDIATION", "system_id": "s1", "resource_id": "r1", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": "evidence_01"},
                {"step_no": 3, "phase": "VERIFICATION", "system_id": "s1", "resource_id": "r1", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
            ])
        }]
        is_valid, issues = validate_contract(bad_rem_rows, expected_row_count=1, valid_file_ids=valid_files)
        self.assertFalse(is_valid)
        self.assertTrue(any("REMEDIATION step 2 must have empty evidence_id" in iss for iss in issues))

        # 2. Non-empty evidence_id on INCOMPLETE VERIFICATION must fail
        bad_ver_rows = [{
            "case_id": "case_bad_ver",
            "deletion_status": "INCOMPLETE",
            "steps_json": json.dumps([
                {"step_no": 1, "phase": "FINDING", "system_id": "s1", "resource_id": "r1", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_01"},
                {"step_no": 2, "phase": "REMEDIATION", "system_id": "s1", "resource_id": "r1", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
                {"step_no": 3, "phase": "VERIFICATION", "system_id": "s1", "resource_id": "r1", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"},
            ])
        }]
        is_valid, issues = validate_contract(bad_ver_rows, expected_row_count=1, valid_file_ids=valid_files)
        self.assertFalse(is_valid)
        self.assertTrue(any("VERIFICATION step 3 must have empty evidence_id" in iss for iss in issues))

        # 3. Empty evidence_id on COMPLETE VERIFICATION must fail
        bad_comp_rows = [{
            "case_id": "case_bad_comp",
            "deletion_status": "COMPLETE",
            "steps_json": json.dumps([
                {"step_no": 1, "phase": "VERIFICATION", "system_id": "s1", "resource_id": "r1", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
            ])
        }]
        is_valid, issues = validate_contract(bad_comp_rows, expected_row_count=1, valid_file_ids=valid_files)
        self.assertFalse(is_valid)
        self.assertTrue(any("missing evidence_id" in iss for iss in issues))

        # 4. Compliant INCOMPLETE case passes
        good_incomp_rows = [{
            "case_id": "case_good_incomp",
            "deletion_status": "INCOMPLETE",
            "steps_json": json.dumps([
                {"step_no": 1, "phase": "FINDING", "system_id": "s1", "resource_id": "r1", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_01"},
                {"step_no": 2, "phase": "REMEDIATION", "system_id": "s1", "resource_id": "r1", "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""},
                {"step_no": 3, "phase": "VERIFICATION", "system_id": "s1", "resource_id": "r1", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
            ])
        }]
        is_valid, issues = validate_contract(good_incomp_rows, expected_row_count=1, valid_file_ids=valid_files)
        self.assertTrue(is_valid, f"Unexpected contract issues: {issues}")

        # 5. Compliant COMPLETE case passes
        good_comp_rows = [{
            "case_id": "case_good_comp",
            "deletion_status": "COMPLETE",
            "steps_json": json.dumps([
                {"step_no": 1, "phase": "VERIFICATION", "system_id": "s1", "resource_id": "r1", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "evidence_01"},
            ])
        }]
        is_valid, issues = validate_contract(good_comp_rows, expected_row_count=1, valid_file_ids=valid_files)
        self.assertTrue(is_valid, f"Unexpected contract issues: {issues}")

    # -------------------------------------------------------------------------
    # Scenario 31: Independent replica isolation (same table name, distinct origins)
    # -------------------------------------------------------------------------
    def test_31_independent_replica_isolation(self):
        id_graph = IdentityGraph([{"user_id": "u_31", "email": "u31@test.com", "email_hash": "h31", "phone": "+31"}], [])
        manifest = [
            {"file_id": "ev_prim", "file_path": "prim.sql", "origin": "db_primary", "captured_at": "2026-04-10T00:00:00Z"},
            {"file_id": "ev_repl", "file_path": "repl.sql", "origin": "db_replica", "captured_at": "2026-04-12T00:00:00Z"}
        ]
        catalog = EvidenceCatalog(manifest)
        # Primary is absent
        catalog.records_by_file["ev_prim"].append({
            "file_id": "ev_prim", "captured_at": "2026-04-10T00:00:00Z", "resource_id": "account_31",
            "category": "USER_PROFILE", "user_id": "u_31", "is_present": False, "is_absent": True,
            "has_pii": False, "table": "customer_profiles"
        })
        # Replica snapshot still has the record present with the same table name
        catalog.records_by_file["ev_repl"].append({
            "file_id": "ev_repl", "captured_at": "2026-04-12T00:00:00Z", "resource_id": "account_31",
            "category": "USER_PROFILE", "user_id": "u_31", "is_present": True, "is_absent": False,
            "has_pii": True, "table": "customer_profiles"
        })

        case_data = {
            "case_id": "c31", "email": "u31@test.com", "requested_at": "2026-04-05T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-15T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my account."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_31": {"account_31"}}, [])
        self.assertEqual(status, "INCOMPLETE")
        findings = [s for s in steps if s["phase"] == "FINDING" and s["operation"] == "REPORT_REMAINING_RECORD"]
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0]["evidence_id"], "ev_repl")

    # -------------------------------------------------------------------------
    # Scenario 32: Multi-subject trace isolation in logs
    # -------------------------------------------------------------------------
    def test_32_multi_subject_trace_isolation(self):
        import tempfile
        log_content = (
            '{"timestamp": "2026-04-10T10:00:00Z", "trace_id": "tr-shared-1", "user_id": "user_alpha", "email": "alpha@test.com"}\n'
            '{"timestamp": "2026-04-10T10:01:00Z", "trace_id": "tr-shared-1", "user_id": "user_beta", "email": "beta@test.com"}\n'
            '{"timestamp": "2026-04-10T10:02:00Z", "trace_id": "tr-shared-1", "resource_id": "account_alpha"}\n'
        )
        with tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False, encoding="utf-8") as tf:
            tf.write(log_content)
            log_path = tf.name

        try:
            id_graph = IdentityGraph(
                [{"user_id": "user_alpha", "email": "alpha@test.com"}, {"user_id": "user_beta", "email": "beta@test.com"}],
                []
            )
            manifest = [{"file_id": "ev_log_shared", "file_path": log_path, "origin": "service_events", "captured_at": "2026-04-15T00:00:00Z"}]
            catalog = EvidenceCatalog(manifest)
            catalog.id_graph = id_graph
            catalog.parse_all()

            # Confirm that user_beta was NOT associated with account_alpha
            beta_records = [r for r in catalog.records_by_file["ev_log_shared"] if r.get("user_id") == "user_beta" and r.get("resource_id") == "account_alpha"]
            self.assertEqual(len(beta_records), 0)
        finally:
            if os.path.exists(log_path):
                os.remove(log_path)

    # -------------------------------------------------------------------------
    # Scenario 33: Future identity change after audit_at is ignored
    # -------------------------------------------------------------------------
    def test_33_future_identity_change_ignored(self):
        from datetime import timezone
        # Current snapshot is updated in the future
        identities = [{"user_id": "user_33", "email": "new_33@test.com", "updated_at": "2026-06-01T00:00:00Z"}]
        # Audit log change happens after audit_at (2026-05-01)
        audit_log = [{"user_id": "user_33", "field_name": "email", "old_value": "old_33@test.com", "new_value": "new_33@test.com", "changed_at": "2026-06-01T00:00:00Z"}]
        id_graph = IdentityGraph(identities, audit_log)

        cutoff = datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc)
        # At cutoff, new_33@test.com was not known/valid
        resolved = id_graph.resolve_user_id("new_33@test.com", at_time=cutoff)
        self.assertIsNone(resolved)
        # But old_33@test.com was valid
        resolved_old = id_graph.resolve_user_id("old_33@test.com", at_time=cutoff)
        self.assertEqual(resolved_old, "user_33")

    # -------------------------------------------------------------------------
    # Scenario 34: Within-phase contract ordering enforced by evaluator
    # -------------------------------------------------------------------------
    def test_34_within_phase_contract_ordering(self):
        # FINDING phase out-of-order: REPORT_ACTIVE_DATA_FLOW (op_num 3) before REPORT_REMAINING_RECORD (op_num 1)
        bad_order_steps = [
            {"step_no": 1, "phase": "FINDING", "system_id": "s1", "resource_id": "r1", "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": "evidence_01"},
            {"step_no": 2, "phase": "FINDING", "system_id": "s1", "resource_id": "r2", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "evidence_01"},
            {"step_no": 3, "phase": "REMEDIATION", "system_id": "s1", "resource_id": "r1", "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""},
            {"step_no": 4, "phase": "VERIFICATION", "system_id": "s1", "resource_id": "r1", "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": ""},
        ]
        row = [{"case_id": "c34", "deletion_status": "INCOMPLETE", "steps_json": json.dumps(bad_order_steps)}]
        is_valid, issues = validate_contract(row, expected_row_count=1, valid_file_ids={"evidence_01"})
        self.assertFalse(is_valid)
        self.assertTrue(any("violates contract order" in iss for iss in issues))

    # -------------------------------------------------------------------------
    # Scenario 35: Missing evidence cannot prove absence
    # -------------------------------------------------------------------------
    def test_35_missing_evidence_cannot_prove_absence(self):
        id_graph = IdentityGraph([{"user_id": "u_35", "email": "u35@test.com"}], [])
        catalog = EvidenceCatalog([])
        case_data = {
            "case_id": "c35", "email": "u35@test.com", "requested_at": "2026-04-01T00:00:00Z",
            "reported_status": "COMPLETE", "reported_at": "2026-04-10T00:00:00Z", "audit_at": "2026-05-01T00:00:00Z",
            "request_text": "Please delete my account."
        }
        status, steps = audit_case(case_data, id_graph, catalog, {"u_35": {"account_35"}}, [])
        self.assertEqual(status, "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()


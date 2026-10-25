import unittest
import os
import sys
import json

# Ensure repo root and code/ are on sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "code"))

from main import IdentityGraph, build_case_output, is_authorized_deletion_request
from evaluation.main import validate_contract, match_steps_strict


class TestAuditEngineRegression(unittest.TestCase):
    """Regression test suite for defects identified during Northstar Shop repository audit."""

    def test_strict_evaluator_matching_prevents_inflation(self):
        """Regression test for Task 4: Ensure duplicate predicted steps cannot match multiple gold steps."""
        gold = [
            {"step_no": 1, "phase": "FINDING", "system_id": "account_service", "resource_id": "account_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_01"}
        ]
        # Prediction contains two identical steps
        pred_duplicate = [
            {"step_no": 1, "phase": "FINDING", "system_id": "account_service", "resource_id": "account_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_01"},
            {"step_no": 2, "phase": "FINDING", "system_id": "account_service", "resource_id": "account_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_01"}
        ]
        
        matches, total_gold, total_pred = match_steps_strict(gold, pred_duplicate)
        self.assertEqual(matches, 1)
        self.assertEqual(total_gold, 1)
        self.assertEqual(total_pred, 2)
        precision = matches / total_pred * 100.0
        recall = matches / total_gold * 100.0
        self.assertAlmostEqual(precision, 50.0, places=2)
        self.assertAlmostEqual(recall, 100.0, places=2)

    def test_support_attachment_verification_absent(self):
        """Regression test for Task 3: Resources remediated via DELETE_RECORD must verify as ABSENT, not REDACTED."""
        violations = [{
            "resource_id": "support_4218",
            "operation": "REPORT_REMAINING_RECORD",
            "finding_state": "PRESENT",
            "evidence_id": "evidence_03",
            "category": "SUPPORT_ATTACHMENT"
        }]
        steps = build_case_output("case_13", "INCOMPLETE", violations, [])
        # Check remediation operation
        rem_steps = [s for s in steps if s["phase"] == "REMEDIATION" and s["resource_id"] == "support_4218"]
        self.assertEqual(len(rem_steps), 1)
        self.assertEqual(rem_steps[0]["operation"], "DELETE_RECORD")
        self.assertEqual(rem_steps[0]["state"], "ABSENT")
        
        # Check post-remediation verification: must be VERIFY_RECORD_ABSENT, ABSENT
        verif_steps = [s for s in steps if s["phase"] == "VERIFICATION" and s["resource_id"] == "support_4218"]
        self.assertEqual(len(verif_steps), 1)
        self.assertEqual(verif_steps[0]["operation"], "VERIFY_RECORD_ABSENT")
        self.assertEqual(verif_steps[0]["state"], "ABSENT")

    def test_identity_graph_historical_resolution(self):
        """Regression test for Task 2: Verify user identity graph handles historical changes."""
        identities = [
            {"user_id": "user_100", "email": "new.email@example.com", "email_hash": "hash_new", "phone": "+100"}
        ]
        audit_log = [
            {"user_id": "user_100", "field_name": "email", "old_value": "old.email@example.com", "new_value": "new.email@example.com", "changed_at": "2026-01-01T00:00:00Z"},
            {"user_id": "user_100", "field_name": "email_hash", "old_value": "hash_old", "new_value": "hash_new", "changed_at": "2026-01-01T00:00:00Z"}
        ]
        id_graph = IdentityGraph(identities, audit_log)
        
        # Resolve by old email
        self.assertEqual(id_graph.resolve_user_id("old.email@example.com"), "user_100")
        # Resolve by new email
        self.assertEqual(id_graph.resolve_user_id("new.email@example.com"), "user_100")
        # All emails and hashes recovered
        self.assertIn("old.email@example.com", id_graph.get_emails("user_100"))
        self.assertIn("new.email@example.com", id_graph.get_emails("user_100"))
        self.assertIn("hash_old", id_graph.get_hashes("user_100"))

    def test_request_authorization_filter(self):
        """Regression test for Task 1: Non-deletion requests must be identified as NOT_APPLICABLE."""
        self.assertFalse(is_authorized_deletion_request("Please download my account information and export my data."))
        self.assertFalse(is_authorized_deletion_request("I want to update my email address, keep the account active."))
        self.assertTrue(is_authorized_deletion_request("Please permanently delete my account and erase all my personal data."))
        self.assertTrue(is_authorized_deletion_request("Je demande la suppression définitive de mes données."))

    def test_contract_validation_catches_invalid_sequences(self):
        """Regression test for Task 4: Evaluator contract validation must catch invalid phase transitions."""
        invalid_rows = [
            {
                "case_id": "case_01",
                "deletion_status": "INCOMPLETE",
                "steps_json": json.dumps([
                    {"step_no": 1, "phase": "VERIFICATION", "system_id": "account_service", "resource_id": "account_01", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""},
                    {"step_no": 2, "phase": "FINDING", "system_id": "account_service", "resource_id": "account_01", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "ev_01"}
                ])
            }
        ]
        is_valid, issues = validate_contract(invalid_rows, expected_row_count=1)
        self.assertFalse(is_valid)
        self.assertTrue(any("Phase out of order" in iss for iss in issues))


if __name__ == "__main__":
    unittest.main()

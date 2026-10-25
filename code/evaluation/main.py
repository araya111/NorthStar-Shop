#!/usr/bin/env python3
"""
Evaluation Runner for HackerRank Orchestrate — Ghost Data Still Exists

Calculates status accuracy, strict 1-to-1 step-level metrics, and field-level precision
against the benchmark sample dataset, and enforces full schema and contract validation.
"""

import os
import sys
import csv
import json

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(BASE_DIR, "code"))

from main import run_pipeline

ALLOWED_OPERATIONS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD": "PRESENT",
        "REPORT_EXPOSED_PII": "PRESENT",
        "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
        "REPORT_RESTORE_RISK": "ACTIVE",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW": "DISABLED",
        "BLOCK_RESTORE": "BLOCKED",
        "DELETE_RECORD": "ABSENT",
        "REDACT_RECORD": "REDACTED",
        "ANONYMIZE_RECORD": "ANONYMIZED",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT": "ABSENT",
        "VERIFY_RECORD_PRESENT": "PRESENT",
        "VERIFY_RECORD_REDACTED": "REDACTED",
        "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
        "VERIFY_RESTORE_BLOCKED": "BLOCKED",
    },
}

PHASE_ORDER = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}


def validate_contract(csv_path_or_rows, expected_row_count=None, valid_file_ids=None, expected_case_ids=None):
    """
    Validates output.csv against all challenge contract rules:
    - Row count and ordering
    - Duplicate, missing, or unexpected case_id check
    - Allowed statuses (COMPLETE, INCOMPLETE, NOT_APPLICABLE)
    - Rejection of empty COMPLETE or empty INCOMPLETE step arrays
    - JSON parsing and structure
    - Strict step dictionary keys and types
    - Consecutive 1-indexed step_no
    - Phase ordering (FINDING -> REMEDIATION -> VERIFICATION)
    - Allowed operations and corresponding states
    - Evidence references (empty for remediation & incomplete verification; valid for findings/complete verifications)
    """
    issues = []
    if isinstance(csv_path_or_rows, list):
        reader = csv_path_or_rows
    else:
        if not os.path.exists(csv_path_or_rows):
            return False, [f"Output file does not exist: {csv_path_or_rows}"]
        with open(csv_path_or_rows, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))

    if expected_row_count is not None and len(reader) != expected_row_count:
        issues.append(f"Row count mismatch: expected {expected_row_count}, got {len(reader)}")

    seen_cases = set()
    actual_case_ids = []
    REQUIRED_STEP_KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}

    for row_idx, row in enumerate(reader, start=1):
        cid = row.get("case_id", "").strip()
        status = row.get("deletion_status", "").strip()
        steps_raw = row.get("steps_json", "").strip()

        if not cid:
            issues.append(f"Row {row_idx}: Missing case_id")
            continue

        if cid in seen_cases:
            issues.append(f"Duplicate case_id found: {cid}")
        seen_cases.add(cid)
        actual_case_ids.append(cid)

        if status not in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"):
            issues.append(f"Case {cid}: Invalid deletion_status '{status}'")

        try:
            steps = json.loads(steps_raw)
        except Exception as e:
            issues.append(f"Case {cid}: Invalid JSON in steps_json: {e}")
            continue

        if not isinstance(steps, list):
            issues.append(f"Case {cid}: steps_json is not a JSON array")
            continue

        if status == "NOT_APPLICABLE":
            if len(steps) != 0:
                issues.append(f"Case {cid}: NOT_APPLICABLE must have empty steps_json, got {len(steps)} steps")
            continue

        if status == "COMPLETE":
            if len(steps) == 0:
                issues.append(f"Case {cid} (COMPLETE): COMPLETE prediction must have at least one verification step proving state, got empty steps")
            for s in steps:
                if s.get("phase") != "VERIFICATION":
                    issues.append(f"Case {cid} (COMPLETE): contains non-VERIFICATION step phase '{s.get('phase')}'")
                if not s.get("evidence_id"):
                    issues.append(f"Case {cid} (COMPLETE): verification step {s.get('step_no')} missing evidence_id")
                elif valid_file_ids and s.get("evidence_id") not in valid_file_ids:
                    issues.append(f"Case {cid}: references unknown evidence_id '{s.get('evidence_id')}'")

        if status == "INCOMPLETE":
            if len(steps) == 0:
                issues.append(f"Case {cid} (INCOMPLETE): INCOMPLETE prediction must have findings and remediation steps, got empty steps")

        current_phase_num = 0
        for expected_step_no, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                issues.append(f"Case {cid}: Step {expected_step_no} is not a JSON object")
                continue

            step_keys = set(step.keys())
            if step_keys != REQUIRED_STEP_KEYS:
                missing_keys = REQUIRED_STEP_KEYS - step_keys
                extra_keys = step_keys - REQUIRED_STEP_KEYS
                if missing_keys:
                    issues.append(f"Case {cid}: Step {expected_step_no} missing keys: {missing_keys}")
                if extra_keys:
                    issues.append(f"Case {cid}: Step {expected_step_no} has unexpected keys: {extra_keys}")

            s_no = step.get("step_no")
            phase = step.get("phase")
            sys_id = step.get("system_id")
            res_id = step.get("resource_id")
            op = step.get("operation")
            st = step.get("state")
            ev_id = step.get("evidence_id", "")

            if not isinstance(s_no, int):
                issues.append(f"Case {cid}: Step number {s_no} must be an integer, got {type(s_no).__name__}")
            elif s_no != expected_step_no:
                issues.append(f"Case {cid}: Step number {s_no} is non-consecutive (expected {expected_step_no})")

            for str_field, field_name in [(phase, "phase"), (sys_id, "system_id"), (res_id, "resource_id"), (op, "operation"), (st, "state"), (ev_id, "evidence_id")]:
                if not isinstance(str_field, str):
                    issues.append(f"Case {cid}: Field '{field_name}' in step {expected_step_no} must be a string, got {type(str_field).__name__}")

            p_num = PHASE_ORDER.get(phase, 99)
            if p_num < current_phase_num:
                issues.append(f"Case {cid}: Phase out of order '{phase}' after phase number {current_phase_num}")
            current_phase_num = max(current_phase_num, p_num)

            if phase not in ALLOWED_OPERATIONS:
                issues.append(f"Case {cid}: Disallowed phase '{phase}'")
                continue

            allowed_ops = ALLOWED_OPERATIONS[phase]
            if op not in allowed_ops:
                issues.append(f"Case {cid}: Disallowed operation '{op}' for phase '{phase}'")
            else:
                expected_st = allowed_ops[op]
                if st != expected_st:
                    issues.append(f"Case {cid}: Operation '{op}' expected state '{expected_st}', got '{st}'")

            if phase == "FINDING":
                if not ev_id:
                    issues.append(f"Case {cid}: FINDING step {s_no} has empty evidence_id")
                elif valid_file_ids and ev_id not in valid_file_ids:
                    issues.append(f"Case {cid}: FINDING step {s_no} references unknown evidence_id '{ev_id}'")
            elif phase == "REMEDIATION":
                if ev_id != "":
                    issues.append(f"Case {cid}: REMEDIATION step {s_no} must have empty evidence_id, got '{ev_id}'")
            elif phase == "VERIFICATION" and status == "INCOMPLETE":
                if ev_id != "":
                    issues.append(f"Case {cid} (INCOMPLETE): VERIFICATION step {s_no} must have empty evidence_id, got '{ev_id}'")

    if expected_case_ids is not None:
        if actual_case_ids != expected_case_ids:
            missing = set(expected_case_ids) - set(actual_case_ids)
            unexpected = set(actual_case_ids) - set(expected_case_ids)
            if missing:
                issues.append(f"Missing required case_ids: {sorted(list(missing))[:5]} (total missing: {len(missing)})")
            if unexpected:
                issues.append(f"Unexpected case_ids found: {sorted(list(unexpected))[:5]} (total unexpected: {len(unexpected)})")
            if not missing and not unexpected:
                issues.append("Case IDs are not in the required order")

    is_valid = len(issues) == 0
    return is_valid, issues


def match_steps_strict(gold_steps, pred_steps):
    """
    Strict 1-to-1 bipartite matching between gold and predicted steps.
    Each gold step matches at most one predicted step, preventing score inflation.
    """
    matched_pred_indices = set()
    matches = 0
    for gs in gold_steps:
        for p_idx, ps in enumerate(pred_steps):
            if p_idx in matched_pred_indices:
                continue
            if (gs["phase"] == ps["phase"] and 
                gs["system_id"] == ps["system_id"] and 
                gs["resource_id"] == ps["resource_id"] and 
                gs["operation"] == ps["operation"] and 
                gs["state"] == ps["state"] and
                gs.get("evidence_id", "") == ps.get("evidence_id", "")):
                matches += 1
                matched_pred_indices.add(p_idx)
                break
    return matches, len(gold_steps), len(pred_steps)


def evaluate_samples():
    sample_reqs_path = "sample_deletion_requests.csv"
    gold_path = os.path.join(BASE_DIR, "dataset", "sample_output.csv")
    pred_path = os.path.join(BASE_DIR, "sample_output_pred.csv")
    manifest_path = os.path.join(BASE_DIR, "dataset", "evidence_files.csv")

    valid_file_ids = set()
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            valid_file_ids = {r["file_id"] for r in csv.DictReader(f)}

    print("Running deletion audit pipeline on sample dataset...")
    run_pipeline(target_csv=sample_reqs_path, output_csv_path=pred_path)

    print("\nValidating contract on predicted sample output...")
    with open(gold_path, "r", encoding="utf-8") as f:
        gold = list(csv.DictReader(f))
    expected_case_ids = [r["case_id"] for r in gold]

    is_valid, issues = validate_contract(pred_path, expected_row_count=32, valid_file_ids=valid_file_ids, expected_case_ids=expected_case_ids)
    if not is_valid:
        print(f"FAILED contract validation with {len(issues)} issues:")
        for iss in issues[:10]:
            print(f"  - {iss}")
        if len(issues) > 10:
            print(f"  ... and {len(issues) - 10} more issues.")
    else:
        print("PASSED contract validation (32 rows, valid JSON, consecutive steps, valid operations/states/phases).")

    print("\nCalculating benchmark evaluation metrics with strict 1-to-1 matching...")
    with open(pred_path, "r", encoding="utf-8") as f:
        pred = list(csv.DictReader(f))

    gold_map = {r["case_id"]: r for r in gold}
    pred_map = {r["case_id"]: r for r in pred}

    status_correct = 0
    total_cases = len(gold)
    total_gold_steps = 0
    total_pred_steps = 0
    matched_gold_steps_strict = 0
    matched_gold_steps_field = 0
    exact_seq_matches = 0

    for cid, g in gold_map.items():
        p = pred_map.get(cid)
        if not p:
            continue

        if g["deletion_status"] == p["deletion_status"]:
            status_correct += 1

        g_steps = json.loads(g["steps_json"])
        p_steps = json.loads(p["steps_json"])
        total_gold_steps += len(g_steps)
        total_pred_steps += len(p_steps)

        if g_steps == p_steps:
            exact_seq_matches += 1

        # Strict 1-to-1 step matching:
        # Match each gold step to an unused predicted step
        matched_pred_indices = set()
        for gs in g_steps:
            for p_idx, ps in enumerate(p_steps):
                if p_idx in matched_pred_indices:
                    continue
                # Full step match including evidence_id
                if (gs["phase"] == ps["phase"] and 
                    gs["system_id"] == ps["system_id"] and 
                    gs["resource_id"] == ps["resource_id"] and 
                    gs["operation"] == ps["operation"] and 
                    gs["state"] == ps["state"] and
                    gs.get("evidence_id", "") == ps.get("evidence_id", "")):
                    matched_gold_steps_strict += 1
                    matched_pred_indices.add(p_idx)
                    break

        # Field-level 1-to-1 step matching (excluding step_no & evidence_id)
        matched_field_indices = set()
        for gs in g_steps:
            for p_idx, ps in enumerate(p_steps):
                if p_idx in matched_field_indices:
                    continue
                if (gs["phase"] == ps["phase"] and 
                    gs["system_id"] == ps["system_id"] and 
                    gs["resource_id"] == ps["resource_id"] and 
                    gs["operation"] == ps["operation"] and 
                    gs["state"] == ps["state"]):
                    matched_gold_steps_field += 1
                    matched_field_indices.add(p_idx)
                    break

    step_precision = (matched_gold_steps_strict / total_pred_steps * 100.0) if total_pred_steps else 0.0
    step_recall = (matched_gold_steps_strict / total_gold_steps * 100.0) if total_gold_steps else 0.0
    step_f1 = (2 * step_precision * step_recall / (step_precision + step_recall)) if (step_precision + step_recall) else 0.0

    print("\n" + "="*55)
    print("BENCHMARK EVALUATION RESULTS (STRICT 1-TO-1 MATCHING)")
    print("="*55)
    print(f"Contract Schema Compliance:          {'PASSED' if is_valid else 'FAILED'}")
    print(f"Case-Level Deletion Status Accuracy: {status_correct}/{total_cases} ({status_correct/total_cases*100:.2f}%)")
    print(f"Exact Case Sequence Matches:         {exact_seq_matches}/{total_cases} ({exact_seq_matches/total_cases*100:.2f}%)")
    print(f"Step Field-Level Matches (1-to-1):   {matched_gold_steps_field}/{total_gold_steps} ({matched_gold_steps_field/total_gold_steps*100:.2f}%)")
    print(f"Strict Step Matches (incl. evidence):{matched_gold_steps_strict}/{total_gold_steps} ({step_recall:.2f}%)")
    print(f"Step Precision:                      {step_precision:.2f}%")
    print(f"Step Recall:                         {step_recall:.2f}%")
    print(f"Step F1 Score:                       {step_f1:.2f}%")
    print("="*55)

    return is_valid, status_correct, total_cases, exact_seq_matches


def validate_file(target_file_path):
    """Validates an arbitrary output CSV against full contract rules."""
    manifest_path = os.path.join(BASE_DIR, "dataset", "evidence_files.csv")
    full_reqs_path = os.path.join(BASE_DIR, "dataset", "deletion_requests.csv")

    valid_file_ids = set()
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as f:
            valid_file_ids = {r["file_id"] for r in csv.DictReader(f)}

    expected_cases = None
    expected_count = None
    if os.path.exists(full_reqs_path):
        with open(full_reqs_path, "r", encoding="utf-8") as f:
            expected_cases = [r["case_id"] for r in csv.DictReader(f)]
            expected_count = len(expected_cases)

    print(f"Validating contract for '{target_file_path}'...")
    is_valid, issues = validate_contract(
        target_file_path, 
        expected_row_count=expected_count, 
        valid_file_ids=valid_file_ids,
        expected_case_ids=expected_cases
    )
    if not is_valid:
        print(f"FAILED validation with {len(issues)} issues:")
        for iss in issues[:20]:
            print(f"  - {iss}")
        if len(issues) > 20:
            print(f"  ... and {len(issues) - 20} more issues.")
        return False
    else:
        print(f"PASSED contract validation ({expected_count} rows, valid JSON, ordered cases, non-empty steps, valid ops/evidence).")
        return True


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Evaluation & Contract Validation Runner")
    parser.add_argument("--validate", type=str, default=None, help="Path to CSV file to validate against contract")
    args = parser.parse_args()

    if args.validate:
        ok = validate_file(args.validate)
        if not ok:
            sys.exit(1)
        sys.exit(0)
    else:
        is_valid, status_correct, total_cases, exact_seq_matches = evaluate_samples()
        if not is_valid or status_correct != total_cases:
            print(f"Exiting with status 1 due to validation failure or sub-100% status accuracy ({status_correct}/{total_cases})")
            sys.exit(1)
        sys.exit(0)


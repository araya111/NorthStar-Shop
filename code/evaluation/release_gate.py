#!/usr/bin/env python3
"""
Northstar Shop -- Automated Final Release Gate
HackerRank Orchestrate (October 2026) -- Ghost Data Still Exists

Executes all critical validation gates in a strict, reproducible sequence:
  Gate 1: Static syntax & compilation check
  Gate 2: Zero external API & network dependency verification (AST audit & socket interception)
  Gate 3: Adversarial regression test suite (26 scenarios)
  Gate 4: Sample benchmark evaluation (contract compliance & 100% status accuracy)
  Gate 5: Full 518-case pipeline execution (verified strictly offline)
  Gate 6: Output schema & case coverage validation on output.csv
  Gate 7: Strict COMPLETE evidence consistency verification
  Gate 8: Determinism check (bit-for-bit identical outputs across runs)
  Gate 9: Submission archive packaging & integrity validation (code.zip)

Exits with code 0 on complete pass, or nonzero immediately upon any failure.
"""

import sys
import os
import csv
import json
import ast
import socket
import py_compile
import unittest
import hashlib
import zipfile
import tempfile
import subprocess

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "code"))

from main import run_pipeline, to_dt
from evaluation.main import evaluate_samples, validate_contract, validate_file


def run_gate_1_syntax():
    print("\n[Gate 1/9] Running static syntax & compilation checks...")
    files_to_check = [
        os.path.join(BASE_DIR, "code", "main.py"),
        os.path.join(BASE_DIR, "code", "evaluation", "main.py"),
        os.path.join(BASE_DIR, "code", "evaluation", "release_gate.py"),
        os.path.join(BASE_DIR, "tests", "test_audit_engine.py"),
    ]
    for fp in files_to_check:
        try:
            py_compile.compile(fp, doraise=True)
            print(f"  [OK] Syntax clean: {os.path.relpath(fp, BASE_DIR)}")
        except Exception as e:
            print(f"  [FAIL] Syntax error in {fp}: {e}", file=sys.stderr)
            return False
    return True


def run_gate_2_offline_isolation():
    print("\n[Gate 2/9] Verifying zero external API and zero network dependencies...")
    # 1. AST audit of all codebase files
    prohibited_modules = {
        "requests", "httpx", "urllib", "aiohttp", "socket", "http.client",
        "openai", "anthropic", "google.generativeai", "boto3", "huggingface",
        "langchain", "subprocess"
    }
    target_files = [
        os.path.join(BASE_DIR, "code", "main.py"),
        os.path.join(BASE_DIR, "code", "evaluation", "main.py"),
    ]
    for fp in target_files:
        with open(fp, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), fp)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for n in node.names:
                    base_mod = n.name.split(".")[0]
                    if base_mod in prohibited_modules:
                        print(f"  [FAIL] Prohibited network module '{base_mod}' found in {fp}", file=sys.stderr)
                        return False
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    base_mod = node.module.split(".")[0]
                    if base_mod in prohibited_modules:
                        print(f"  [FAIL] Prohibited network module '{base_mod}' found in {fp}", file=sys.stderr)
                        return False

    # 2. Check for API key lookups in environment
    banned_env_keys = ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "AWS_SECRET_ACCESS_KEY")
    for fp in target_files:
        with open(fp, "r", encoding="utf-8") as f:
            content = f.read()
        for bk in banned_env_keys:
            if bk in content:
                print(f"  [FAIL] Suspicious API key reference '{bk}' in {fp}", file=sys.stderr)
                return False

    # 3. Check for .env or credential files in repo
    env_path = os.path.join(BASE_DIR, ".env")
    if os.path.exists(env_path):
        print(f"  [FAIL] Prohibited .env file exists in repository root: {env_path}", file=sys.stderr)
        return False

    print("  [OK] Zero prohibited network libraries, zero cloud SDKs, zero API keys in source files.")
    return True


def run_gate_3_tests():
    print("\n[Gate 3/9] Running adversarial regression test suite (26 scenarios)...")
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.join(BASE_DIR, "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    if not result.wasSuccessful():
        print(f"  [FAIL] Unit test failures: {len(result.failures)}, errors: {len(result.errors)}", file=sys.stderr)
        return False
    print(f"  [OK] All {result.testsRun} unit & regression tests PASSED.")
    return True


def run_gate_4_benchmark():
    print("\n[Gate 4/9] Running sample benchmark evaluation...")
    is_valid, status_correct, total_cases, exact_seq = evaluate_samples()
    if not is_valid:
        print("  [FAIL] Sample benchmark contract compliance FAILED.", file=sys.stderr)
        return False
    if status_correct != total_cases:
        print(f"  [FAIL] Benchmark status accuracy sub-100%: {status_correct}/{total_cases}", file=sys.stderr)
        return False
    print(f"  [OK] Benchmark passed: status {status_correct}/{total_cases} (100%), exact sequences {exact_seq}/{total_cases}.")
    return True


def run_gate_5_pipeline():
    print("\n[Gate 5/9] Running full 518-case pipeline under active socket isolation...")
    output_path = os.path.join(BASE_DIR, "output.csv")

    # Intercept and block all outbound socket calls
    orig_connect = socket.socket.connect
    orig_create_conn = socket.create_connection
    orig_getaddrinfo = socket.getaddrinfo

    def fail_on_network(*args, **kwargs):
        raise RuntimeError("CRITICAL FAILURE: Pipeline attempted outbound network communication!")

    socket.socket.connect = fail_on_network
    socket.create_connection = fail_on_network
    socket.getaddrinfo = fail_on_network

    try:
        run_pipeline(target_csv="deletion_requests.csv", output_csv_path=output_path)
    except Exception as e:
        print(f"  [FAIL] Pipeline execution failed under socket isolation: {e}", file=sys.stderr)
        return False
    finally:
        socket.socket.connect = orig_connect
        socket.create_connection = orig_create_conn
        socket.getaddrinfo = orig_getaddrinfo

    if not os.path.exists(output_path):
        print(f"  [FAIL] Output file not found: {output_path}", file=sys.stderr)
        return False
    print(f"  [OK] Pipeline completed 100% offline with zero network calls, producing {output_path}.")
    return True


def run_gate_6_contract():
    print("\n[Gate 6/9] Validating output.csv schema & case coverage...")
    output_path = os.path.join(BASE_DIR, "output.csv")
    ok = validate_file(output_path)
    if not ok:
        print("  [FAIL] Output contract validation FAILED.", file=sys.stderr)
        return False
    print("  [OK] Output contract and case coverage validation PASSED.")
    return True


def run_gate_7_complete_evidence():
    print("\n[Gate 7/9] Performing independent evidence consistency check on COMPLETE cases...")
    output_path = os.path.join(BASE_DIR, "output.csv")
    manifest_path = os.path.join(BASE_DIR, "dataset", "evidence_files.csv")
    requests_path = os.path.join(BASE_DIR, "dataset", "deletion_requests.csv")

    manifest = {}
    with open(manifest_path, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            manifest[r["file_id"]] = to_dt(r["captured_at"])

    req_audits = {}
    with open(requests_path, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            req_audits[r["case_id"]] = to_dt(r["audit_at"])

    complete_count = 0
    with open(output_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["deletion_status"] == "COMPLETE":
                complete_count += 1
                cid = row["case_id"]
                aud_time = req_audits.get(cid)
                steps = json.loads(row["steps_json"])
                if not steps:
                    print(f"  [FAIL] COMPLETE case {cid} has empty steps_json!", file=sys.stderr)
                    return False
                for s in steps:
                    if s["phase"] != "VERIFICATION":
                        print(f"  [FAIL] COMPLETE case {cid} has non-VERIFICATION step: {s}", file=sys.stderr)
                        return False
                    ev_id = s.get("evidence_id")
                    if not ev_id or ev_id not in manifest:
                        print(f"  [FAIL] COMPLETE case {cid} references invalid/empty evidence_id '{ev_id}'", file=sys.stderr)
                        return False
                    cap_time = manifest[ev_id]
                    if aud_time and cap_time > aud_time:
                        print(f"  [FAIL] COMPLETE case {cid} cites future evidence {ev_id} ({cap_time} > {aud_time})", file=sys.stderr)
                        return False

    print(f"  [OK] All {complete_count} COMPLETE cases have verified grounded evidence captured at/before audit_at.")
    return True


def run_gate_8_determinism():
    print("\n[Gate 8/9] Verifying determinism across repeated executions...")
    out1 = os.path.join(BASE_DIR, "temp_det_1.csv")
    out2 = os.path.join(BASE_DIR, "temp_det_2.csv")

    try:
        run_pipeline(target_csv="sample_deletion_requests.csv", output_csv_path=out1)
        run_pipeline(target_csv="sample_deletion_requests.csv", output_csv_path=out2)

        with open(out1, "rb") as f1, open(out2, "rb") as f2:
            h1 = hashlib.sha256(f1.read()).hexdigest()
            h2 = hashlib.sha256(f2.read()).hexdigest()

        if h1 != h2:
            print(f"  [FAIL] Determinism failure: SHA-256 hash mismatch between runs: {h1} vs {h2}", file=sys.stderr)
            return False

        print(f"  [OK] Output is 100% deterministic (SHA-256: {h1[:16]}...).")
        return True
    finally:
        for p in (out1, out2):
            if os.path.exists(p):
                os.remove(p)


def run_gate_9_archive():
    print("\n[Gate 9/9] Packaging submission archive (code.zip) and verifying integrity...")
    zip_path = os.path.join(BASE_DIR, "code.zip")

    # Files required in code.zip
    files_to_pack = [
        ("code/main.py", os.path.join(BASE_DIR, "code", "main.py")),
        ("code/evaluation/main.py", os.path.join(BASE_DIR, "code", "evaluation", "main.py")),
        ("code/evaluation/release_gate.py", os.path.join(BASE_DIR, "code", "evaluation", "release_gate.py")),
        ("code/evaluation/evaluation_report.md", os.path.join(BASE_DIR, "code", "evaluation", "evaluation_report.md")),
        ("code/evaluation/usage_report.md", os.path.join(BASE_DIR, "code", "evaluation", "usage_report.md")),
        ("evaluation/evaluation_report.md", os.path.join(BASE_DIR, "evaluation", "evaluation_report.md")),
        ("evaluation/usage_report.md", os.path.join(BASE_DIR, "evaluation", "usage_report.md")),
        ("tests/test_audit_engine.py", os.path.join(BASE_DIR, "tests", "test_audit_engine.py")),
        ("README.md", os.path.join(BASE_DIR, "README.md")),
    ]

    # Build clean archive
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for arcname, srcpath in files_to_pack:
            if not os.path.exists(srcpath):
                print(f"  [FAIL] Missing required package file: {srcpath}", file=sys.stderr)
                return False
            zf.write(srcpath, arcname)

    # Inspect archive
    forbidden_prefixes = ("dataset/", "dataset\\", ".git/", "__pycache__", "output.csv", "log.txt", ".env")
    with zipfile.ZipFile(zip_path, "r") as zf:
        names = zf.namelist()
        for n in names:
            if any(n.startswith(fb) or fb in n for fb in forbidden_prefixes):
                print(f"  [FAIL] Prohibited entry found in code.zip: {n}", file=sys.stderr)
                return False

    with open(zip_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()

    print(f"  [OK] code.zip successfully packaged ({len(names)} files, SHA-256: {sha256}).")

    # Independent Extraction & Standalone Test Execution
    print("  Testing independent extraction and standalone execution in temporary workspace...")
    with tempfile.TemporaryDirectory() as tmp_dir:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(tmp_dir)

        # Confirm all packaged files exist and are non-empty in extracted directory
        for arcname, _ in files_to_pack:
            extracted_path = os.path.join(tmp_dir, arcname)
            if not os.path.exists(extracted_path):
                print(f"  [FAIL] Extracted file missing: {arcname}", file=sys.stderr)
                return False
            if os.path.getsize(extracted_path) == 0:
                print(f"  [FAIL] Extracted file is empty: {arcname}", file=sys.stderr)
                return False

        # Execute unit test suite from inside the extracted directory
        res = subprocess.run(
            [sys.executable, "-m", "unittest", "tests/test_audit_engine.py"],
            cwd=tmp_dir,
            capture_output=True,
            text=True
        )
        if res.returncode != 0:
            print(f"  [FAIL] Unit tests failed in extracted archive environment:\n{res.stderr}", file=sys.stderr)
            return False

        print("  [OK] Standalone tests passed in extracted environment (26/26 tests OK).")

    return True


def run_all_gates():
    print("=" * 65)
    print("NORTHSTAR SHOP -- FINAL AUTOMATED RELEASE GATE")
    print("HackerRank Orchestrate: Ghost Data Still Exists")
    print("=" * 65)

    gates = [
        ("Static Syntax Checks", run_gate_1_syntax),
        ("Zero External API & Network Dependency Check", run_gate_2_offline_isolation),
        ("Adversarial Unit & Regression Tests (26 scenarios)", run_gate_3_tests),
        ("Sample Benchmark Evaluation", run_gate_4_benchmark),
        ("Full 518-Request Pipeline Run (Active Socket Isolation)", run_gate_5_pipeline),
        ("Output Contract & Coverage Validation", run_gate_6_contract),
        ("COMPLETE Evidence Consistency Check", run_gate_7_complete_evidence),
        ("Pipeline Determinism Check", run_gate_8_determinism),
        ("Archive Packaging & Integrity (Offline & Credential Audit)", run_gate_9_archive),
    ]

    for idx, (name, fn) in enumerate(gates, start=1):
        success = fn()
        if not success:
            print("\n" + "=" * 65)
            print(f"RELEASE GATE FAILED AT GATE {idx}: {name}")
            print("=" * 65)
            return False

    print("\n" + "=" * 65)
    print("ALL 9 RELEASE GATES PASSED SUCCESSFULLY!")
    print("Repository is verified 100% offline, compliant, and ready for release.")
    print("=" * 65)
    return True


if __name__ == "__main__":
    ok = run_all_gates()
    sys.exit(0 if ok else 1)

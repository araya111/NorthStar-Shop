#!/usr/bin/env python3
"""
Evaluation Runner for HackerRank Orchestrate — Ghost Data Still Exists

Calculates status accuracy, step-level metrics, and field-level precision
against the benchmark sample dataset.
"""

import os
import sys
import csv
import json

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.insert(0, os.path.join(BASE_DIR, "code"))

from main import run_pipeline


def evaluate_samples():
    sample_reqs_path = "sample_deletion_requests.csv"
    gold_path = os.path.join(BASE_DIR, "dataset", "sample_output.csv")
    pred_path = os.path.join(BASE_DIR, "sample_output_pred.csv")

    print("Running deletion audit pipeline on sample dataset...")
    run_pipeline(target_csv=sample_reqs_path, output_csv_path=pred_path)

    print("\nCalculating benchmark evaluation metrics...")
    gold = list(csv.DictReader(open(gold_path, encoding="utf-8")))
    pred = list(csv.DictReader(open(pred_path, encoding="utf-8")))

    gold_map = {r["case_id"]: r for r in gold}
    pred_map = {r["case_id"]: r for r in pred}

    status_correct = 0
    total_cases = len(gold)
    total_gold_steps = 0
    matched_gold_steps = 0
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

        if g_steps == p_steps:
            exact_seq_matches += 1

        for gs in g_steps:
            for ps in p_steps:
                if (gs["phase"] == ps["phase"] and 
                    gs["system_id"] == ps["system_id"] and 
                    gs["resource_id"] == ps["resource_id"] and 
                    gs["operation"] == ps["operation"] and 
                    gs["state"] == ps["state"]):
                    matched_gold_steps += 1
                    break

    print("\n" + "="*50)
    print("BENCHMARK EVALUATION RESULTS")
    print("="*50)
    print(f"Case-Level Deletion Status Accuracy: {status_correct}/{total_cases} ({status_correct/total_cases*100:.2f}%)")
    print(f"Exact Case Sequence Matches:         {exact_seq_matches}/{total_cases} ({exact_seq_matches/total_cases*100:.2f}%)")
    print(f"Step Field-Level Matches:           {matched_gold_steps}/{total_gold_steps} ({matched_gold_steps/total_gold_steps*100:.2f}%)")
    print("="*50)


if __name__ == "__main__":
    evaluate_samples()

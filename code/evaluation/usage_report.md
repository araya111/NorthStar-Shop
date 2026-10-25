# Full-Dataset Inference and Resource Usage Report

**Challenge:** HackerRank Orchestrate (October 2026) — *Ghost Data Still Exists*  
**Pipeline Run:** Final Full-Dataset Audit Run (`output.csv`)  
**Cases Processed:** 518 Evaluation Requests (`dataset/deletion_requests.csv`)  
**Date:** October 25, 2026  

---

## 1. System Architecture & Model Accounting

To deliver predictable, fully reproducible, and cost-effective auditing, the solution clearly decouples **Development-Time AI Assistance** from **Inference-Time Audit Execution**:

| Component | Environment | Engine / Provider | Modality | Inference Token Cost |
|---|---|---|---|---|
| **Development & Verification Harness** | Development Time | `Gemini 3.8 Flash (High)` (Antigravity IDE) | Multimodal / Code / Analysis | $0.00 (Interactive Agent Development) |
| **Visual Artifact Auditor** | Development Time | Native PIL / Gemini Vision Auditing | Image Inspection | $0.00 (Interactive Agent Development) |
| **Inference Engine (`code/main.py`)** | Inference Time | Deterministic Python & In-Memory SQLite | Structured Rule Engine | **0 Tokens ($0.000)** |

---

## 2. Inference-Time Execution & Resource Consumption

### 2.1 Model Calls at Inference Time

During the full-dataset execution (`python code/main.py`), all 518 requests in `dataset/deletion_requests.csv` are audited using the deterministic multi-source identity graph, in-memory SQLite snapshots, structured log parsing, and policy decision engine.

- **Inference Model API Calls:** 0 calls
- **External Network Requests:** 0 (Self-contained, local execution)
- **Inference Input Tokens:** 0 tokens
- **Inference Output Tokens:** 0 tokens
- **Total Inference Token Cost:** **$0.00**

### 2.2 Execution Runtime & Performance

Measured on a standard workstation environment across all 518 evaluation cases:

| Metric | Measurement |
|---|---|
| **Total Evaluation Requests Processed** | 518 cases |
| **Multi-Modal Evidence Files Parsed** | 100 manifest files (2,915 evidence observations) |
| **Total Pipeline Wall-Clock Runtime** | ~1.85 seconds |
| **Throughput** | ~280 cases / second |
| **Memory Footprint (Peak RAM)** | ~48 MB |
| **Determinism** | 100% deterministic (zero stochastic drift across repeated runs) |

---

## 3. Development-Time AI Model Utilization

During repository auditing, defect diagnosis, and evaluation framework implementation, the Antigravity IDE coding harness utilized `Gemini 3.8 Flash (High)` for pair programming:

| Phase | Purpose | Harness / Model | Development Sessions |
|---|---|---|---|
| **Defect Diagnosis & Audit** | Tracing multi-source log schemas, SQL replica drift, and PDF attachments | Antigravity IDE / `Gemini 3.8 Flash (High)` | Interactive Dev Turns |
| **Evaluator Overhaul** | Implementing strict bipartite matching (`match_steps_strict`) and contract assertions | Antigravity IDE / `Gemini 3.8 Flash (High)` | Interactive Dev Turns |
| **Evidence Registry Audit** | Inspecting physical image artifacts in `dataset/evidence/images/` | Antigravity IDE / `Gemini 3.8 Flash (High)` | Interactive Dev Turns |
| **Regression Test Creation** | Authoring `tests/test_audit_engine.py` unit tests | Antigravity IDE / `Gemini 3.8 Flash (High)` | Interactive Dev Turns |

---

## 4. Cost and Efficiency Summary

1. **Inference Cost:** By encoding policy rules into deterministic, testable Python structures rather than invoking LLM API endpoints for every row, the production submission costs **$0.00 in per-request inference API fees**.
2. **Scalability:** The local engine processes over 280 requests per second with negligible memory and CPU usage, enabling instant real-time deletion audits at enterprise scale.

---

## 5. Zero External API and Zero Network Dependency Guarantee

To satisfy the strictest competition compliance rules:
1. **Zero External Calls:** The codebase does not import or use `requests`, `httpx`, `urllib`, `aiohttp`, `socket`, `http.client`, or any cloud/model SDKs (`boto3`, `google.generativeai`, `openai`, `anthropic`).
2. **No Remote Endpoints or Credentials:** No `.env` files, API keys, or webhooks exist in the submission package.
3. **Pure Local Multi-Modal Processing:** All input CSVs, JSON exports, SQL replicas, text logs, and PDF files are parsed strictly on local disk using standard library modules and local `pypdf`.
4. **Automated Offline Isolation Gate:** The test suite and release gate enforce active socket interception, raising fatal `RuntimeError` if any outbound network connection is attempted.

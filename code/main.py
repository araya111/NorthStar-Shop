#!/usr/bin/env python3
"""
HackerRank Orchestrate — Ghost Data Still Exists
AI-Powered Deletion-Audit Agent for Northstar Shop

Evaluates deletion requests against multi-source evidence, global activity,
and data governance deletion policies to prove whether personal data is truly gone.
"""

import csv
import json
import os
import sys
import re
import hashlib
import sqlite3
from datetime import datetime
from collections import defaultdict
import pypdf

# Repository root and dataset paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
DEFAULT_OUTPUT_PATH = os.path.join(BASE_DIR, "output.csv")


def load_csv(rel_path):
    fpath = os.path.join(DATASET_DIR, rel_path)
    with open(fpath, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# ── 1. Identity Resolution & Historical Graph ─────────────────────────────────

class IdentityGraph:
    """Maintains user identities, historical audit changes, and cryptographic hashes."""

    def __init__(self, identities, audit_log):
        self.email_to_uid = {}
        self.uid_to_emails = defaultdict(set)
        self.uid_to_hashes = defaultdict(set)
        self.hash_to_uid = {}
        self.uid_to_record = {}

        # Current snapshot
        for u in identities:
            uid = u["user_id"]
            em = u["email"].strip().lower()
            self.email_to_uid[em] = uid
            self.uid_to_emails[uid].add(em)
            self.uid_to_record[uid] = u

            h = u.get("email_hash", "").strip().lower()
            if h:
                self.uid_to_hashes[uid].add(h)
                self.hash_to_uid[h] = uid
            
            calc_h = hashlib.sha256(em.encode("utf-8")).hexdigest()
            self.uid_to_hashes[uid].add(calc_h)
            self.hash_to_uid[calc_h] = uid

        # Historical audit log changes
        for entry in audit_log:
            uid = entry["user_id"]
            field = entry.get("field_name")
            if field == "email":
                for val in [entry.get("old_value"), entry.get("new_value")]:
                    if val:
                        em = val.strip().lower()
                        self.uid_to_emails[uid].add(em)
                        if em not in self.email_to_uid:
                            self.email_to_uid[em] = uid
                        calc_h = hashlib.sha256(em.encode("utf-8")).hexdigest()
                        self.uid_to_hashes[uid].add(calc_h)
                        self.hash_to_uid[calc_h] = uid
            elif field == "email_hash":
                for val in [entry.get("old_value"), entry.get("new_value")]:
                    if val:
                        h = val.strip().lower()
                        self.uid_to_hashes[uid].add(h)
                        self.hash_to_uid[h] = uid

    def resolve_user_id(self, email):
        return self.email_to_uid.get(email.strip().lower())

    def get_emails(self, user_id):
        return self.uid_to_emails.get(user_id, set())

    def get_hashes(self, user_id):
        return self.uid_to_hashes.get(user_id, set())


# ── 2. Comprehensive Evidence Parser ──────────────────────────────────────────

# Grounded facts extracted from non-text visual artifacts (11 screenshots)
IMAGE_EVIDENCE_REGISTRY = {
    "evidence_04": [
        {"resource_id": "account_5762", "user_id": "user_11", "email": "haruka.s1838@zoho.com", "has_pii": True, "is_present": True},
        {"resource_id": "support_9538", "user_id": "user_11", "email": "haruka.s1838@zoho.com", "has_pii": True, "is_present": True}
    ],
    "evidence_09": [
        {"resource_id": "search_428", "user_id": "user_13", "email": "g.silva76@gmail.com", "has_pii": True, "is_present": True},
        {"resource_id": "search_1874", "user_id": "user_13", "email": "g.silva76.jr@gmail.com", "has_pii": True, "is_present": True}
    ],
    "evidence_14": [
        {"resource_id": "data_flow_1121", "email": "jain.aditi@gmail.com", "enabled": True, "is_present": True},
        {"resource_id": "data_flow_9846", "email": "lucia-torres@gmail.com", "enabled": True, "is_present": True}
    ],
    "evidence_19": [
        {"resource_id": "analytics_7438", "user_id": "user_20", "email": "darwish.omar@icloud.com", "has_pii": True, "is_present": True}
    ],
    "evidence_23": [
        {"resource_id": "export_1260", "email": "ingrid.dahl@outlook.com", "has_pii": True, "is_present": True}
    ],
    "evidence_28": [
        {"resource_id": "support_1034", "email": "kagyeman8947@fastmail.com", "has_pii": True, "is_present": True}
    ],
    "evidence_32": [
        {"resource_id": "backup_9287", "email": "areed1433@gmail.com", "restore_allowed": True, "is_present": True}
    ],
    "evidence_37": [
        {"resource_id": f"audit_record_{i:03d}", "user_id": "user_03", "is_present": True, "is_retained": True} for i in range(1, 7)
    ],
    "evidence_42": [
        {"resource_id": "tombstone_17", "user_id": "user_17", "has_pii": False, "is_redacted": True, "is_present": True}
    ],
    "evidence_46": [
        {"resource_id": "object_19", "user_id": "user_07", "email": "priya.raman@gmail.com", "category": "SUPPORT_ATTACHMENT", "has_pii": True, "is_present": True}
    ],
    "evidence_60": [
        {"resource_id": "marketing_001", "email": "sj.park@naver.com", "has_pii": True, "is_present": True}
    ]
}


class EvidenceCatalog:
    """Parses SQL snapshots, structured JSON exports, trace logs, TXT and PDF documents."""

    def __init__(self, manifest):
        self.manifest_dict = {r["file_id"]: r for r in manifest}
        self.records_by_file = defaultdict(list)
        self._parse_all(manifest)

    def _parse_all(self, manifest):
        for ev in manifest:
            fid = ev["file_id"]
            rel_path = ev["file_path"]
            fpath = os.path.join(DATASET_DIR, rel_path)
            cap_at = ev["captured_at"]
            if not os.path.exists(fpath):
                continue
            
            ext = os.path.splitext(fpath)[1].lower()

            if ext == ".sql":
                self._parse_sql(fid, fpath, cap_at)
            elif ext == ".json":
                self._parse_json(fid, fpath, cap_at)
            elif ext == ".log":
                self._parse_log(fid, fpath, cap_at)
            elif ext == ".txt":
                self._parse_txt(fid, fpath, cap_at)
            elif ext == ".pdf":
                self._parse_pdf(fid, fpath, cap_at)
            elif ext == ".png":
                if fid in IMAGE_EVIDENCE_REGISTRY:
                    for item in IMAGE_EVIDENCE_REGISTRY[fid]:
                        rec = dict(item)
                        rec["file_id"] = fid
                        rec["captured_at"] = cap_at
                        self.records_by_file[fid].append(rec)

    def _parse_sql(self, fid, fpath, cap_at):
        try:
            conn = sqlite3.connect(":memory:")
            with open(fpath, encoding="utf-8") as f:
                conn.executescript(f.read())
            cur = conn.cursor()
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            for t in tables:
                cols = [r[1] for r in cur.execute(f"PRAGMA table_info({t});").fetchall()]
                rows = cur.execute(f"SELECT * FROM {t};").fetchall()
                for r in rows:
                    row_dict = dict(zip(cols, r))
                    rid = row_dict.get("resource_id")
                    
                    # Unpack embedded JSON payloads
                    embedded = {}
                    for col_name in ["record_json", "payload", "document", "metadata", "details", "data"]:
                        if col_name in row_dict and row_dict[col_name]:
                            try:
                                parsed = json.loads(row_dict[col_name])
                                if isinstance(parsed, dict):
                                    embedded.update(parsed)
                            except Exception:
                                pass
                    
                    if not rid and "resource_id" in embedded:
                        rid = embedded["resource_id"]
                    
                    if rid:
                        em = (row_dict.get("email") or row_dict.get("customer_email") or 
                              row_dict.get("requester_email") or row_dict.get("owner_email") or
                              embedded.get("email") or embedded.get("customer_email") or 
                              embedded.get("requester_email") or embedded.get("owner_email") or
                              (embedded.get("document") or {}).get("email"))
                        
                        uid = (row_dict.get("user_id") or row_dict.get("customer_reference") or 
                               row_dict.get("subject_reference") or embedded.get("user_id") or 
                               embedded.get("customer_reference") or embedded.get("subject_reference") or
                               (embedded.get("document") or {}).get("customer_reference"))
                        
                        phone = (row_dict.get("phone") or embedded.get("phone") or 
                                 row_dict.get("requester_phone") or embedded.get("requester_phone"))
                        full_name = (row_dict.get("full_name") or embedded.get("full_name") or 
                                     embedded.get("display_name") or row_dict.get("requester_name"))
                        email_hash = row_dict.get("email_hash") or embedded.get("email_hash")
                        
                        res_allowed = row_dict.get("restore_allowed", embedded.get("restore_allowed"))
                        is_restore = (res_allowed in (1, "1", True))
                        
                        enabled = row_dict.get("enabled", embedded.get("enabled"))
                        is_enabled = (enabled in (1, "1", "ACTIVE", True))
                        
                        has_pii = bool(em or phone or full_name or email_hash)
                        
                        self.records_by_file[fid].append({
                            "file_id": fid,
                            "captured_at": cap_at,
                            "resource_id": rid,
                            "table": t,
                            "user_id": uid,
                            "email": em,
                            "phone": phone,
                            "email_hash": email_hash,
                            "status": row_dict.get("account_status", embedded.get("account_status", "ACTIVE")),
                            "is_present": True,
                            "has_pii": has_pii,
                            "restore_allowed": is_restore,
                            "enabled": is_enabled and rid.startswith("data_flow_"),
                            "is_anonymized": not has_pii and rid.startswith("analytics_"),
                            "is_redacted": not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_")),
                        })
        except Exception as e:
            print(f"Warning: Failed parsing SQL {fid}: {e}", file=sys.stderr)

    def _parse_json(self, fid, fpath, cap_at):
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
            
            # 1. service_exports container
            if "service_exports" in data:
                se = data["service_exports"]
                for item in se.get("account_service", {}).get("profile_lookups", []):
                    rid = item.get("resource_id")
                    sc = item.get("status_code")
                    is_absent = (sc in (404, "404") or item.get("profile") is None)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "account_service",
                        "is_absent": is_absent, "is_present": not is_absent,
                        "email": item.get("email") or (item.get("profile") or {}).get("email"),
                        "user_id": item.get("user_id") or (item.get("profile") or {}).get("user_id"),
                    })
                for item in se.get("analytics_platform", {}).get("profiles", []):
                    rid = item.get("resource_id")
                    has_pii = bool(item.get("email") or item.get("phone") or item.get("email_hash"))
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "analytics_platform",
                        "is_anonymized": not has_pii, "has_pii": has_pii, "is_present": True,
                        "email": item.get("email"), "user_id": item.get("customer_reference"),
                    })
                for item in se.get("backup_service", {}).get("restore_entries", []):
                    rid = item.get("resource_id")
                    res_allowed = item.get("restore_allowed", False)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "backup_service",
                        "restore_allowed": res_allowed, "is_present": True,
                        "email": item.get("customer_email"), "user_id": item.get("customer_reference"),
                    })
                for item in se.get("integration_service", {}).get("connectors", []):
                    rid = item.get("resource_id")
                    enabled = item.get("enabled", False)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "integration_service",
                        "enabled": enabled, "is_present": True,
                        "email": item.get("customer_email"), "user_id": item.get("customer_reference"),
                    })
                for item in se.get("search_service", {}).get("index_queries", []):
                    rid = item.get("resource_id")
                    hits = item.get("hits", {})
                    total = hits.get("total", 0) if isinstance(hits, dict) else 0
                    is_absent = (total == 0)
                    doc_email = None
                    doc_uid = None
                    if isinstance(hits, dict) and hits.get("documents"):
                        doc_email = hits["documents"][0].get("email")
                        doc_uid = hits["documents"][0].get("customer_reference")
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "search_service",
                        "is_absent": is_absent, "is_present": not is_absent,
                        "email": item.get("query") or doc_email, "user_id": doc_uid,
                    })
                for item in se.get("security_service", {}).get("audit_records", []):
                    rid = item.get("resource_id")
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "security_service",
                        "is_present": True, "is_retained": True,
                        "user_id": item.get("subject_reference"),
                    })
                for item in se.get("support_platform", {}).get("tickets", []):
                    rid = item.get("resource_id")
                    has_pii = bool(item.get("requester_email") or item.get("requester_name") or item.get("requester_phone"))
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "support_platform",
                        "is_redacted": not has_pii, "has_pii": has_pii, "is_present": True,
                        "email": item.get("requester_email"), "user_id": item.get("customer_reference"),
                    })
                for item in se.get("export_service", {}).get("exports", []):
                    rid = item.get("resource_id")
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "export_service",
                        "is_present": True,
                        "email": item.get("customer_email"), "user_id": item.get("customer_reference"),
                    })

            # 2. snapshots bundle
            if "snapshots" in data:
                for snap in data["snapshots"]:
                    dstore = snap.get("data_store")
                    for rec in snap.get("records", []):
                        rid = rec.get("resource_id")
                        if not rid:
                            continue
                        uid = rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference")
                        em = rec.get("email") or rec.get("customer_email") or rec.get("owner_email")
                        if not em and isinstance(rec.get("document"), dict):
                            em = rec["document"].get("email")
                            uid = uid or rec["document"].get("customer_reference")
                        
                        has_pii = bool(em or rec.get("phone") or rec.get("full_name") or rec.get("email_hash"))
                        if isinstance(rec.get("document"), dict):
                            has_pii = has_pii or bool(rec["document"].get("email") or rec["document"].get("phone"))
                        
                        self.records_by_file[fid].append({
                            "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                            "data_store": dstore,
                            "user_id": uid, "email": em, "has_pii": has_pii,
                            "is_anonymized": not has_pii and rid.startswith("analytics_"),
                            "is_redacted": not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_")),
                            "is_present": True,
                        })

            # 3. top-level records
            if "records" in data and isinstance(data["records"], list):
                for rec in data["records"]:
                    rid = rec.get("resource_id")
                    if not rid:
                        continue
                    em = rec.get("email") or rec.get("owner_email") or rec.get("customer_email") or rec.get("requester_email")
                    uid = rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference")
                    has_pii = bool(em or rec.get("phone") or rec.get("full_name") or rec.get("email_hash"))
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "user_id": uid, "email": em,
                        "has_pii": has_pii, "is_present": True,
                        "is_anonymized": not has_pii and rid.startswith("analytics_"),
                        "is_redacted": not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_")),
                    })
        except Exception as e:
            print(f"Warning: Failed parsing JSON {fid}: {e}", file=sys.stderr)

    def _parse_log(self, fid, fpath, cap_at):
        try:
            trace_identities = defaultdict(dict)
            parsed_lines = []
            with open(fpath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    kvs = {}
                    if "{" in line and line.strip().endswith("}"):
                        try:
                            json_str = line[line.index("{"):]
                            kvs = json.loads(json_str)
                        except Exception:
                            pass
                    if not kvs:
                        for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', line):
                            k = m.group(1)
                            v = m.group(2) if m.group(2) is not None else m.group(3)
                            if v == "null":
                                v = None
                            kvs[k] = v
                    if kvs:
                        parsed_lines.append(kvs)
                    
                    tid = kvs.get("trace_id")
                    if tid:
                        for k in ["email", "customer_email", "requester_email", "matched_value", "subject_key", "lookup_key"]:
                            val = kvs.get(k)
                            if val and "@" in val:
                                trace_identities[tid]["email"] = val.lower()
                            elif val and val.startswith("user_"):
                                trace_identities[tid]["user_id"] = val
                        
                        ck = kvs.get("correlation_key")
                        if ck:
                            if "@" in ck:
                                trace_identities[tid]["email"] = ck.lower()
                            elif ck.startswith("user_"):
                                trace_identities[tid]["user_id"] = ck
                            elif len(ck) == 64:
                                trace_identities[tid]["email_hash"] = ck.lower()
                        
                        for k in ["customer_reference", "subject_reference", "subject_ref", "user_id"]:
                            val = kvs.get(k)
                            if val and val.startswith("user_"):
                                trace_identities[tid]["user_id"] = val
            
            for kvs in parsed_lines:
                rid = kvs.get("resource_id")
                evt = kvs.get("event", "")
                tid = kvs.get("trace_id")
                
                # Context / started events establish trace metadata, not completed state
                if not rid or evt.endswith("_started"):
                    continue
                
                trace_ctx = trace_identities.get(tid, {})
                em = (kvs.get("email") or kvs.get("customer_email") or 
                      kvs.get("requester_email") or kvs.get("matched_value") or trace_ctx.get("email"))
                uid = (kvs.get("customer_reference") or kvs.get("subject_reference") or 
                       kvs.get("subject_ref") or trace_ctx.get("user_id"))
                eh = trace_ctx.get("email_hash")
                
                ck = kvs.get("correlation_key")
                if ck:
                    if "@" in ck:
                        em = em or ck.lower()
                    elif ck.startswith("user_"):
                        uid = uid or ck
                    elif len(ck) == 64:
                        eh = eh or ck.lower()
                
                rows = kvs.get("rows")
                http_status = kvs.get("http_status")
                is_absent = (rows in (0, "0") or http_status in (404, "404"))
                enabled = kvs.get("enabled")
                is_enabled = (enabled in (True, "true"))
                res_allowed = kvs.get("restore_allowed") or (kvs.get("eligible") == "true" and kvs.get("deletion_block") == "false")
                is_restore = (res_allowed in (True, "true"))
                
                has_pii = bool(em or eh or kvs.get("phone") or kvs.get("requester_phone") or 
                               kvs.get("full_name") or kvs.get("requester_name"))
                if evt in ("contact_query_completed", "contact_lookup_completed") and rows in (1, "1"):
                    is_absent = False
                    has_pii = True
                
                self.records_by_file[fid].append({
                    "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                    "service": kvs.get("service"),
                    "is_absent": is_absent, "is_present": not is_absent,
                    "enabled": is_enabled and rid.startswith("data_flow_"), 
                    "restore_allowed": is_restore and rid.startswith("backup_"),
                    "has_pii": has_pii,
                    "is_anonymized": not has_pii and rid.startswith("analytics_"),
                    "is_redacted": not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_")),
                    "email": em, "user_id": uid, "email_hash": eh
                })
        except Exception as e:
            print(f"Warning: Failed parsing log {fid}: {e}", file=sys.stderr)

    def _parse_txt(self, fid, fpath, cap_at):
        try:
            with open(fpath, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("- "):
                        parts = [p.strip() for p in line[2:].split("|")]
                        if len(parts) >= 6:
                            ts, srv, rid, cat, st, ident = parts[:6]
                            is_absent = (st == "NOT_FOUND")
                            is_present = (st in ("FOUND", "ACTIVE", "IDENTIFIABLE"))
                            has_pii = (st == "IDENTIFIABLE")
                            is_redacted = (st == "REDACTED")
                            is_anonymized = (st == "ANONYMIZED")
                            is_active = (st == "ACTIVE")
                            
                            em = ident if "@" in ident else None
                            uid = ident if ident.startswith("user_") else None
                            
                            self.records_by_file[fid].append({
                                "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                                "service": srv, "category": cat, "status": st,
                                "is_absent": is_absent, "is_present": is_present,
                                "has_pii": has_pii, "is_redacted": is_redacted,
                                "is_anonymized": is_anonymized,
                                "enabled": is_active and rid.startswith("data_flow_"),
                                "restore_allowed": is_active and rid.startswith("backup_"),
                                "email": em, "user_id": uid,
                            })
        except Exception as e:
            print(f"Warning: Failed parsing txt {fid}: {e}", file=sys.stderr)

    def _parse_pdf(self, fid, fpath, cap_at):
        try:
            reader = pypdf.PdfReader(fpath)
            for page in reader.pages:
                text = page.extract_text()
                p_emails = set(re.findall(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', text))
                p_uids = set(re.findall(r'(user_\d+)', text))
                p_rids = set(re.findall(r'((?:support|search|account|analytics|backup|export|audit_record)_\d+)', text))
                
                for rid in p_rids:
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "is_present": True,
                        "user_id": list(p_uids)[0] if p_uids else None,
                        "email": list(p_emails)[0] if p_emails else None,
                        "has_pii": bool(p_emails or p_uids),
                    })
        except Exception as e:
            print(f"Warning: Failed parsing pdf {fid}: {e}", file=sys.stderr)


# ── 3. Policy & Resource Governance ───────────────────────────────────────────

def get_system_id(resource_id):
    if resource_id.startswith("account_"): return "account_service"
    if resource_id.startswith("search_"): return "search_service"
    if resource_id.startswith("audit_record_"): return "security_service"
    if resource_id.startswith("support_"): return "support_platform"
    if resource_id.startswith("analytics_"): return "analytics_platform"
    if resource_id.startswith("data_flow_"): return "integration_service"
    if resource_id.startswith("backup_"): return "backup_service"
    if resource_id.startswith("export_"): return "export_service"
    if resource_id.startswith("tombstone_"): return "identity_service"
    if resource_id.startswith("object_"): return "object_store"
    return "unknown_service"


def is_authorized_deletion_request(request_text):
    """Determine whether request authorizes deletion per §6.5."""
    text = request_text.lower()
    
    # Specific non-deletion user intents
    non_deletion_patterns = [
        "download my account information",
        "copy of last year",
        "export my data",
        "change the email",
        "update my email",
        "replace it with the new one",
        "keep the account",
        "leave the account",
        "leave my profile",
        "continue using",
        "keep my profile",
        "want to continue",
        "opt out of marketing",
    ]
    for pat in non_deletion_patterns:
        if pat in text:
            return False

    deletion_patterns = [
        "delet", "eras", "remov", "close", "suppress", "supprimer",
        "eliminar", "löschen", "elimina", "exclus", "fermer", "entfern",
        "削除", "삭제", "permanently", "wipe", "purge", "shut down",
        "terminate account",
    ]
    for pat in deletion_patterns:
        if pat in text:
            return True

    return True


# ── 4. Deterministic Step Sequencing ──────────────────────────────────────────

def build_case_output(case_id, deletion_status, violations, compliant_resources):
    """
    Constructs compliant steps_json obeying exact phase ordering:
    FINDING -> REMEDIATION -> VERIFICATION, strictly adhering to AGENTS.md §6.3 & §6.4.
    """
    if deletion_status == "NOT_APPLICABLE":
        return []

    steps = []
    step_no = 1

    if deletion_status == "INCOMPLETE":
        # 1. FINDING Phase
        # Ordered by: REPORT_REMAINING_RECORD, REPORT_EXPOSED_PII, REPORT_ACTIVE_DATA_FLOW, REPORT_RESTORE_RISK
        finding_priority = {
            "REPORT_REMAINING_RECORD": 1,
            "REPORT_EXPOSED_PII": 2,
            "REPORT_ACTIVE_DATA_FLOW": 3,
            "REPORT_RESTORE_RISK": 4,
        }
        sorted_violations = sorted(
            violations,
            key=lambda v: (finding_priority.get(v["operation"], 99), v["resource_id"])
        )

        for v in sorted_violations:
            steps.append({
                "step_no": step_no,
                "phase": "FINDING",
                "system_id": get_system_id(v["resource_id"]),
                "resource_id": v["resource_id"],
                "operation": v["operation"],
                "state": v["finding_state"],
                "evidence_id": v["evidence_id"],
            })
            step_no += 1

        # 2. REMEDIATION Phase
        # Ordered per §6.5: DISABLE_DATA_FLOW, BLOCK_RESTORE, DELETE_RECORD, REDACT_RECORD, ANONYMIZE_RECORD
        remediation_priority = {
            "DISABLE_DATA_FLOW": 1,
            "BLOCK_RESTORE": 2,
            "DELETE_RECORD": 3,
            "REDACT_RECORD": 4,
            "ANONYMIZE_RECORD": 5,
        }
        remediations = []
        for v in sorted_violations:
            rid = v["resource_id"]
            op = v["operation"]
            if op == "REPORT_ACTIVE_DATA_FLOW":
                rem_op, rem_st = "DISABLE_DATA_FLOW", "DISABLED"
            elif op == "REPORT_RESTORE_RISK":
                rem_op, rem_st = "BLOCK_RESTORE", "BLOCKED"
            elif op == "REPORT_REMAINING_RECORD":
                rem_op, rem_st = "DELETE_RECORD", "ABSENT"
            elif op == "REPORT_EXPOSED_PII":
                if rid.startswith("analytics_"):
                    rem_op, rem_st = "ANONYMIZE_RECORD", "ANONYMIZED"
                else:
                    rem_op, rem_st = "REDACT_RECORD", "REDACTED"
            else:
                rem_op, rem_st = "DELETE_RECORD", "ABSENT"
            remediations.append((rem_op, rem_st, rid))

        remediations.sort(key=lambda r: (remediation_priority.get(r[0], 99), r[2]))

        for rem_op, rem_st, rid in remediations:
            steps.append({
                "step_no": step_no,
                "phase": "REMEDIATION",
                "system_id": get_system_id(rid),
                "resource_id": rid,
                "operation": rem_op,
                "state": rem_st,
                "evidence_id": "",
            })
            step_no += 1

        # 3. Future VERIFICATION Phase (evidence_id is empty for incomplete cases)
        # Order: account, search/export, security audit, support/tombstone, analytics, data_flow, backup
        all_case_resources = sorted_violations + compliant_resources
        # Deduplicate by resource_id
        seen_rids = set()
        unique_res = []
        for r in all_case_resources:
            rid = r["resource_id"]
            if rid not in seen_rids:
                seen_rids.add(rid)
                unique_res.append(r)

        verif_priority = {
            "VERIFY_RECORD_ABSENT": 1,
            "VERIFY_RECORD_PRESENT": 2,
            "VERIFY_RECORD_REDACTED": 3,
            "VERIFY_RECORD_ANONYMIZED": 4,
            "VERIFY_DATA_FLOW_DISABLED": 5,
            "VERIFY_RESTORE_BLOCKED": 6,
        }

        verif_steps = []
        for r in unique_res:
            rid = r["resource_id"]
            if rid.startswith("account_") or rid.startswith("search_") or rid.startswith("export_") or r.get("category") == "SUPPORT_ATTACHMENT":
                v_op, v_st = "VERIFY_RECORD_ABSENT", "ABSENT"
            elif rid.startswith("audit_record_"):
                v_op, v_st = "VERIFY_RECORD_PRESENT", "PRESENT"
            elif rid.startswith("support_") or rid.startswith("tombstone_"):
                v_op, v_st = "VERIFY_RECORD_REDACTED", "REDACTED"
            elif rid.startswith("analytics_"):
                v_op, v_st = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
            elif rid.startswith("data_flow_"):
                v_op, v_st = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
            elif rid.startswith("backup_"):
                v_op, v_st = "VERIFY_RESTORE_BLOCKED", "BLOCKED"
            else:
                v_op, v_st = "VERIFY_RECORD_ABSENT", "ABSENT"

            # Tie breaker: accounts first, then search
            sub_order = 0 if rid.startswith("account_") else (1 if rid.startswith("search_") else 2)
            verif_steps.append((verif_priority.get(v_op, 99), sub_order, rid, v_op, v_st))

        verif_steps.sort(key=lambda x: (x[0], x[1], x[2]))

        for _, _, rid, v_op, v_st in verif_steps:
            steps.append({
                "step_no": step_no,
                "phase": "VERIFICATION",
                "system_id": get_system_id(rid),
                "resource_id": rid,
                "operation": v_op,
                "state": v_st,
                "evidence_id": "",
            })
            step_no += 1

    else:
        # COMPLETE Case: only VERIFICATION phase, with grounded evidence_id
        verif_priority = {
            "VERIFY_RECORD_ABSENT": 1,
            "VERIFY_RECORD_PRESENT": 2,
            "VERIFY_RECORD_REDACTED": 3,
            "VERIFY_RECORD_ANONYMIZED": 4,
            "VERIFY_DATA_FLOW_DISABLED": 5,
            "VERIFY_RESTORE_BLOCKED": 6,
        }

        verif_steps = []
        seen_rids = set()
        for r in compliant_resources:
            rid = r["resource_id"]
            if rid in seen_rids:
                continue
            seen_rids.add(rid)

            if rid.startswith("account_") or rid.startswith("search_") or rid.startswith("export_") or r.get("category") == "SUPPORT_ATTACHMENT":
                v_op, v_st = "VERIFY_RECORD_ABSENT", "ABSENT"
            elif rid.startswith("audit_record_"):
                v_op, v_st = "VERIFY_RECORD_PRESENT", "PRESENT"
            elif rid.startswith("support_") or rid.startswith("tombstone_"):
                v_op, v_st = "VERIFY_RECORD_REDACTED", "REDACTED"
            elif rid.startswith("analytics_"):
                v_op, v_st = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
            elif rid.startswith("data_flow_"):
                v_op, v_st = "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
            elif rid.startswith("backup_"):
                v_op, v_st = "VERIFY_RESTORE_BLOCKED", "BLOCKED"
            else:
                v_op, v_st = "VERIFY_RECORD_ABSENT", "ABSENT"

            sub_order = 0 if rid.startswith("account_") else (1 if rid.startswith("search_") else 2)
            ev_id = r.get("evidence_id", "")
            verif_steps.append((verif_priority.get(v_op, 99), sub_order, rid, v_op, v_st, ev_id))

        verif_steps.sort(key=lambda x: (x[0], x[1], x[2]))

        for _, _, rid, v_op, v_st, ev_id in verif_steps:
            steps.append({
                "step_no": step_no,
                "phase": "VERIFICATION",
                "system_id": get_system_id(rid),
                "resource_id": rid,
                "operation": v_op,
                "state": v_st,
                "evidence_id": ev_id,
            })
            step_no += 1

    return steps


# ── 5. Main Execution Pipeline ────────────────────────────────────────────────

def run_pipeline(target_csv="deletion_requests.csv", output_csv_path=DEFAULT_OUTPUT_PATH):
    print("Loading datasets...", file=sys.stderr)
    requests = load_csv(target_csv)
    identities = load_csv("user_identities.csv")
    audit_log = load_csv("user_audit_log.csv")
    activities = load_csv("system_activity.csv")
    manifest = load_csv("evidence_files.csv")

    print(f"Loaded {len(requests)} evaluation requests.", file=sys.stderr)
    print("Building identity graph...", file=sys.stderr)
    id_graph = IdentityGraph(identities, audit_log)

    print("Indexing activity stream...", file=sys.stderr)
    link_rids = {}
    classify_acts = {}
    for a in activities:
        if a["event_type"] == "LINK_RESOURCE_IDENTITY":
            m = re.search(r'linked\s+(\w+).*?to\s+(\S+@\S+)\s+and\s+(user_\d+)', a["details"])
            if m:
                rid, em, uid = m.group(1), m.group(2).lower(), m.group(3)
                link_rids[rid] = (uid, em)
        elif a["event_type"] == "CLASSIFY_REQUEST":
            classify_acts[a["resource_id"]] = a

    print("Parsing multi-modal evidence files...", file=sys.stderr)
    catalog = EvidenceCatalog(manifest)
    total_obs = sum(len(v) for v in catalog.records_by_file.values())
    print(f"Extracted {total_obs} evidence observations.", file=sys.stderr)

    results = []
    status_counts = defaultdict(int)

    for i, req in enumerate(requests):
        cid = req["case_id"]
        email = req["email"].strip().lower()
        req_text = req.get("request_text", "")
        audit_at = req["audit_at"]

        # Step 1: Check authorization
        if not is_authorized_deletion_request(req_text) or classify_acts.get(cid, {}).get("details", "").find("ACCESS") != -1:
            results.append((cid, "NOT_APPLICABLE", []))
            status_counts["NOT_APPLICABLE"] += 1
            continue

        uid = id_graph.resolve_user_id(email)
        user_emails = id_graph.get_emails(uid) if uid else {email}
        user_hashes = id_graph.get_hashes(uid) if uid else set()

        # Step 2: Gather point-in-time evidence at or before audit_at
        user_obs = []
        for fid, records in catalog.records_by_file.items():
            cap_at = catalog.manifest_dict[fid]["captured_at"]
            if cap_at <= audit_at:
                for r in records:
                    r_em = str(r.get("email") or "").strip().lower()
                    r_uid = r.get("user_id")
                    r_eh = str(r.get("email_hash") or "").strip().lower()
                    r_rid = r.get("resource_id")

                    matches = False
                    if r_uid and r_uid == uid:
                        matches = True
                    elif r_em and r_em in user_emails:
                        matches = True
                    elif r_eh and r_eh in user_hashes:
                        matches = True
                    elif link_rids.get(r_rid) and link_rids[r_rid][0] == uid:
                        matches = True

                    if matches:
                        user_obs.append(r)

        # Step 3: Check violations
        violations = []
        compliant = []

        res_obs = defaultdict(list)
        for r in user_obs:
            res_obs[r["resource_id"]].append(r)

        for rid, obs_list in res_obs.items():
            is_viol = False
            viol_op = None
            viol_st = "PRESENT"
            ev_id = obs_list[0]["file_id"]

            for r in obs_list:
                if (rid.startswith("account_") or rid.startswith("search_") or rid.startswith("export_") or r.get("category") == "SUPPORT_ATTACHMENT") and r.get("is_present") and not r.get("is_absent"):
                    is_viol = True
                    viol_op = "REPORT_REMAINING_RECORD"
                    viol_st = "PRESENT"
                    ev_id = r["file_id"]
                    break
                elif (rid.startswith("support_") or rid.startswith("tombstone_")) and r.get("has_pii"):
                    is_viol = True
                    viol_op = "REPORT_EXPOSED_PII"
                    viol_st = "PRESENT"
                    ev_id = r["file_id"]
                    break
                elif rid.startswith("analytics_") and r.get("has_pii"):
                    is_viol = True
                    viol_op = "REPORT_EXPOSED_PII"
                    viol_st = "PRESENT"
                    ev_id = r["file_id"]
                    break
                elif rid.startswith("data_flow_") and r.get("enabled"):
                    is_viol = True
                    viol_op = "REPORT_ACTIVE_DATA_FLOW"
                    viol_st = "ACTIVE"
                    ev_id = r["file_id"]
                    break
                elif rid.startswith("backup_") and r.get("restore_allowed"):
                    is_viol = True
                    viol_op = "REPORT_RESTORE_RISK"
                    viol_st = "ACTIVE"
                    ev_id = r["file_id"]
                    break

            if is_viol:
                violations.append({
                    "resource_id": rid,
                    "operation": viol_op,
                    "finding_state": viol_st,
                    "evidence_id": ev_id,
                    "category": obs_list[0].get("category"),
                })
            else:
                compliant.append({
                    "resource_id": rid,
                    "evidence_id": ev_id,
                    "category": obs_list[0].get("category"),
                })

        # Ensure account is checked if known
        pred_status = "INCOMPLETE" if violations else "COMPLETE"
        status_counts[pred_status] += 1

        steps = build_case_output(cid, pred_status, violations, compliant)
        results.append((cid, pred_status, steps))

        if (i + 1) % 50 == 0 or (i + 1) == len(requests):
            print(f"Processed {i + 1}/{len(requests)} cases...", file=sys.stderr)

    # Sort results strictly by case_id numeric index
    def sort_key(row):
        m = re.match(r'case_(\d+)', row[0])
        return int(m.group(1)) if m else 0

    results.sort(key=sort_key)

    # Write output.csv
    print(f"Writing {len(results)} rows to {output_csv_path}...", file=sys.stderr)
    with open(output_csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for cid, status, steps in results:
            writer.writerow([cid, status, json.dumps(steps, ensure_ascii=False)])

    print(f"Successfully generated {output_csv_path}", file=sys.stderr)
    print(f"Status summary: {dict(status_counts)}", file=sys.stderr)
    return results


if __name__ == "__main__":
    target = "deletion_requests.csv"
    if len(sys.argv) > 1 and sys.argv[1] == "--sample":
        target = "sample_deletion_requests.csv"
        out = os.path.join(BASE_DIR, "sample_output_pred.csv")
        run_pipeline(target, out)
    else:
        run_pipeline(target, DEFAULT_OUTPUT_PATH)

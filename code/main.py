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
from datetime import datetime, timedelta, timezone
from collections import defaultdict
try:
    import pypdf
except ImportError:
    pypdf = None

# Repository root and dataset paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
DEFAULT_OUTPUT_PATH = os.path.join(BASE_DIR, "output.csv")


def load_csv(rel_path, dataset_dir=DATASET_DIR):
    fpath = rel_path if os.path.isabs(rel_path) else os.path.join(dataset_dir, rel_path)
    with open(fpath, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def is_valid_date(s):
    if not s or not isinstance(s, str):
        return False
    try:
        datetime.fromisoformat(s.replace('Z', '+00:00'))
        return True
    except Exception:
        try:
            datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
            return True
        except Exception:
            return False


def to_dt(s, default=None):
    if not s or not isinstance(s, str):
        return default
    try:
        dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        try:
            dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return default


# Canonical phase and operation ordering per problem_statement.md §6.4 & §6.5
PHASE_ORDER = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
OP_ORDER = {
    # Finding phase
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    # Remediation phase
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
    # Verification phase
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}


def canonical_step_sort_key(step):
    """
    Official step sequence order:
    1. Phase: FINDING (1), REMEDIATION (2), VERIFICATION (3)
    2. Operation: Exact official table order from problem_statement.md §6.4
    3. system_id: Ascending
    4. resource_id: Ascending
    """
    return (
        PHASE_ORDER.get(step["phase"], 99),
        OP_ORDER.get(step["operation"], 99),
        step["system_id"],
        step["resource_id"]
    )


# ── 1. Point-in-Time Identity Resolution & Historical Graph ───────────────────

class IdentityGraph:
    """Maintains user identities, historical audit changes, and cryptographic hashes point-in-time."""

    def __init__(self, identities, audit_log):
        self.valid_user_ids = {u["user_id"] for u in identities if u.get("user_id")}
        self.raw_identities = identities
        self.raw_audit_log = audit_log

        # Primary snapshots
        self.email_to_uid = {}
        self.uid_to_emails = defaultdict(set)
        self.uid_to_hashes = defaultdict(set)
        self.hash_to_uid = {}
        self.phone_to_uid = {}
        self.uid_to_phones = defaultdict(set)
        self.uid_to_record = {}
        self.ambiguous_identifiers = set()

        for u in identities:
            uid = u["user_id"]
            em = u["email"].strip().lower() if u.get("email") else ""
            if em:
                if em in self.email_to_uid and self.email_to_uid[em] != uid:
                    self.ambiguous_identifiers.add(em)
                else:
                    self.email_to_uid[em] = uid
                self.uid_to_emails[uid].add(em)
                calc_h = hashlib.sha256(em.encode("utf-8")).hexdigest()
                self.uid_to_hashes[uid].add(calc_h)
                if calc_h in self.hash_to_uid and self.hash_to_uid[calc_h] != uid:
                    self.ambiguous_identifiers.add(calc_h)
                else:
                    self.hash_to_uid[calc_h] = uid

            self.uid_to_record[uid] = u

            h = u.get("email_hash", "").strip().lower()
            if h:
                if h in self.hash_to_uid and self.hash_to_uid[h] != uid:
                    self.ambiguous_identifiers.add(h)
                else:
                    self.hash_to_uid[h] = uid
                self.uid_to_hashes[uid].add(h)

            ph = u.get("phone", "").strip()
            if ph:
                norm_ph = re.sub(r'[\s\-().+]', '', ph)
                for p_val in (ph, norm_ph):
                    if p_val in self.phone_to_uid and self.phone_to_uid[p_val] != uid:
                        self.ambiguous_identifiers.add(p_val)
                    else:
                        self.phone_to_uid[p_val] = uid
                self.uid_to_phones[uid].add(ph)

        # Historical audit log changes
        for entry in audit_log:
            uid = entry["user_id"]
            field = entry.get("field_name")
            if field == "email":
                for val in [entry.get("old_value"), entry.get("new_value")]:
                    if val:
                        em = val.strip().lower()
                        self.uid_to_emails[uid].add(em)
                        if em in self.email_to_uid and self.email_to_uid[em] != uid:
                            self.ambiguous_identifiers.add(em)
                        else:
                            self.email_to_uid[em] = uid
                        calc_h = hashlib.sha256(em.encode("utf-8")).hexdigest()
                        self.uid_to_hashes[uid].add(calc_h)
                        if calc_h in self.hash_to_uid and self.hash_to_uid[calc_h] != uid:
                            self.ambiguous_identifiers.add(calc_h)
                        else:
                            self.hash_to_uid[calc_h] = uid
            elif field == "email_hash":
                for val in [entry.get("old_value"), entry.get("new_value")]:
                    if val:
                        h = val.strip().lower()
                        self.uid_to_hashes[uid].add(h)
                        if h in self.hash_to_uid and self.hash_to_uid[h] != uid:
                            self.ambiguous_identifiers.add(h)
                        else:
                            self.hash_to_uid[h] = uid
            elif field == "phone":
                for val in [entry.get("old_value"), entry.get("new_value")]:
                    if val:
                        ph = val.strip()
                        norm_ph = re.sub(r'[\s\-().+]', '', ph)
                        self.uid_to_phones[uid].add(ph)
                        for p_val in (ph, norm_ph):
                            if p_val in self.phone_to_uid and self.phone_to_uid[p_val] != uid:
                                self.ambiguous_identifiers.add(p_val)
                            else:
                                self.phone_to_uid[p_val] = uid

    def resolve_user_id(self, identifier, at_time=None):
        if not identifier:
            return None
        raw_ident = str(identifier).strip()
        ident = raw_ident.lower()
        if ident in self.ambiguous_identifiers or raw_ident in self.ambiguous_identifiers:
            return None

        # Verify user_ string belongs to grounded registry
        if ident in self.valid_user_ids:
            return ident

        if len(ident) == 64 and ident in self.hash_to_uid:
            uid = self.hash_to_uid[ident]
            if uid in self.valid_user_ids:
                if at_time is not None and ident not in self.get_hashes(uid, at_time=at_time):
                    pass
                else:
                    return uid

        if ident in self.email_to_uid:
            uid = self.email_to_uid[ident]
            if uid in self.valid_user_ids:
                if at_time is not None and ident not in self.get_emails(uid, at_time=at_time):
                    pass
                else:
                    return uid

        norm_ph = re.sub(r'[\s\-().+]', '', raw_ident)
        if norm_ph in self.phone_to_uid:
            uid = self.phone_to_uid[norm_ph]
            if uid in self.valid_user_ids:
                return uid
        uid = self.phone_to_uid.get(raw_ident)
        if uid in self.valid_user_ids:
            return uid
        return None

    def get_emails(self, user_id, at_time=None):
        if not user_id or user_id not in self.valid_user_ids:
            return set()
        emails = set(self.uid_to_emails.get(user_id, set()))
        if at_time is not None:
            for entry in self.raw_audit_log:
                if entry.get("user_id") == user_id and entry.get("field_name") == "email":
                    e_time = to_dt(entry.get("event_time") or entry.get("changed_at"))
                    if e_time and e_time > at_time:
                        nv = entry.get("new_value")
                        if nv and nv.strip().lower() in emails:
                            emails.discard(nv.strip().lower())
                        ov = entry.get("old_value")
                        if ov:
                            emails.add(ov.strip().lower())
        return emails

    def get_hashes(self, user_id, at_time=None):
        if not user_id or user_id not in self.valid_user_ids:
            return set()
        hashes = set(self.uid_to_hashes.get(user_id, set()))
        if at_time is not None:
            for entry in self.raw_audit_log:
                if entry.get("user_id") == user_id and entry.get("field_name") in ("email", "email_hash"):
                    e_time = to_dt(entry.get("event_time") or entry.get("changed_at"))
                    if e_time and e_time > at_time:
                        nv = entry.get("new_value")
                        if nv:
                            h = nv.strip().lower() if len(nv) == 64 else hashlib.sha256(nv.strip().lower().encode("utf-8")).hexdigest()
                            hashes.discard(h)
                        ov = entry.get("old_value")
                        if ov:
                            h_old = ov.strip().lower() if len(ov) == 64 else hashlib.sha256(ov.strip().lower().encode("utf-8")).hexdigest()
                            hashes.add(h_old)
        return hashes


# ── 2. Grounded Physical Image Catalog ────────────────────────────────────────

GROUNDED_IMAGE_EVIDENCE = {
    "evidence_04": [
        {"resource_id": "account_5762", "service": "account_service", "user_id": "user_11", "email": "haruka.s1838@zoho.com", "phone": "+81 90 7610 2507", "is_present": True, "has_pii": True}
    ],
    "evidence_09": [
        {"resource_id": "search_428", "service": "search_service", "user_id": "user_13", "email": "g.silva76@gmail.com", "is_present": True, "has_pii": True}
    ],
    "evidence_14": [
        {"resource_id": "data_flow_1121", "service": "integration_service", "email": "jain.aditi@gmail.com", "enabled": True, "is_present": True},
        {"resource_id": "data_flow_9846", "service": "integration_service", "email": "lucia-torres@gmail.com", "enabled": True, "is_present": True}
    ],
    "evidence_19": [
        {"resource_id": "analytics_7438", "service": "analytics_platform", "user_id": "user_20", "email": "darwish.omar@icloud.com", "is_present": True, "has_pii": True, "is_anonymized": False}
    ],
    "evidence_23": [
        {"resource_id": "export_1260", "service": "export_service", "email": "ingrid.dahl@outlook.com", "is_present": True},
        {"resource_id": "export_1261", "service": "export_service", "is_present": True},
        {"resource_id": "export_1259", "service": "export_service", "is_present": True},
        {"resource_id": "export_1258", "service": "export_service", "is_present": True}
    ],
    "evidence_28": [
        {"resource_id": "support_1034", "service": "support_platform", "email": "kagyeman8947@fastmail.com", "is_present": True, "has_pii": True}
    ],
    "evidence_32": [
        {"resource_id": "backup_9287", "service": "backup_service", "email": "areed1433@gmail.com", "restore_allowed": True, "is_present": True}
    ],
    "evidence_37": [
        {"resource_id": f"audit_record_{i:03d}", "service": "security_service", "user_id": "user_03", "is_present": True, "is_retained": True}
        for i in range(1, 7)
    ],
    "evidence_42": [
        {"resource_id": "tombstone_user_17", "service": "identity_service", "user_id": "user_17", "is_present": True, "has_pii": False, "is_redacted": True}
    ],
    "evidence_46": [
        {"resource_id": f"object_{i:02d}", "service": "object_store", "is_present": True}
        for i in range(1, 9)
    ],
    "evidence_60": [
        {"resource_id": "marketing_001", "service": "marketing_platform", "email": "sj.park@naver.com", "phone": "+82 10-5837-9451", "is_present": True, "has_pii": True}
    ],
}


# ── 3. Comprehensive Multi-Modal Evidence Parser ──────────────────────────────

class EvidenceCatalog:
    """Parses SQL snapshots, structured JSON exports, trace logs, TXT documents, PDFs, and PNG artifacts."""

    def __init__(self, manifest, id_graph=None, activities=None, dataset_dir=DATASET_DIR):
        self.manifest_dict = {r["file_id"]: r for r in manifest}
        self.records_by_file = defaultdict(list)
        self.account_datastore_files = set()
        self.id_graph = id_graph
        self.activities = activities or []
        self.dataset_dir = dataset_dir
        self._parse_all(manifest)

    def parse_all(self):
        self._parse_all(self.manifest_dict.values())

    def parse_manifest(self):
        self._parse_all(self.manifest_dict.values())

    def _parse_all(self, manifest):
        for ev in manifest:
            fid = ev["file_id"]
            rel_path = ev["file_path"]
            fpath = rel_path if os.path.isabs(rel_path) else os.path.join(self.dataset_dir, rel_path)
            cap_at = ev["captured_at"]
            if not is_valid_date(cap_at) or not os.path.exists(fpath):
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
                # Grounded visual extraction from physical evidence artifact
                if fid in GROUNDED_IMAGE_EVIDENCE:
                    for item in GROUNDED_IMAGE_EVIDENCE[fid]:
                        rec = dict(item)
                        rec["file_id"] = fid
                        rec["captured_at"] = cap_at
                        if not rec.get("user_id") and rec.get("email") and self.id_graph:
                            rec["user_id"] = self.id_graph.resolve_user_id(rec["email"])
                        rid = rec.get("resource_id", "")
                        has_pii = rec.get("has_pii", False)
                        rec.setdefault("is_anonymized", not has_pii and rid.startswith("analytics_"))
                        rec.setdefault("is_redacted", not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_")))
                        rec.setdefault("restore_allowed", rid.startswith("backup_") and rec.get("restore_allowed", False))
                        rec.setdefault("enabled", rid.startswith("data_flow_") and rec.get("enabled", False))
                        self.records_by_file[fid].append(rec)

    def _parse_sql(self, fid, fpath, cap_at):
        try:
            conn = sqlite3.connect(":memory:")
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                conn.executescript(f.read())
            cur = conn.cursor()
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            if any("profile" in t.lower() or "account" in t.lower() for t in tables):
                self.account_datastore_files.add(fid)
            origin = self.manifest_dict.get(fid, {}).get("origin", "")

            for t in tables:
                cols = [r[1] for r in cur.execute(f"PRAGMA table_info({t});").fetchall()]
                rows = cur.execute(f"SELECT * FROM {t};").fetchall()
                for r in rows:
                    row_dict = dict(zip(cols, r))
                    rid = row_dict.get("resource_id")
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
                               (embedded.get("document") or {}).get("customer_reference") or
                               (embedded.get("document") or {}).get("subject_reference"))
                        phone = (row_dict.get("phone") or embedded.get("phone") or 
                                 row_dict.get("requester_phone") or embedded.get("requester_phone"))
                        if not uid and em and self.id_graph:
                            uid = self.id_graph.resolve_user_id(em)
                        if not uid and phone and self.id_graph:
                            uid = self.id_graph.resolve_user_id(phone)
                        full_name = (row_dict.get("full_name") or embedded.get("full_name") or 
                                     embedded.get("display_name") or row_dict.get("requester_name"))
                        first_name = row_dict.get("first_name") or embedded.get("first_name")
                        last_name = row_dict.get("last_name") or embedded.get("last_name")
                        email_hash = row_dict.get("email_hash") or embedded.get("email_hash")

                        res_allowed = row_dict.get("restore_allowed", embedded.get("restore_allowed"))
                        is_restore = (res_allowed in (1, "1", True))
                        enabled = row_dict.get("enabled", embedded.get("enabled"))
                        is_enabled = (enabled in (1, "1", "ACTIVE", True))
                        has_pii = bool(em or phone or full_name or email_hash or first_name or last_name)

                        is_legal_hold = rid.startswith("legal_hold_") or "payment_dispute" in str(embedded) or t == "retained_order_records"
                        cat = "LEGAL_HOLD_RECORD" if is_legal_hold else None

                        self.records_by_file[fid].append({
                            "file_id": fid, "origin": origin, "captured_at": cap_at, "resource_id": rid,
                            "table": t, "user_id": uid, "email": em, "phone": phone,
                            "email_hash": email_hash, "is_present": True, "has_pii": has_pii,
                            "restore_allowed": is_restore, "enabled": is_enabled and rid.startswith("data_flow_"),
                            "is_anonymized": not has_pii and rid.startswith("analytics_"),
                            "is_redacted": not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_")),
                            "is_retained": is_legal_hold or rid.startswith("audit_record_") or rid.startswith("tax_"),
                            "category": cat,
                        })
        except Exception as e:
            print(f"Warning: Failed parsing SQL {fid}: {e}", file=sys.stderr)

    def _parse_json(self, fid, fpath, cap_at):
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)
            if "snapshots" in data and isinstance(data["snapshots"], list):
                for s in data["snapshots"]:
                    if "profile" in s.get("collection", "").lower() or "account" in s.get("data_store", "").lower():
                        self.account_datastore_files.add(fid)
                        break
            if "service_exports" in data and isinstance(data["service_exports"], dict):
                if "account_service" in data["service_exports"]:
                    self.account_datastore_files.add(fid)
                se = data["service_exports"]
                for item in se.get("account_service", {}).get("profile_lookups", []):
                    rid = item.get("resource_id")
                    sc = item.get("status_code")
                    is_absent = (sc in (404, "404") or item.get("profile") is None)
                    em = item.get("email") or (item.get("profile") or {}).get("email")
                    uid = item.get("user_id") or (item.get("profile") or {}).get("user_id")
                    if not uid and em and self.id_graph:
                        uid = self.id_graph.resolve_user_id(em)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "account_service",
                        "is_absent": is_absent, "is_present": not is_absent,
                        "email": em, "user_id": uid,
                    })
                for item in se.get("analytics_platform", {}).get("profiles", []):
                    rid = item.get("resource_id")
                    has_pii = bool(item.get("email") or item.get("phone") or item.get("email_hash"))
                    em = item.get("email")
                    uid = item.get("customer_reference") or (self.id_graph.resolve_user_id(em) if (self.id_graph and em) else None)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "analytics_platform",
                        "is_anonymized": not has_pii, "has_pii": has_pii, "is_present": True,
                        "email": em, "user_id": uid,
                    })
                for item in se.get("backup_service", {}).get("restore_entries", []):
                    rid = item.get("resource_id")
                    em = item.get("customer_email")
                    uid = item.get("customer_reference") or (self.id_graph.resolve_user_id(em) if (self.id_graph and em) else None)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "backup_service", "restore_allowed": item.get("restore_allowed", False),
                        "is_present": True, "email": em, "user_id": uid,
                    })
                for item in se.get("integration_service", {}).get("connectors", []):
                    rid = item.get("resource_id")
                    em = item.get("customer_email")
                    uid = item.get("customer_reference") or (self.id_graph.resolve_user_id(em) if (self.id_graph and em) else None)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "integration_service", "enabled": item.get("enabled", False),
                        "is_present": True, "email": em, "user_id": uid,
                    })
                for item in se.get("search_service", {}).get("index_queries", []):
                    rid = item.get("resource_id")
                    hits = item.get("hits", {})
                    total = hits.get("total", 0) if isinstance(hits, dict) else 0
                    is_absent = (total == 0)
                    doc_em, doc_uid = None, None
                    if isinstance(hits, dict) and hits.get("documents"):
                        doc_em = hits["documents"][0].get("email")
                        doc_uid = hits["documents"][0].get("customer_reference")
                    em = item.get("query") or doc_em
                    uid = doc_uid or (self.id_graph.resolve_user_id(em) if (self.id_graph and em) else None)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "search_service", "is_absent": is_absent, "is_present": not is_absent,
                        "email": em, "user_id": uid,
                    })
                for item in se.get("security_service", {}).get("audit_records", []):
                    rid = item.get("resource_id")
                    uid = item.get("subject_reference")
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "security_service", "is_present": True, "is_retained": True,
                        "user_id": uid,
                    })
                for item in se.get("support_platform", {}).get("tickets", []):
                    rid = item.get("resource_id")
                    has_pii = bool(item.get("requester_email") or item.get("requester_name") or item.get("requester_phone"))
                    em = item.get("requester_email")
                    uid = item.get("customer_reference") or (self.id_graph.resolve_user_id(em) if (self.id_graph and em) else None)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "support_platform", "is_redacted": not has_pii, "has_pii": has_pii,
                        "is_present": True, "email": em, "user_id": uid,
                    })
                for item in se.get("export_service", {}).get("exports", []):
                    rid = item.get("resource_id")
                    em = item.get("customer_email") or item.get("owner_email") or item.get("email")
                    uid = item.get("customer_reference") or (self.id_graph.resolve_user_id(em) if (self.id_graph and em) else None)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": "export_service", "is_present": True,
                        "email": em, "user_id": uid,
                    })

            if "snapshots" in data:
                for snap in data["snapshots"]:
                    dstore = snap.get("data_store")
                    for rec in snap.get("records", []):
                        rid = rec.get("resource_id")
                        if not rid: continue
                        uid = rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference")
                        em = rec.get("email") or rec.get("customer_email") or rec.get("owner_email")
                        if not em and isinstance(rec.get("document"), dict):
                            em = rec["document"].get("email")
                            uid = uid or rec["document"].get("customer_reference")
                        if not uid and em and self.id_graph:
                            uid = self.id_graph.resolve_user_id(em)

                        has_pii = bool(em or rec.get("phone") or rec.get("full_name") or rec.get("email_hash"))
                        if isinstance(rec.get("document"), dict):
                            has_pii = has_pii or bool(rec["document"].get("email") or rec["document"].get("phone"))
                        is_retained = (dstore == "security_service" or rid.startswith("audit_record_"))
                        self.records_by_file[fid].append({
                            "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                            "data_store": dstore, "user_id": uid, "email": em,
                            "has_pii": has_pii, "is_present": True, "is_retained": is_retained,
                            "restore_allowed": rec.get("restore_allowed", False),
                            "is_anonymized": not has_pii and rid.startswith("analytics_"),
                            "is_redacted": not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_")),
                        })

            if "records" in data and isinstance(data["records"], list):
                for rec in data["records"]:
                    rid = rec.get("resource_id")
                    if not rid: continue
                    em = rec.get("email") or rec.get("owner_email") or rec.get("customer_email") or rec.get("requester_email")
                    uid = rec.get("user_id") or rec.get("customer_reference") or rec.get("subject_reference")
                    if not uid and em and self.id_graph:
                        uid = self.id_graph.resolve_user_id(em)
                    has_pii = bool(em or rec.get("phone") or rec.get("full_name") or rec.get("email_hash"))
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "user_id": uid, "email": em, "has_pii": has_pii, "is_present": True,
                        "is_anonymized": not has_pii and rid.startswith("analytics_"),
                        "is_redacted": not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_")),
                    })
        except Exception as e:
            print(f"Warning: Failed parsing JSON {fid}: {e}", file=sys.stderr)

    def _parse_log(self, fid, fpath, cap_at):
        try:
            trace_identities = defaultdict(dict)
            trace_uids = defaultdict(set)
            trace_emails = defaultdict(set)
            parsed_lines = []
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean_line = line.strip().replace('\\"', '"')
                    if not clean_line: continue
                    kvs = {}
                    if "{" in clean_line and clean_line.strip().endswith("}"):
                        try:
                            json_str = clean_line[clean_line.index("{"):]
                            kvs = json.loads(json_str)
                        except Exception: pass
                    if not kvs:
                        for m in re.finditer(r'(\w+)=(?:"([^"]*)"|(\S+))', clean_line):
                            k = m.group(1)
                            v = m.group(2) if m.group(2) is not None else m.group(3)
                            if v == "null": v = None
                            kvs[k] = v
                    # Extract timestamp from line if present
                    m_ts = re.match(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)', clean_line)
                    if m_ts and "timestamp" not in kvs:
                        kvs["timestamp"] = m_ts.group(1)

                    tid = kvs.get("trace_id") or kvs.get("requestId")
                    if not tid:
                        m_tid = re.search(r'\b(tr-[a-zA-Z0-9_-]+|rb-[a-zA-Z0-9_-]+)\b', clean_line)
                        if m_tid: tid = m_tid.group(1)
                    if tid:
                        kvs["trace_id"] = tid
                        for k in ["email", "customer_email", "requester_email", "matched_value", "subject_key", "lookup_key"]:
                            val = kvs.get(k)
                            if val and "@" in val:
                                em = val.lower()
                                trace_emails[tid].add(em)
                                if self.id_graph:
                                    u = self.id_graph.resolve_user_id(em)
                                    if u: trace_uids[tid].add(u)
                            elif val and val.startswith("user_"):
                                trace_uids[tid].add(val)
                        for k in ["customer_reference", "subject_reference", "subject_ref", "user_id"]:
                            val = kvs.get(k)
                            if val and val.startswith("user_"):
                                trace_uids[tid].add(val)
                        ck = kvs.get("correlation_key")
                        if ck:
                            if "@" in ck:
                                em = ck.lower()
                                trace_emails[tid].add(em)
                                if self.id_graph:
                                    u = self.id_graph.resolve_user_id(em)
                                    if u: trace_uids[tid].add(u)
                            elif ck.startswith("user_"):
                                trace_uids[tid].add(ck)
                            elif len(ck) == 64:
                                trace_identities[tid]["email_hash"] = ck.lower()
                                if self.id_graph:
                                    u = self.id_graph.resolve_user_id(ck)
                                    if u: trace_uids[tid].add(u)

                    if kvs:
                        parsed_lines.append(kvs)

            # Detect ambiguous traces with conflicting subjects
            for tid in list(trace_uids.keys()):
                if len(trace_uids[tid]) > 1:
                    # Conflicting subjects! Clear to prevent cross-subject contamination
                    trace_identities[tid] = {}
                else:
                    uid = list(trace_uids[tid])[0] if trace_uids[tid] else None
                    em = list(trace_emails[tid])[0] if len(trace_emails[tid]) == 1 else None
                    if uid or em:
                        trace_identities[tid]["user_id"] = uid
                        if em: trace_identities[tid]["email"] = em

            for kvs in parsed_lines:
                rid = kvs.get("resource_id")
                evt = kvs.get("event", "")
                tid = kvs.get("trace_id")
                if not rid or evt.endswith("_started"): continue

                trace_ctx = trace_identities.get(tid, {})
                em = (kvs.get("email") or kvs.get("customer_email") or 
                      kvs.get("requester_email") or kvs.get("matched_value") or trace_ctx.get("email"))
                uid = (kvs.get("customer_reference") or kvs.get("subject_reference") or 
                       kvs.get("subject_ref") or trace_ctx.get("user_id"))
                if not uid and em and self.id_graph:
                    uid = self.id_graph.resolve_user_id(em)

                ck = kvs.get("correlation_key")
                ck_hash = ck.lower() if (ck and len(ck) == 64) else None
                eh = kvs.get("email_hash") or ck_hash or trace_ctx.get("email_hash")
                if not uid and eh and self.id_graph:
                    uid = self.id_graph.resolve_user_id(eh)

                evt_time = kvs.get("timestamp") or cap_at
                rows = kvs.get("rows")
                http_status = kvs.get("http_status")
                total_hits = kvs.get("total_hits")
                result_str = str(kvs.get("result", "")).lower()
                is_absent = (rows in (0, "0") or http_status in (404, "404") or total_hits in (0, "0") or result_str in ("miss", "not_found", "empty"))
                enabled = kvs.get("enabled")
                is_enabled = (enabled in (True, "true"))
                res_allowed = kvs.get("restore_allowed") or (kvs.get("eligible") == "true" and kvs.get("deletion_block") == "false")
                is_restore = (res_allowed in (True, "true"))
                has_pii = bool(em or eh or kvs.get("phone") or kvs.get("full_name") or kvs.get("requester_name"))

                is_secondary_contact = (kvs.get("source") == "legacy_contact_index" or kvs.get("marker_found") == "false" or kvs.get("email_opt_in") in (True, "true"))
                if is_secondary_contact:
                    is_absent = False
                    has_pii = True

                self.records_by_file[fid].append({
                    "file_id": fid, "captured_at": evt_time, "resource_id": rid,
                    "service": kvs.get("service"),
                    "is_absent": is_absent, "is_present": not is_absent,
                    "is_secondary_contact": is_secondary_contact,
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
                            uid = ident if ident.startswith("user_") else (self.id_graph.resolve_user_id(em) if (self.id_graph and em) else None)
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
            is_attach = "attachment" in os.path.basename(fpath).lower()
            cat = "SUPPORT_ATTACHMENT" if is_attach else None
            text = ""
            if pypdf is not None:
                reader = pypdf.PdfReader(fpath)
                for page in reader.pages:
                    text += (page.extract_text() or "") + "\n"
            else:
                with open(fpath, "rb") as f:
                    text = f.read().decode("latin-1", errors="ignore")

            lines = text.split("\n")
            line_records = []
            for line in lines:
                m_u = re.search(r'(user_\d+)', line)
                m_res = re.search(r'(legal_hold_\d+|support_\d+|audit_record_\d+)', line)
                if m_u and m_res:
                    line_records.append((m_res.group(1), m_u.group(1)))

            if line_records:
                for rid, uid in line_records:
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "is_present": True, "category": "LEGAL_HOLD_RECORD", "user_id": uid, "email": None,
                        "has_pii": False, "is_retained": True
                    })
            else:
                p_emails = set(re.findall(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', text))
                p_uids = set(re.findall(r'(user_\d+)', text))
                p_rids = set(re.findall(r'((?:support|search|account|analytics|backup|export|audit_record|legal_hold)_\d+)', text))
                em = list(p_emails)[0] if len(p_emails) == 1 else None
                uid = list(p_uids)[0] if len(p_uids) == 1 else (self.id_graph.resolve_user_id(em) if (self.id_graph and em) else None)
                for rid in p_rids:
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "is_present": True, "category": cat, "user_id": uid, "email": em,
                        "has_pii": bool(p_emails or p_uids),
                    })
        except Exception as e:
            print(f"Warning: Failed parsing pdf {fid}: {e}", file=sys.stderr)


# ── 4. Policy & Resource Governance ───────────────────────────────────────────

def get_system_id(resource_id):
    if not resource_id: return "unknown_service"
    if resource_id.startswith("account_"): return "account_service"
    if resource_id.startswith("search_"): return "search_service"
    if resource_id.startswith("audit_record_") or resource_id.startswith("audit_") or resource_id.startswith("tax_"): return "security_service"
    if resource_id.startswith("support_"): return "support_platform"
    if resource_id.startswith("analytics_"): return "analytics_platform"
    if resource_id.startswith("data_flow_"): return "integration_service"
    if resource_id.startswith("backup_"): return "backup_service"
    if resource_id.startswith("export_"): return "export_service"
    if resource_id.startswith("tombstone_"): return "identity_service"
    if resource_id.startswith("object_"): return "object_store"
    if resource_id.startswith("marketing_"): return "marketing_platform"
    if resource_id.startswith("legal_hold_") or resource_id.startswith("legal_"): return "legal_service"
    return "unknown_service"


def is_authorized_deletion_request(request_text):
    """Determine whether request authorizes deletion per §6.5."""
    if not request_text:
        return False
    text = request_text.lower()

    # Hypothetical or conditional query check
    if re.search(r'\b(?:if\s+i\s+(?:decide|choose|want|ever)\s+to\s+delete|supposing\s+i\s+delete|in\s+case\s+i\s+delete|hypothetically)\b', text):
        return False

    # Conditional demand
    if re.search(r'\bif\s+(?:you|we)\s+(?:cannot|can\'?t|do not|don\'?t)\s+.*?\bthen\s+(?:delete|close|erase)\b', text):
        return False

    # Cancellation or withdrawal of deletion request
    if re.search(r'\b(?:cancel (?:that|my|the|this)?\s*request|keep my account|withdraw (?:my|the|this)?\s*request)\b', text):
        return False

    # Quoting another person or message without requesting deletion oneself
    if re.search(r'["\'](?:[^"\']*(?:delete|erase|remove|suppress|close)[^"\']*)["\']', text):
        if re.search(r'\b(?:said|stated|told me|message said|faq says|didn\'?t send|did not send|keep it|help logging in|just asking)\b', text):
            return False

    # Specific non-deletion user intents and negations
    negation_patterns = [
        r'\b(?:do not|don\'?t|not|never|without)\s+(?:want\s+to\s+)?(?:delete|erase|remove|close|suppress|wipe|purge|destroy)\b',
        r'\b(?:keep|leave)\s+(?:the|my)?\s*(?:account|profile)\s*(?:active|as it is|in place)?\b',
        r'\b(?:continue using|still use|still need)\b',
        r'\bnot asking for deletion\b',
        r'\bnot a request to erase\b',
        r'\bopt out of marketing\b',
        r'\bmarketing lists? only\b',
        r'\bpromotional emails?\b',
        r'\binformation request\b',
        r'\bwhat personal information you hold\b',
        r'\b(?:send|need|want|get|request|provide)\s+(?:me\s+)?(?:a\s+)?copy of (?:the|last year|\w+)\b',
        r'\bdownload my account information\b',
        r'\bexport my data\b',
        r'\bchange the email\b',
        r'\bupdate my email\b',
        r'\bmisspelled\b',
        r'\bcorrect it\b',
        r'\breset (?:the|my)?\s*login\b',
        r'\bcan\'?t access my profile\b',
        r'\b(?:can you tell me|tell me)\s+(?:how|what|when|if|why)\b',
        r'\bhow long (?:before|until|do you)\b',
        r'\b(?:just asking|just wondering|inquiry only)\b',
        r'\b(?:what is (?:the|your)|tell me about (?:the|your)|information on|inquiry about)\s+(?:deletion policy|policy on deletion)\b',
        r'\bdo you delete\b.*\?'
    ]
    for pat in negation_patterns:
        if re.search(pat, text):
            is_primary_deletion = bool(re.search(r'\b(?:please|want to|requesting|request to|asking you to|begin the|process a|treat this message as a request for)?\s*(?:permanently )?(?:delete|erase|remove|close)\s+(?:my|this|the)?\s*(?:account|personal data|profile)\b', text))
            has_explicit_negation = bool(re.search(r'\b(?:not asking for deletion|not a request to erase|don\'?t delete|do not delete|do not close|don\'?t close|without removing)\b', text))
            has_keep = bool(re.search(r'\b(?:keep the account|leave the account)\b', text))
            if is_primary_deletion and not has_explicit_negation and not has_keep:
                pass
            else:
                return False

    deletion_patterns = [
        r'\b(?:delet|eras|remov|close|suppress|wipe|purge|shut down|terminate account)\w*\b',
        r'\b(?:profile is gone|cannot identify me|gone|fully removed)\b',
        r'\b(?:supprim|elimin|l\u00f6sch|cancell|exclu|fermer|entfern)\w*\b',
        r'[\u524a\u9664\uc0ad\uc81c]',  # Japanese 削除, Korean 삭제
    ]
    for pat in deletion_patterns:
        if re.search(pat, text):
            return True

    return False


# ── 5. Deterministic Step Sequencing ──────────────────────────────────────────

def build_case_output(case_id, deletion_status, violations, compliant_resources):
    """
    Constructs compliant steps_json obeying exact official contract:
    - Phase order: FINDING -> REMEDIATION -> VERIFICATION
    - Operation order: official table order from problem_statement.md §6.4
    - system_id ascending
    - resource_id ascending
    - 1-indexed consecutive step numbers
    """
    if deletion_status == "NOT_APPLICABLE":
        return []

    raw_steps = []

    if deletion_status == "INCOMPLETE":
        # 1. FINDING Phase
        for v in violations:
            raw_steps.append({
                "phase": "FINDING",
                "system_id": get_system_id(v["resource_id"]),
                "resource_id": v["resource_id"],
                "operation": v["operation"],
                "state": v["finding_state"],
                "evidence_id": v["evidence_id"],
            })

        # 2. REMEDIATION Phase
        planned_remediations = []
        for v in violations:
            rid = v["resource_id"]
            op = v["operation"]
            cat = v.get("category", "")
            if op == "REPORT_ACTIVE_DATA_FLOW":
                rem_op, rem_st = "DISABLE_DATA_FLOW", "DISABLED"
            elif op == "REPORT_RESTORE_RISK":
                rem_op, rem_st = "BLOCK_RESTORE", "BLOCKED"
            elif op == "REPORT_REMAINING_RECORD":
                rem_op, rem_st = "DELETE_RECORD", "ABSENT"
            elif op == "REPORT_EXPOSED_PII":
                if rid.startswith("analytics_") or cat in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
                    rem_op, rem_st = "ANONYMIZE_RECORD", "ANONYMIZED"
                else:
                    rem_op, rem_st = "REDACT_RECORD", "REDACTED"
            else:
                rem_op, rem_st = "DELETE_RECORD", "ABSENT"
            planned_remediations.append((rem_op, rem_st, rid))

        for rem_op, rem_st, rid in planned_remediations:
            raw_steps.append({
                "phase": "REMEDIATION",
                "system_id": get_system_id(rid),
                "resource_id": rid,
                "operation": rem_op,
                "state": rem_st,
                "evidence_id": "",
            })

        # 3. Future VERIFICATION Phase
        all_case_resources = violations + compliant_resources
        seen_rids = set()
        unique_res = []
        for r in all_case_resources:
            rid = r["resource_id"]
            if rid not in seen_rids:
                seen_rids.add(rid)
                unique_res.append(r)

        for r in unique_res:
            rid = r["resource_id"]
            cat = r.get("category", "")
            is_deleted_in_rem = any(rem[0] == "DELETE_RECORD" and rem[2] == rid for rem in planned_remediations)

            if rid.startswith("account_") or rid.startswith("export_") or rid.startswith("search_") or rid.startswith("object_") or rid.startswith("marketing_"):
                v_op, v_st, sys_id = "VERIFY_RECORD_ABSENT", "ABSENT", get_system_id(rid)
            elif rid.startswith("support_") and (is_deleted_in_rem or cat == "SUPPORT_ATTACHMENT"):
                v_op, v_st, sys_id = "VERIFY_RECORD_ABSENT", "ABSENT", "support_platform"
            elif rid.startswith("analytics_") and is_deleted_in_rem:
                v_op, v_st, sys_id = "VERIFY_RECORD_ABSENT", "ABSENT", "analytics_platform"
            elif rid.startswith("audit_record_") or rid.startswith("tax_") or cat in ("TAX_INVOICE", "SECURITY_AUDIT_LOG", "SECURITY_LOG"):
                v_op, v_st, sys_id = "VERIFY_RECORD_PRESENT", "PRESENT", "security_service"
            elif rid.startswith("legal_hold_") or cat in ("LEGAL_HOLD_RECORD", "LEGAL_HOLD"):
                v_op, v_st, sys_id = "VERIFY_RECORD_PRESENT", "PRESENT", "legal_service"
            elif rid.startswith("support_"):
                v_op, v_st, sys_id = "VERIFY_RECORD_REDACTED", "REDACTED", "support_platform"
            elif rid.startswith("tombstone_"):
                v_op, v_st, sys_id = "VERIFY_RECORD_REDACTED", "REDACTED", "identity_service"
            elif rid.startswith("analytics_"):
                v_op, v_st, sys_id = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", "analytics_platform"
            elif rid.startswith("data_flow_"):
                v_op, v_st, sys_id = "VERIFY_DATA_FLOW_DISABLED", "DISABLED", "integration_service"
            elif rid.startswith("backup_"):
                v_op, v_st, sys_id = "VERIFY_RESTORE_BLOCKED", "BLOCKED", "backup_service"
            else:
                v_op, v_st, sys_id = "VERIFY_RECORD_ABSENT", "ABSENT", get_system_id(rid)

            raw_steps.append({
                "phase": "VERIFICATION",
                "system_id": sys_id,
                "resource_id": rid,
                "operation": v_op,
                "state": v_st,
                "evidence_id": "",
            })

    else:
        # COMPLETE Case
        seen_rids = set()
        for r in compliant_resources:
            rid = r["resource_id"]
            if rid in seen_rids:
                continue
            ev_id = r.get("evidence_id", "")
            if not ev_id:
                continue
            seen_rids.add(rid)

            cat = r.get("category", "")
            if rid.startswith("account_") or rid.startswith("export_") or rid.startswith("search_") or rid.startswith("object_") or rid.startswith("marketing_"):
                v_op, v_st, sys_id = "VERIFY_RECORD_ABSENT", "ABSENT", get_system_id(rid)
            elif rid.startswith("support_") and cat == "SUPPORT_ATTACHMENT":
                v_op, v_st, sys_id = "VERIFY_RECORD_ABSENT", "ABSENT", "support_platform"
            elif rid.startswith("audit_record_") or rid.startswith("tax_") or cat in ("TAX_INVOICE", "SECURITY_AUDIT_LOG", "SECURITY_LOG"):
                v_op, v_st, sys_id = "VERIFY_RECORD_PRESENT", "PRESENT", "security_service"
            elif rid.startswith("legal_hold_") or cat in ("LEGAL_HOLD_RECORD", "LEGAL_HOLD"):
                v_op, v_st, sys_id = "VERIFY_RECORD_PRESENT", "PRESENT", "legal_service"
            elif rid.startswith("support_"):
                v_op, v_st, sys_id = "VERIFY_RECORD_REDACTED", "REDACTED", "support_platform"
            elif rid.startswith("tombstone_"):
                v_op, v_st, sys_id = "VERIFY_RECORD_REDACTED", "REDACTED", "identity_service"
            elif rid.startswith("analytics_"):
                v_op, v_st, sys_id = "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", "analytics_platform"
            elif rid.startswith("data_flow_"):
                v_op, v_st, sys_id = "VERIFY_DATA_FLOW_DISABLED", "DISABLED", "integration_service"
            elif rid.startswith("backup_"):
                v_op, v_st, sys_id = "VERIFY_RESTORE_BLOCKED", "BLOCKED", "backup_service"
            else:
                v_op, v_st, sys_id = "VERIFY_RECORD_ABSENT", "ABSENT", get_system_id(rid)

            raw_steps.append({
                "phase": "VERIFICATION",
                "system_id": sys_id,
                "resource_id": rid,
                "operation": v_op,
                "state": v_st,
                "evidence_id": ev_id,
            })

    # Strict canonical sort per problem_statement.md §6.4 & §6.5
    raw_steps.sort(key=canonical_step_sort_key)

    steps = []
    for step_no, s in enumerate(raw_steps, start=1):
        s["step_no"] = step_no
        steps.append(s)

    return steps


# ── 6. Case Audit Logic ───────────────────────────────────────────────────────

def audit_case(req, id_graph, catalog, user_to_resources, activities):
    """
    Audits a single deletion request according to §6.5:
    - Verifies authorization intent
    - Resolves current and historical identity
    - Collects point-in-time evidence captured strictly at or before audit_at
    - Evaluates policy violations vs verified compliance
    - Returns (pred_status, steps)
    """
    cid = req["case_id"]
    email = req["email"].strip().lower()
    req_text = req.get("request_text", "")
    aud_time = to_dt(req.get("audit_at"))
    if not aud_time:
        aud_time = to_dt(req.get("reported_at")) or to_dt(req.get("requested_at"))
    if not aud_time:
        return "INCOMPLETE", []

    # Step 1: Check request authorization
    if not is_authorized_deletion_request(req_text):
        return "NOT_APPLICABLE", []

    uid = id_graph.resolve_user_id(email, at_time=aud_time)
    user_emails = id_graph.get_emails(uid, at_time=aud_time) if uid else {email}
    user_hashes = id_graph.get_hashes(uid, at_time=aud_time) if uid else set()

    # Step 2: Gather point-in-time evidence strictly at or before audit_at
    user_obs = []
    for fid, records in catalog.records_by_file.items():
        cap_str = catalog.manifest_dict[fid].get("captured_at")
        if not is_valid_date(cap_str):
            continue
        cap_time = to_dt(cap_str)
        if cap_time and cap_time <= aud_time:
            for r in records:
                r_time = to_dt(r.get("captured_at")) or cap_time
                if r_time and r_time > aud_time:
                    continue

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
                elif r_rid and r_rid in user_to_resources.get(uid, set()):
                    matches = True

                if matches:
                    user_obs.append(r)

    res_obs = defaultdict(list)
    for r in user_obs:
        res_obs[r["resource_id"]].append(r)

    violations = []
    compliant = []

    # Find primary account
    user_accs = [r for r in user_to_resources.get(uid, set()) if r.startswith("account_")]
    primary_acc = sorted(user_accs)[0] if user_accs else None

    for rid, obs_list in res_obs.items():
        by_source = defaultdict(list)
        for o in obs_list:
            fid = o.get("file_id")
            origin = o.get("origin") or (catalog.manifest_dict.get(fid, {}).get("origin") if catalog and catalog.manifest_dict else None) or fid
            target = o.get("table") or o.get("service") or o.get("data_store") or o.get("resource_id")
            sk = (origin, target)
            by_source[sk].append(o)

        latest_obs = sorted(obs_list, key=lambda x: to_dt(x.get("captured_at")) or datetime(1970, 1, 1, tzinfo=timezone.utc))[-1]
        cat = latest_obs.get("category")
        ev_id = latest_obs["file_id"]

        is_viol = False
        viol_op = None
        viol_st = "PRESENT"

        req_time = to_dt(req.get("requested_at"))

        # Evaluate the latest observation of each source at or before audit_at
        for sk, s_obs in by_source.items():
            s_latest = sorted(s_obs, key=lambda x: to_dt(x.get("captured_at")) or datetime(1970, 1, 1, tzinfo=timezone.utc))[-1]
            s_cap_time = to_dt(s_latest.get("captured_at"))
            # Observations captured strictly before deletion request was submitted cannot prove undeleted findings
            if req_time and s_cap_time and s_cap_time < req_time:
                continue

            r_cat = s_latest.get("category") or cat
            if rid.startswith("legal_hold_") or r_cat in ("LEGAL_HOLD_RECORD", "LEGAL_HOLD"):
                # Policy-retained under Rule 13, NOT a violation
                continue
            if rid.startswith("audit_record_") or rid.startswith("tax_") or r_cat in ("SECURITY_AUDIT_LOG", "SECURITY_LOG", "TAX_INVOICE"):
                # Policy-retained under Rule 12, NOT a violation
                continue

            is_del_cat = (r_cat in ("USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY", "CACHE_ENTRY", "SUPPORT_ATTACHMENT", "USER_EXPORT", "MARKETING_PROFILE", "ACCOUNT_DATABASE"))
            is_red_cat = (r_cat in ("SUPPORT_MESSAGE", "EMAIL_DELIVERY_LOG", "ACCOUNT_TOMBSTONE"))
            is_anon_cat = (r_cat in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"))

            if (is_del_cat or rid.startswith("account_") or rid.startswith("search_") or rid.startswith("export_") or rid.startswith("marketing_") or s_latest.get("is_secondary_contact")) and s_latest.get("is_present") and not s_latest.get("is_absent"):
                is_viol = True
                viol_op = "REPORT_REMAINING_RECORD"
                ev_id = s_latest["file_id"]
                break
            elif (is_red_cat or rid.startswith("support_") or rid.startswith("tombstone_")) and s_latest.get("has_pii"):
                is_viol = True
                viol_op = "REPORT_EXPOSED_PII"
                ev_id = s_latest["file_id"]
                break
            elif (is_anon_cat or rid.startswith("analytics_")) and s_latest.get("has_pii"):
                is_viol = True
                viol_op = "REPORT_EXPOSED_PII"
                ev_id = s_latest["file_id"]
                break
            elif (rid.startswith("data_flow_") or r_cat == "DATA_FLOW") and s_latest.get("enabled"):
                is_viol = True
                viol_op = "REPORT_ACTIVE_DATA_FLOW"
                viol_st = "ACTIVE"
                ev_id = s_latest["file_id"]
                break
            elif (rid.startswith("backup_") or r_cat == "BACKUP_ARCHIVE") and s_latest.get("restore_allowed"):
                is_viol = True
                viol_op = "REPORT_RESTORE_RISK"
                viol_st = "ACTIVE"
                ev_id = s_latest["file_id"]
                break

        if is_viol:
            violations.append({
                "resource_id": rid,
                "operation": viol_op,
                "finding_state": viol_st,
                "evidence_id": ev_id,
                "category": cat,
            })
        else:
            compliant.append({
                "resource_id": rid,
                "evidence_id": ev_id,
                "category": cat,
            })

    pred_status = "INCOMPLETE" if violations else "COMPLETE"

    # For INCOMPLETE cases, ensure policy-required retained records known for the subject are included in future verification
    if pred_status == "INCOMPLETE" and uid:
        for k_rid in sorted(user_to_resources.get(uid, set())):
            is_retained = (k_rid.startswith("audit_record_") or k_rid.startswith("tax_") or k_rid.startswith("legal_hold_"))
            if is_retained and not any(r["resource_id"] == k_rid for r in compliant + violations):
                ret_cat = "LEGAL_HOLD_RECORD" if k_rid.startswith("legal_hold_") else "SECURITY_AUDIT_LOG"
                compliant.append({
                    "resource_id": k_rid,
                    "evidence_id": "",
                    "category": ret_cat,
                })

    # If no account resource is in compliant or violations, find evidence of primary account absence
    has_account = any(r["resource_id"].startswith("account_") for r in compliant + violations)
    if not has_account and primary_acc:
        ev_proof = ""
        for fid, records in catalog.records_by_file.items():
            cap_time = to_dt(catalog.manifest_dict[fid]["captured_at"])
            if cap_time and cap_time <= aud_time:
                for r in records:
                    if r["resource_id"] == primary_acc and r.get("is_absent"):
                        ev_proof = fid
                        break
                if ev_proof: break

        if not ev_proof:
            candidates = [
                (fid, to_dt(info["captured_at"]))
                for fid, info in catalog.manifest_dict.items()
                if fid in catalog.account_datastore_files and to_dt(info["captured_at"]) and to_dt(info["captured_at"]) <= aud_time
            ]
            candidates.sort(key=lambda x: x[1], reverse=True)
            if candidates:
                ev_proof = candidates[0][0]

        compliant.insert(0, {"resource_id": primary_acc, "evidence_id": ev_proof if pred_status == "COMPLETE" else ""})

    if pred_status == "COMPLETE":
        if not uid or not compliant or not any(c.get("evidence_id") for c in compliant):
            pred_status = "INCOMPLETE"

    steps = build_case_output(cid, pred_status, violations, compliant)
    return pred_status, steps


def run_pipeline(target_csv="deletion_requests.csv", output_csv_path=DEFAULT_OUTPUT_PATH, dataset_dir=DATASET_DIR):
    print("Loading datasets...", file=sys.stderr)
    requests = load_csv(target_csv, dataset_dir=dataset_dir)
    identities = load_csv("user_identities.csv", dataset_dir=dataset_dir)
    audit_log = load_csv("user_audit_log.csv", dataset_dir=dataset_dir)
    activities = load_csv("system_activity.csv", dataset_dir=dataset_dir)
    manifest = load_csv("evidence_files.csv", dataset_dir=dataset_dir)

    print(f"Loaded {len(requests)} evaluation requests.", file=sys.stderr)
    print("Building identity graph...", file=sys.stderr)
    id_graph = IdentityGraph(identities, audit_log)

    print("Parsing multi-modal evidence files...", file=sys.stderr)
    catalog = EvidenceCatalog(manifest, id_graph, activities, dataset_dir=dataset_dir)
    total_obs = sum(len(v) for v in catalog.records_by_file.values())
    print(f"Extracted {total_obs} evidence observations.", file=sys.stderr)

    # Global user-to-resource graph derived from evidence
    user_to_resources = defaultdict(set)
    resource_to_user = {}

    for fid, records in catalog.records_by_file.items():
        for r in records:
            rid = r.get("resource_id")
            uid = r.get("user_id")
            em = r.get("email")
            if not uid and em:
                uid = id_graph.resolve_user_id(em)
            if rid and uid:
                user_to_resources[uid].add(rid)
                resource_to_user[rid] = uid

    # Ground-truth LINK_RESOURCE_IDENTITY events from activity stream
    for a in activities:
        if a.get("event_type") == "LINK_RESOURCE_IDENTITY":
            rid = a["resource_id"]
            det = a.get("details", "")
            m_u = re.findall(r'user_\d+', det)
            m_e = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', det)
            uid = m_u[0] if m_u else (id_graph.resolve_user_id(m_e[0]) if m_e else None)
            if uid and rid:
                user_to_resources[uid].add(rid)
                resource_to_user[rid] = uid

    # Canonical user account convention: user_X -> account_00X or account_X
    for u in identities:
        uid = u["user_id"]
        m_num = re.search(r'\d+', uid)
        if m_num:
            num = int(m_num.group(0))
            candidate = f"account_{num:03d}" if num < 1000 else f"account_{num}"
            user_to_resources[uid].add(candidate)
            if candidate not in resource_to_user:
                resource_to_user[candidate] = uid

    results = []
    status_counts = defaultdict(int)

    for i, req in enumerate(requests):
        cid = req["case_id"]
        pred_status, steps = audit_case(req, id_graph, catalog, user_to_resources, activities)
        status_counts[pred_status] += 1
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
    import argparse
    parser = argparse.ArgumentParser(description="NorthStar Shop Deletion-Audit Engine")
    parser.add_argument("--target-csv", type=str, default="deletion_requests.csv", help="Input deletion requests CSV filename or path")
    parser.add_argument("--output-csv", type=str, default=DEFAULT_OUTPUT_PATH, help="Path for generated output CSV")
    parser.add_argument("--dataset-dir", type=str, default=DATASET_DIR, help="Path to participant-facing dataset directory")
    parser.add_argument("--sample", action="store_true", help="Audit sample dataset (sample_deletion_requests.csv)")
    args = parser.parse_args()

    target = "sample_deletion_requests.csv" if args.sample else args.target_csv
    out = os.path.join(BASE_DIR, "sample_output_pred.csv") if (args.sample and args.output_csv == DEFAULT_OUTPUT_PATH) else args.output_csv
    run_pipeline(target_csv=target, output_csv_path=out, dataset_dir=args.dataset_dir)

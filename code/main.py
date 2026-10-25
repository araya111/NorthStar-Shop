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
import pypdf

# Repository root and dataset paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATASET_DIR = os.path.join(BASE_DIR, "dataset")
DEFAULT_OUTPUT_PATH = os.path.join(BASE_DIR, "output.csv")


def load_csv(rel_path):
    fpath = os.path.join(DATASET_DIR, rel_path)
    with open(fpath, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def to_dt(s):
    if not s or not isinstance(s, str):
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(s.replace('Z', '+00:00'))
    except Exception:
        try:
            return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except Exception:
            return datetime(1970, 1, 1, tzinfo=timezone.utc)


# ── 1. Identity Resolution & Historical Graph ─────────────────────────────────

class IdentityGraph:
    """Maintains user identities, historical audit changes, and cryptographic hashes."""

    def __init__(self, identities, audit_log):
        self.email_to_uid = {}
        self.uid_to_emails = defaultdict(set)
        self.uid_to_hashes = defaultdict(set)
        self.hash_to_uid = {}
        self.uid_to_record = {}
        self.ambiguous_identifiers = set()

        # Current snapshot
        for u in identities:
            uid = u["user_id"]
            em = u["email"].strip().lower()
            if em in self.email_to_uid and self.email_to_uid[em] != uid:
                self.ambiguous_identifiers.add(em)
            else:
                self.email_to_uid[em] = uid
            self.uid_to_emails[uid].add(em)
            self.uid_to_record[uid] = u

            h = u.get("email_hash", "").strip().lower()
            if h:
                if h in self.hash_to_uid and self.hash_to_uid[h] != uid:
                    self.ambiguous_identifiers.add(h)
                else:
                    self.hash_to_uid[h] = uid
                self.uid_to_hashes[uid].add(h)
            
            calc_h = hashlib.sha256(em.encode("utf-8")).hexdigest()
            if calc_h in self.hash_to_uid and self.hash_to_uid[calc_h] != uid:
                self.ambiguous_identifiers.add(calc_h)
            else:
                self.hash_to_uid[calc_h] = uid
            self.uid_to_hashes[uid].add(calc_h)

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

    def resolve_user_id(self, identifier):
        if not identifier:
            return None
        ident = str(identifier).strip().lower()
        if ident in self.ambiguous_identifiers:
            return None
        if ident.startswith("user_"):
            return ident
        if len(ident) == 64 and ident in self.hash_to_uid:
            return self.hash_to_uid[ident]
        return self.email_to_uid.get(ident)

    def get_emails(self, user_id):
        return self.uid_to_emails.get(user_id, set())

    def get_hashes(self, user_id):
        return self.uid_to_hashes.get(user_id, set())


# ── 2. Comprehensive Evidence Parser ──────────────────────────────────────────

class EvidenceCatalog:
    """Parses SQL snapshots, structured JSON exports, trace logs, TXT documents, PDFs, and PNG artifacts."""

    def __init__(self, manifest, id_graph=None, activities=None):
        self.manifest_dict = {r["file_id"]: r for r in manifest}
        self.records_by_file = defaultdict(list)
        self.account_datastore_files = set()
        self.id_graph = id_graph
        self.activities = activities or []
        self._parse_all(manifest)

    def _parse_all(self, manifest):
        # Index LINK_RESOURCE_IDENTITY events from global activity stream
        link_events_by_time = []
        for a in self.activities:
            if a.get("event_type") == "LINK_RESOURCE_IDENTITY":
                t = to_dt(a["event_time"])
                det = a.get("details", "")
                m_u = re.findall(r'user_\d+', det)
                m_e = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', det)
                uid = m_u[0] if m_u else (self.id_graph.resolve_user_id(m_e[0]) if (self.id_graph and m_e) else None)
                em = m_e[0].lower() if m_e else None
                link_events_by_time.append((t, a["resource_id"], uid, em, det, a.get("target_system")))

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
                # Evidence-based dynamic extraction: match LINK_RESOURCE_IDENTITY event within 15 mins
                t_png = to_dt(cap_at)
                matched_links = []
                for t_act, rid, uid, em, det, tgt in link_events_by_time:
                    diff = abs((t_act - t_png).total_seconds())
                    if diff <= 900:
                        matched_links.append((rid, uid, em, det, tgt))
                for rid, uid, em, det, tgt in matched_links:
                    cat = "SUPPORT_ATTACHMENT" if "attachment" in rel_path.lower() or "attachment" in det.lower() else None
                    is_pres = True
                    has_pii = bool(em or uid)
                    if rid.startswith("tombstone_"):
                        has_pii = False
                    is_anonymized = not has_pii and rid.startswith("analytics_")
                    is_redacted = not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_"))
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "service": tgt, "category": cat,
                        "user_id": uid, "email": em,
                        "is_present": is_pres, "has_pii": has_pii,
                        "is_anonymized": is_anonymized, "is_redacted": is_redacted,
                        "restore_allowed": rid.startswith("backup_"),
                        "enabled": rid.startswith("data_flow_"),
                    })

    def _parse_sql(self, fid, fpath, cap_at):
        try:
            conn = sqlite3.connect(":memory:")
            with open(fpath, encoding="utf-8", errors="ignore") as f:
                conn.executescript(f.read())
            cur = conn.cursor()
            tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            if any("profile" in t.lower() or "account" in t.lower() for t in tables):
                self.account_datastore_files.add(fid)
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
                               (embedded.get("document") or {}).get("customer_reference"))
                        if not uid and em and self.id_graph:
                            uid = self.id_graph.resolve_user_id(em)

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
                            "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                            "table": t, "user_id": uid, "email": em, "phone": phone,
                            "email_hash": email_hash, "is_present": True, "has_pii": has_pii,
                            "restore_allowed": is_restore, "enabled": is_enabled and rid.startswith("data_flow_"),
                            "is_anonymized": not has_pii and rid.startswith("analytics_"),
                            "is_redacted": not has_pii and (rid.startswith("support_") or rid.startswith("tombstone_")),
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
                    tid = kvs.get("trace_id") or kvs.get("requestId")
                    if not tid:
                        m_tid = re.search(r'\b(tr-[a-zA-Z0-9_-]+|rb-[a-zA-Z0-9_-]+)\b', clean_line)
                        if m_tid: tid = m_tid.group(1)
                    if tid:
                        kvs["trace_id"] = tid
                        for k in ["email", "customer_email", "requester_email", "matched_value", "subject_key", "lookup_key"]:
                            val = kvs.get(k)
                            if val and "@" in val:
                                trace_identities[tid]["email"] = val.lower()
                                if self.id_graph:
                                    u = self.id_graph.resolve_user_id(val.lower())
                                    if u: trace_identities[tid]["user_id"] = u
                            elif val and val.startswith("user_"):
                                trace_identities[tid]["user_id"] = val
                        for k in ["customer_reference", "subject_reference", "subject_ref", "user_id"]:
                            val = kvs.get(k)
                            if val and val.startswith("user_"):
                                trace_identities[tid]["user_id"] = val
                        ck = kvs.get("correlation_key")
                        if ck:
                            if "@" in ck:
                                trace_identities[tid]["email"] = ck.lower()
                                if self.id_graph:
                                    u = self.id_graph.resolve_user_id(ck.lower())
                                    if u: trace_identities[tid]["user_id"] = u
                            elif ck.startswith("user_"):
                                trace_identities[tid]["user_id"] = ck
                            elif len(ck) == 64:
                                trace_identities[tid]["email_hash"] = ck.lower()
                    if kvs:
                        parsed_lines.append(kvs)

            for kvs in parsed_lines:
                rid = kvs.get("resource_id")
                evt = kvs.get("event", "")
                tid = kvs.get("trace_id")
                # Context / started events establish lookup metadata, not completed state
                if not rid or evt.endswith("_started"): continue

                trace_ctx = trace_identities.get(tid, {})
                em = (kvs.get("email") or kvs.get("customer_email") or 
                      kvs.get("requester_email") or kvs.get("matched_value") or trace_ctx.get("email"))
                uid = (kvs.get("customer_reference") or kvs.get("subject_reference") or 
                       kvs.get("subject_ref") or trace_ctx.get("user_id"))
                if not uid and em and self.id_graph:
                    uid = self.id_graph.resolve_user_id(em)
                eh = trace_ctx.get("email_hash") or kvs.get("email_hash")

                rows = kvs.get("rows")
                http_status = kvs.get("http_status")
                is_absent = (rows in (0, "0") or http_status in (404, "404"))
                enabled = kvs.get("enabled")
                is_enabled = (enabled in (True, "true"))
                res_allowed = kvs.get("restore_allowed") or (kvs.get("eligible") == "true" and kvs.get("deletion_block") == "false")
                is_restore = (res_allowed in (True, "true"))
                has_pii = bool(em or eh or kvs.get("phone") or kvs.get("full_name") or kvs.get("requester_name"))

                # Special checks for contact index / opt-in secondary markers
                is_secondary_contact = (kvs.get("source") == "legacy_contact_index" or kvs.get("marker_found") == "false" or kvs.get("email_opt_in") in (True, "true"))
                if is_secondary_contact:
                    is_absent = False
                    has_pii = True

                self.records_by_file[fid].append({
                    "file_id": fid, "captured_at": cap_at, "resource_id": rid,
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
            reader = pypdf.PdfReader(fpath)
            for page in reader.pages:
                text = page.extract_text()
                p_emails = set(re.findall(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', text))
                p_uids = set(re.findall(r'(user_\d+)', text))
                p_rids = set(re.findall(r'((?:support|search|account|analytics|backup|export|audit_record)_\d+)', text))
                for rid in p_rids:
                    em = list(p_emails)[0] if p_emails else None
                    uid = list(p_uids)[0] if p_uids else (self.id_graph.resolve_user_id(em) if (self.id_graph and em) else None)
                    self.records_by_file[fid].append({
                        "file_id": fid, "captured_at": cap_at, "resource_id": rid,
                        "is_present": True, "category": cat, "user_id": uid, "email": em,
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
    if resource_id.startswith("marketing_"): return "marketing_platform"
    return "unknown_service"


def is_authorized_deletion_request(request_text):
    """Determine whether request authorizes deletion per §6.5."""
    if not request_text:
        return False
    text = request_text.lower()

    # Hypothetical or conditional query check
    if re.search(r'\b(?:if\s+i\s+(?:decide|choose|want|ever)\s+to\s+delete|supposing\s+i\s+delete|in\s+case\s+i\s+delete|hypothetically)\b', text):
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
        r'\b(?:deletion policy|policy on deletion)\b',
        r'\bdo you delete\b.*\?'
    ]
    for pat in negation_patterns:
        if re.search(pat, text):
            # Allow requests that affirmatively ask for deletion while specifying policy retention
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


# ── 4. Deterministic Step Sequencing ──────────────────────────────────────────

def build_case_output(case_id, deletion_status, violations, compliant_resources):
    """
    Constructs compliant steps_json obeying exact phase ordering:
    FINDING -> REMEDIATION -> VERIFICATION, strictly adhering to AGENTS.md §6.3, §6.4 & §6.5.
    """
    if deletion_status == "NOT_APPLICABLE":
        return []

    steps = []
    step_no = 1

    if deletion_status == "INCOMPLETE":
        # 1. FINDING Phase
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
        planned_remediations = []
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
            planned_remediations.append((rem_op, rem_st, rid))

        planned_remediations.sort(key=lambda r: (remediation_priority.get(r[0], 99), r[2]))

        for rem_op, rem_st, rid in planned_remediations:
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
        all_case_resources = sorted_violations + compliant_resources
        seen_rids = set()
        unique_res = []
        for r in all_case_resources:
            rid = r["resource_id"]
            if rid not in seen_rids:
                seen_rids.add(rid)
                unique_res.append(r)

        verif_steps = []
        for r in unique_res:
            rid = r["resource_id"]
            is_deleted_in_rem = any(rem[0] == "DELETE_RECORD" and rem[2] == rid for rem in planned_remediations)

            if rid.startswith("account_"):
                v_tuple = (1, 0, rid, "account_service", "VERIFY_RECORD_ABSENT", "ABSENT")
            elif rid.startswith("export_"):
                v_tuple = (2, 1, rid, "export_service", "VERIFY_RECORD_ABSENT", "ABSENT")
            elif rid.startswith("search_"):
                v_tuple = (2, 2, rid, "search_service", "VERIFY_RECORD_ABSENT", "ABSENT")
            elif rid.startswith("support_") and is_deleted_in_rem:
                v_tuple = (2, 3, rid, "support_platform", "VERIFY_RECORD_ABSENT", "ABSENT")
            elif rid.startswith("analytics_") and is_deleted_in_rem:
                v_tuple = (2, 4, rid, "analytics_platform", "VERIFY_RECORD_ABSENT", "ABSENT")
            elif rid.startswith("audit_record_"):
                v_tuple = (3, 0, rid, "security_service", "VERIFY_RECORD_PRESENT", "PRESENT")
            elif rid.startswith("support_"):
                v_tuple = (4, 1, rid, "support_platform", "VERIFY_RECORD_REDACTED", "REDACTED")
            elif rid.startswith("tombstone_"):
                v_tuple = (4, 2, rid, "identity_service", "VERIFY_RECORD_REDACTED", "REDACTED")
            elif rid.startswith("analytics_"):
                v_tuple = (5, 0, rid, "analytics_platform", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED")
            elif rid.startswith("data_flow_"):
                v_tuple = (6, 0, rid, "integration_service", "VERIFY_DATA_FLOW_DISABLED", "DISABLED")
            elif rid.startswith("backup_"):
                v_tuple = (7, 0, rid, "backup_service", "VERIFY_RESTORE_BLOCKED", "BLOCKED")
            else:
                v_tuple = (9, 0, rid, get_system_id(rid), "VERIFY_RECORD_ABSENT", "ABSENT")
            verif_steps.append(v_tuple)

        verif_steps.sort(key=lambda x: (x[0], x[1], x[2]))

        for _, _, rid, sys_id, v_op, v_st in verif_steps:
            steps.append({
                "step_no": step_no,
                "phase": "VERIFICATION",
                "system_id": sys_id,
                "resource_id": rid,
                "operation": v_op,
                "state": v_st,
                "evidence_id": "",
            })
            step_no += 1

    else:
        # COMPLETE Case: only VERIFICATION phase, with grounded evidence_id
        verif_steps = []
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
            if rid.startswith("account_"):
                v_tuple = (1, 0, rid, "account_service", "VERIFY_RECORD_ABSENT", "ABSENT", ev_id)
            elif rid.startswith("export_"):
                v_tuple = (2, 1, rid, "export_service", "VERIFY_RECORD_ABSENT", "ABSENT", ev_id)
            elif rid.startswith("search_"):
                v_tuple = (2, 2, rid, "search_service", "VERIFY_RECORD_ABSENT", "ABSENT", ev_id)
            elif rid.startswith("audit_record_") or rid.startswith("tax_") or cat in ("TAX_INVOICE", "LEGAL_HOLD", "SECURITY_AUDIT_LOG", "SECURITY_LOG"):
                v_tuple = (3, 0, rid, "security_service", "VERIFY_RECORD_PRESENT", "PRESENT", ev_id)
            elif rid.startswith("support_"):
                v_tuple = (4, 1, rid, "support_platform", "VERIFY_RECORD_REDACTED", "REDACTED", ev_id)
            elif rid.startswith("tombstone_"):
                v_tuple = (4, 2, rid, "identity_service", "VERIFY_RECORD_REDACTED", "REDACTED", ev_id)
            elif rid.startswith("analytics_"):
                v_tuple = (5, 0, rid, "analytics_platform", "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED", ev_id)
            elif rid.startswith("data_flow_"):
                v_tuple = (6, 0, rid, "integration_service", "VERIFY_DATA_FLOW_DISABLED", "DISABLED", ev_id)
            elif rid.startswith("backup_"):
                v_tuple = (7, 0, rid, "backup_service", "VERIFY_RESTORE_BLOCKED", "BLOCKED", ev_id)
            else:
                v_tuple = (9, 0, rid, get_system_id(rid), "VERIFY_RECORD_ABSENT", "ABSENT", ev_id)
            verif_steps.append(v_tuple)

        verif_steps.sort(key=lambda x: (x[0], x[1], x[2]))

        for _, _, rid, sys_id, v_op, v_st, ev_id in verif_steps:
            steps.append({
                "step_no": step_no,
                "phase": "VERIFICATION",
                "system_id": sys_id,
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

    print("Parsing multi-modal evidence files...", file=sys.stderr)
    catalog = EvidenceCatalog(manifest, id_graph, activities)
    total_obs = sum(len(v) for v in catalog.records_by_file.values())
    print(f"Extracted {total_obs} evidence observations.", file=sys.stderr)

    # 1. Global user-to-resource graph derived from evidence
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

    # 2. Integrate ground-truth LINK_RESOURCE_IDENTITY events from activity stream
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

    # 3. Grounded deletion worker activities within 30 minutes of reported_at
    worker_acts = [a for a in activities if a.get("source_system") == "deletion_worker"]
    for req in requests:
        uid = id_graph.resolve_user_id(req["email"])
        if not uid: continue
        rep_time = to_dt(req["reported_at"])
        for a in worker_acts:
            t_act = to_dt(a["event_time"])
            diff = abs((t_act - rep_time).total_seconds())
            if diff <= 1800:
                rid = a["resource_id"]
                user_to_resources[uid].add(rid)
                resource_to_user[rid] = uid

    # 4. Canonical user account convention: user_X -> account_X or account_00X
    all_known_accounts = set()
    for a in activities:
        if a["resource_id"].startswith("account_"):
            all_known_accounts.add(a["resource_id"])
    for fid, records in catalog.records_by_file.items():
        for r in records:
            if r["resource_id"].startswith("account_"):
                all_known_accounts.add(r["resource_id"])

    for u in identities:
        uid = u["user_id"]
        m_num = re.search(r'\d+', uid)
        if m_num:
            num = int(m_num.group(0))
            for candidate in [f"account_{num:03d}", f"account_{num}"]:
                if candidate in all_known_accounts:
                    user_to_resources[uid].add(candidate)
                    if candidate not in resource_to_user:
                        resource_to_user[candidate] = uid

    results = []
    status_counts = defaultdict(int)

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
    aud_time = to_dt(req["audit_at"])

    # Step 1: Check request authorization
    if not is_authorized_deletion_request(req_text):
        return "NOT_APPLICABLE", []

    uid = id_graph.resolve_user_id(email)
    user_emails = id_graph.get_emails(uid) if uid else {email}
    user_hashes = id_graph.get_hashes(uid) if uid else set()

    # Step 2: Gather point-in-time evidence strictly at or before audit_at
    user_obs = []
    for fid, records in catalog.records_by_file.items():
        cap_time = to_dt(catalog.manifest_dict[fid]["captured_at"])
        if cap_time <= aud_time:
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
            sk = o.get("table") or o.get("source") or o.get("service") or o.get("file_id")
            by_source[sk].append(o)

        latest_obs = sorted(obs_list, key=lambda x: to_dt(x["captured_at"]))[-1]
        cat = latest_obs.get("category")
        ev_id = latest_obs["file_id"]

        is_viol = False
        viol_op = None
        viol_st = "PRESENT"

        # Evaluate the latest observation of each source at or before audit_at
        for sk, s_obs in by_source.items():
            s_latest = sorted(s_obs, key=lambda x: to_dt(x["captured_at"]))[-1]
            r_cat = s_latest.get("category") or cat
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

    # If primary account not yet in lists, find evidence of its absence via resource-aware datastore resolution
    if primary_acc and not any(r["resource_id"] == primary_acc for r in compliant + violations):
        ev_proof = ""
        # 1. Direct explicit absent/404 lookup in parsed records
        for fid, records in catalog.records_by_file.items():
            cap_time = to_dt(catalog.manifest_dict[fid]["captured_at"])
            if cap_time <= aud_time:
                for r in records:
                    if r["resource_id"] == primary_acc and r.get("is_absent"):
                        ev_proof = fid
                        break
                if ev_proof: break

        # 2. Account datastore snapshot (files verified to contain customer_profiles / account_service tables)
        if not ev_proof:
            candidates = [
                (fid, to_dt(info["captured_at"]))
                for fid, info in catalog.manifest_dict.items()
                if fid in catalog.account_datastore_files and to_dt(info["captured_at"]) <= aud_time
            ]
            candidates.sort(key=lambda x: x[1], reverse=True)
            if candidates:
                ev_proof = candidates[0][0]

        compliant.insert(0, {"resource_id": primary_acc, "evidence_id": ev_proof if pred_status == "COMPLETE" else ""})

    # Evidence coverage check: A COMPLETE case cannot have 0 evidence or 0 compliant steps!
    if pred_status == "COMPLETE":
        if not uid or not compliant or not any(c.get("evidence_id") for c in compliant):
            pred_status = "INCOMPLETE"

    steps = build_case_output(cid, pred_status, violations, compliant)
    return pred_status, steps


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

    print("Parsing multi-modal evidence files...", file=sys.stderr)
    catalog = EvidenceCatalog(manifest, id_graph, activities)
    total_obs = sum(len(v) for v in catalog.records_by_file.values())
    print(f"Extracted {total_obs} evidence observations.", file=sys.stderr)

    # 1. Global user-to-resource graph derived from evidence
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

    # 2. Integrate ground-truth LINK_RESOURCE_IDENTITY events from activity stream
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

    # 3. Grounded deletion worker activities within 30 minutes of reported_at
    worker_acts = [a for a in activities if a.get("source_system") == "deletion_worker"]
    for req in requests:
        uid = id_graph.resolve_user_id(req["email"])
        if not uid: continue
        rep_time = to_dt(req["reported_at"])
        for a in worker_acts:
            t_act = to_dt(a["event_time"])
            diff = abs((t_act - rep_time).total_seconds())
            if diff <= 1800:
                rid = a["resource_id"]
                user_to_resources[uid].add(rid)
                resource_to_user[rid] = uid

    # 4. Canonical user account convention: user_X -> account_X or account_00X
    all_known_accounts = set()
    for a in activities:
        if a["resource_id"].startswith("account_"):
            all_known_accounts.add(a["resource_id"])
    for fid, records in catalog.records_by_file.items():
        for r in records:
            if r["resource_id"].startswith("account_"):
                all_known_accounts.add(r["resource_id"])

    for u in identities:
        uid = u["user_id"]
        m_num = re.search(r'\d+', uid)
        if m_num:
            num = int(m_num.group(0))
            for candidate in [f"account_{num:03d}", f"account_{num}"]:
                if candidate in all_known_accounts:
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
    target = "deletion_requests.csv"
    if len(sys.argv) > 1 and sys.argv[1] == "--sample":
        target = "sample_deletion_requests.csv"
        out = os.path.join(BASE_DIR, "sample_output_pred.csv")
        run_pipeline(target, out)
    else:
        run_pipeline(target, DEFAULT_OUTPUT_PATH)

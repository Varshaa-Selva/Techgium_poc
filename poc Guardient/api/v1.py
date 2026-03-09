"""
Guardient API v1 — Frontend Bridge
====================================
Mounted at /api/v1 by api/main.py.
Reads real-time data from PostgreSQL to serve the techgium frontend.

Endpoints
----------
GET  /api/v1/entities/           → all devices + latest trust/risk
GET  /api/v1/audit/              → alerts table shaped as AuditLog[]
GET  /api/v1/transparency/stats  → aggregate event counts + severity
POST /api/v1/response/approve    → simulated SOC action (logs to alerts table)
"""

from __future__ import annotations
import uuid
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from db.db import get_conn, put_conn

router = APIRouter()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _trust_to_decision(trust: float) -> dict:
    """Map numeric trust score to frontend decision/action fields."""
    trust = float(trust or 80)
    if trust >= 80:
        return {"decision": "trusted",   "active_actions": [],                    "approval_required": False}
    if trust >= 60:
        return {"decision": "monitor",   "active_actions": ["monitor"],           "approval_required": False}
    if trust >= 40:
        return {"decision": "monitor",   "active_actions": ["require_mfa"],       "approval_required": False}
    if trust >= 20:
        return {"decision": "isolate",   "active_actions": ["restrict_network"],  "approval_required": True}
    return     {"decision": "emergency", "active_actions": ["lock_account"],      "approval_required": True}


def _pct(v) -> float:
    return round(min(100.0, float(v or 0) * 100), 1)


def _build_category_breakdown(state: dict) -> dict:
    """Convert I/C/V/N risk magnitudes from trust_states to frontend category_breakdown."""
    return {
        "network":  _pct(state.get("N", 0)),
        "identity": _pct(state.get("I", 0)),
        "cloud":    _pct(state.get("C", 0)),
        "hardware": _pct(state.get("V", 0)),
        "temporal": 0,
    }


def _build_trust_evaluation(device_id: str, trust: float, adj: float,
                             state: dict, ts) -> dict:
    """Build the TrustEvaluation object the entity detail page expects."""
    n = float(state.get("N", 0) or 0)
    i = float(state.get("I", 0) or 0)
    c = float(state.get("C", 0) or 0)
    v = float(state.get("V", 0) or 0)

    def _cat(rc, signals):
        return {"weight": 0.25, "Rc": round(float(rc), 4), "delta": 0.0, "signals": signals}

    ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts or "")

    return {
        "entity_id":            device_id,
        "timestamp":            ts_str,
        "simulation":           False,
        "final_trust_score":    round(float(trust), 1),
        "previous_trust_score": round(float(trust), 1),
        "confidence":           round(min(100, max(0, (1 - adj) * 100)), 1),
        "decision":             _trust_to_decision(trust)["decision"],
        "trust_evaluation": {
            "network":  _cat(n, ["bytes_total", "port_risk"] if n > 0 else []),
            "identity": _cat(i, ["login_failure"]         if i > 0 else []),
            "cloud":    _cat(c, ["api_call"]              if c > 0 else []),
            "hardware": _cat(v, ["cpu_spike"]             if v > 0 else []),
            "temporal": _cat(0, []),
        },
    }


# ─────────────────────────────────────────────
# GET /entities/
# ─────────────────────────────────────────────

@router.get("/entities/")
def get_entities():
    """
    Returns all devices with their latest trust score and metadata.

    Strategy:
    - Fetch all devices from the `devices` table
    - For EACH device, LATERAL-join its latest trust_score
    - Join trust_states on device_id (supports dev_* format ids)
    - Handles NULL adjusted_risk gracefully
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    d.device_id,
                    d.hostname,
                    d.mac_address,
                    d.os,
                    d.device_type,
                    d.last_seen,
                    COALESCE(ts.trust_score, 80)       AS trust_score,
                    COALESCE(ts.adjusted_risk, 0.0)    AS adjusted_risk,
                    COALESCE(ts.timestamp, d.last_seen) AS score_ts,
                    tst.state                           AS trust_state,
                    (
                        SELECT ip FROM events
                        WHERE device_id = d.device_id
                        ORDER BY timestamp DESC LIMIT 1
                    ) AS last_ip
                FROM devices d
                LEFT JOIN LATERAL (
                    SELECT trust_score, adjusted_risk, timestamp
                    FROM trust_scores
                    WHERE device_id = d.device_id
                    ORDER BY timestamp DESC
                    LIMIT 1
                ) ts ON true
                LEFT JOIN trust_states tst ON tst.device_id = d.device_id
                ORDER BY d.last_seen DESC NULLS LAST
                LIMIT 500
            """)
            rows = [dict(zip([d[0] for d in cur.description], r))
                    for r in cur.fetchall()]

        entities = []
        for row in rows:
            trust  = float(row.get("trust_score") or 80)
            adj    = float(row.get("adjusted_risk") or 0)
            state  = row.get("trust_state") or {}
            ts_val = row.get("score_ts") or row.get("last_seen")
            dec    = _trust_to_decision(trust)
            confidence = round(min(100, max(0, (1 - adj) * 100)), 1)
            cat_bd = _build_category_breakdown(state)
            te     = _build_trust_evaluation(
                row["device_id"], trust, adj, state, ts_val
            )

            ts_str = ts_val.isoformat() if hasattr(ts_val, "isoformat") \
                     else str(ts_val or datetime.now(timezone.utc).isoformat())

            entities.append({
                "entity_id":         row["device_id"],
                "trust_score":       round(trust, 1),
                "confidence":        confidence,
                "decision":          dec["decision"],
                "category_breakdown": cat_bd,
                "last_updated":      ts_str,
                "active_actions":    dec["active_actions"],
                "last_action":       dec["active_actions"][0] if dec["active_actions"] else None,
                "approval_required": dec["approval_required"],
                "metadata": {
                    "ip":       row.get("last_ip"),
                    "mac":      row.get("mac_address"),
                    "hostname": row.get("hostname"),
                    "os":       row.get("os"),
                    "type":     row.get("device_type") or "workstation",
                    "simulated": "false",
                },
                "trust_evaluation": te,
                "trust_history":    [],
            })

        return entities

    except Exception as exc:
        import traceback
        print(f"[v1/entities] Error: {exc}")
        traceback.print_exc()
        return []
    finally:
        put_conn(conn)


# ─────────────────────────────────────────────
# GET /audit/
# ─────────────────────────────────────────────

@router.get("/audit/")
def get_audit():
    """
    Returns the audit log for the frontend.
    Sourced from the `alerts` table (real pipeline output from decision_engine).
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    timestamp,
                    device_id,
                    event_type,
                    severity,
                    COALESCE(risk_score, 0)  AS risk_score,
                    COALESCE(trust_score, 0) AS trust_score,
                    action,
                    source
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 1000
            """)
            rows = cur.fetchall()

        logs = []
        for row in rows:
            ts, device_id, event_type, severity, risk_score, trust_score, action, source = row
            reason = (
                f"trust={trust_score}, risk={risk_score}, "
                f"event={event_type or source}, severity={severity}"
            )
            logs.append({
                "timestamp":   ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
                "entity_id":   device_id,
                "action_type": (action or "monitor").upper(),
                "status":      "success",
                "reason":      reason,
                "approved_by": None,
                "simulated":   False,
            })

        return logs

    except Exception as exc:
        print(f"[v1/audit] Error: {exc}")
        return []
    finally:
        put_conn(conn)


# ─────────────────────────────────────────────
# GET /transparency/stats
# ─────────────────────────────────────────────

@router.get("/transparency/stats")
def get_transparency_stats():
    """
    Returns aggregate statistics across all pipeline events.
    Draws from 'features' instead of 'events' as a reliable proxy,
    since raw network events might skip the 'events' table if event_id is missing.
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM features")
            total_events = cur.fetchone()[0] or 0

            cur.execute("""
                SELECT COUNT(*) FROM alerts
                WHERE UPPER(severity) IN ('CRITICAL', 'HIGH') OR risk_score >= 70
            """)
            high_sev = cur.fetchone()[0] or 0

            cur.execute("""
                SELECT source, COUNT(*)
                FROM features
                WHERE source IS NOT NULL
                GROUP BY source
                ORDER BY COUNT(*) DESC
                LIMIT 10
            """)
            by_category = {r[0]: r[1] for r in cur.fetchall()}

            cur.execute("""
                SELECT device_id, severity, risk_score, action, timestamp
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 10
            """)
            recent_alerts = [
                {
                    "entity_id":  r[0],
                    "severity":   r[1],
                    "risk_score": r[2],
                    "action":     r[3],
                    "timestamp":  r[4].isoformat() if hasattr(r[4], "isoformat") else str(r[4]),
                }
                for r in cur.fetchall()
            ]

        return {
            "total_events":        total_events,
            "high_severity_count": high_sev,
            "by_category":         by_category,
            "by_source_type":      by_category,
            "by_event_type":       {},
            "category_severity":   {},
            "source_activity":     {},
            "recent_events":       recent_alerts,
            "last_updated":        datetime.now(timezone.utc).isoformat(),
        }

    except Exception as exc:
        print(f"[v1/transparency] Error: {exc}")
        return {
            "total_events": 0, "high_severity_count": 0,
            "by_category": {}, "by_source_type": {}, "by_event_type": {},
            "category_severity": {}, "source_activity": {}, "recent_events": [],
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        put_conn(conn)


# ─────────────────────────────────────────────
# GET /entities/{entity_id}  — Detail view
# ─────────────────────────────────────────────

@router.get("/entities/{entity_id}")
def get_entity_detail(entity_id: str):
    """
    Returns detailed per-entity data for the Adaptive Trust page:
    - Core entity fields (same as list)
    - trust_history: last 50 trust_score rows (for timeline chart)
    - anomaly_history: last 50 ml_scores (for ML chart)
    - risk_history:   last 50 risk_scores
    - ml_state:       latest device_baselines Welford state
    - category_risks: I/C/V/N from trust_states
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Core device row
            cur.execute("""
                SELECT d.device_id, d.hostname, d.mac_address, d.os, d.device_type, d.last_seen,
                       COALESCE(ts.trust_score, 80)    AS trust_score,
                       COALESCE(ts.adjusted_risk, 0.0) AS adjusted_risk,
                       COALESCE(ts.timestamp, d.last_seen) AS score_ts,
                       tst.state AS trust_state,
                       (SELECT ip FROM events WHERE device_id = d.device_id ORDER BY timestamp DESC LIMIT 1) AS last_ip
                FROM devices d
                LEFT JOIN LATERAL (
                    SELECT trust_score, adjusted_risk, timestamp
                    FROM trust_scores WHERE device_id = d.device_id
                    ORDER BY timestamp DESC LIMIT 1
                ) ts ON true
                LEFT JOIN trust_states tst ON tst.device_id = d.device_id
                WHERE d.device_id = %s
            """, (entity_id,))
            row = cur.fetchone()
            if not row:
                return {"error": "not found"}
            cols = [d[0] for d in cur.description]
            row = dict(zip(cols, row))

            # Trust score history (last 50)
            cur.execute("""
                SELECT timestamp, trust_score, COALESCE(adjusted_risk, 0) AS adjusted_risk
                FROM trust_scores WHERE device_id = %s
                ORDER BY timestamp DESC LIMIT 50
            """, (entity_id,))
            trust_history = [
                {"time": r[0].isoformat(), "score": float(r[1] or 80), "adjusted_risk": float(r[2] or 0)}
                for r in cur.fetchall()
            ][::-1]  # oldest first for charts

            # ML anomaly history (last 50)
            cur.execute("""
                SELECT timestamp, anomaly_score, anomaly_reasons
                FROM ml_scores WHERE device_id = %s
                ORDER BY timestamp DESC LIMIT 50
            """, (entity_id,))
            anomaly_history = [
                {"time": r[0].isoformat(), "score": float(r[1] or 0), "reasons": r[2] or []}
                for r in cur.fetchall()
            ][::-1]

            # Risk score history (last 50)
            cur.execute("""
                SELECT timestamp, risk_score, severity
                FROM risk_scores WHERE device_id = %s
                ORDER BY timestamp DESC LIMIT 50
            """, (entity_id,))
            risk_history = [
                {"time": r[0].isoformat(), "score": float(r[1] or 0), "severity": r[2]}
                for r in cur.fetchall()
            ][::-1]

            # ML Welford baseline
            cur.execute("SELECT baseline FROM device_baselines WHERE device_id = %s", (entity_id,))
            bl_row = cur.fetchone()
            ml_state = bl_row[0] if bl_row else None

        trust  = float(row.get("trust_score") or 80)
        adj    = float(row.get("adjusted_risk") or 0)
        state  = row.get("trust_state") or {}
        ts_val = row.get("score_ts") or row.get("last_seen")
        dec    = _trust_to_decision(trust)
        cat_bd = _build_category_breakdown(state)
        te     = _build_trust_evaluation(entity_id, trust, adj, state, ts_val)
        ts_str = ts_val.isoformat() if hasattr(ts_val, "isoformat") else str(ts_val or "")

        return {
            "entity_id":    entity_id,
            "trust_score":  round(trust, 1),
            "confidence":   round(min(100, max(0, (1 - adj) * 100)), 1),
            "decision":     dec["decision"],
            "category_breakdown": cat_bd,
            "last_updated": ts_str,
            "active_actions":    dec["active_actions"],
            "last_action":  dec["active_actions"][0] if dec["active_actions"] else None,
            "approval_required": dec["approval_required"],
            "metadata": {
                "ip":       row.get("last_ip"),
                "mac":      row.get("mac_address"),
                "hostname": row.get("hostname"),
                "os":       row.get("os"),
                "type":     row.get("device_type") or "workstation",
                "simulated": "false",
            },
            "trust_evaluation":  te,
            "trust_history":     trust_history,
            "anomaly_history":   anomaly_history,
            "risk_history":      risk_history,
            "ml_state":          ml_state,
            "category_risks":    {
                "N": round(float(state.get("N", 0) or 0), 4),
                "I": round(float(state.get("I", 0) or 0), 4),
                "C": round(float(state.get("C", 0) or 0), 4),
                "V": round(float(state.get("V", 0) or 0), 4),
            },
        }
    except Exception as exc:
        import traceback; traceback.print_exc()
        return {"error": str(exc)}
    finally:
        put_conn(conn)


# ─────────────────────────────────────────────
# POST /response/approve  (SIMULATED)
# ─────────────────────────────────────────────

class ApprovalRequest(BaseModel):
    entity_id:   str
    action:      str
    approved:    bool
    approved_by: Optional[str] = "SOC_ANALYST"


@router.post("/response/approve")
def approve_response(payload: ApprovalRequest):
    """
    Simulated response engine: logs the SOC approval to the alerts table.
    Does NOT perform real network isolation/account lock (TBD).
    """
    action_id = f"ACT-{payload.entity_id[:8]}-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO alerts (
                    alert_id, device_id, source, event_type,
                    severity, risk_score, trust_score,
                    anomaly_reasons, action, timestamp
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (alert_id) DO NOTHING
            """, (
                action_id,
                payload.entity_id,
                "soc_analyst",
                "manual_response",
                "INFO",
                0, 0, '[]',
                f"{'approved' if payload.approved else 'rejected'}:{payload.action}",
                now,
            ))
        conn.commit()
    except Exception as exc:
        print(f"[v1/response] Error: {exc}")
        conn.rollback()
    finally:
        put_conn(conn)

    return {
        "status":    "ok",
        "action_id": action_id,
        "entity_id": payload.entity_id,
        "action":    payload.action,
        "approved":  payload.approved,
        "simulated": True,
        "timestamp": now.isoformat(),
    }

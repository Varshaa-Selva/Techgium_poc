"""
Guardient Device Resolver
=========================
Identifies unique endpoints across the telemetry streams using deterministic DGID.
Priority: MAC > Instance ID > Hostname > IP

DGID = SHA256(MAC + Hostname + DeviceType + HardwareFingerprint)
"""

from __future__ import annotations
import uuid
import hashlib
from datetime import datetime, timezone
import logging

from db.db import get_conn, put_conn

logger = logging.getLogger(__name__)


def generate_dgid(mac: str = None, hostname: str = None, device_type: str = None, hardware: str = None) -> str:
    """Generate deterministic device ID."""
    key = f"{mac}|{hostname}|{device_type}|{hardware}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    return "dev_" + digest


def lookup_alias(alias: str) -> str | None:
    if not alias:
        return None
    
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT device_id FROM device_aliases WHERE alias = %s", (alias,))
            row = cur.fetchone()
        return row[0] if row else None
    except Exception as exc:
        logger.error(f"[Resolver] Lookup error for alias {alias}: {exc}")
        conn.rollback()
        return None
    finally:
        put_conn(conn)


def store_device_and_aliases(device_id: str, aliases: list[tuple[str, str]], metadata: dict):
    """Upsert device metadata and array of aliases."""
    now = datetime.now(timezone.utc)
    
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # 1. Update/Create the device record metadata
            cur.execute(
                """
                INSERT INTO devices (device_id, first_seen, last_seen, hostname, os, mac_address, device_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (device_id) DO UPDATE SET
                    last_seen = EXCLUDED.last_seen,
                    hostname = COALESCE(EXCLUDED.hostname, devices.hostname),
                    os = COALESCE(EXCLUDED.os, devices.os),
                    mac_address = COALESCE(EXCLUDED.mac_address, devices.mac_address),
                    device_type = COALESCE(EXCLUDED.device_type, devices.device_type)
                """,
                (device_id, now, now, metadata.get("hostname"), metadata.get("os"), 
                 metadata.get("mac_address"), metadata.get("device_type"))
            )
            
            # 2. Insert/Backfill all aliases mapping to this device_id
            for alias, alias_type in aliases:
                if not alias:
                    continue
                cur.execute(
                    """
                    INSERT INTO device_aliases (alias, alias_type, device_id)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (alias) DO NOTHING
                    """,
                    (alias, alias_type, device_id)
                )
        conn.commit()
    except Exception as exc:
        logger.error(f"[Resolver] Create device error: {exc}")
        conn.rollback()
    finally:
        put_conn(conn)


def resolve_device(event: dict) -> str:
    """
    Examine incoming CanonicalEvent, compute DGID, and backfill aliases.
    IP is used for lookup only, it will not create a new device alone.
    """
    mac = event.get("mac_address")
    hostname = event.get("hostname")
    device_type = event.get("device_type")
    
    # instance_id / hardware_fingerprint mapped from resource or raw payload
    hardware = event.get("hardware_fingerprint") or event.get("resource")
    
    source_ip = event.get("source_ip")

    aliases = []
    # MAC > Instance > Hostname > IP
    if mac:
        aliases.append((mac, "mac"))
    if hardware:
        aliases.append((hardware, "hardware_fingerprint"))
    if hostname:
        aliases.append((hostname, "hostname"))

    lookup_aliases = list(aliases)
    if source_ip:
        lookup_aliases.append((source_ip, "ip"))

    # 1. Try to lookup existing alias (including IP)
    for alias, _ in lookup_aliases:
        if not alias:
            continue
        existing_id = lookup_alias(alias)
        if existing_id:
            # If found, backfill any new strong aliases and update last seen
            store_device_and_aliases(existing_id, aliases, event)
            return existing_id

    # 2. No match found -> Compute deterministic DGID, but ONLY if we have strong aliases
    if not aliases:
        # Fallback for purely IP-based events that have no strong alias
        return "dev_unidentified_" + uuid.uuid4().hex[:8]
        
    dgid = generate_dgid(mac=mac, hostname=hostname, device_type=device_type, hardware=hardware)
    store_device_and_aliases(dgid, aliases, event)
    return dgid

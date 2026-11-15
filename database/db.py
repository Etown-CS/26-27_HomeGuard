import os
from pathlib import Path

import oracledb
from dotenv import load_dotenv

oracledb.defaults.fetch_lobs = False   # return CLOB columns (explanations) as plain strings

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")

_pool = None


class EmailTaken(Exception):
    """Raised when an account with that email already exists."""


def _require(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is missing. Add it to .env.")
    return value


def _resolve(path_str: str) -> str:
    p = Path(path_str).expanduser()
    return str(p if p.is_absolute() else (BASE / p).resolve())


def get_pool() -> "oracledb.ConnectionPool":
    """Create the connection pool on first use, then reuse it."""
    global _pool
    if _pool is not None:
        return _pool

    client_dir = os.getenv("ORACLE_CLIENT_DIR", "").strip()
    if client_dir:                                   # optional thick mode
        oracledb.init_oracle_client(lib_dir=_resolve(client_dir))

    options = dict(
        user=_require("DB_USER"),
        password=_require("DB_PASSWORD"),
        dsn=_require("DB_DSN"),
        min=1, max=4, increment=1,
    )
    wallet_dir = os.getenv("WALLET_DIR", "").strip()
    if wallet_dir:
        wallet = _resolve(wallet_dir)
        if not Path(wallet).is_dir():
            raise RuntimeError(f"WALLET_DIR does not exist: {wallet}")
        options["config_dir"] = wallet               # where tnsnames.ora lives
        options["wallet_location"] = wallet          # where ewallet.pem lives
        wallet_password = os.getenv("WALLET_PASSWORD", "")
        if wallet_password:
            options["wallet_password"] = wallet_password

    _pool = oracledb.create_pool(**options)
    return _pool


# ---------------------------------------------------------------
# users
# ---------------------------------------------------------------
def create_user(fname: str, lname: str, email: str, pwd_hash: str) -> int:
    """Insert a user and return the new user_id. Raises EmailTaken on a duplicate email."""
    with get_pool().acquire() as conn:
        with conn.cursor() as cur:
            new_id = cur.var(int)
            try:
                cur.execute(
                    """INSERT INTO users (fname, lname, email, pwd_hash)
                       VALUES (:fname, :lname, :email, :pwd_hash)
                       RETURNING user_id INTO :new_id""",
                    fname=fname, lname=lname, email=email, pwd_hash=pwd_hash, new_id=new_id,
                )
            except oracledb.IntegrityError as err:
                if err.args and getattr(err.args[0], "code", None) == 1:   # ORA-00001 unique constraint
                    raise EmailTaken() from err
                raise
            conn.commit()
            return int(new_id.getvalue()[0])


def get_user_by_email(email: str):
    """Return {'user_id', 'fname', 'pwd_hash'} or None."""
    with get_pool().acquire() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, fname, pwd_hash FROM users WHERE LOWER(email) = :email",
                email=email.lower(),
            )
            row = cur.fetchone()
    return {"user_id": row[0], "fname": row[1], "pwd_hash": row[2]} if row else None


def get_user_by_id(user_id: int):
    with get_pool().acquire() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id, fname, lname, email FROM users WHERE user_id = :id", id=user_id)
            row = cur.fetchone()
    return {"user_id": row[0], "fname": row[1], "lname": row[2], "email": row[3]} if row else None

# ---------------------------------------------------------------
# devices and flagged events
# Used by backend/llm_explain.py (to save events) and app.py (to serve them to the dashboard).
# SQL lives in constants so it is easy to read; every value is a bind variable (:p_...).
# ---------------------------------------------------------------
SQL_ALL_USER_IDS = "SELECT user_id FROM users ORDER BY user_id"
SQL_USER_ID_BY_EMAIL = "SELECT user_id FROM users WHERE LOWER(email) = :p_email"

SQL_DEVICE_ID = "SELECT device_id FROM devices WHERE user_id = :p_user AND ip = :p_ip"
SQL_DEVICE_INSERT = """INSERT INTO devices (user_id, device_name, device_type, ip, last_active)
                       VALUES (:p_user, :p_name, 'Other', :p_ip, :p_seen)"""
SQL_DEVICE_TOUCH = """UPDATE devices SET last_active = :p_seen
                      WHERE device_id = :p_id AND (last_active IS NULL OR last_active < :p_seen)"""

SQL_FLAGGED_KEYS = """SELECT event_time, src_ip, dst_ip, dst_port, packet_length
                      FROM flagged WHERE user_id = :p_user"""
SQL_FLAGGED_EXPLANATION = """SELECT explanation FROM flagged
                             WHERE src_ip = :p_src AND dst_ip = :p_dst AND event_time = :p_time
                               AND NVL(dst_port, -1) = :p_port AND NVL(packet_length, -1) = :p_len"""
SQL_FLAGGED_INSERT = """INSERT INTO flagged
                        (user_id, device_id, status, event_time, src_ip, dst_ip, protocol,
                         dst_port, packet_length, anomaly_score, explanation)
                        VALUES (:p_user, :p_device, :p_status, :p_time, :p_src, :p_dst, :p_proto,
                                :p_port, :p_len, :p_score, :p_text)"""

SQL_ALERTS = """SELECT flagged_id, status, event_time, src_ip, dst_ip, protocol,
                       dst_port, packet_length, explanation
                FROM flagged WHERE user_id = :p_user
                ORDER BY anomaly_score NULLS LAST, event_time DESC"""
SQL_DEVICES = """SELECT device_id, device_name, device_type, ip, last_active
                 FROM devices WHERE user_id = :p_user ORDER BY ip"""


def event_key(event_time, src_ip, dst_ip, dst_port, packet_length):
    """Identity of one event. Used to tell new events from ones already saved."""
    return (
        event_time,
        str(src_ip),
        str(dst_ip),
        int(dst_port) if dst_port is not None else -1,
        int(packet_length) if packet_length is not None else -1,
    )


def get_target_user_ids(owner_email: str = "") -> list:
    """Accounts that should receive the imported events: one owner if given, otherwise every account."""
    with get_pool().acquire() as conn, conn.cursor() as cur:
        if owner_email:
            cur.execute(SQL_USER_ID_BY_EMAIL, p_email=owner_email.strip().lower())
        else:
            cur.execute(SQL_ALL_USER_IDS)
        return [int(r[0]) for r in cur.fetchall()]


def existing_event_keys(user_id: int) -> set:
    """Keys of every event this user already has, so a re-run only handles new ones."""
    with get_pool().acquire() as conn, conn.cursor() as cur:
        cur.execute(SQL_FLAGGED_KEYS, p_user=user_id)
        return {event_key(r[0], r[1], r[2], r[3], r[4]) for r in cur.fetchall()}


def find_explanation(key):
    """If any account already has this event, return its explanation so the LLM is not asked twice."""
    event_time, src, dst, port, length = key
    with get_pool().acquire() as conn, conn.cursor() as cur:
        cur.execute(SQL_FLAGGED_EXPLANATION, p_src=src, p_dst=dst, p_time=event_time, p_port=port, p_len=length)
        row = cur.fetchone()
    return row[0] if row and row[0] else None


def get_or_create_device(user_id: int, ip: str, seen) -> int:
    """Return the device_id for this user's device at `ip`, creating it the first time it is seen."""
    with get_pool().acquire() as conn, conn.cursor() as cur:
        cur.execute(SQL_DEVICE_ID, p_user=user_id, p_ip=ip)
        row = cur.fetchone()
        if row is None:
            cur.execute(SQL_DEVICE_INSERT, p_user=user_id, p_name=f"Device {ip}", p_ip=ip, p_seen=seen)
            cur.execute(SQL_DEVICE_ID, p_user=user_id, p_ip=ip)
            row = cur.fetchone()
        else:
            cur.execute(SQL_DEVICE_TOUCH, p_id=row[0], p_seen=seen)
        conn.commit()
        return int(row[0])


def save_flagged(user_id, device_id, status, event_time, src_ip, dst_ip,
                 protocol, dst_port, packet_length, anomaly_score, explanation) -> None:
    with get_pool().acquire() as conn, conn.cursor() as cur:
        cur.execute(
            SQL_FLAGGED_INSERT,
            p_user=user_id, p_device=device_id, p_status=status, p_time=event_time,
            p_src=src_ip, p_dst=dst_ip, p_proto=protocol, p_port=dst_port,
            p_len=packet_length, p_score=anomaly_score, p_text=explanation,
        )
        conn.commit()


def _iso(value):
    return value.isoformat(timespec="seconds") if value is not None else None


def list_alerts(user_id: int) -> list:
    """This user's flagged events, most anomalous first, in the shape the dashboard expects."""
    with get_pool().acquire() as conn, conn.cursor() as cur:
        cur.execute(SQL_ALERTS, p_user=user_id)
        rows = cur.fetchall()
    return [
        {"id": int(r[0]), "status": r[1], "timestamp": _iso(r[2]), "src_ip": r[3], "dst_ip": r[4],
         "protocol": r[5], "dst_port": int(r[6]) if r[6] is not None else None,
         "length": int(r[7]) if r[7] is not None else None, "explanation": r[8] or ""}
        for r in rows
    ]


def list_devices(user_id: int) -> list:
    with get_pool().acquire() as conn, conn.cursor() as cur:
        cur.execute(SQL_DEVICES, p_user=user_id)
        rows = cur.fetchall()
    return [
        {"id": int(r[0]), "name": r[1], "type": r[2], "ip": r[3], "last_active": _iso(r[4])}
        for r in rows
    ]
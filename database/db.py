import os
from pathlib import Path

import oracledb
from dotenv import load_dotenv

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
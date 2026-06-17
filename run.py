"""Run Trap (4040) and Admin (4090) via Waitress WSGI servers."""
import os
import sys
import threading

from waitress import serve

from db import init_db
from trap_app import app as trap_app
from admin_app import app as admin_app, validate_admin_auth_config

TRAP_PORT = int(os.environ.get("TRAP_PORT", "4040"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "4090"))
TRAP_THREADS = int(os.environ.get("TRAP_THREADS", "8"))
ADMIN_THREADS = int(os.environ.get("ADMIN_THREADS", "4"))
TRAP_CONNECTION_LIMIT = int(os.environ.get("TRAP_CONNECTION_LIMIT", "64"))
ADMIN_CONNECTION_LIMIT = int(os.environ.get("ADMIN_CONNECTION_LIMIT", "32"))


def run_trap():
    serve(
        trap_app,
        host="0.0.0.0",
        port=TRAP_PORT,
        threads=TRAP_THREADS,
        connection_limit=TRAP_CONNECTION_LIMIT,
        channel_timeout=30,
        ident=None,
    )


def run_admin():
    serve(
        admin_app,
        host="0.0.0.0",
        port=ADMIN_PORT,
        threads=ADMIN_THREADS,
        connection_limit=ADMIN_CONNECTION_LIMIT,
        channel_timeout=120,
        ident=None,
    )


if __name__ == "__main__":
    validate_admin_auth_config()
    init_db()
    t1 = threading.Thread(target=run_trap, daemon=False, name="trap-waitress")
    t2 = threading.Thread(target=run_admin, daemon=False, name="admin-waitress")
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    sys.exit(0)

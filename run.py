"""Run Trap (4040) and Admin (4090) via Waitress WSGI servers."""

import logging
import os
import sys
import threading

from waitress import serve

from admin_app import app as admin_app
from admin_app import validate_admin_auth_config
from maintenance import start_maintenance_scheduler
from spam_summary_scheduler import start_spam_summary_scheduler
from store import initialize_store
from trap_app import app as trap_app

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)

TRAP_PORT = int(os.environ.get("TRAP_PORT", "4040"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "4090"))
TRAP_THREADS = int(os.environ.get("TRAP_THREADS", "8"))
ADMIN_THREADS = int(os.environ.get("ADMIN_THREADS", "4"))
TRAP_CONNECTION_LIMIT = int(os.environ.get("TRAP_CONNECTION_LIMIT", "64"))
ADMIN_CONNECTION_LIMIT = int(os.environ.get("ADMIN_CONNECTION_LIMIT", "32"))
TRAP_MAX_REQUEST_BODY_SIZE = int(os.environ.get("TRAP_MAX_REQUEST_BODY_SIZE", "65536"))
ADMIN_MAX_REQUEST_BODY_SIZE = int(os.environ.get("ADMIN_MAX_REQUEST_BODY_SIZE", "1048576"))
MAX_REQUEST_HEADER_SIZE = int(os.environ.get("MAX_REQUEST_HEADER_SIZE", "65536"))


def run_trap():
    # The process listens inside its network namespace; Docker controls host exposure.
    serve(
        trap_app,
        host="0.0.0.0",  # noqa: S104  # nosec B104
        port=TRAP_PORT,
        threads=TRAP_THREADS,
        connection_limit=TRAP_CONNECTION_LIMIT,
        channel_timeout=30,
        max_request_body_size=TRAP_MAX_REQUEST_BODY_SIZE,
        max_request_header_size=MAX_REQUEST_HEADER_SIZE,
        ident=None,
    )


def run_admin():
    # The host-side binding is restricted by ADMIN_BIND_IP in Compose.
    serve(
        admin_app,
        host="0.0.0.0",  # noqa: S104  # nosec B104
        port=ADMIN_PORT,
        threads=ADMIN_THREADS,
        connection_limit=ADMIN_CONNECTION_LIMIT,
        channel_timeout=120,
        max_request_body_size=ADMIN_MAX_REQUEST_BODY_SIZE,
        max_request_header_size=MAX_REQUEST_HEADER_SIZE,
        ident=None,
    )


if __name__ == "__main__":
    validate_admin_auth_config()
    initialize_store()
    start_spam_summary_scheduler()
    start_maintenance_scheduler()
    t1 = threading.Thread(target=run_trap, daemon=False, name="trap-waitress")
    t2 = threading.Thread(target=run_admin, daemon=False, name="admin-waitress")
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    sys.exit(0)

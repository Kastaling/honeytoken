"""Run Trap (4040) and Admin (4090) in one process."""
import os
import threading

from db import init_db
from trap_app import app as trap_app
from admin_app import app as admin_app

init_db()

TRAP_PORT = int(os.environ.get("TRAP_PORT", "4040"))
ADMIN_PORT = int(os.environ.get("ADMIN_PORT", "4090"))


def run_trap():
    trap_app.run(host="0.0.0.0", port=TRAP_PORT, threaded=True, use_reloader=False)


def run_admin():
    admin_app.run(host="0.0.0.0", port=ADMIN_PORT, threaded=True, use_reloader=False)


if __name__ == "__main__":
    t1 = threading.Thread(target=run_trap, daemon=False)
    t2 = threading.Thread(target=run_admin, daemon=False)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

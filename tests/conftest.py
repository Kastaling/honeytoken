import os
import tempfile

_TEST_DATA_DIR = tempfile.mkdtemp(prefix="honey-tests-")
os.environ["DATA_DIR"] = _TEST_DATA_DIR
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DATA_DIR}/honey.db"
os.environ["ADMIN_USER"] = "test-admin"
os.environ["ADMIN_PASS"] = "test-password"
os.environ["ADMIN_SECRET_KEY"] = "test-secret-key"
os.environ["CARTO_API_KEY"] = "test-carto-key"
os.environ["MEDIA_DIR"] = _TEST_DATA_DIR

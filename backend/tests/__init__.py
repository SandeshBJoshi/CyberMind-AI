"""Test environment: runs against a throw-away database and strong, known secrets, never your real data.

Run everything from the backend folder with:
    python -m unittest discover -s tests -t .
"""
import os
import tempfile

_tmp = os.path.join(tempfile.gettempdir(), "cybermind_test_security.db")
if os.path.exists(_tmp):
    os.remove(_tmp)

os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}"
os.environ["APP_ENV"] = "development"
os.environ["JWT_SECRET"] = "test-secret-" + "x" * 40
os.environ["ADMIN_USERNAME"] = "admin"
os.environ["ADMIN_PASSWORD"] = "Test-Admin-Pass-2026!"
os.environ["ALLOW_CLIENT_IP_HEADER"] = "false"
os.environ["APP_API_KEYS"] = "test-app-key"
os.environ["CORS_ORIGINS"] = "http://localhost:5173"

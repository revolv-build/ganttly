"""
Test configuration — creates a fresh database for each test session.
"""

import os
import tempfile
import pytest

# Set test environment before importing app
os.environ["FLASK_ENV"] = "testing"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"

from app import app as flask_app, DB_PATH, init_db


@pytest.fixture(scope="session")
def app():
    """Create application for testing."""
    flask_app.config["TESTING"] = True
    flask_app.config["WTF_CSRF_ENABLED"] = False  # Disable CSRF for tests
    return flask_app


@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()


@pytest.fixture
def auth_client(client):
    """Create a test client that's logged in as admin."""
    client.post("/login", data={
        "email": "admin@example.com",
        "password": "changeme",
        "_ts": "0",
    })
    return client


@pytest.fixture
def user_client(client):
    """Create a test client logged in as a regular user."""
    # Register a test user
    client.post("/register", data={
        "name": "Test User",
        "email": "test@example.com",
        "password": "testpassword123",
        "password_confirm": "testpassword123",
        "_ts": "0",
    })
    return client

"""
Auth tests — login, register, logout, password reset.
"""


def test_landing_page(client):
    """Landing page loads for unauthenticated users."""
    resp = client.get("/")
    assert resp.status_code == 200


def test_login_page(client):
    """Login page loads."""
    resp = client.get("/login")
    assert resp.status_code == 200


def test_register_page(client):
    """Register page loads."""
    resp = client.get("/register")
    assert resp.status_code == 200


def test_login_success(client):
    """Admin can log in with default credentials."""
    resp = client.post("/login", data={
        "email": "admin@example.com",
        "password": "changeme",
        "_ts": "0",
    }, follow_redirects=True)
    assert resp.status_code == 200


def test_login_failure(client):
    """Wrong password shows error."""
    resp = client.post("/login", data={
        "email": "admin@example.com",
        "password": "wrongpassword",
        "_ts": "0",
    })
    assert resp.status_code == 200
    assert b"Invalid email or password" in resp.data


def test_register_success(client):
    """New user can register."""
    resp = client.post("/register", data={
        "name": "New User",
        "email": "new@example.com",
        "password": "password123",
        "password_confirm": "password123",
        "_ts": "0",
    }, follow_redirects=True)
    assert resp.status_code == 200


def test_register_duplicate_email(client):
    """Can't register with existing email."""
    resp = client.post("/register", data={
        "name": "Duplicate",
        "email": "admin@example.com",
        "password": "password123",
        "password_confirm": "password123",
        "_ts": "0",
    })
    assert resp.status_code == 200
    assert b"already exists" in resp.data


def test_register_password_mismatch(client):
    """Password confirmation must match."""
    resp = client.post("/register", data={
        "name": "Mismatch",
        "email": "mismatch@example.com",
        "password": "password123",
        "password_confirm": "different123",
        "_ts": "0",
    })
    assert resp.status_code == 200
    assert b"do not match" in resp.data


def test_logout(auth_client):
    """Logged in user can log out."""
    resp = auth_client.get("/logout", follow_redirects=True)
    assert resp.status_code == 200


def test_dashboard_requires_login(client):
    """Dashboard redirects to login when not authenticated."""
    resp = client.get("/dashboard")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_dashboard_works_when_logged_in(auth_client):
    """Dashboard loads for authenticated users."""
    resp = auth_client.get("/dashboard")
    assert resp.status_code == 200


def test_account_page(auth_client):
    """Account page loads for authenticated users."""
    resp = auth_client.get("/account")
    assert resp.status_code == 200


def test_admin_page(auth_client):
    """Admin page loads for admin users."""
    resp = auth_client.get("/admin")
    assert resp.status_code == 200


def test_forgot_password_page(client):
    """Forgot password page loads."""
    resp = client.get("/forgot-password")
    assert resp.status_code == 200

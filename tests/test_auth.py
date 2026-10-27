"""
tests/test_auth.py
=============================================================================
Comprehensive unit and integration tests for:
1. Password Hashing (bcrypt / salted)
2. Persistent Database Storage (SQLite / SQLAlchemy)
3. User Registration & Admin Approval Flow
4. Forgot Password / Self-Service Token Reset
5. Brute-Force Rate Limiting & Account Lockout
=============================================================================
"""

import os
import tempfile
import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import auth_db
from auth_db import (
    Base,
    User,
    hash_password,
    verify_password,
    init_db,
    authenticate_user_detailed,
    authenticate_user,
    register_user,
    approve_user_registration,
    reject_user_registration,
    unlock_user_account,
    request_password_reset,
    reset_password_with_token,
    admin_reset_password,
    get_all_users,
    get_pending_users,
    MAX_FAILED_ATTEMPTS,
    LOCKOUT_DURATION_MINUTES
)


@pytest.fixture(scope="function")
def test_db():
    """Sets up a clean temporary SQLite database for isolated testing."""
    fd, temp_db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    
    test_engine = create_engine(f"sqlite:///{temp_db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=test_engine)
    
    # Override SessionLocal in auth_db for testing
    original_session = auth_db.SessionLocal
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    auth_db.SessionLocal = TestingSessionLocal
    
    # Initialize with default seed accounts
    init_db(db_engine=test_engine)
    
    yield TestingSessionLocal
    
    # Cleanup
    auth_db.SessionLocal = original_session
    test_engine.dispose()
    if os.path.exists(temp_db_path):
        try:
            os.remove(temp_db_path)
        except Exception:
            pass


# =============================================================================
# 1. Password Hashing Tests (bcrypt)
# =============================================================================
def test_password_hashing_creates_unique_salted_hashes():
    pwd = "SecurePassword123!"
    hash1 = hash_password(pwd)
    hash2 = hash_password(pwd)
    
    # Bcrypt produces different salted outputs for identical plaintext
    assert hash1 != hash2
    assert hash1.startswith("$2b$") or hash1.startswith("$2a$")
    assert verify_password(pwd, hash1) is True
    assert verify_password(pwd, hash2) is True
    assert verify_password("WrongPassword", hash1) is False


def test_password_hashing_handles_edge_cases():
    assert verify_password("", "") is False
    assert verify_password(None, "some_hash") is False
    assert verify_password("pwd", "invalid_hash_string") is False


# =============================================================================
# 2. Database Persistence & Default Seeding Tests
# =============================================================================
def test_default_seed_accounts_exist(test_db):
    users = get_all_users()
    usernames = [u["username"] for u in users]
    assert "analyst" in usernames
    assert "admin" in usernames

    # Verify analyst profile attributes
    analyst_res = authenticate_user_detailed("analyst", "analyst123")
    assert analyst_res["success"] is True
    assert analyst_res["user"]["role"] == "analyst"
    assert analyst_res["user"]["status"] == "active"

    # Verify admin profile attributes
    admin_res = authenticate_user_detailed("admin", "admin123")
    assert admin_res["success"] is True
    assert admin_res["user"]["role"] == "admin"
    assert admin_res["user"]["accessible_pages"] == 11


# =============================================================================
# 3. User Registration & Admin Approval Flow Tests
# =============================================================================
def test_user_registration_pending_approval(test_db):
    reg = register_user(
        username="john_analyst",
        password="MySecretPassword123",
        name="John Analyst",
        email="john@soc.internal",
        role="analyst",
        justification="Incident triage shift rotation",
        require_approval=True
    )
    assert reg["success"] is True
    assert reg["status"] == "pending_approval"

    # Pending user should NOT be able to log in yet
    auth = authenticate_user_detailed("john_analyst", "MySecretPassword123")
    assert auth["success"] is False
    assert auth["status"] == "pending"

    # Verify appearance in pending list
    pending = get_pending_users()
    assert any(p["username"] == "john_analyst" for p in pending)

    # Admin approves user
    user_id = reg["user"]["id"]
    approved = approve_user_registration(user_id)
    assert approved is True

    # User should now successfully authenticate
    auth_after = authenticate_user_detailed("john_analyst", "MySecretPassword123")
    assert auth_after["success"] is True
    assert auth_after["user"]["status"] == "active"


def test_user_registration_rejection(test_db):
    reg = register_user(
        username="unauthorized_user",
        password="Password123",
        name="Bad Actor",
        email="bad@external.net",
        role="analyst"
    )
    user_id = reg["user"]["id"]
    
    # Admin rejects user
    assert reject_user_registration(user_id) is True

    # Login should report rejected status
    auth = authenticate_user_detailed("unauthorized_user", "Password123")
    assert auth["success"] is False
    assert auth["status"] == "rejected"


def test_user_registration_validation(test_db):
    # Short username
    r1 = register_user("ab", "password123", "Name", "test@soc.internal")
    assert r1["success"] is False

    # Short password
    r2 = register_user("validuser", "123", "Name", "test@soc.internal")
    assert r2["success"] is False

    # Invalid email
    r3 = register_user("validuser", "password123", "Name", "invalidemail")
    assert r3["success"] is False

    # Duplicate username
    r4 = register_user("analyst", "password123", "Analyst Two", "diff@soc.internal")
    assert r4["success"] is False
    assert "already registered" in r4["message"]


# =============================================================================
# 4. Brute-Force Rate Limiting & Account Lockout Tests
# =============================================================================
def test_brute_force_lockout_after_five_failed_attempts(test_db):
    # Attempts 1 to 4 should report remaining attempts
    for attempt in range(1, MAX_FAILED_ATTEMPTS):
        res = authenticate_user_detailed("analyst", "wrongpassword")
        assert res["success"] is False
        assert res["status"] == "invalid_credentials"
        assert res["remaining_attempts"] == MAX_FAILED_ATTEMPTS - attempt

    # Attempt 5 triggers account lockout
    res_lock = authenticate_user_detailed("analyst", "wrongpassword")
    assert res_lock["success"] is False
    assert res_lock["status"] == "locked"
    assert "locked for 15 minutes" in res_lock["message"].lower()

    # Attempt 6 (even with the CORRECT password) should be BLOCKED while locked
    res_blocked = authenticate_user_detailed("analyst", "analyst123")
    assert res_blocked["success"] is False
    assert res_blocked["status"] == "locked"


def test_admin_unlock_account(test_db):
    # Lock the account with 5 failed attempts
    for _ in range(MAX_FAILED_ATTEMPTS):
        authenticate_user_detailed("analyst", "wrongpassword")

    assert authenticate_user("analyst", "analyst123") is None

    # Admin unlocks the account
    session = auth_db.get_db()
    user = session.query(User).filter_by(username="analyst").first()
    user_id = user.id
    session.close()

    assert unlock_user_account(user_id) is True

    # Account should now be accessible with correct credentials
    unlocked_auth = authenticate_user_detailed("analyst", "analyst123")
    assert unlocked_auth["success"] is True
    assert unlocked_auth["user"]["failed_attempts"] == 0


# =============================================================================
# 5. Forgot Password / Token Reset Tests
# =============================================================================
def test_forgot_password_flow(test_db):
    # Request token
    req = request_password_reset("analyst")
    assert req["success"] is True
    assert "token" in req
    token = req["token"]
    assert len(token) == 6
    assert token.isdigit()

    # Reset with wrong token should fail
    fail_reset = reset_password_with_token("analyst", "999999", "NewPassword999!")
    assert fail_reset["success"] is False

    # Reset with correct token should succeed
    success_reset = reset_password_with_token("analyst", token, "NewPassword999!")
    assert success_reset["success"] is True

    # Old password no longer works
    assert authenticate_user_detailed("analyst", "analyst123")["success"] is False

    # New password works
    new_auth = authenticate_user_detailed("analyst", "NewPassword999!")
    assert new_auth["success"] is True


def test_expired_reset_token_fails(test_db):
    req = request_password_reset("analyst")
    token = req["token"]

    # Artificially expire token in DB
    session = auth_db.get_db()
    user = session.query(User).filter_by(username="analyst").first()
    user.reset_token_expires_at = auth_db.utcnow() - timedelta(minutes=5)
    session.commit()
    session.close()

    res = reset_password_with_token("analyst", token, "BrandNewPassword123")
    assert res["success"] is False
    assert "expired" in res["message"].lower()


def test_admin_direct_password_reset(test_db):
    session = auth_db.get_db()
    user = session.query(User).filter_by(username="analyst").first()
    user_id = user.id
    session.close()

    assert admin_reset_password(user_id, "AdminGivenPassword123") is True
    assert authenticate_user_detailed("analyst", "AdminGivenPassword123")["success"] is True

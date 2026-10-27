"""
tests/test_data_layer_auth.py
=============================================================================
Integration test verifying that data_layer properly re-exports auth functions,
handles USER_PROFILES backwards compatibility, and runs with the persistent DB.
=============================================================================
"""

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from data_layer import (
    authenticate_user,
    authenticate_user_detailed,
    get_user_profile,
    USER_PROFILES,
    log_audit_event,
    get_audit_logs,
    register_user,
    request_password_reset,
    reset_password_with_token
)


def test_data_layer_exports_work():
    # Test analyst login via data_layer wrapper
    user = authenticate_user("analyst", "analyst123")
    assert user is not None
    assert user["role"] == "analyst"

    # Test admin login via data_layer wrapper
    admin_user = authenticate_user("admin", "admin123")
    assert admin_user is not None
    assert admin_user["role"] == "admin"

    # Test detailed authentication
    detailed = authenticate_user_detailed("analyst", "analyst123")
    assert detailed["success"] is True
    assert detailed["user"]["name"] == "Analyst Alex"


def test_data_layer_user_profiles_proxy():
    # Fastpass demo dictionary indexing
    analyst_profile = USER_PROFILES["analyst"]
    assert analyst_profile["role"] == "analyst"
    assert analyst_profile["name"] == "Analyst Alex"

    admin_profile = USER_PROFILES.get("admin")
    assert admin_profile["role"] == "admin"
    assert admin_profile["name"] == "Admin Sarah"


def test_data_layer_audit_logging_fallback():
    # Outside streamlit, log_audit_event shouldn't crash
    log_audit_event("TEST_ACTION", "TEST_TARGET", "Testing fallback audit logs", "Success")
    logs = get_audit_logs()
    assert isinstance(logs, list)
    assert any(log["action"] == "TEST_ACTION" for log in logs)

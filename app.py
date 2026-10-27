"""
app.py
=============================================================================
Explainable AI for Network Security & Threat Investigation
Main Streamlit Application Controller & Role-Based Access Controller (RBAC)

Features:
- Separate Secure Authentication for User (SOC Analyst) and Admin (Security Lead)
- Persistent SQLite Database Integration with Salted Bcrypt Hashing
- 15-Minute Account Lockout after 5 Failed Consecutive Attempts
- Self-Service User Registration & Admin Approval Workflow
- Password Recovery with Verification OTP Tokens
- Fastpass 1-Click Demo Access for Live Presentations
- Dynamic Role-Gated Multi-Page Navigation Structure
- Dark "Security Operations" Visual Theme (#0B1220 navy, #121A2B cards)
- Live SOC Security Audit Logging for Login / Logout / Access Events
=============================================================================
"""

import os
from datetime import datetime
import streamlit as st
import sys
import importlib

if "data_layer" in sys.modules:
    importlib.reload(sys.modules["data_layer"])

from data_layer import (
    authenticate_user,
    authenticate_user_detailed,
    get_user_profile,
    log_audit_event,
    register_user,
    request_password_reset,
    reset_password_with_token,
    USER_PROFILES
)
from components.badges import render_demo_banner, render_demo_tag

# 1. Page Configuration (Must be first Streamlit command)
logo_file = os.path.join(os.path.dirname(__file__), "assets", "logo.png")

st.set_page_config(
    page_title="Explainable AI Network Security SOC",
    page_icon=logo_file if os.path.exists(logo_file) else "🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 2. Top-Left Native Streamlit Logo
if os.path.exists(logo_file):
    st.logo(logo_file)

# 3. Inject Dark Security Operations Theme CSS
css_file = os.path.join(os.path.dirname(__file__), "assets", "style.css")
if os.path.exists(css_file):
    with open(css_file, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


# =============================================================================
# 4. Login Gateway UI (Rendered when unauthenticated)
# =============================================================================
def render_login_gateway():
    render_demo_banner()

    st.markdown("""
    <div style="text-align: center; margin-top: 1.5rem; margin-bottom: 2rem;">
        <div style="display: inline-flex; align-items: center; justify-content: center; width: 68px; height: 68px; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 16px; margin-bottom: 1rem; box-shadow: 0 0 20px rgba(56, 189, 248, 0.15);">
            <span style="font-size: 2.2rem;">🛡️</span>
        </div>
        <h1 style="font-size: 2.2rem; font-weight: 800; color: #F8FAFC; margin-bottom: 0.35rem; letter-spacing: -0.02em;">
            Explainable AI Threat Investigation SOC
        </h1>
        <div style="color: #94A3B8; font-size: 0.95rem; max-width: 680px; margin: 0 auto;">
            Identity & Access Management Gateway • Select Profile and Authenticate with Assigned Credentials
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_spacer_l, col_main, col_spacer_r = st.columns([1, 2.4, 1])

    with col_main:
        tab_user, tab_admin, tab_register, tab_forgot = st.tabs([
            "🛡️ Analyst Login",
            "🔑 Admin Login",
            "📝 Request Access",
            "🔄 Forgot Password"
        ])

        # ----------------- 1. User (Analyst) Tab -----------------
        with tab_user:
            st.markdown("""
            <div style="background: rgba(56, 189, 248, 0.06); border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 8px; padding: 1rem; margin-bottom: 1.25rem;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="font-size: 1.1rem;">🛡️</span>
                        <strong style="color: #38BDF8; font-size: 0.95rem;">Analyst Alex (Tier-2 SOC Analyst)</strong>
                    </div>
                    <span style="font-size: 0.7rem; background: rgba(56, 189, 248, 0.2); color: #38BDF8; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 700;">USER PROFILE</span>
                </div>
                <div style="color: #CBD5E1; font-size: 0.82rem; line-height: 1.5;">
                    Access operational incident triage, 30s packet window inspection, TreeSHAP explainability, and forensic report export.
                    <strong>Client IPs are automatically anonymized</strong> to adhere to PII privacy standards.
                </div>
            </div>
            """, unsafe_allow_html=True)

            with st.form("form_analyst_login"):
                u_user = st.text_input("Username", value="analyst", key="input_analyst_user")
                u_pass = st.text_input("Password", type="password", value="analyst123", key="input_analyst_pass")

                st.markdown("""
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.2rem; margin-bottom: 0.8rem; font-size: 0.78rem; color: #64748B;">
                    <span>Assigned Credentials: <code>analyst</code> / <code>analyst123</code></span>
                    <span style="color: #38BDF8;">Tier-2 Operational Scope</span>
                </div>
                """, unsafe_allow_html=True)

                submit_analyst = st.form_submit_button("Sign In as SOC Analyst 🛡️", use_container_width=True, type="primary")

                if submit_analyst:
                    auth_res = authenticate_user_detailed(u_user, u_pass)
                    if auth_res["success"]:
                        user_record = auth_res["user"]
                        if user_record["role"] in ["analyst", "admin"]:
                            st.session_state["authenticated"] = True
                            st.session_state["user_role"] = user_record["role"]
                            st.session_state["user_name"] = user_record["name"]
                            st.session_state["user_profile"] = user_record
                            st.session_state["login_time"] = datetime.now().strftime("%H:%M:%S")
                            log_audit_event("AUTH_LOGIN_SUCCESS", target="SOC Gateway", details=f"User '{user_record['name']}' logged in successfully as [{user_record['role'].upper()}]", status="Success")
                            st.success("✅ Access Granted. Loading SOC Analyst environment...")
                            st.rerun()
                    elif auth_res["status"] == "locked":
                        st.error(f"🔒 {auth_res['message']}")
                        log_audit_event("AUTH_LOGIN_BLOCKED_LOCKED", target="SOC Gateway", details=f"Account locked: '{u_user}'", status="Blocked")
                    elif auth_res["status"] == "pending":
                        st.warning(f"⏳ {auth_res['message']}")
                    elif auth_res["status"] == "rejected":
                        st.error(f"❌ {auth_res['message']}")
                    else:
                        st.error(f"❌ {auth_res['message']}")
                        log_audit_event("AUTH_LOGIN_FAILED", target="SOC Gateway", details=f"Failed login attempt for '{u_user}' (Analyst Gateway)", status="Blocked")

        # ----------------- 2. Admin (Lead) Tab -----------------
        with tab_admin:
            st.markdown("""
            <div style="background: rgba(245, 166, 35, 0.06); border: 1px solid rgba(245, 166, 35, 0.25); border-radius: 8px; padding: 1rem; margin-bottom: 1.25rem;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="font-size: 1.1rem;">🔑</span>
                        <strong style="color: #F5A623; font-size: 0.95rem;">Admin Sarah (Lead Security / ML Engineer)</strong>
                    </div>
                    <span style="font-size: 0.7rem; background: rgba(245, 166, 35, 0.2); color: #F5A623; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 700;">ADMIN PROFILE</span>
                </div>
                <div style="color: #CBD5E1; font-size: 0.82rem; line-height: 1.5;">
                    Access Level-5 Clearance: <strong>raw unmasked endpoint IPs</strong>, Adversarial Evasion Lab, full dataset CSV exports, Model Cross-Validation benchmarks, Dynamic Threshold Tuning, and live SOC Audit Trails.
                </div>
            </div>
            """, unsafe_allow_html=True)

            with st.form("form_admin_login"):
                a_user = st.text_input("Admin Username", value="admin", key="input_admin_user")
                a_pass = st.text_input("Admin Password", type="password", value="admin123", key="input_admin_pass")

                st.markdown("""
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.2rem; margin-bottom: 0.8rem; font-size: 0.78rem; color: #64748B;">
                    <span>Assigned Credentials: <code>admin</code> / <code>admin123</code></span>
                    <span style="color: #F5A623;">Level-5 Full Clearance</span>
                </div>
                """, unsafe_allow_html=True)

                submit_admin = st.form_submit_button("Sign In as Security Admin 🔑", use_container_width=True, type="primary")

                if submit_admin:
                    auth_res = authenticate_user_detailed(a_user, a_pass)
                    if auth_res["success"]:
                        user_record = auth_res["user"]
                        if user_record["role"] == "admin":
                            st.session_state["authenticated"] = True
                            st.session_state["user_role"] = user_record["role"]
                            st.session_state["user_name"] = user_record["name"]
                            st.session_state["user_profile"] = user_record
                            st.session_state["login_time"] = datetime.now().strftime("%H:%M:%S")
                            log_audit_event("AUTH_LOGIN_SUCCESS", target="SOC Gateway", details=f"User '{user_record['name']}' logged in successfully as [ADMIN]", status="Success")
                            st.success("✅ Level-5 Clearance Granted. Loading Admin Console...")
                            st.rerun()
                        else:
                            st.warning("⚠️ This account has Analyst permissions. Please sign in via the Analyst Login tab.")
                    elif auth_res["status"] == "locked":
                        st.error(f"🔒 {auth_res['message']}")
                        log_audit_event("AUTH_LOGIN_BLOCKED_LOCKED", target="SOC Gateway", details=f"Account locked: '{a_user}'", status="Blocked")
                    elif auth_res["status"] == "pending":
                        st.warning(f"⏳ {auth_res['message']}")
                    elif auth_res["status"] == "rejected":
                        st.error(f"❌ {auth_res['message']}")
                    else:
                        st.error(f"❌ {auth_res['message']}")
                        log_audit_event("AUTH_LOGIN_FAILED", target="SOC Gateway", details=f"Failed login attempt for '{a_user}' (Admin Gateway)", status="Blocked")

        # ----------------- 3. Request Access (Sign Up) Tab -----------------
        with tab_register:
            st.markdown("""
            <div style="background: rgba(139, 92, 246, 0.06); border: 1px solid rgba(139, 92, 246, 0.25); border-radius: 8px; padding: 1rem; margin-bottom: 1.25rem;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.3rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="font-size: 1.1rem;">📝</span>
                        <strong style="color: #A78BFA; font-size: 0.95rem;">New SOC Investigator Registration</strong>
                    </div>
                    <span style="font-size: 0.7rem; background: rgba(139, 92, 246, 0.2); color: #A78BFA; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 700;">SELF-SERVICE</span>
                </div>
                <div style="color: #CBD5E1; font-size: 0.82rem; line-height: 1.5;">
                    Submit a credential request for SOC operations. New analyst registrations are verified and approved by <strong>Admin Sarah</strong> before access is granted.
                </div>
            </div>
            """, unsafe_allow_html=True)

            with st.form("form_registration"):
                r_name = st.text_input("Full Name *", placeholder="e.g. Jordan Lee", key="reg_name")
                r_email = st.text_input("Corporate / SOC Email *", placeholder="e.g. jordan.lee@soc.internal", key="reg_email")
                r_user = st.text_input("Desired Username *", placeholder="e.g. jlee_soc", key="reg_user")

                c_r1, c_r2 = st.columns(2)
                with c_r1:
                    r_role = st.selectbox("Requested Operational Tier", ["Tier-2 SOC Analyst", "Admin (Lead / ML Engineer)"], key="reg_role")
                with c_r2:
                    r_just = st.text_input("Department / Justification", placeholder="e.g. Q4 Threat Intel Rotation", key="reg_just")

                c_p1, c_p2 = st.columns(2)
                with c_p1:
                    r_pass = st.text_input("Password (min 6 chars) *", type="password", key="reg_pass")
                with c_p2:
                    r_pass_conf = st.text_input("Confirm Password *", type="password", key="reg_pass_conf")

                submit_reg = st.form_submit_button("Submit Access Request 📝", use_container_width=True, type="primary")

                if submit_reg:
                    if not r_name or not r_email or not r_user or not r_pass:
                        st.error("❌ Please complete all mandatory fields (*).")
                    elif r_pass != r_pass_conf:
                        st.error("❌ Passwords do not match. Please re-enter your password.")
                    else:
                        role_key = "admin" if "Admin" in r_role else "analyst"
                        reg_res = register_user(
                            username=r_user,
                            password=r_pass,
                            name=r_name,
                            email=r_email,
                            role=role_key,
                            justification=r_just,
                            require_approval=True
                        )
                        if reg_res["success"]:
                            log_audit_event("USER_REGISTRATION_SUBMITTED", target="Access Gateway", details=f"New registration requested by '{r_name}' ({r_user}) for [{role_key.upper()}]", status="Pending")
                            st.success("✅ **Access Request Submitted!**")
                            st.markdown(f"""
                            <div style="background: rgba(46, 204, 113, 0.1); border: 1px solid #2ECC71; border-radius: 6px; padding: 0.8rem; margin-top: 0.5rem; font-size: 0.82rem; color: #CBD5E1;">
                                <strong>Request Details:</strong><br/>
                                • <strong>Username:</strong> <code>{r_user}</code><br/>
                                • <strong>Email:</strong> <code>{r_email}</code><br/>
                                • <strong>Status:</strong> <span style="color:#F5A623; font-weight:700;">Pending SOC Admin Approval</span><br/>
                                • <em>Please notify Admin Sarah or log in once your approval is granted.</em>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.error(f"❌ {reg_res['message']}")

        # ----------------- 4. Forgot Password Tab -----------------
        with tab_forgot:
            st.markdown("""
            <div style="background: rgba(245, 166, 35, 0.06); border: 1px solid rgba(245, 166, 35, 0.25); border-radius: 8px; padding: 1rem; margin-bottom: 1.25rem;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.3rem;">
                    <div style="display: flex; align-items: center; gap: 0.5rem;">
                        <span style="font-size: 1.1rem;">🔄</span>
                        <strong style="color: #F5A623; font-size: 0.95rem;">Self-Service Password Reset & Account Recovery</strong>
                    </div>
                    <span style="font-size: 0.7rem; background: rgba(245, 166, 35, 0.2); color: #F5A623; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 700;">SECURITY TOKEN</span>
                </div>
                <div style="color: #CBD5E1; font-size: 0.82rem; line-height: 1.5;">
                    Generate a secure one-time verification token (valid 15 minutes) to reset your account password and restore locked accounts.
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Step 1: Generate Verification Token
            st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #F8FAFC; margin-bottom: 0.4rem;'>Step 1: Request Secure OTP Verification Code</div>", unsafe_allow_html=True)
            with st.form("form_request_reset_token"):
                f_identity = st.text_input("Enter Registered Username or Email", value="", placeholder="e.g. analyst or alex.analyst@soc.internal", key="input_reset_id")
                btn_req_token = st.form_submit_button("Generate & Dispatch Verification OTP 📩", use_container_width=True)

                if btn_req_token:
                    if not f_identity.strip():
                        st.error("❌ Please enter your username or email address.")
                    else:
                        req_res = request_password_reset(f_identity)
                        if req_res["success"]:
                            st.session_state["last_reset_token"] = req_res["token"]
                            st.session_state["last_reset_user"] = req_res["username"]
                            log_audit_event("PASSWORD_RESET_TOKEN_GENERATED", target="Security Gateway", details=f"Verification token generated for '{req_res['username']}'", status="Success")
                            st.success("✅ One-Time Verification Token successfully generated!")
                        else:
                            st.error(f"❌ {req_res['message']}")

            # Display simulated offline dispatch if active
            if "last_reset_token" in st.session_state:
                st.markdown(f"""
                <div style="background: rgba(56, 189, 248, 0.1); border: 1px solid #38BDF8; border-radius: 6px; padding: 0.75rem 1rem; margin: 0.75rem 0; font-size: 0.82rem; color: #CBD5E1;">
                    <div style="color: #38BDF8; font-weight: 700; margin-bottom: 0.2rem;">
                        📧 SIMULATED SOC SECURE DISPATCH GATEWAY
                    </div>
                    <div>A secure one-time token was dispatched for investigator <strong>{st.session_state.get('last_reset_user', '')}</strong>:</div>
                    <div style="margin-top: 0.4rem; font-size: 1.15rem; font-family: monospace; letter-spacing: 0.15em; color: #F8FAFC; background: #0B1220; padding: 0.35rem 0.65rem; border-radius: 4px; display: inline-block; border: 1px solid #1E293B;">
                        {st.session_state['last_reset_token']}
                    </div>
                    <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 0.3rem;">Token expiration window: 15 minutes. Copy this OTP to complete Step 2 below.</div>
                </div>
                """, unsafe_allow_html=True)

            # Step 2: Set New Password
            st.markdown("<div style='font-size: 0.85rem; font-weight: 700; color: #F8FAFC; margin-top: 1rem; margin-bottom: 0.4rem;'>Step 2: Enter Verification Code & New Password</div>", unsafe_allow_html=True)
            with st.form("form_submit_new_pass"):
                reset_user_input = st.text_input("Username or Email", value=st.session_state.get("last_reset_user", ""), key="reset_user_val")
                reset_token_input = st.text_input("6-Digit Verification OTP Token", value=st.session_state.get("last_reset_token", ""), key="reset_token_val")

                c_np1, c_np2 = st.columns(2)
                with c_np1:
                    new_pass = st.text_input("New Password (min 6 chars)", type="password", key="reset_new_pass")
                with c_np2:
                    new_pass_conf = st.text_input("Confirm New Password", type="password", key="reset_new_pass_conf")

                btn_apply_pass = st.form_submit_button("Update Password & Restore Access 🔐", use_container_width=True, type="primary")

                if btn_apply_pass:
                    if not reset_user_input or not reset_token_input or not new_pass:
                        st.error("❌ Please provide username, token, and new password.")
                    elif new_pass != new_pass_conf:
                        st.error("❌ New passwords do not match.")
                    else:
                        reset_res = reset_password_with_token(reset_user_input, reset_token_input, new_pass)
                        if reset_res["success"]:
                            log_audit_event("PASSWORD_RESET_SUCCESS", target="Security Gateway", details=f"Password successfully reset for '{reset_user_input}'", status="Success")
                            st.session_state.pop("last_reset_token", None)
                            st.session_state.pop("last_reset_user", None)
                            st.success(f"✅ {reset_res['message']}")
                        else:
                            st.error(f"❌ {reset_res['message']}")

        # ----------------- Fast Demo Access -----------------
        st.markdown("<div style='height: 0.8rem;'></div>", unsafe_allow_html=True)
        st.markdown("""
        <div style="background: #121A2B; border: 1px solid #1E293B; border-radius: 8px; padding: 0.85rem 1rem; margin-bottom: 0.8rem;">
            <div style="font-size: 0.75rem; font-weight: 700; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.05em;">
                ⚡ Fastpass Demo Login (Instant Evaluator Access)
            </div>
        </div>
        """, unsafe_allow_html=True)

        c1, c2 = st.columns(2)
        with c1:
            if st.button("🛡️ 1-Click: User (Analyst)", use_container_width=True):
                p = USER_PROFILES["analyst"]
                st.session_state["authenticated"] = True
                st.session_state["user_role"] = p["role"]
                st.session_state["user_name"] = p["name"]
                st.session_state["user_profile"] = p
                st.session_state["login_time"] = datetime.now().strftime("%H:%M:%S")
                log_audit_event("AUTH_DEMO_FASTPASS", target="SOC Gateway", details="Fastpass demo login as Analyst Alex", status="Success")
                st.rerun()
        with c2:
            if st.button("🔑 1-Click: Admin (Security Lead)", use_container_width=True):
                p = USER_PROFILES["admin"]
                st.session_state["authenticated"] = True
                st.session_state["user_role"] = p["role"]
                st.session_state["user_name"] = p["name"]
                st.session_state["user_profile"] = p
                st.session_state["login_time"] = datetime.now().strftime("%H:%M:%S")
                log_audit_event("AUTH_DEMO_FASTPASS", target="SOC Gateway", details="Fastpass demo login as Admin Sarah", status="Success")
                st.rerun()

        render_demo_tag()


# =============================================================================
# 5. Routing Controller & Session Management
# =============================================================================
is_authenticated = st.session_state.get("authenticated", False)

if not is_authenticated:
    # Render dedicated login gateway
    login_page = st.Page(render_login_gateway, title="SOC Login Gateway", icon="🔒")
    pg = st.navigation([login_page], position="hidden")
    pg.run()
else:
    active_role = st.session_state.get("user_role", "analyst")
    user_name = st.session_state.get("user_name", "Analyst Alex")
    login_time = st.session_state.get("login_time", "12:00:00")

    # 5.1 Sidebar Brand & Profile Box
    with st.sidebar:
        if os.path.exists(logo_file):
            col_img, col_info = st.columns([1, 2.5])
            with col_img:
                st.image(logo_file, width=64)
            with col_info:
                st.markdown("""
                <div style="font-size: 1.1rem; font-weight: 700; color: #F8FAFC; line-height: 1.2; margin-top: 0.2rem;">
                    XAI Threat SOC
                </div>
                <div style="font-size: 0.72rem; color: #94A3B8; margin-top: 0.2rem;">
                    Network Threat Investigation
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="sidebar-title">
                <span style="font-size: 1.3rem;">🛡️</span>
                <span>XAI Threat SOC</span>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("""
        <div style="margin-top: 0.4rem; padding-bottom: 0.6rem; border-bottom: 1px solid #1E293B;">
            <span class="sidebar-version-badge">
                v1.2-eval • LightGBM + TreeSHAP
            </span>
        </div>
        """, unsafe_allow_html=True)

        # Authenticated Profile Card
        if active_role == "admin":
            st.markdown(f"""
            <div style="background: rgba(245, 166, 35, 0.1); border: 1px solid rgba(245, 166, 35, 0.4); border-radius: 8px; padding: 0.6rem 0.75rem; margin-top: 0.7rem; margin-bottom: 0.5rem;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div style="font-size: 0.8rem; font-weight: 700; color: #F5A623;">🔑 {user_name}</div>
                    <span style="font-size: 0.62rem; background: #F5A623; color: #000; padding: 0.1rem 0.35rem; border-radius: 3px; font-weight: 800;">ADMIN</span>
                </div>
                <div style="font-size: 0.68rem; color: #CBD5E1; margin-top: 0.2rem;">Level-5 Full Clearance • Raw Telemetry</div>
                <div style="font-size: 0.64rem; color: #94A3B8; margin-top: 0.2rem;">● Session Active (Since {login_time})</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(f"""
            <div style="background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.4); border-radius: 8px; padding: 0.6rem 0.75rem; margin-top: 0.7rem; margin-bottom: 0.5rem;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div style="font-size: 0.8rem; font-weight: 700; color: #38BDF8;">🛡️ {user_name}</div>
                    <span style="font-size: 0.62rem; background: #38BDF8; color: #000; padding: 0.1rem 0.35rem; border-radius: 3px; font-weight: 800;">USER</span>
                </div>
                <div style="font-size: 0.68rem; color: #CBD5E1; margin-top: 0.2rem;">Tier-2 Operational Scope • Masked IPs</div>
                <div style="font-size: 0.64rem; color: #94A3B8; margin-top: 0.2rem;">● Session Active (Since {login_time})</div>
            </div>
            """, unsafe_allow_html=True)

        # Log Out Button
        if st.button("🚪 Sign Out (Switch Profile)", use_container_width=True):
            log_audit_event("AUTH_LOGOUT", target="SOC Gateway", details=f"User '{user_name}' signed out of SOC session", status="Success")
            st.session_state["authenticated"] = False
            st.session_state["user_role"] = None
            st.session_state["user_name"] = None
            st.session_state["user_profile"] = None
            st.rerun()

    # 5.2 Dynamic Role-Based Multi-Page Navigation Structure
    if active_role == "admin":
        # Admin Profile: Full unrestricted access to all 11 pages
        pages = [
            st.Page("pages/1_Overview.py", title="Command Center", icon="📊"),
            st.Page("pages/2_Upload_and_Analyze.py", title="Upload & Analyze", icon="📁"),
            st.Page("pages/3_Session_Investigation.py", title="Session Investigation", icon="🔍"),
            st.Page("pages/4_Explainability.py", title="Explainability & SHAP", icon="🔬"),
            st.Page("pages/5_Ask_the_Analyst.py", title="Ask the Analyst (RAG)", icon="💬"),
            st.Page("pages/6_Evasion_Lab.py", title="Adversarial Evasion Lab", icon="🧪"),
            st.Page("pages/7_Dataset_Explorer.py", title="Dataset Explorer", icon="📈"),
            st.Page("pages/8_Model_Performance.py", title="Model Performance", icon="🎯"),
            st.Page("pages/9_Reports_and_Export.py", title="Reports & Export", icon="📑"),
            st.Page("pages/10_About_and_Research.py", title="About & Research", icon="🎓"),
            st.Page("pages/11_Admin_Console.py", title="Admin & Governance", icon="⚙️"),
        ]
    else:
        # User (Analyst) Profile: Focused operational triage, explanations & reporting (Sensitive ML internals hidden)
        pages = [
            st.Page("pages/1_Overview.py", title="Command Center", icon="📊"),
            st.Page("pages/2_Upload_and_Analyze.py", title="Upload & Analyze", icon="📁"),
            st.Page("pages/3_Session_Investigation.py", title="Session Investigation", icon="🔍"),
            st.Page("pages/4_Explainability.py", title="Explainability & SHAP", icon="🔬"),
            st.Page("pages/5_Ask_the_Analyst.py", title="Ask the Analyst (RAG)", icon="💬"),
            st.Page("pages/9_Reports_and_Export.py", title="Reports & Export", icon="📑"),
            st.Page("pages/10_About_and_Research.py", title="About & Research", icon="🎓"),
        ]

    pg = st.navigation(pages)

    # 5.3 Sidebar Traffic Class Legend Footer
    with st.sidebar:
        st.markdown("---")
        st.markdown("""
        <div style="padding: 0 0.5rem; font-size: 0.75rem; color: #94A3B8;">
            <div style="font-weight: 700; color: #CBD5E1; text-transform: uppercase; margin-bottom: 0.5rem; letter-spacing: 0.05em;">
                Traffic Class Legend
            </div>
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
                <span style="width: 9px; height: 9px; border-radius: 50%; background-color: #2ECC71; display: inline-block;"></span>
                <span style="color: #F8FAFC; font-weight: 500;">HUMAN:</span>
                <span style="color: #64748B;">Organic browsing</span>
            </div>
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
                <span style="width: 9px; height: 9px; border-radius: 50%; background-color: #F5A623; display: inline-block;"></span>
                <span style="color: #F8FAFC; font-weight: 500;">BOT:</span>
                <span style="color: #64748B;">Scripted automation</span>
            </div>
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.35rem;">
                <span style="width: 9px; height: 9px; border-radius: 50%; background-color: #8B5CF6; display: inline-block;"></span>
                <span style="color: #F8FAFC; font-weight: 500;">AI-AGENT:</span>
                <span style="color: #64748B;">LLM browsing agent</span>
            </div>
            <div style="display: flex; align-items: center; gap: 0.5rem; margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid #1E293B;">
                <span style="width: 9px; height: 9px; border-radius: 50%; background-color: #94A3B8; display: inline-block;"></span>
                <span style="color: #F8FAFC; font-weight: 500;">UNCERTAIN:</span>
                <span style="color: #64748B;">Confidence &lt; 65%</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # 5.4 Execute Selected Page
    pg.run()

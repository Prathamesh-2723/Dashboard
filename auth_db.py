"""
auth_db.py
=============================================================================
Explainable AI Network Security SOC - Authentication & RBAC Database Engine
Persistent SQLite + SQLAlchemy backend with:
1. Cryptographic password hashing with bcrypt (salted)
2. Persistent user profiles & role storage across app reboots
3. User self-registration & Admin approval workflow
4. Forgot password / self-service token reset mechanism
5. Brute-force rate limiting with 15-minute account lockout after 5 failures
6. Admin user management (approve, reject, unlock, role change, password reset)
=============================================================================
"""

import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List, Tuple

def utcnow() -> datetime:
    """Returns naive UTC datetime object."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

import bcrypt
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    desc
)
from sqlalchemy.orm import sessionmaker, declarative_base

# Define DB Path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "soc_auth.db")

# Ensure directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Database connection
DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    name = Column(String(128), nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    role = Column(String(32), default="analyst", nullable=False)  # "analyst" or "admin"
    title = Column(String(128), default="Tier-2 SOC Analyst")
    badge_label = Column(String(64), default="User (SOC Analyst)")
    clearance = Column(String(128), default="Operational Triage • Masked IPs • Read-Only ML")
    icon = Column(String(16), default="🛡️")
    color = Column(String(16), default="#38BDF8")
    
    # Status: 'active', 'pending_approval', 'rejected', 'locked'
    status = Column(String(32), default="active", nullable=False)
    
    # Brute-force rate limiting & lockout
    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    
    # Self-service password reset
    reset_token = Column(String(64), nullable=True)
    reset_token_expires_at = Column(DateTime, nullable=True)
    
    # Registration details
    justification = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        """Converts user record to dictionary representation."""
        is_locked = False
        remaining_lock_sec = 0
        now = utcnow()
        if self.locked_until and self.locked_until > now:
            is_locked = True
            remaining_lock_sec = int((self.locked_until - now).total_seconds())

        return {
            "id": self.id,
            "username": self.username,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "title": self.title,
            "badge_label": self.badge_label,
            "clearance": self.clearance,
            "icon": self.icon,
            "color": self.color,
            "status": self.status,
            "failed_attempts": self.failed_attempts,
            "is_locked": is_locked,
            "locked_until": self.locked_until.strftime("%Y-%m-%d %H:%M:%S") if self.locked_until else None,
            "remaining_lock_seconds": remaining_lock_sec,
            "justification": self.justification,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None,
            "last_login": self.last_login.strftime("%Y-%m-%d %H:%M:%S") if self.last_login else None,
            "accessible_pages": 11 if self.role == "admin" else 7
        }


# =============================================================================
# Cryptographic Password Hashing (bcrypt)
# =============================================================================
def hash_password(plain_password: str) -> str:
    """Hashes a plaintext password using bcrypt with a cryptographic salt."""
    if not isinstance(plain_password, str):
        plain_password = str(plain_password)
    salt = bcrypt.gensalt(rounds=12)
    hashed_bytes = bcrypt.hashpw(plain_password.encode("utf-8"), salt)
    return hashed_bytes.decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# =============================================================================
# Database Initialization & Default Seeding
# =============================================================================
def init_db(db_engine=None):
    """Initializes tables and seeds default admin and analyst accounts if absent."""
    target_engine = db_engine or engine
    Base.metadata.create_all(bind=target_engine)
    
    Session = sessionmaker(bind=target_engine)
    session = Session()
    try:
        # Check if analyst exists
        analyst = session.query(User).filter_by(username="analyst").first()
        if not analyst:
            analyst = User(
                username="analyst",
                password_hash=hash_password("analyst123"),
                name="Analyst Alex",
                email="alex.analyst@soc.internal",
                role="analyst",
                title="Tier-2 SOC Analyst",
                badge_label="User (SOC Analyst)",
                clearance="Operational Triage • Masked IPs • Read-Only ML",
                icon="🛡️",
                color="#38BDF8",
                status="active"
            )
            session.add(analyst)

        # Check if admin exists
        admin = session.query(User).filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                password_hash=hash_password("admin123"),
                name="Admin Sarah",
                email="sarah.admin@soc.internal",
                role="admin",
                title="Lead Security / ML Engineer",
                badge_label="Admin (Security Lead)",
                clearance="Level-5 Clearance • Raw IPs • Governance Controls",
                icon="🔑",
                color="#F5A623",
                status="active"
            )
            session.add(admin)

        session.commit()
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_db():
    """Provides a fresh database session."""
    return SessionLocal()


# =============================================================================
# Authentication with Rate Limiting & Account Lockout
# =============================================================================
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

def authenticate_user_detailed(username: str, password: str) -> Dict[str, Any]:
    """
    Authenticates user with cryptographic password verification,
    brute-force rate limiting, and 15-minute account lockout logic.

    Returns dict with keys:
    - success (bool)
    - user (Optional[dict])
    - status (str: 'success', 'locked', 'pending', 'rejected', 'invalid_credentials', 'not_found')
    - message (str)
    - remaining_attempts (int)
    """
    if not username or not password:
        return {
            "success": False,
            "user": None,
            "status": "invalid_credentials",
            "message": "Username and password are required.",
            "remaining_attempts": MAX_FAILED_ATTEMPTS
        }

    clean_user = str(username).strip().lower()
    clean_pass = str(password).strip()

    session = get_db()
    try:
        user = session.query(User).filter(User.username.ilike(clean_user)).first()
        if not user:
            return {
                "success": False,
                "user": None,
                "status": "not_found",
                "message": "User account does not exist.",
                "remaining_attempts": 0
            }

        now = utcnow()

        # Check if account is currently locked
        if user.locked_until and user.locked_until > now:
            remaining_seconds = int((user.locked_until - now).total_seconds())
            remaining_minutes = max(1, (remaining_seconds + 59) // 60)
            return {
                "success": False,
                "user": user.to_dict(),
                "status": "locked",
                "message": f"Account is locked due to {MAX_FAILED_ATTEMPTS} consecutive failed attempts. Please retry in {remaining_minutes} minute(s) or contact an Admin.",
                "remaining_seconds": remaining_seconds,
                "remaining_minutes": remaining_minutes
            }

        # Check approval status
        if user.status == "pending_approval":
            return {
                "success": False,
                "user": user.to_dict(),
                "status": "pending",
                "message": "Your registration request is pending SOC Admin approval. Please contact Admin Sarah."
            }
        elif user.status == "rejected":
            return {
                "success": False,
                "user": user.to_dict(),
                "status": "rejected",
                "message": "Your account access request was declined by the SOC Administrator."
            }

        # Verify password
        if verify_password(clean_pass, user.password_hash):
            # Login successful: reset failed attempts & lockout
            user.failed_attempts = 0
            user.locked_until = None
            user.status = "active"
            user.last_login = now
            session.commit()
            return {
                "success": True,
                "user": user.to_dict(),
                "status": "success",
                "message": "Authentication successful."
            }
        else:
            # Login failed: increment failure counter
            user.failed_attempts += 1
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                user.status = "locked"
                session.commit()
                return {
                    "success": False,
                    "user": user.to_dict(),
                    "status": "locked",
                    "message": f"Account locked for {LOCKOUT_DURATION_MINUTES} minutes due to {MAX_FAILED_ATTEMPTS} consecutive failed attempts.",
                    "remaining_minutes": LOCKOUT_DURATION_MINUTES
                }
            else:
                remaining = MAX_FAILED_ATTEMPTS - user.failed_attempts
                session.commit()
                return {
                    "success": False,
                    "user": user.to_dict(),
                    "status": "invalid_credentials",
                    "message": f"Invalid password. {remaining} attempt(s) remaining before a {LOCKOUT_DURATION_MINUTES}-minute lockout.",
                    "remaining_attempts": remaining
                }
    finally:
        session.close()


def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Backwards-compatible wrapper.
    Returns user dict on success, None on failure.
    """
    res = authenticate_user_detailed(username, password)
    if res["success"]:
        return res["user"]
    return None


def get_user_profile(role_or_username: str) -> Optional[Dict[str, Any]]:
    """Retrieves user profile dictionary by username or role."""
    key = str(role_or_username).strip().lower()
    session = get_db()
    try:
        user = session.query(User).filter(User.username.ilike(key)).first()
        if not user:
            user = session.query(User).filter(User.role == key).first()
        if user:
            return user.to_dict()
        return None
    finally:
        session.close()


# =============================================================================
# Registration & Approval Flow
# =============================================================================
def register_user(
    username: str,
    password: str,
    name: str,
    email: str,
    role: str = "analyst",
    justification: str = "",
    require_approval: bool = True
) -> Dict[str, Any]:
    """
    Registers a new user account.
    If require_approval is True, status is set to 'pending_approval'.
    """
    clean_user = str(username).strip().lower()
    clean_pass = str(password).strip()
    clean_name = str(name).strip()
    clean_email = str(email).strip().lower()
    clean_role = "admin" if role.lower() == "admin" else "analyst"

    if len(clean_user) < 3:
        return {"success": False, "message": "Username must be at least 3 characters."}
    if len(clean_pass) < 6:
        return {"success": False, "message": "Password must be at least 6 characters."}
    if "@" not in clean_email or "." not in clean_email:
        return {"success": False, "message": "Please provide a valid corporate email address."}

    session = get_db()
    try:
        # Check existing username
        if session.query(User).filter(User.username.ilike(clean_user)).first():
            return {"success": False, "message": f"Username '{clean_user}' is already registered."}
        # Check existing email
        if session.query(User).filter(User.email.ilike(clean_email)).first():
            return {"success": False, "message": f"Email '{clean_email}' is already associated with an account."}

        status = "pending_approval" if require_approval else "active"
        title = "Lead Security / ML Engineer" if clean_role == "admin" else "Tier-2 SOC Analyst"
        badge = "Admin (Security Lead)" if clean_role == "admin" else "User (SOC Analyst)"
        clearance = "Level-5 Clearance • Raw IPs • Governance Controls" if clean_role == "admin" else "Operational Triage • Masked IPs • Read-Only ML"
        icon = "🔑" if clean_role == "admin" else "🛡️"
        color = "#F5A623" if clean_role == "admin" else "#38BDF8"

        new_user = User(
            username=clean_user,
            password_hash=hash_password(clean_pass),
            name=clean_name,
            email=clean_email,
            role=clean_role,
            title=title,
            badge_label=badge,
            clearance=clearance,
            icon=icon,
            color=color,
            status=status,
            justification=justification.strip() if justification else "Standard SOC account request"
        )
        session.add(new_user)
        session.commit()
        return {
            "success": True,
            "status": status,
            "user": new_user.to_dict(),
            "message": "Account created successfully." if not require_approval else "Registration submitted! Your request is pending SOC Administrator approval."
        }
    except Exception as e:
        session.rollback()
        return {"success": False, "message": f"Database error: {str(e)}"}
    finally:
        session.close()


def approve_user_registration(user_id: int) -> bool:
    """Approves a pending registration, setting status to active."""
    session = get_db()
    try:
        user = session.query(User).filter_by(id=user_id).first()
        if user and user.status in ["pending_approval", "rejected"]:
            user.status = "active"
            user.failed_attempts = 0
            user.locked_until = None
            session.commit()
            return True
        return False
    finally:
        session.close()


def reject_user_registration(user_id: int) -> bool:
    """Rejects a registration request."""
    session = get_db()
    try:
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.status = "rejected"
            session.commit()
            return True
        return False
    finally:
        session.close()


def unlock_user_account(user_id: int) -> bool:
    """Manually unlocks a locked user account and resets failed attempts."""
    session = get_db()
    try:
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.locked_until = None
            user.failed_attempts = 0
            if user.status == "locked":
                user.status = "active"
            session.commit()
            return True
        return False
    finally:
        session.close()


def get_all_users() -> List[Dict[str, Any]]:
    """Returns a list of all user profile dictionaries ordered by creation."""
    session = get_db()
    try:
        users = session.query(User).order_by(desc(User.created_at)).all()
        return [u.to_dict() for u in users]
    finally:
        session.close()


def get_pending_users() -> List[Dict[str, Any]]:
    """Returns users with status 'pending_approval'."""
    session = get_db()
    try:
        users = session.query(User).filter_by(status="pending_approval").order_by(desc(User.created_at)).all()
        return [u.to_dict() for u in users]
    finally:
        session.close()


# =============================================================================
# Forgot Password / Self-Service Token Reset
# =============================================================================
def request_password_reset(identity: str) -> Dict[str, Any]:
    """
    Generates a secure 6-digit numeric token valid for 15 minutes.
    In an enterprise SOC, this is emailed; offline, it is displayed/returned.
    """
    clean_id = str(identity).strip().lower()
    session = get_db()
    try:
        user = session.query(User).filter(
            (User.username.ilike(clean_id)) | (User.email.ilike(clean_id))
        ).first()

        if not user:
            return {
                "success": False,
                "message": "No account found matching that username or email address."
            }

        # Generate 6-digit cryptographic OTP token
        token = f"{secrets.randbelow(900000) + 100000:06d}"
        expires_at = utcnow() + timedelta(minutes=15)

        user.reset_token = token
        user.reset_token_expires_at = expires_at
        session.commit()

        return {
            "success": True,
            "username": user.username,
            "email": user.email,
            "token": token,
            "expires_in_minutes": 15,
            "message": f"A secure reset token was dispatched for {user.email}."
        }
    finally:
        session.close()


def reset_password_with_token(username_or_email: str, token: str, new_password: str) -> Dict[str, Any]:
    """
    Validates reset token and sets the new password.
    """
    clean_id = str(username_or_email).strip().lower()
    clean_token = str(token).strip()
    clean_pass = str(new_password).strip()

    if len(clean_pass) < 6:
        return {"success": False, "message": "New password must be at least 6 characters long."}

    session = get_db()
    try:
        user = session.query(User).filter(
            (User.username.ilike(clean_id)) | (User.email.ilike(clean_id))
        ).first()

        if not user:
            return {"success": False, "message": "User account not found."}

        if not user.reset_token or user.reset_token != clean_token:
            return {"success": False, "message": "Invalid or mismatched reset token."}

        if not user.reset_token_expires_at or user.reset_token_expires_at < utcnow():
            return {"success": False, "message": "Reset token has expired. Please request a new token."}

        # Valid token: update password
        user.password_hash = hash_password(clean_pass)
        user.reset_token = None
        user.reset_token_expires_at = None
        user.failed_attempts = 0
        user.locked_until = None
        if user.status == "locked":
            user.status = "active"
        session.commit()

        return {
            "success": True,
            "message": "Password updated successfully! You can now log in with your new credentials."
        }
    finally:
        session.close()


def admin_reset_password(user_id: int, new_password: str) -> bool:
    """Allows an administrator to reset a user's password directly."""
    if len(new_password.strip()) < 6:
        return False
    session = get_db()
    try:
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.password_hash = hash_password(new_password.strip())
            user.failed_attempts = 0
            user.locked_until = None
            session.commit()
            return True
        return False
    finally:
        session.close()


# Initialize database automatically on module import
init_db()

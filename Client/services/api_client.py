import os, re, requests
from urllib.parse import urljoin
from dotenv import load_dotenv
import json
from typing import Optional

load_dotenv()
API_BASE = os.getenv("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/") + "/"

_auth_token: Optional[str] = None


class ApiError(Exception):
    pass


class PolicyViolationError(ApiError):
    def __init__(self, message):
        super().__init__(message)
        self.requires_password_check = True


def set_auth_token(token: str):
    """Set the authentication token for subsequent requests"""
    global _auth_token
    _auth_token = token


def clear_auth_token():
    """Clear the authentication token"""
    global _auth_token
    _auth_token = None


def get_auth_headers():
    """Get headers with authentication token if available"""
    headers = {"Content-Type": "application/json"}
    if _auth_token:
        headers["Authorization"] = f"Bearer {_auth_token}"
    return headers


class ApiError(Exception):
    pass


def _url(path: str) -> str:
    return urljoin(API_BASE, path.lstrip("/"))


def _normalize_detail(r):
    """Convert FastAPI error detail (str, list, dict) into a readable string."""
    try:
        response_json = r.json()
        detail = response_json.get("detail", "")
        print(f"DEBUG: Full response detail: {detail}")
    except Exception:
        return ""

    if isinstance(detail, list):
        # FastAPI validation errors list
        messages = []
        for d in detail:
            if isinstance(d, dict):
                msg = d.get("msg") or str(d)
                # Check if this is specifically a reuse error by looking at the error context
                ctx = d.get("ctx", {})
                error_details = ctx.get("error", {})
                print(f"DEBUG: Error context: {ctx}")
                print(f"DEBUG: Error details: {error_details}")

                # If we can identify it's a reuse error from the context, modify the message
                if "reuse" in str(error_details).lower() or "history" in str(error_details).lower():
                    msg = "HISTORY_REUSE_ERROR"

                messages.append(msg)
            else:
                messages.append(str(d))
        return "; ".join(messages)

    if isinstance(detail, dict):
        return detail.get("msg") or str(detail)

    return str(detail)


# ---------- Auth ----------
def register(username, email, password):
    r = requests.post(_url("/api/v1/auth/register"), json={
        "username": username, "email": email, "password": password
    })
    if r.status_code >= 400:
        raise ApiError(_normalize_detail(r) or "Register failed")
    return r.json()


def login(username, password, remember_me=False):
    r = requests.post(_url("/api/v1/auth/login"), json={
        "username": username, "password": password, "remember_me": remember_me

    })

    print(f"DEBUG API: Login status code: {r.status_code}")
    if r.status_code >= 400:
        clear_auth_token()
        try:
            print(f"DEBUG API: Login response JSON: {r.json()}")
        except:
            print(f"DEBUG API: Login response text: {r.text}")

        detail = _normalize_detail(r)
        print(f"DEBUG API: Login normalized detail: '{detail}'")

        if r.status_code == 401:
            if "user not found" in detail.lower():
                raise ApiError("User not found")
            if "password not set" in detail.lower():
                raise ApiError("Password not set for this user")
            if "incorrect password" in detail.lower():
                raise ApiError("Incorrect password")
            raise ApiError(detail or "Invalid credentials")

        if r.status_code == 422:
            raise ApiError(detail or "Password does not meet requirements")

        if r.status_code == 423:
            raise ApiError(detail or "Account is temporarily locked")

        # Handle password policy violation
        if r.status_code == 426:
            clear_auth_token()
            error = ApiError("Password policy violation - please update your password")
            error.requires_password_change = True
            raise error

        raise ApiError(detail or "Login failed")

    result = r.json()

    if "access_token" in result:
        set_auth_token(result["access_token"])

    return result


def change_password(username, current_password, new_password):
    print("DEBUG: change_password function called!")
    r = requests.post(_url("/api/v1/auth/change-password"), json={
        "username": username, "current_password": current_password, "new_password": new_password
    })

    print(f"DEBUG API: Change password status code: {r.status_code}")
    if r.status_code >= 400:
        try:
            response_json = r.json()
            print(f"DEBUG API: Change password response JSON: {response_json}")
        except:
            print(f"DEBUG API: Change password response text: {r.text}")

        detail = _normalize_detail(r)
        print(f"DEBUG API: Change password normalized detail: '{detail}'")

        # Handle specific status codes
        if r.status_code == 422:
            print("DEBUG API: 422 status - raising ApiError")

        raise ApiError(detail or "Change password failed")

    return r.json()


def forgot_password(email):
    r = requests.post(_url("/api/v1/auth/forgot-password"), json={"email": email})
    if r.status_code >= 400:
        raise ApiError(_normalize_detail(r) or "Request failed")
    return r.json()


def reset_password(email, token, new_password):
    if not re.fullmatch(r"[a-f0-9]{40}", token):
        raise ApiError("Invalid reset code format")

    r = requests.post(_url("/api/v1/auth/reset-password"), json={
        "email": email, "token": token, "new_password": new_password
    })

    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", "")
        except Exception:
            detail = ""

        # Handle FastAPI validation errors (422 list of errors)
        if r.status_code == 422:
            if isinstance(detail, list):
                # Extract validation error messages
                messages = []
                for d in detail:
                    if isinstance(d, dict) and d.get("msg"):
                        msg = d.get("msg", "")
                        if "password" in msg.lower():
                            messages.append("Password does not meet requirements")
                        else:
                            messages.append(msg)
                if messages:
                    raise ApiError("; ".join(messages))
            raise ApiError("Password does not meet requirements")

        if isinstance(detail, str):
            if "user not found" in detail.lower():
                raise ApiError("User not found")
            if "expired" in detail.lower():
                raise ApiError("Reset code expired or invalid")
            if "password" in detail.lower():
                raise ApiError("Password does not meet requirements")
            raise ApiError(detail or "Reset failed")

        raise ApiError("Reset failed")
    return r.json()


# ---------- Customers ----------
def list_customers():
    r = requests.get(_url("/api/v1/customers"), headers=get_auth_headers())
    if r.status_code == 401:
        clear_auth_token()
        raise ApiError("Authentication required")
    elif r.status_code == 426:
        clear_auth_token()
        raise PolicyViolationError("Password policy check required")
    r.raise_for_status()
    return r.json()


def create_customer(full_name, email, phone, plan_id=None):
    payload = {"full_name": full_name, "email": email, "phone": phone, "plan_id": plan_id}
    r = requests.post(_url("/api/v1/customers"), json=payload, headers=get_auth_headers())
    if r.status_code == 401:
        clear_auth_token()
        raise ApiError("Authentication required")
    if r.status_code >= 400:
        raise ApiError(_normalize_detail(r) or "Create failed")
    return r.json()


# ---------- Plans ----------
def list_plans():
    r = requests.get(_url("/api/v1/plans"), headers=get_auth_headers())
    if r.status_code == 401:
        clear_auth_token()
        raise ApiError("Authentication required")
    r.raise_for_status()
    return r.json()


# ---------- Single Customer page for stored XSS presentation --------------
def get_customer(customer_id):
    r = requests.get(_url(f"/api/v1/customers/{customer_id}"), headers=get_auth_headers())
    if r.status_code == 401:
        clear_auth_token()
        raise ApiError("Authentication required")
    if r.status_code >= 400:
        raise ApiError(_normalize_detail(r) or "Failed to fetch customer")
    return r.json()


def logout():
    """Logout - clear the stored token"""
    clear_auth_token()
    return {"message": "Logged out successfully"}


def refresh_token():
    """Refresh the current access token"""
    r = requests.post(_url("/api/v1/auth/refresh-token"), headers=get_auth_headers())
    if r.status_code >= 400:
        clear_auth_token()
        raise ApiError(_normalize_detail(r) or "Token refresh failed")

    result = r.json()
    if "access_token" in result:
        set_auth_token(result["access_token"])
    return result


def get_current_user():
    """Get current user information"""
    r = requests.get(_url("/api/v1/auth/me"), headers=get_auth_headers())
    if r.status_code >= 400:
        if r.status_code == 401:
            clear_auth_token()
            raise ApiError("Authentication required")
        raise ApiError(_normalize_detail(r) or "Failed to get user info")
    return r.json()

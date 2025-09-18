import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from dotenv import load_dotenv
from services import api_client as api  # ensure services/__init__.py exists
import yaml
import hashlib
import json

load_dotenv()


def get_password_requirements():
    """Fetch password requirements from same config as server"""
    try:
        # Use same path as server: CONFIG_DIR + PASSWORD_POLICY_FILE
        config_path = '/config/password_policy.yaml'

        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)

        password_reqs = config.get('password_requirements', {})

        return {
            'min_length': password_reqs.get('min_length', 10),
            'uppercase': password_reqs.get('uppercase', True),
            'lowercase': password_reqs.get('lowercase', True),
            'digits': password_reqs.get('digits', True),
            'special': password_reqs.get('special', True),
            'history_count': password_reqs.get('history_count', 3)
        }

    except Exception as e:
        print(f"Error reading config: {e}")
        return None


def validate_password_client_side(password: str, requirements: dict) -> tuple:
    """Client-side password validation matching server logic"""
    import re

    if not password:
        return False, ["Password cannot be empty"]

    if not requirements:
        return False, ["Unable to load password requirements"]

    fails = []

    # Length check
    min_length = requirements.get("min_length", 10)
    if len(password) < min_length:
        fails.append(f"Must be at least {min_length} characters long")

    # Character requirements
    if requirements.get("uppercase", True) and not re.search(r"[A-Z]", password):
        fails.append("Must contain at least one uppercase letter")
    if requirements.get("lowercase", True) and not re.search(r"[a-z]", password):
        fails.append("Must contain at least one lowercase letter")
    if requirements.get("digits", True) and not re.search(r"\d", password):
        fails.append("Must contain at least one number")
    if requirements.get("special", True) and not re.search(r"[\W_]", password):
        fails.append("Must contain at least one special character")

    # Blacklist check (simplified - read from config if needed)
    password_lower = password.lower()
    common_passwords = ["password", "123456", "qwerty", "admin", "letmein"]
    for bad_password in common_passwords:
        if bad_password in password_lower:
            fails.append(f"Must not contain common words like '{bad_password}'")
            break

    return len(fails) == 0, fails


def clean_error_message(error_str):
    """Error message sanitization prevents information leakage and potential XSS through error responses"""
    error_lower = error_str.lower()

    # Handle specific error patterns
    if "history_reuse_error" in error_lower:
        return "Cannot reuse a previous password. Please choose a different password."
    elif "value error" in error_lower and "password does not meet complexity requirements" in error_lower:
        return "Password does not meet the security requirements. Please check the requirements above and try again."
    elif "password does not meet complexity requirements" in error_lower:
        return "Password does not meet the security requirements. Please check the requirements above and try again."
    elif "must be at least" in error_lower and "characters long" in error_lower:
        return "Password is too short. Please use the minimum required length."
    elif "incorrect password" in error_lower or "current password" in error_lower:
        return "Current password is incorrect"
    elif "passwords does not match" in error_lower or "passwords do not match" in error_lower:
        return "Passwords do not match"
    elif "user not found" in error_lower:
        return "User not found"
    elif "expired" in error_lower and "token" in error_lower:
        return "Reset code has expired or is invalid"
    elif "choose another username" in error_lower:
        return "Username already exists. Please choose a different username."
    elif "email already exists" in error_lower:
        return "Email address is already registered. Please use a different email."
    elif "username must be between" in error_lower:
        return "Please choose a username between 3-50 characters."
    elif "value error" in error_lower and "username" in error_lower:
        return "Invalid username format. Please use only valid characters."
    elif "full name must be" in error_lower:
        return "Please enter a valid full name."
    elif "phone number too long" in error_lower:
        return "Please enter a valid phone number."
    else:
        # Return sanitized generic message
        return f"Please check your input and try again.\n{error_lower}"


def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.secret_key = os.getenv("SECRET_KEY", "dev-only")

    MAX_CLIENT_ATTEMPTS = 3

    @app.get("/")
    def home():
        return redirect(url_for("dashboard"))

    @app.get("/dashboard")
    def dashboard():
        # customers = []
        if not session.get("username"):
            return redirect(url_for("login_form"))
        try:
            api.get_current_user()
            customers = api.list_customers()
        except api.PolicyViolationError:
            session["policy_violation"] = True
            flash("Your password policy needs verification. Please log in again.", "warning")
            return redirect(url_for("login_form"))
        except api.ApiError:
            session.clear()
            flash("Session expired, please login again", "warning")
            return redirect(url_for("login_form"))
        except Exception as e:
            flash(f"Error loading customers: {e}", "danger")
            customers = []

        return render_template("dashboard.html", customers=customers)

    # ---------- Auth ----------
    @app.get("/login")
    def login_form():
        return render_template("login.html")

    @app.post("/login")
    def login_submit():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember_me = request.form.get("remember_me") == 'true'

        if "login_attempts" not in session or not isinstance(session["login_attempts"], dict):
            session["login_attempts"] = {}

        user_attempts = session["login_attempts"].get(username, 0)

        try:
            data = api.login(username, password, remember_me)
            session["username"] = data.get("username")
            session["login_attempts"][username] = 0

            if data.get("access_token"):
                session["access_token"] = data.get("access_token")
                session["token_expires"] = data.get("expires_in", 1800)  # 30 minutes default
                session["remember_me"] = data.get("remember_me", False)

            flash("Login successful", "success")
            return redirect(url_for("dashboard"))

        except api.ApiError as e:
            msg = str(e)

            # Handle password policy violation - direct redirect
            if hasattr(e, 'requires_password_change') and e.requires_password_change:
                session["username"] = username
                session["policy_violation"] = True
                flash("Your password no longer meets our updated security policy. Please update your password now.",
                      "warning")
                return redirect(url_for("change_password_form"))

            if "user not found" in msg.lower():
                # show message but do NOT increment counter
                flash("User does not exist in the system.", "danger")
                return redirect(url_for("login_form"))

            # only count if user exists but password is wrong
            user_attempts += 1
            session["login_attempts"][username] = user_attempts
            remaining = max(0, 3 - user_attempts)

            if remaining > 0:
                flash(f"{msg}. You have {remaining} attempts left.", "danger")
            else:
                flash(f"Account {username} is temporarily locked due to multiple failed attempts.", "danger")

            return redirect(url_for("login_form"))

    @app.get("/logout")
    def logout():
        api.logout()
        session.pop("access_token", None)
        session.clear()
        flash("Logged out", "info")
        return redirect(url_for("login_form"))

    @app.get("/register")
    def register_form():
        password_requirements = get_password_requirements()
        return render_template("register.html", password_requirements=password_requirements)

    @app.post("/register")
    def register_submit():
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # Get current config at submission time
        password_requirements = get_password_requirements()

        # Store original config hash from form
        original_hash = request.form.get("config_hash", "")

        # Get current config hash
        current_config = config_status()
        current_hash = current_config.get("hash", "")
        current_requirements = current_config.get("requirements")

        # Check if config changed during user session
        if original_hash and original_hash != current_hash:
            flash(
                "Password requirements have been updated while you were on this page. Please review the new requirements below and try again.",
                "warning")
            return render_template("register.html",
                                   password_requirements=current_requirements,
                                   config_changed=True)

        # Basic validation
        if password != confirm:
            flash("Passwords do not match", "danger")
            return render_template("register.html", password_requirements=current_requirements or password_requirements)

        # NEW: Validate password against CURRENT configuration
        is_valid, validation_errors = validate_password_client_side(password,
                                                                    current_requirements or password_requirements)
        if not is_valid:
            error_message = f"Password does not meet current requirements: {'; '.join(validation_errors)}"
            flash(error_message, "danger")
            return render_template("register.html", password_requirements=current_requirements or password_requirements)

        try:
            api.register(username, email, password)
            flash("Account created. Please login.", "success")
            return redirect(url_for("login_form"))
        except api.ApiError as e:
            clean_message = clean_error_message(str(e))
            flash(clean_message, "danger")
            return render_template("register.html", password_requirements=current_requirements or password_requirements)

    @app.get("/change-password")
    def change_password_form():
        if not session.get("username"):
            return redirect(url_for("login_form"))

        # Check if this is due to policy violation
        policy_violation = session.pop("policy_violation", False)
        password_requirements = get_password_requirements()

        return render_template("change_password.html",
                               policy_violation=policy_violation,
                               password_requirements=password_requirements)

    @app.post("/change-password")
    def change_password_submit():
        if not session.get("username"):
            return redirect(url_for("login_form"))

        username = session["username"]
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        # Get current config at submission time
        password_requirements = get_password_requirements()

        # Store original config hash from form
        original_hash = request.form.get("config_hash", "")

        # Get current config hash
        current_config = config_status()
        current_hash = current_config.get("hash", "")
        current_requirements = current_config.get("requirements")

        # Check if config changed during user session
        if original_hash and original_hash != current_hash:
            flash(
                "Password requirements have been updated while you were on this page. Please review the new requirements below and try again.",
                "warning")
            return render_template("change_password.html",
                                   password_requirements=current_requirements,
                                   config_changed=True)

        # Basic validation
        if new != confirm:
            flash("Passwords do not match", "danger")
            return render_template("change_password.html",
                                   password_requirements=current_requirements or password_requirements)

        # NEW: Validate password against CURRENT configuration
        is_valid, validation_errors = validate_password_client_side(new, current_requirements or password_requirements)
        if not is_valid:
            error_message = f"Password does not meet current requirements: {'; '.join(validation_errors)}"
            flash(error_message, "danger")
            return render_template("change_password.html",
                                   password_requirements=current_requirements or password_requirements)

        try:
            api.change_password(username, current, new)
            flash("Password changed successfully", "success")
            return redirect(url_for("dashboard"))
        except api.ApiError as e:
            clean_message = clean_error_message(str(e))
            flash(clean_message, "danger")
            return render_template("change_password.html",
                                   password_requirements=current_requirements or password_requirements)

    @app.get("/forgot-password")
    def forgot_password_form():
        return render_template("forgot_password.html", code_verified=False)

    @app.post("/forgot-password")
    def forgot_password_submit():
        email = request.form.get("email", "").strip()
        try:
            api.forgot_password(email)
            flash("If the email exists in the system, a reset code was sent.", "info")
        except api.ApiError as e:
            flash(str(e), "danger")
        return redirect(url_for("forgot_password_form"))

    @app.get("/reset-password")
    def reset_password_form():
        print("DEBUG: Accessing reset password form")
        print(f"DEBUG: Flash messages in session: {session.get('_flashes', [])}")

        # Clear messages only on initial page load (not after form submission)
        if not request.referrer or 'reset-password' not in request.referrer:
            print("DEBUG: Initial page load - clearing flash messages")
            session.pop('_flashes', None)
        else:
            print("DEBUG: Coming from form submission - keeping flash messages")

        return render_template("reset_password.html")

    @app.post("/reset-password")
    def reset_password_submit():
        email = request.form.get("email", "").strip()
        token = request.form.get("reset_code", "").strip()
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        # NEW: Check if all fields are empty (initial page load/redirect)
        if not email and not token and not new and not confirm:
            return redirect(url_for("reset_password_form"))

        # Get current config at submission time
        password_requirements = get_password_requirements()

        # Store original config hash from form
        original_hash = request.form.get("config_hash", "")

        # Get current config hash
        current_config = config_status()
        current_hash = current_config.get("hash", "")
        current_requirements = current_config.get("requirements")

        # Check if config changed during user session
        if original_hash and original_hash != current_hash:
            flash(
                "Password requirements have been updated while you were on this page. Please review the new requirements below and try again.",
                "warning")
            return render_template("reset_password.html",
                                   password_requirements=current_requirements,
                                   config_changed=True)

        # Basic validation
        if new != confirm:
            flash("Passwords do not match", "danger")
            return render_template("reset_password.html",
                                   password_requirements=current_requirements or password_requirements)

        # NEW: Validate password against CURRENT configuration
        is_valid, validation_errors = validate_password_client_side(new, current_requirements or password_requirements)
        if not is_valid:
            error_message = f"Password does not meet current requirements: {'; '.join(validation_errors)}"
            flash(error_message, "danger")
            return render_template("reset_password.html",
                                   password_requirements=current_requirements or password_requirements)

        try:
            result = api.reset_password(email, token, new)
            flash("Password reset successful. Please login.", "success")
            return redirect(url_for("login_form"))

        except api.ApiError as e:
            clean_message = clean_error_message(str(e))
            flash(clean_message, "danger")
            return render_template("reset_password.html",
                                   password_requirements=current_requirements or password_requirements)

    # ---------- Customers ----------
    @app.get("/add-customer")
    def add_customer_form():
        if not session.get("username"):
            return redirect(url_for("login_form"))
        return render_template("add_customer.html")

    @app.post("/add-customer")
    def add_customer_submit():
        if not session.get("username"):
            return redirect(url_for("login_form"))

        full_name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # NEW: read plan_id from the form and convert to int or None
        plan_id_raw = request.form.get("plan_id", "").strip()
        plan_id = int(plan_id_raw) if plan_id_raw.isdigit() else None

        try:
            api.create_customer(full_name, email, phone, plan_id)
            flash("Customer added", "success")
            return redirect(url_for("dashboard"))
        except api.ApiError as e:
            flash(str(e), "danger")
            return redirect(url_for("add_customer_form"))

    @app.get("/api/config-status")
    def config_status():
        """Return hash of current password configuration for change detection"""

        try:
            config_path = '/config/password_policy.yaml'
            with open(config_path, 'r', encoding='utf-8') as file:
                content = file.read()

            # Create hash of config content
            config_hash = hashlib.md5(content.encode()).hexdigest()

            # Also return current requirements for immediate update
            password_reqs = get_password_requirements()

            return {
                "hash": config_hash,
                "requirements": password_reqs
            }
        except Exception as e:
            return {"error": str(e)}, 500

    @app.get("/plans")
    def plans():
        if not session.get("username"):
            return redirect(url_for("login_form"))
        plans_list = api.list_plans()
        return render_template("plans.html", plans=plans_list)

        # Single Customer details page - for XSS stored presentation:

    @app.route('/search-customer')
    def search_customer_page():
        if 'username' not in session:
            return redirect(url_for('login_form'))
        return render_template('search_customer.html')

    @app.route('/search-customer-api/<name>', methods=['POST'])
    def search_customer_api(name):
        if 'username' not in session:
            return jsonify({'error': 'Unauthorized'}), 401

        try:
            import requests
            server_url = "http://app:8000"

            token = session.get('access_token') or session.get('token')

            # If no token in session, try to get from request body
            if not token:
                data = request.get_json()
                token = data.get('token') if data else None

            if not token:
                return jsonify({'error': 'No authentication token found'}), 401

            headers = {
                'Content-Type': 'application/json',
                'Authorization': f'Bearer {token}'
            }

            print(f"DEBUG: Making request to {server_url}/api/v1/customers/search/{name}")
            print(f"DEBUG: Token exists: {bool(token)}")
            print(f"DEBUG: Token starts with: {token[:20] if token else 'None'}...")

            response = requests.get(f"{server_url}/api/v1/customers/search-vulnerable/{name}", headers=headers)

            print(f"DEBUG: Response status: {response.status_code}")

            if response.status_code == 200:
                customers = response.json()
                print(f"DEBUG: Found {len(customers)} customers")
                return jsonify(customers)
            else:
                print(f"DEBUG: Error response: {response.text}")
                return jsonify(
                    {'error': f'Server error: {response.status_code}', 'details': response.text}), response.status_code

        except Exception as e:
            print(f"DEBUG: Exception occurred: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.get("/customers/<int:customer_id>")
    def customer_detail(customer_id):
        if not session.get("username"):
            return redirect(url_for("login_form"))
        try:
            # You need an API endpoint to fetch a single customer by ID
            customer = api.get_customer(customer_id)
        except api.ApiError as e:
            flash(str(e), "danger")
            return redirect(url_for("dashboard"))

        return render_template("customer_detail.html", customer=customer)

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=5173, debug=True)

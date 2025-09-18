import re
import yaml
from pathlib import Path
import os
from typing import Tuple, List, Dict, Optional

# Module-level state with sensible defaults to avoid import errors
password_config: Dict = {}
regex: Optional[re.Pattern] = None


def _default_config() -> Dict:
    return {
        "password_requirements": {
            "min_length": 10,
            "uppercase": True,
            "lowercase": True,
            "digits": True,
            "special": True,
            "history_count": 3,
            "max_login_attempts": 3,
            "lockout_duration_minutes": 15,
            "blacklist": [
                "password", "123456", "qwerty", "admin", "letmein",
                "welcome", "monkey", "1234567890", "password123",
                "abc123", "111111", "123123", "admin123", "root",
                "user", "guest", "test", "demo", "sample"
            ],
            "custom_regex": None
        }
    }


def load_password_config() -> Dict:
    config_dir = Path(os.getenv("CONFIG_DIR", "./config"))
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / os.getenv("PASSWORD_POLICY_FILE", "password_policy.yaml")

    defaults = _default_config()
    if not config_path.exists():
        with open(config_path, "w") as f:
            yaml.safe_dump(defaults, f, default_flow_style=False, indent=2)
        return defaults

    try:
        with open(config_path, "r") as f:
            loaded = yaml.safe_load(f) or {}
        if "password_requirements" not in loaded:
            return defaults

        merged = defaults.copy()
        merged["password_requirements"].update(loaded["password_requirements"])
        return merged
    except Exception:
        # Fall back to a safe default if the YAML is malformed
        return defaults


def compose_regex(config: Dict) -> str:
    req = config["password_requirements"]
    if req.get("custom_regex"):
        return req["custom_regex"]

    parts = []
    if req.get("uppercase"):
        parts.append(r"(?=.*[A-Z])")
    if req.get("lowercase"):
        parts.append(r"(?=.*[a-z])")
    if req.get("digits"):
        parts.append(r"(?=.*\d)")
    if req.get("special"):
        parts.append(r"(?=.*[\W_])")

    min_len = req.get("min_length", 8)
    return "".join(parts) + r".{" + str(min_len) + r",}"


def setup_password_validation() -> None:
    """Load password policy from YAML and compile the complexity regex."""
    global password_config, regex
    password_config = load_password_config()
    pattern = compose_regex(password_config)
    regex = re.compile(pattern)


def get_password_config() -> Dict:
    """Return the loaded password configuration, initializing if needed."""
    global password_config, regex
    if not password_config or regex is None:
        setup_password_validation()
    return password_config


def validate_password(password: str) -> bool:
    """Check password against complexity rules and blacklist."""
    if not password:
        return False
    cfg = get_password_config()
    req = cfg["password_requirements"]

    # blacklist
    p_low = password.lower()
    for bad in req.get("blacklist", []):
        if bad.lower() in p_low:
            return False

    # length + complexity
    assert regex is not None
    return bool(regex.match(password))


def get_password_requirements_description() -> str:
    cfg = get_password_config()
    req = cfg["password_requirements"]
    parts: List[str] = [f"At least {req['min_length']} characters long"]
    if req.get("uppercase"):
        parts.append("At least one uppercase letter (A-Z)")
    if req.get("lowercase"):
        parts.append("At least one lowercase letter (a-z)")
    if req.get("digits"):
        parts.append("At least one number (0-9)")
    if req.get("special"):
        parts.append("At least one special character (!@#$%^&*)")
    if req.get("blacklist"):
        parts.append("Must not contain common dictionary words")
    parts.append(f"Cannot reuse your last {req['history_count']} passwords")
    return "Password requirements:\n• " + "\n• ".join(parts)


def validate_password_with_details(password: str) -> Tuple[bool, List[str]]:
    """Return (is_valid, reasons[]) with granular validation messages."""
    if not password:
        return False, ["Password cannot be empty"]
    cfg = get_password_config()
    req = cfg["password_requirements"]
    fails: List[str] = []

    if len(password) < req["min_length"]:
        fails.append(f"Must be at least {req['min_length']} characters long")
    if req.get("uppercase") and not re.search(r"[A-Z]", password):
        fails.append("Must contain at least one uppercase letter")
    if req.get("lowercase") and not re.search(r"[a-z]", password):
        fails.append("Must contain at least one lowercase letter")
    if req.get("digits") and not re.search(r"\d", password):
        fails.append("Must contain at least one number")
    if req.get("special") and not re.search(r"[\W_]", password):
        fails.append("Must contain at least one special character")

    p_low = password.lower()
    for bad in req.get("blacklist", []):
        if bad.lower() in p_low:
            fails.append(f"Must not contain common words like '{bad}'")
            break

    return (len(fails) == 0), fails

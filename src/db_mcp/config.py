"""Access-level configuration (roles.yaml).

Mechanism vs policy split:
  - The gateway owns MECHANISM: parse this file, enforce it fail-closed.
  - The deployer owns POLICY: which roles exist, which tables they touch.
No tool may read or modify this file at runtime; it is loaded once at startup.
A missing or broken file fails CLOSED to the built-in `reader` definition.
"""
import os
from pathlib import Path

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    yaml = None
    _YAML_AVAILABLE = False

# Project-root roles file. Override path (tests) via GATEWAY_ROLES_FILE.
_DEFAULT_ROLES_FILE = (
    Path(__file__).resolve().parent.parent.parent / "roles.yaml"
)

# Built-in fail-closed fallback: least privilege, used when the file is
# missing, unreadable, or invalid. Mirrors roles.yaml `reader`.
_FALLBACK_ROLE = {
    "description": "Built-in fail-closed reader (roles.yaml missing/invalid).",
    "tables_read": ["album", "artist", "genre", "invoice", "invoice_line",
                    "media_type", "playlist", "playlist_track", "track",
                    "customer_masked"],
    "tables_write": [],
    "can_propose": False,
    "can_approve": False,
    "management": False,
}

_config_cache = None
_config_cache_path = None


def _roles_file() -> Path:
    override = os.getenv("GATEWAY_ROLES_FILE")
    return Path(override) if override else _DEFAULT_ROLES_FILE


def _warn(msg: str) -> None:
    try:
        print(f"ACCESS-CONTROL WARNING: {msg}")
    except Exception:
        pass


def load_config(force_reload: bool = False) -> dict:
    """Load and cache {default_role, roles}. Fail-closed to reader on any error."""
    global _config_cache, _config_cache_path
    path = _roles_file()
    if _config_cache is not None and not force_reload and _config_cache_path == str(path):
        return _config_cache

    fallback = {"default_role": "reader", "roles": {"reader": dict(_FALLBACK_ROLE)},
                "_degraded": True}
    if not _YAML_AVAILABLE:
        _warn("pyyaml not installed; running fail-closed as reader.")
        _config_cache, _config_cache_path = fallback, str(path)
        return _config_cache
    try:
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
        roles = data.get("roles") or {}
        default_role = data.get("default_role", "reader")
        if not isinstance(roles, dict) or not roles:
            raise ValueError("no roles defined")
        if default_role not in roles:
            raise ValueError(f"default_role '{default_role}' not in roles")
        normalized = {}
        for name, spec in roles.items():
            if not isinstance(spec, dict):
                raise ValueError(f"role '{name}' is not a mapping")
            normalized[str(name)] = {
                "description": str(spec.get("description", "")),
                "tables_read": [str(t).lower() for t in (spec.get("tables_read") or [])],
                "tables_write": [str(t).lower() for t in (spec.get("tables_write") or [])],
                "can_propose": bool(spec.get("can_propose", False)),
                "can_approve": bool(spec.get("can_approve", False)),
                "management": bool(spec.get("management", False)),
            }
        _config_cache = {"default_role": str(default_role),
                         "roles": normalized, "_degraded": False}
        _config_cache_path = str(path)
        return _config_cache
    except Exception as e:
        _warn(f"{e}; running fail-closed as reader.")
        _config_cache, _config_cache_path = fallback, str(path)
        return _config_cache


def get_active_role() -> str:
    """Role for this deployment: GATEWAY_ROLE env wins, else YAML default_role."""
    cfg = load_config()
    override = (os.getenv("GATEWAY_ROLE") or "").strip().lower()
    if override and override in cfg["roles"]:
        return override
    if override:
        _warn(f"GATEWAY_ROLE '{override}' unknown; using default_role.")
    return cfg["default_role"]


def get_role_spec(role: str) -> dict:
    """Role spec dict; unknown roles resolve to the fail-closed reader spec."""
    cfg = load_config()
    spec = cfg["roles"].get(role)
    if spec is None:
        _warn(f"unknown role '{role}'; enforcing fail-closed reader.")
        return dict(_FALLBACK_ROLE)
    return spec


def is_degraded() -> bool:
    """True when running on the fail-closed fallback (file missing/invalid)."""
    return bool(load_config().get("_degraded", False))

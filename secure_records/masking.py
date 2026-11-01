"""Masking of personal data. Applied in the service layer, before any response is built,
so a route cannot return a raw value by accident."""

from __future__ import annotations

SENSITIVE_FIELDS = ("full_name", "email", "phone", "national_id")


def mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    if not domain:
        return "***"
    host, _, tld = domain.rpartition(".")
    return f"{local[:1]}***@{host[:1]}***.{tld}" if host else f"{local[:1]}***@***"


def mask_phone(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    return "*" * max(0, len(digits) - 4) + digits[-4:] if digits else "***"


def mask_national_id(value: str) -> str:
    compact = "".join(ch for ch in value if ch.isalnum())
    return "XXXX-XXXX-" + compact[-4:] if len(compact) >= 4 else "XXXX"


def mask_name(value: str) -> str:
    return " ".join(part[:1] + "***" for part in value.split()) or "***"


_MASKERS = {
    "full_name": mask_name,
    "email": mask_email,
    "phone": mask_phone,
    "national_id": mask_national_id,
}


def mask_record(data: dict) -> dict:
    return {k: (_MASKERS[k](v) if k in _MASKERS and v is not None else v) for k, v in data.items()}


def record_to_dict(rec, unmasked: bool = False) -> dict:
    data = {
        "id": rec.id,
        "snapshot_id": rec.snapshot_id,
        "external_id": rec.external_id,
        "full_name": rec.full_name,
        "email": rec.email,
        "phone": rec.phone,
        "national_id": rec.national_id,
        "city": rec.city,
        "balance": format(rec.balance, ".2f"),   # exact string, so no float rounding
    }
    return data if unmasked else mask_record(data)

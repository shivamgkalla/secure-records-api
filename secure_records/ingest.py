"""Load an uploaded CSV as a new snapshot, in batches, validating every row."""

from __future__ import annotations

import csv
import io
import re
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from dataclasses import dataclass, field

from sqlalchemy import insert
from sqlalchemy.orm import Session

from .models import Record, Snapshot

REQUIRED = ["external_id", "full_name", "email", "phone", "national_id", "city", "balance"]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_ERRORS_REPORTED = 20


class UploadError(ValueError):
    """The whole file is unusable. The message says why."""


@dataclass
class IngestResult:
    snapshot_id: int
    rows_loaded: int
    rows_rejected: int
    errors: list = field(default_factory=list)


def check_header(fieldnames) -> None:
    if not fieldnames:
        raise UploadError("The file is empty.")
    names = [f.strip() for f in fieldnames]
    missing = [c for c in REQUIRED if c not in names]
    if missing:
        raise UploadError(
            f"This does not look like a records file. Missing column(s): {', '.join(missing)}. "
            f"Expected columns: {', '.join(REQUIRED)}."
        )


MAX_ABS_BALANCE = Decimal("999999999999.99")   # the most a NUMERIC(14,2) column can hold


def parse_amount(text: str) -> Decimal:
    """An exact two-decimal amount, or ValueError. Rejects NaN, infinity and out-of-range values."""
    try:
        value = Decimal(text.replace(",", ""))
    except InvalidOperation:
        raise ValueError("balance is not a number") from None
    if not value.is_finite():
        raise ValueError("balance is not a finite number")
    if abs(value) > MAX_ABS_BALANCE + Decimal("0.005"):     # check before rounding: huge values cannot be rounded
        raise ValueError("balance is too large")
    value = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
    if abs(value) > MAX_ABS_BALANCE:
        raise ValueError("balance is too large")
    return value


def validate_row(row: dict) -> dict:
    clean = {k: (row.get(k) or "").strip() for k in REQUIRED}
    for key in ("external_id", "full_name", "city"):
        if not clean[key]:
            raise ValueError(f"{key} is empty")
    if not EMAIL_RE.match(clean["email"]):
        raise ValueError("email is not a valid address")
    if not sum(ch.isdigit() for ch in clean["phone"]) >= 7:
        raise ValueError("phone has fewer than 7 digits")
    if len(clean["national_id"]) < 4:
        raise ValueError("national_id is too short")
    clean["balance"] = parse_amount(clean["balance"])
    return clean


def load_snapshot(db: Session, raw: bytes, filename: str, user_id: int, batch_size: int = 5000) -> IngestResult:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UploadError("The file is not UTF-8 text.") from exc
    reader = csv.DictReader(io.StringIO(text))
    check_header(reader.fieldnames)

    snapshot = Snapshot(filename=filename[:255], uploaded_by=user_id)
    db.add(snapshot)
    db.flush()

    loaded = rejected = 0
    errors: list = []
    batch: list = []

    def flush_batch():
        if batch:
            db.execute(insert(Record), batch)
            batch.clear()

    for line_no, row in enumerate(reader, start=2):
        try:
            clean = validate_row(row)
        except ValueError as exc:
            rejected += 1
            if len(errors) < MAX_ERRORS_REPORTED:
                errors.append({"line": line_no, "problem": str(exc)})
            continue
        clean["snapshot_id"] = snapshot.id
        batch.append(clean)
        loaded += 1
        if len(batch) >= batch_size:
            flush_batch()
    flush_batch()

    if loaded == 0:
        raise UploadError("No valid rows were found in the file.")
    snapshot.rows_loaded, snapshot.rows_rejected = loaded, rejected
    return IngestResult(snapshot.id, loaded, rejected, errors)

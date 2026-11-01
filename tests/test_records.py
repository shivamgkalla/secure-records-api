import csv
import io

import pytest

from secure_records.masking import mask_email, mask_name, mask_national_id, mask_phone
from secure_records.synthetic import generate_rows
from tests.conftest import csv_bytes


# ------------------------------------------------------------------ masking
def test_masking_functions():
    assert mask_email("priya.rao@example.com") == "p***@e***.com"
    assert mask_phone("9876543210") == "******3210"
    assert mask_phone("+91 98765 43210") == "********3210"   # 12 digits incl. country code
    assert mask_national_id("123456789012") == "XXXX-XXXX-9012"
    assert mask_name("Priya Rao") == "P*** R***"
    assert mask_email("broken") == "***"


@pytest.mark.parametrize("fn", [mask_email, mask_phone, mask_national_id, mask_name])
def test_masking_handles_empty_input(fn):
    assert fn("")          # returns something safe, never raises


def _assert_no_raw_personal_data(text, rows):
    for row in rows:
        for field in ("email", "phone", "national_id", "full_name"):
            assert row[field] not in text, f"raw {field} leaked: {row[field]}"


# ------------------------------------------------------------------ viewing
def test_analyst_never_sees_raw_personal_data(client, analyst_h, loaded):
    r = client.get("/records?limit=200", headers=analyst_h)
    assert r.status_code == 200 and r.json()["total"] == 300 and len(r.json()["items"]) == 200
    _assert_no_raw_personal_data(r.text, loaded["rows"])
    assert r.json()["items"][0]["external_id"] == "C0000001"          # non-sensitive fields are intact


def test_analyst_cannot_request_unmasked_data(client, analyst_h, loaded):
    assert client.get("/records?unmasked=true", headers=analyst_h).status_code == 403
    assert client.get("/records/export?unmasked=true", headers=analyst_h).status_code == 403


def test_admin_unmasked_view_works_and_is_audited(client, admin_h, loaded):
    r = client.get("/records?unmasked=true&q=C0000001", headers=admin_h)
    assert r.json()["items"][0]["email"] == loaded["rows"][0]["email"]
    entries = client.get("/audit?action=unmasked_view", headers=admin_h).json()
    assert len(entries) == 1 and "rows=1" in entries[0]["detail"]


def test_search_and_pagination(client, analyst_h, loaded):
    city = loaded["rows"][0]["city"]
    expected = sum(1 for r in loaded["rows"] if r["city"] == city)
    assert client.get(f"/records?q={city.lower()}&limit=200", headers=analyst_h).json()["total"] == expected
    page1 = client.get("/records?limit=100&offset=0", headers=analyst_h).json()["items"]
    page2 = client.get("/records?limit=100&offset=100", headers=analyst_h).json()["items"]
    assert not {r["id"] for r in page1} & {r["id"] for r in page2}
    assert client.get("/records?limit=1000", headers=analyst_h).status_code == 422     # capped
    assert client.get("/records?offset=-1", headers=analyst_h).status_code == 422


def test_like_wildcards_in_search_are_treated_literally(client, analyst_h, loaded):
    assert client.get("/records?q=%25", headers=analyst_h).json()["total"] == 0      # "%" matches nothing
    assert client.get("/records?q=_", headers=analyst_h).json()["total"] == 0


def test_no_data_yet_gives_404(client, analyst_h):
    assert client.get("/records", headers=analyst_h).status_code == 404
    assert client.get("/records?snapshot_id=99", headers=analyst_h).status_code == 404


# ------------------------------------------------------------------- export
def test_export_streams_masked_csv(client, analyst_h, loaded):
    r = client.get("/records/export", headers=analyst_h)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 300
    _assert_no_raw_personal_data(r.text, loaded["rows"])


def test_export_defends_against_csv_formula_injection(client, admin_h, analyst_h):
    rows = list(generate_rows(5, seed=2))
    rows[0]["city"] = '=HYPERLINK("http://bad.example","click")'
    rows[1]["city"] = "@SUM(1+1)"
    client.post("/snapshots", headers=admin_h, files={"file": ("a.csv", csv_bytes(rows), "text/csv")})
    out = list(csv.DictReader(io.StringIO(client.get("/records/export", headers=analyst_h).text)))
    assert out[0]["city"].startswith("'=") and out[1]["city"].startswith("'@")


def test_export_is_audited(client, admin_h, analyst_h, loaded):
    client.get("/records/export", headers=analyst_h)
    assert [a["action"] for a in client.get("/audit?action=export", headers=admin_h).json()] == ["export"]


# ------------------------------------------------------------------ uploads
def test_only_admins_can_upload(client, analyst_h):
    r = client.post("/snapshots", headers=analyst_h, files={"file": ("a.csv", b"x", "text/csv")})
    assert r.status_code == 403


def test_each_upload_is_a_new_snapshot_and_history_is_kept(client, admin_h, analyst_h, loaded):
    second_rows = list(generate_rows(50, seed=99))
    r = client.post("/snapshots", headers=admin_h, files={"file": ("b.csv", csv_bytes(second_rows), "text/csv")})
    second_id = r.json()["snapshot_id"]
    assert second_id != loaded["snapshot_id"]
    listing = client.get("/snapshots", headers=analyst_h).json()
    assert [s["id"] for s in listing] == [second_id, loaded["snapshot_id"]]           # newest first
    assert client.get("/records", headers=analyst_h).json()["total"] == 50             # default: latest
    old = client.get(f"/records?snapshot_id={loaded['snapshot_id']}", headers=analyst_h).json()
    assert old["total"] == 300                                                          # earlier data untouched


def test_wrong_file_gets_a_helpful_error(client, admin_h):
    r = client.post("/snapshots", headers=admin_h, files={"file": ("x.csv", b"a,b\n1,2\n", "text/csv")})
    assert r.status_code == 422 and "Missing column(s)" in r.json()["detail"]
    assert client.post("/snapshots", headers=admin_h, files={"file": ("x.csv", b"", "text/csv")}).status_code == 422
    assert client.post("/snapshots", headers=admin_h, files={"file": ("x.bin", b"\xff\xfe\x00", "text/csv")}).status_code == 422


def test_bad_rows_are_rejected_individually_and_reported(client, admin_h):
    rows = list(generate_rows(10, seed=3))
    rows[2]["email"] = "not-an-email"
    rows[5]["balance"] = "lots"
    rows[7]["phone"] = "12"
    r = client.post("/snapshots", headers=admin_h, files={"file": ("a.csv", csv_bytes(rows), "text/csv")})
    body = r.json()
    assert r.status_code == 201 and body["rows_loaded"] == 7 and body["rows_rejected"] == 3
    assert [e["line"] for e in body["first_errors"]] == [4, 7, 9]
    assert "email" in body["first_errors"][0]["problem"]


def test_file_with_only_bad_rows_creates_no_snapshot(client, admin_h, analyst_h):
    rows = list(generate_rows(3, seed=3))
    for row in rows:
        row["email"] = "bad"
    r = client.post("/snapshots", headers=admin_h, files={"file": ("a.csv", csv_bytes(rows), "text/csv")})
    assert r.status_code == 422 and client.get("/snapshots", headers=analyst_h).json() == []


def test_large_upload_is_loaded_in_batches(client, admin_h, analyst_h):
    rows = list(generate_rows(12_000, seed=8))
    r = client.post("/snapshots", headers=admin_h, files={"file": ("big.csv", csv_bytes(rows), "text/csv")})
    assert r.json()["rows_loaded"] == 12_000                       # crosses two 5,000-row batches
    assert client.get("/records?limit=1", headers=analyst_h).json()["total"] == 12_000


def test_oversized_upload_is_refused():
    from fastapi.testclient import TestClient

    from tests.conftest import ADMIN, auth, make_app

    small = TestClient(make_app(max_upload_mb=0))
    r = small.post("/snapshots", headers=auth(small, ADMIN), files={"file": ("a.csv", b"abc", "text/csv")})
    assert r.status_code == 413


@pytest.mark.parametrize(
    "value, ok",
    [("1234.50", True), ("1,234.5", True), ("-20", True), ("12.345", True), ("nan", False),
     ("inf", False), ("1e400", False), ("9999999999999", False), ("", False), ("12abc", False)],
)
def test_balance_parsing(value, ok):
    from secure_records.ingest import parse_amount

    if ok:
        assert parse_amount(value).as_tuple().exponent == -2
    else:
        with pytest.raises(ValueError):
            parse_amount(value)


def test_balances_are_stored_and_returned_exactly(client, admin_h, analyst_h):
    rows = list(generate_rows(2, seed=4))
    rows[0]["balance"], rows[1]["balance"] = "0.10", "1234567.89"
    client.post("/snapshots", headers=admin_h, files={"file": ("a.csv", csv_bytes(rows), "text/csv")})
    items = client.get("/records", headers=analyst_h).json()["items"]
    assert [i["balance"] for i in items] == ["0.10", "1234567.89"]

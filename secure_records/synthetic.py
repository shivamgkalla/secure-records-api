"""Synthetic customer records for demos and tests. Every name, address and number is
generated at random; none of it belongs to a real person."""

from __future__ import annotations

import csv
import random

FIRST = ["Aarav", "Diya", "Kabir", "Meera", "Rohan", "Isha", "Vihaan", "Anaya", "Arjun", "Sara",
         "Neel", "Tara", "Dev", "Riya", "Kian", "Zoya", "Om", "Nila", "Ravi", "Leela"]
LAST = ["Rao", "Shah", "Iyer", "Khan", "Das", "Nair", "Patel", "Menon", "Gill", "Bose", "Joshi", "Sen"]
CITIES = ["Jaipur", "Pune", "Kochi", "Indore", "Nagpur", "Surat", "Lucknow", "Mysuru", "Vizag", "Bhopal"]
DOMAINS = ["example.com", "example.org", "example.net"]   # reserved for documentation


def generate_rows(n: int, seed: int = 1):
    rng = random.Random(seed)
    for i in range(n):
        first, last = rng.choice(FIRST), rng.choice(LAST)
        yield {
            "external_id": f"C{i + 1:07d}",
            "full_name": f"{first} {last}",
            "email": f"{first}.{last}{rng.randint(1, 999)}@{rng.choice(DOMAINS)}".lower(),
            "phone": "9" + "".join(str(rng.randint(0, 9)) for _ in range(9)),
            "national_id": "".join(str(rng.randint(0, 9)) for _ in range(12)),
            "city": rng.choice(CITIES),
            "balance": round(rng.uniform(-500, 90000), 2),
        }


def write_csv(path: str, n: int, seed: int = 1) -> None:
    rows = list(generate_rows(n, seed))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    import sys

    out = sys.argv[1] if len(sys.argv) > 1 else "sample_records.csv"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1000
    write_csv(out, count)
    print(f"Wrote {count} synthetic records to {out}")

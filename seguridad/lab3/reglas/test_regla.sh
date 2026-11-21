#!/usr/bin/env bash
# Prueba de la regla del Lab 3: el fixture vulnerable se marca, el seguro no.
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
RULE="$DIR/sql-por-concatenacion.yml"

semgrep --config "$RULE" --json --metrics=off "$DIR/fixtures/vulnerable.py" > "$DIR/fixtures/vulnerable.json" || true
semgrep --config "$RULE" --json --metrics=off "$DIR/fixtures/seguro.py" > "$DIR/fixtures/seguro.json" || true

python3 - "$DIR" <<'PY'
import json
import pathlib
import sys

base = pathlib.Path(sys.argv[1]) / "fixtures"
vuln = json.loads((base / "vulnerable.json").read_text())
safe = json.loads((base / "seguro.json").read_text())

ids = [r["check_id"].split(".")[-1] for r in vuln.get("results", [])]
print("fixture vulnerable:", [r["check_id"] for r in vuln.get("results", [])] or "SIN HALLAZGOS")
print("fixture seguro:    ", [r["check_id"] for r in safe.get("results", [])] or "sin hallazgos")

assert "sql-por-concatenacion" in ids, "La regla NO marcó el fixture vulnerable"
assert not safe.get("results"), "La regla marcó el fixture seguro (falso positivo)"
print("✅ Regla verificada: falla el vulnerable, pasa el seguro.")
PY

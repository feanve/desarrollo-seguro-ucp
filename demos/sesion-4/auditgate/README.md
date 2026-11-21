# Demo del gate · Auditgate (Sesión 4)

Un objetivo de práctica para ver el **gate determinista** bloquear un hallazgo **nuevo**
y liberarlo al corregirlo. Es la base del **Laboratorio 3** (`labs/LAB3.md`): aquí lo
practican sobre un archivo de ejemplo; en el Lab 3 lo hacen sobre el repo de su equipo.

| Archivo | Qué es |
|---|---|
| `buscar-vulnerable.py` | Endpoint Flask con **SQLi** por interpolación de string → el gate **bloquea** |
| `buscar-seguro.py` | La misma función con **consulta parametrizada** → el gate **pasa** |

La diferencia, la única línea que importa:

```python
# ❌ la entrada entra al SQL
con.execute(f"SELECT nombre FROM productos WHERE nombre = '{q}'")
# ✅ la entrada viaja como parámetro
con.execute("SELECT nombre FROM productos WHERE nombre = ?", (q,))
```

## Montaje (una vez)

```bash
git clone https://github.com/Jawy77/auditgate.git
cd auditgate
pip3 install --break-system-packages --ignore-installed semgrep   # en Kali/Debian
# brew install gitleaks osv-scanner   # opcional: los otros controles
```

## El gate bloquea lo NUEVO

```bash
git checkout -b demo-busqueda
cp .../buscar-vulnerable.py buscar.py
git add buscar.py && git commit -m "feat: busqueda"

PYTHONPATH=src python3 -m auditgate scan
#   ✖ sast  semgrep  1 nuevo(s) — BLOQUEA   (auditgate.flask.sqli-string-built-query)
#   🚫 Bloqueado · exit 1
```

> Si la descarga de reglas de semgrep se traba, agrega `--no-registry`.

## Y lo libera al corregir

```bash
cp .../buscar-seguro.py buscar.py
git commit -aqm "fix: consulta parametrizada"

PYTHONPATH=src python3 -m auditgate scan
#   ✔ sast  0 nuevos · exit 0
```

**La idea:** el gate solo responsabiliza por lo que agregas en tu diff contra la rama base.
La deuda vieja no bloquea; el patrón que introduces, sí. El mismo comando corre en CI.

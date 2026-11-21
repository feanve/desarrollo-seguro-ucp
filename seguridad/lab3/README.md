# Laboratorio 3 · Verificación de Auditgate

**Repo:** `feanve/desarrollo-seguro-ucp` · **Rama:** `lab3/gate-verificacion` · **Base:** `origin/main` (`cf94312`)

## 1. Gate instalado

```bash
auditgate init --provider none --yes
auditgate doctor
```

Workflow: `.github/workflows/auditgate.yml` (commit `1483edd`), fijado por SHA a Auditgate `07faee3`.

## 2. PR que bloquea y se corrige

| Paso | Commit | Comando | Resultado |
|---|---|---|---|
| Fallo introducido | `demo(lab3): introduce SQLi por concatenacion en el buscador` | `auditgate scan --base origin/main --checks secrets,sast,actions --json` | `gate: blocked`, exit 1 — 2 hallazgos nuevos en `seguridad/lab3/poc/buscar.py:15` |
| Corrección | `fix(lab3): parametriza la consulta del buscador` | el mismo comando | `gate: passed`, exit 0 — 0 hallazgos nuevos |

Hallazgos del estado bloqueado:

- `auditgate.flask.sqli-string-built-query`
- `python.flask.security.injection.tainted-sql-string.tainted-sql-string`

Evidencia: `gate-bloqueado.json` y `gate-final.json`.

> Nota: el check `deps` se omite en la VM porque `api.osv.dev` no responde aquí. En GitHub Actions sí corre. `secrets` y `actions` pasaron en ambos estados.

## 3. Regla codificada con prueba

- Regla: `reglas/sql-por-concatenacion.yml` → `lab3.sql-por-concatenacion`.
- Fixture vulnerable: `reglas/fixtures/vulnerable.py` → **marcado**.
- Fixture seguro: `reglas/fixtures/seguro.py` → **no marcado**.
- Prueba: `bash seguridad/lab3/reglas/test_regla.sh` → `✅ Regla verificada: falla el vulnerable, pasa el seguro.` (exit 0).

La regla reconoce el **patrón** (`$CUR.execute($SQL % $ARGS)` y `.format(...)`), no la línea concreta del PoC. Los fixtures están excluidos del SAST del gate mediante `.semgrepignore`.

## 4. Trazabilidad

| Elemento | Valor |
|---|---|
| Amenaza del Lab 1 | Inyección SQL en el buscador de usuarios |
| Requisito ASVS 5.0 | V1.14 — consultas parametrizadas en todo acceso a datos |
| Hallazgo del gate | `auditgate.flask.sqli-string-built-query` en `poc/buscar.py:15` |
| Control | Consulta parametrizada (`?` + tupla) |
| Prueba | `test_regla.sh` + `gate-bloqueado.json` / `gate-final.json` |

## 5. Reflexión

1. El gate bloqueó una consulta SQL concatenada en `poc/buscar.py:15` que a simple vista parecía una consulta normal; una revisión rápida la habría dejado pasar.
2. No se configuró agente de triage (`--provider none`), así que la clasificación fue determinista: verdadeiro positivo confirmado por dos reglas independientes y por la regla propia del laboratorio.
3. Los hallazgos viejos de `app-src/` no bloquearon porque no son nuevos respecto a la base; está bien: la deuda se paga con PRs pequeños, no apagando el gate.

## Entrega

- PR: `lab3/gate-verificacion` → `main` en `feanve/desarrollo-seguro-ucp`.
- Regla y prueba: `seguridad/lab3/reglas/`.
- Este archivo con la reflexión y los JSON de evidencia.

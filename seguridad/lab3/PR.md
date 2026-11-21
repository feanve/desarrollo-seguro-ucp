Requisito ASVS: V1.14 — Usar consultas parametrizadas en todo acceso a datos.

Amenaza del Lab 1 mitigada: Inyección SQL en el buscador de usuarios.

Hallazgo del gate: `auditgate.flask.sqli-string-built-query` (y `python.flask.security.injection.tainted-sql-string.tainted-sql-string`) en `seguridad/lab3/poc/buscar.py:15`.

Cómo ejecutar la prueba: `bash seguridad/lab3/reglas/test_regla.sh`

Evidencia: `seguridad/lab3/gate-final.json`, `seguridad/lab3/gate-bloqueado.json`, `seguridad/lab3/gate-limpio.json`, `seguridad/lab3/gate-deuda.json`, `seguridad/lab3/TRIAGE.md` y `seguridad/lab3/checks-bloqueado.txt`.

Detalle del gate:

- `8d58f8a` introdujo la SQLi y el gate bloqueó con 2 hallazgos nuevos (`gate: blocked`, exit 1).
- `ac1ef54` parametrizó la consulta; `7d92220` y el HEAD actual pasan con 0 hallazgos nuevos (`gate: passed`, exit 0).
- La deuda previa de `app-src/` se reporta en `gate-deuda.json` pero no bloquea los PRs (`gate-limpio.json`).

Ejecución en GitHub Actions: corrida roja `44852994260`, corrida verde `44853183288` y corrida sobre el HEAD del PR `44856453891`. `main` requiere los checks `🚦 Security Gate`, `🔍 SAST`, `🔑 Secrets`, `📦 Dependencies` y `🧬 Rules + Tests + Pipeline integrity`.

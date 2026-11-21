# Triaje · Laboratorio 3

Fuente: `gate-bloqueado.json` (HEAD `8d58f8a`, base `origin/main` `cf94312`). Ambos hallazgos son nuevos y bloqueantes; la corrección está en `ac1ef54` y el pase en `gate-final.json`.

## Hallazgos nuevos

| Regla | Archivo:línea | Clasificación | Por qué | ASVS 5.0 |
|---|---|---|---|---|
| `auditgate.flask.sqli-string-built-query` | `seguridad/lab3/poc/buscar.py:15` | **Verdadero positivo** | La consulta se construye por interpolación de strings y se ejecuta con `db.execute()`. El valor `nombre` viene de `request.args` y viaja dentro del SQL. Introducido a propósito en `8d58f8a` para la demo. | **V1.14** — usar consultas parametrizadas en todo acceso a datos |
| `python.flask.security.injection.tainted-sql-string.tainted-sql-string` | `seguridad/lab3/poc/buscar.py:15` | **Verdadero positivo** | Regla independiente confirma que la entrada del cliente (`request.args.get`) llega a la consulta sin parametrizar. Dos motores distintos coinciden en la misma línea, así que no es falso positivo. | **V1.14** — usar consultas parametrizadas en todo acceso a datos |

**Control aplicado:** `db.execute("SELECT * FROM users WHERE name = ?", (nombre,)).fetchall()` en `ac1ef54`. El valor viaja como parámetro, no como texto SQL.

**Prueba:** `bash seguridad/lab3/reglas/test_regla.sh` — la regla propia marca el fixture vulnerable y no marca el seguro; reproduciendo el patrón del PoC.

## Deuda previa (reportada, no bloqueante)

Del barrido de referencia `gate-deuda.json` (HEAD = base = `cf94312`, 14 hallazgos). Son ejemplos representativos; el triaje completo de esos componentes corresponde al LAB2:

| Regla | Archivo:línea | Clasificación | Por qué no bloquea este PR | ASVS 5.0 |
|---|---|---|---|---|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `app-src/routes/search.ts:23` | Verdadero positivo (deuda) | Ya estaba en `main` antes de la rama; no es introducido por el PR | V1.14 |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | `app-src/routes/userProfile.ts:65` | Verdadero positivo (deuda) | Ídem | V1.14 |
| `auditgate.python.hardcoded-credential` | `demos/sesion-1/03-api/app_insegura.py:15` | Verdadero positivo (demo docente) | Ídem; código de demostración, no del producto | V2 — secretos y credenciales |
| `auditgate.flask.debug-enabled` | `demos/sesion-1/03-api/app_insegura.py:80` | Verdadero positivo (demo docente) | Ídem | V7 — configuración segura |

Esta deuda se paga con PRs pequeños de remediación; no desactivando los checks ni quitando la protección de `main`.

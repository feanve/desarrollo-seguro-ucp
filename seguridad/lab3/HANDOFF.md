# Handoff · Laboratorio 3 (Sesión 4)

**Repo:** `feanve/desarrollo-seguro-ucp` (fork) · **Upstream:** `Hackwy402/desarrollo-seguro-ucp`
**Rama de trabajo:** `lab3/pr-bloqueo-verde` · **Base:** `origin/main` = `cf94312`
**PR:** https://github.com/feanve/desarrollo-seguro-ucp/pull/3 · **Evidencia en el PR:** https://github.com/feanve/desarrollo-seguro-ucp/pull/3#issuecomment-7063603006

## 1. Objetivo del laboratorio

Responder: **¿cómo evito que una falla nueva llegue a `main` sin frenar al equipo por la deuda que ya existe?**

Tres evidencias que se complementan:

| Fuente | Demuestra | No demuestra |
|---|---|---|
| Gate determinista (Auditgate) | Lo nuevo se bloquea; la deuda previa se reporta | Que el artefacto publicado sea el escaneado |
| SBOM CycloneDX (Trivy) | Qué componentes lleva el artefacto y si tienen CVE | Cómo entró ni quién lo firmó |
| Firma + provenance (cosign / SLSA) | Que el artefacto viene de este pipeline | Que el código sea seguro |

Además: corregir un hallazgo con una prueba que falla antes y pasa después, y abrir un PR con ASVS + amenaza del Lab 1. Entrega: comentar en el issue del equipo el enlace a `seguridad/lab3/` y al PR.

## 2. Estado actual

- Auditgate `0.2.0` instalado y funcionando (`auditgate doctor` → todo en orden). Provider `none`: gate determinista, sin agente con llave.
- Workflow `.github/workflows/auditgate.yml` instalado en `1483edd`, fijado por SHA a `07faee3bc9092019a8543b6168f72f3b963afcb6`.
- `main` del fork tiene branch protection: required checks `🚦 Security Gate`, `🔍 SAST`, `🔑 Secrets`, `📦 Dependencies`, `🧬 Rules + Tests + Pipeline integrity`; `strict: true`, `enforce_admins: true`, sin force pushes ni borrado. No hay rulesets. Upstream no está protegido y no hay permisos de admin allí.
- PR #3 abierto, `mergeStateStatus: CLEAN`, todos los checks en `success` (run final `44910483605`). Título y cuerpo actualizados desde `seguridad/lab3/PR.md`.
- **Las capturas de terminal las tomó el estudiante**, no el asistente. El asistente ejecutó comandos en su propio entorno; esa salida no constituye evidencia del estudiante.

## 3. Pasos realizados (cronología)

1. `cf94312` — base `main`: se agrega el laboratorio (`labs/LAB3.md`).
2. `1483edd` — `ci: instala Auditgate` (workflow fijado por SHA).
3. `8d58f8a` — `demo(lab3): introduce SQLi por concatenacion en el buscador`. Hallazgo nuevo en `seguridad/lab3/poc/buscar.py:15`.
   - CI: `auditgate / 🚦 Security Gate` = failure, `🔍 SAST` = failure (run `44852994260`).
   - `auditgate scan --base origin/main --checks secrets,sast,actions --json` → `gate: blocked`, exit 1, 2 hallazgos.
4. `2acd3ab` — se guarda la evidencia del gate en rojo (`checks-bloqueado.txt`).
5. `ac1ef54` — `fix(lab3): parametriza la consulta del buscador`: `db.execute("... WHERE name = ?", (nombre,))`.
6. `7d92220` — regla propia `lab3.sql-por-concatenacion`, fixtures vulnerable/seguro, `test_regla.sh` y evidencia.
7. `80a3f6f` — `docs(lab3): regenera evidencias del gate contra esta rama`:
   - `gate-deuda.json`, `gate-limpio.json`, `gate-bloqueado.json`, `gate-final.json`, `TRIAGE.md` y `README.md` reescrito con SHAs reales.
   - Se detectó que los JSON anteriores apuntaban a otra rama (`249edc4` / `ba9e479`), por eso se regeneraron.
8. `ffc858f` — `docs(lab3): agrega descripcion del PR con ASVS y amenaza` (`PR.md`).
9. PR #3 creado/actualizado:
   - `gh pr edit` falló por el warning de *Projects classic* en GraphQL; se usó `gh api --method PATCH repos/feanve/desarrollo-seguro-ucp/pulls/3 --input /tmp/pr-patch.json`.
   - Se publicó el comentario de evidencia con `auditgate doctor`, `auditgate scan` (head `ffc858f`, `passed`, 0 hallazgos) y `test_regla.sh`.
10. El estudiante tomó sus propias capturas de terminal.

## 4. Resultados del gate

| Estado | HEAD | Base | Gate | Hallazgos nuevos | Evidencia |
|---|---|---|---|---|---|
| Deuda previa (barrido, no es PR) | `cf94312` | `origin/main` | `blocked` | 14 antiguos | `gate-deuda.json` |
| PR limpio (solo docs) | `cf94312` | `1483edd` (padre) | `passed` | 0 | `gate-limpio.json` |
| PR con falla nueva | `8d58f8a` | `cf94312` | `blocked` | 2 | `gate-bloqueado.json` |
| PR corregido | `7d92220` | `cf94312` | `passed` | 0 | `gate-final.json` |
| HEAD del PR | `ffc858f` | `origin/main` | `passed` | 0 | comentario del PR |

Hallazgos bloqueantes: `auditgate.flask.sqli-string-built-query` y `python.flask.security.injection.tainted-sql-string.tainted-sql-string`, ambos en `seguridad/lab3/poc/buscar.py:15`. Clasificados como verdaderos positivos con ASVS 5.0 V1.14 en `TRIAGE.md`.

> Nota: se usó `1483edd` como base del “PR limpio” porque la rama no tenía ningún commit limpio previo a la SQLi. Así se demuestra que la deuda de `app-src/`/`demos/` se reporta pero no bloquea.

## 5. Evidencia ya disponible en `seguridad/lab3/`

- `README.md` — índice, trazabilidad, reflexión y política de bloqueo.
- `TRIAGE.md` — 2 hallazgos nuevos + ejemplos de deuda previa.
- `PR.md` — cuerpo del PR (ASVS V1.14, amenaza, regla, prueba, evidencia).
- `checks-bloqueado.txt` — checks de la corrida roja.
- `gate-deuda.json`, `gate-limpio.json`, `gate-bloqueado.json`, `gate-final.json`.
- `poc/buscar.py` — PoC corregida.
- `reglas/sql-por-concatenacion.yml`, `reglas/test_regla.sh`, `reglas/fixtures/{vulnerable,seguro}.py`.
- `.semgrepignore` excluye los fixtures del SAST del gate; `.gitignore` ignora `seguridad/lab3/reglas/fixtures/*.json` y `*.key`.

## 6. Pendiente

1. **Capturas:** guardarlas en `seguridad/lab3/capturas/` y referenciarlas desde `README.md`.
2. **SBOM (§2):**
   ```bash
   trivy fs --quiet --format cyclonedx --output seguridad/lab3/sbom.cdx.json .
   trivy sbom seguridad/lab3/sbom.cdx.json --scanners vuln --severity CRITICAL \
     --format json --output seguridad/lab3/trivy-sbom.json || true
   ```
   Redactar `SBOM.md` respondiendo: nº de componentes y transitivos; `log4j-core`, versión y CVE Critical; si entró por transitividad; qué cambia al corregir.
3. **Firma (§3):**
   ```bash
   cd seguridad/lab3
   cosign generate-key-pair
   docker build -t devseguro-ucp/lab3:demo ../../demos/sesion-1/03-api
   cosign sign --key cosign.key devseguro-ucp/lab3:demo
   cosign verify --key cosign.pub devseguro-ucp/lab3:demo > firma-verificada.json
   cd ../..
   printf 'seguridad/lab3/cosign.key\n' >> .gitignore
   git check-ignore -v seguridad/lab3/cosign.key
   ```
   Redactar `FIRMA.md` con la tabla local vs keyless. **Nunca subir `cosign.key`.**
4. **Reflexión (§5):** `REFLEXION.md` con tres párrafos: deuda vs nuevo; qué dio SBOM/firma; cómo pagar deuda sin apagar el gate.
5. **Cierre:** actualizar el índice de `README.md`, `git add/commit/push` desde la terminal del estudiante, verificar que los checks del PR #3 vuelvan a pasar y comentar el enlace en el issue del equipo (issue #4, “Equipo: Valencia Velez”).
6. **Aparte:** el PR #8 en upstream (`contrib/lab3-apendice`, SBOM/firma opcional) es otro trabajo, no parte de esta entrega.

## 7. Comandos de verificación (seguros, solo lectura)

```bash
cd "$HOME/Documentos/desarrollo-seguro-ucp"
auditgate doctor
auditgate scan --base origin/main --checks secrets,sast,actions --json > /tmp/gate.json
echo "exit=$?"
python3 -c "import json;d=json.load(open('/tmp/gate.json'));print(d['gate'], d['head'][:8], d['summary']['blocking_findings'])"
bash seguridad/lab3/reglas/test_regla.sh
gh pr checks 3 --repo feanve/desarrollo-seguro-ucp
gh pr view 3 --repo feanve/desarrollo-seguro-ucp \
  --json number,url,title,state,mergeStateStatus,statusCheckRollup
```

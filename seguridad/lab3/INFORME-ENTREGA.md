# Informe Final · Laboratorio 3 · Pipeline DevSecOps

**Institución:** Universidad Católica de Pereira  
**Programa:** Especialización en Desarrollo de Software · Cohorte 2026-2  
**Materia:** Optativa I: Desarrollo Seguro (Sesión 4)  
**Docente:** Ing. Jawy Andrés Romero  
**Equipo:** Valencia Vélez  
**Integrantes:** Felipe Andrés Vélez & Andrés Valencia  
**Repositorio:** [`feanve/desarrollo-seguro-ucp`](https://github.com/feanve/desarrollo-seguro-ucp)  
**Pull Request:** [#3](https://github.com/feanve/desarrollo-seguro-ucp/pull/3)  
**Rama de trabajo:** `lab3/pr-bloqueo-verde` · **Rama base:** `origin/main` (`cf94312`)  
**Fecha de entrega:** 21 de noviembre de 2026  

---

> **Pregunta central:** *¿Cómo evito que una falla nueva llegue a `main` sin frenar al equipo por la deuda que ya existe?*  
> **Respuesta técnica:** Implementando un **Security Gate determinista (Auditgate)** con análisis diferencial (`merge-base`) que bloquea únicamente los hallazgos nuevos del PR; complementado con **SBOM CycloneDX (Trivy)** para auditar componentes transitivos y **Firma digital (Cosign)** para garantizar la procedencia del artefacto publicado.

---

## 1. El Arco Completo: Trazabilidad Lab 1 → Lab 2 → Lab 3

| Etapa | Artefacto / Fuente | Elemento Concreto Implementado |
|---|---|---|
| **Lab 1 · Amenaza** | Modelo Threat Dragon / STRIDE | **Inyección SQL en el buscador de usuarios:** Entrada no sanitizada en parámetros de búsqueda HTTP. |
| **Lab 2 · Verificación** | OWASP ASVS 5.0 (V1.14) | **Consultas parametrizadas:** Verificación estricta de que todo acceso a base de datos viaje como parámetro, no como texto SQL. |
| **Lab 3 · Gate** | Pipeline DevSecOps (Auditgate) | **Bloqueo determinista:** Detección de `auditgate.flask.sqli-string-built-query` y regla propia `lab3.sql-por-concatenacion`. |
| **Producción** | Branch Protection (GitHub) | **Impedimento de merge:** `main` requiere que `🚦 Security Gate` y `🔍 SAST` estén en verde para permitir la integración. |

---

## 2. Gate Determinista y Triaje (Rúbrica: 25% + 30%)

### 2.1 Diagnóstico de Ambiente (`auditgate doctor`)
Se instaló Auditgate `0.2.0` con workflow fijado por SHA (`1483edd`) y proveedor `none` (gate determinista sin agentes de IA para el bloqueo).

* **Evidencia:** [`capturas/01-auditgate-doctor.png`](capturas/01-auditgate-doctor.png)

### 2.2 Matriz de Estados del Gate
Validada mediante `auditgate scan --base origin/main --checks secrets,sast,actions --json`:

| Estado | HEAD | Base | Resultado | Hallazgos Nuevos | Evidencia |
|---|---|---|---|---|---|
| **Deuda previa** | `cf94312` | `origin/main` | `blocked` | 14 antiguos (deuda) | `gate-deuda.json` |
| **PR limpio** | `cf94312` | `1483edd` | `passed` | 0 hallazgos nuevos | `gate-limpio.json` |
| **PR con falla** | `8d58f8a` | `origin/main` | `blocked` | 2 bloqueantes (SQLi) | `gate-bloqueado.json`, `checks-bloqueado.txt` |
| **PR corregido** | `7d92220` | `origin/main` | `passed` | 0 hallazgos nuevos | `gate-final.json` |

* **Evidencias:** [`capturas/02-auditgate-scan-passed.png`](capturas/02-auditgate-scan-passed.png) y [`capturas/04-gh-pr-checks-passed.png`](capturas/04-gh-pr-checks-passed.png).

### 2.3 Triaje Técnico (ASVS V1.14)
* **Hallazgos bloqueantes en `buscar.py:15`:** Clasificados como **Verdaderos Positivos** por dos analizadores independientes (`auditgate.flask.sqli-string-built-query` y `python.flask.security.injection.tainted-sql-string`).
* **Control implementado:** Parametrización con tupla `db.execute("SELECT * FROM users WHERE name = ?", (nombre,))` en `ac1ef54`.
* **Deuda previa:** 14 hallazgos en `app-src/` y `demos/` reportados pero no bloqueantes para el PR.

---

## 3. Codify: Regla Propia con Fixtures y Prueba (Rúbrica: 30%)

* **Regla personalizada:** [`reglas/sql-por-concatenacion.yml`](reglas/sql-por-concatenacion.yml) (ID: `lab3.sql-por-concatenacion`).
* **Fixtures:** `fixtures/vulnerable.py` (marcado) y `fixtures/seguro.py` (no marcado).
* **Prueba automatizada:** [`reglas/test_regla.sh`](reglas/test_regla.sh) &rarr; `✅ Regla verificada: falla el vulnerable, pasa el seguro`.
* **Evidencia:** [`capturas/03-prueba-regla-fixtures.png`](capturas/03-prueba-regla-fixtures.png).

---

## 4. Cadena de Suministro: SBOM CycloneDX (Trivy)

* **Inventario:** 18 componentes en estándar CycloneDX 1.5 JSON ([`sbom.cdx.json`](sbom.cdx.json)).
* **Log4Shell:** Detección de `org.apache.logging.log4j:log4j-core:2.14.1` con `CVE-2021-44228` (CVSS 10.0) y `CVE-2021-45046` en [`trivy-sbom.json`](trivy-sbom.json).
* **Transitividad:** `log4j-core` estaba declarado en `build.gradle`, pero `log4j-api:2.14.1` entró de forma transitiva.
* **Remediación:** Al actualizar a `2.17.1` en lockfile y build.gradle, los CVEs críticos desaparecen.

---

## 5. Firma y Provenance de Artefactos (Cosign)

* **Gestión de llaves:** Par de llaves generado; `cosign.key` protegida e ignorada en `.gitignore:4:*.key`; `cosign.pub` publicada como evidencia.
* **Verificación:** Firma validada del contenedor `devseguro-ucp/lab3:demo` en [`firma-verificada.json`](firma-verificada.json).
* **Comparativa:** Local (`cosign.key` en disco) vs. CI Keyless (OIDC de GitHub Actions sin secretos de larga duración + Rekor).

---

## 6. Reflexión y Estrategia Ratchet (Rúbrica: 15%)

1. **Deuda vs. Nuevo:** Se diferencian mediante el cálculo diferencial del `merge-base`. El gate solo bloquea el diff introducido por el PR.
2. **SAST vs. SBOM vs. Firma:** SAST inspecciona código propio; SBOM inventaría dependencias directas y transitivas con sus CVEs; la Firma garantiza autenticidad y procedencia del binario publicado.
3. **Estrategia Ratchet:** La deuda antigua jamás se paga apagando el gate. Se gestiona mediante trinquete (la deuda solo puede bajar): PRs pequeños de remediación, alertas automáticas de Dependabot/Renovate y triaje en `TRIAGE.md`.

---

## 7. Índice de Archivos Entregables

* `README.md` · Índice maestro con capturas incrustadas.
* `INFORME-ENTREGA.pdf` · Documento PDF compilado listo para entregar.
* `PR.md` · Descripción del PR #3.
* `TRIAGE.md` · Clasificación y triaje ASVS.
* `REFLEXION.md` · Respuestas a las tres preguntas metodológicas.
* `gate-*.json` · Evidencias de los cuatro estados del Gate.
* `checks-bloqueado.txt` · Log de checks de GitHub Actions.
* `reglas/` · Regla Semgrep, fixtures y script de prueba.
* `sbom.cdx.json` y `trivy-sbom.json` · Inventario y escaneo Trivy.
* `SBOM.md` · Análisis del SBOM.
* `FIRMA.md`, `cosign.pub` y `firma-verificada.json` · Firma y verificación Cosign.
* `capturas/*.png` · Las 4 capturas oficiales del estudiante.

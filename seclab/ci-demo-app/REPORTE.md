# Informe de seguridad — Lab Log4Shell

| | |
|---|---|
| **Alumno** | Felipe A Velez (@feanve) |
| **Fecha** | 2026-11-27 23:11 |
| **Repositorio** | feanve/desarrollo-seguro-ucp |
| **Rama** | `lab/feanve-log4shell` |
| **Herramientas** | gitleaks · semgrep · osv-scanner · trivy + IA (`openai-fast`) |

## 1. Vulnerabilidad descubierta

El escaneo de dependencias (SCA) detectó **Log4Shell — CVE-2021-44228** en
`org.apache.logging.log4j:log4j-core@2.14.1`: ejecución remota de código (RCE)
crítica cuando la aplicación registra texto controlado por el atacante.

**Hallazgos del gate (antes del parche):** 18 — veredicto **🚫 BLOQUEADO** (exit 1)

| Herramienta | Severidad | Regla / CVE | Ubicacion |
|---|---|---|---|
| deps | HIGH | GHSA-qv9r-c865-cp47 | org.apache.logging.log4j:log4j-api@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-3pxv-7cmr-fjr4 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-6hg6-v5c8-fphq | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-7rjr-3q55-vv33 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-8489-44mv-ggj8 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-h383-gmxw-35v2 | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-jfh8-c2jp-5v3q | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-p6xc-xr62-6r2g | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| deps | HIGH | GHSA-vc5p-v9hr-52mj | org.apache.logging.log4j:log4j-core@2.14.1 (pom.xml) |
| trivy | MEDIUM | CVE-2026-49844 | org.apache.logging.log4j:log4j-api@2.14.1 |
| trivy | CRITICAL | CVE-2021-44228 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | CRITICAL | CVE-2021-45046 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | HIGH | CVE-2021-45105 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2021-44832 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2025-68161 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2026-34477 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2026-34479 | org.apache.logging.log4j:log4j-core@2.14.1 |
| trivy | MEDIUM | CVE-2026-34480 | org.apache.logging.log4j:log4j-core@2.14.1 |

## 2. Análisis con IA

### 🤖 Explicacion y remediacion (IA)

- **Riesgo principal:** Log4j 2.14.1 está obsoleto y acumula vulnerabilidades, incluida ejecución remota de código (RCE).

- **CVE-2021-44228 — Log4Shell (RCE):** permite ejecutar código remotamente en determinadas condiciones al procesar mensajes manipulados. **CVE-2021-45046, CVE-2021-45105 y CVE-2021-44832** son vulnerabilidades adicionales de Log4j 2; también requieren actualizar.
- **CVE-2025-68161, CVE-2026-34477, CVE-2026-34479, CVE-2026-34480 y CVE-2026-49844:** el escáner las reporta en `log4j-core`/`log4j-api`; son hallazgos posteriores a los CVE de 2021, por lo que 2.17.1 no basta.
- **GHSA-qv9r-c865-cp47, GHSA-3pxv-7cmr-fjr4, GHSA-6hg6-v5c8-fphq, GHSA-7rjr-3q55-vv33, GHSA-8489-44mv-ggj8, GHSA-h383-gmxw-35v2, GHSA-jfh8-c2jp-5v3q, GHSA-p6xc-xr62-6r2g y GHSA-vc5p-v9hr-52mj:** avisos de seguridad asociados a las versiones de Log4j detectadas; refuerzan la necesidad de actualizar.

- **Arreglo concreto:** sube `log4j-api` y `log4j-core` a la **última versión estable 2.x, al menos 2.26.1**, manteniendo ambos módulos en la misma versión en `pom.xml`, y vuelve a ejecutar el escaneo. **2.17.1 corrige los CVE de 2021, pero no los hallazgos posteriores.**

## 3. Remediación aplicada

Se actualizó `log4j-api` y `log4j-core` a **2.26.1** en `pom.xml`.

> **Lección:** 2.17.1 corrige los CVE de 2021, pero el escaneo aún marcaba CVEs
> de 2025/2026 en log4j; por eso no basta y se sube a la última 2.x estable (2.26.1).

**Hallazgos del gate (después del parche):** 0 — veredicto **✅ PASA** (exit 0)

_Sin hallazgos._

## 4. Evidencia

- Pull Request y corridas del gate (rojo → verde) en GitHub Actions del repo feanve/desarrollo-seguro-ucp.
- Este informe: `seclab/ci-demo-app/REPORTE.md` (en el repo) + subido a **Moodle**.

## Conclusión

El pipeline **bloqueó el merge** hasta corregir la dependencia; la **IA** explicó el
riesgo y la remediación. El gate se re-evalúa contra bases de vulnerabilidades
actualizadas, por eso un fix "histórico" (2.17.1) puede no bastar hoy.

---
_Generado con `seclab/bin/informe.sh` el 2026-11-27 23:11._

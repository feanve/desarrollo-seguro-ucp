# Análisis de SBOM · Laboratorio 3

**Herramienta:** Trivy `0.76.2`  
**Estándar:** CycloneDX 1.5 JSON  
**Artefactos analizados:** Repositorio completo (Python y Java) con foco en `demos/sesion-4/log4shell/proyecto-java`

---

## 1. Inventario y Dependencias Transitivas

El escaneo de inventario realizado con:

```bash
trivy fs --quiet --format cyclonedx --output seguridad/lab3/sbom.cdx.json .
```

Generó un inventario total de **18 componentes** en el archivo [`sbom.cdx.json`](file:///home/andru/Documentos/desarrollo-seguro-ucp/seguridad/lab3/sbom.cdx.json).

### Desglose en el proyecto Java (`demos/sesion-4/log4shell/proyecto-java`):

* **Dependencias Directas** (declaradas en `build.gradle`):
  * `org.apache.logging.log4j:log4j-core` (`2.14.1`)
  * `com.fasterxml.jackson.core:jackson-databind` (`2.12.3`)
  * `org.slf4j:slf4j-api` (`1.7.30`)

* **Dependencias Transitivas** (resueltas en `gradle.lockfile` y capturadas en el SBOM):
  * `org.apache.logging.log4j:log4j-api` (`2.14.1`) — arrastrada transitivamente por `log4j-core`.
  * `com.fasterxml.jackson.core:jackson-annotations` (`2.12.3`) — arrastrada por `jackson-databind`.
  * `com.fasterxml.jackson.core:jackson-core` (`2.12.3`) — arrastrada por `jackson-databind`.

### Componentes en el stack Python:
* **Directos:** `Flask`, `gunicorn`, `pyjwt`, `cryptography`.
* **Transitivos:** `Werkzeug`, `Jinja2`, `itsdangerous`, `click`, `blinker`, `MarkupSafe`, `cffi`, `pycparser`.

---

## 2. Presencia de `log4j-core` y Vulnerabilidades CRITICAL

Al cruzar el inventario CycloneDX con la base de vulnerabilidades conocidas:

```bash
trivy sbom seguridad/lab3/sbom.cdx.json --scanners vuln --severity CRITICAL \
  --format json --output seguridad/lab3/trivy-sbom.json
```

Se identificó la presencia explícita de:
* **Componente:** `org.apache.logging.log4j:log4j-core`
* **Versión:** `2.14.1`

### CVEs Críticos disparados:
1. **`CVE-2021-44228` (CVSS 10.0 · CRITICAL) — Log4Shell:**
   * Ejecución remota de código (RCE) cuando los logs evalúan cadenas controladas por un atacante mediante búsquedas JNDI (`${jndi:ldap://...}`).
2. **`CVE-2021-45046` (CVSS 9.0 · CRITICAL):**
   * Denegación de servicio (DoS) y potencial RCE debido a la solución incompleta inicial de CVE-2021-44228 en contextos de búsqueda no predeterminados.

Evidencia completa registrada en [`trivy-sbom.json`](file:///home/andru/Documentos/desarrollo-seguro-ucp/seguridad/lab3/trivy-sbom.json).

---

## 3. Origen de la versión: ¿Declarada o Transitiva?

* En el caso de **`log4j-core:2.14.1`**, la versión estaba **declarada directamente** en el archivo manifiesto `build.gradle`:
  ```groovy
  dependencies {
      implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
      implementation 'com.fasterxml.jackson.core:jackson-databind:2.12.3'
      implementation 'org.slf4j:slf4j-api:1.7.30'
  }
  ```
* Sin embargo, la biblioteca compañera **`log4j-api:2.14.1`** no figuraba en `build.gradle`; fue incorporada al árbol de dependencias como una **dependencia transitiva**. Sin un SBOM o un lockfile, las organizaciones típicamente desconocen la presencia y versiones de sus componentes transitivos.

---

## 4. Cambios en el SBOM tras la Corrección

Siguiendo el procedimiento de remediación en el proyecto Java:

```bash
sed -i 's/2\.14\.1/2.17.1/g' build.gradle gradle.lockfile
```

1. **En el SBOM (`sbom.cdx.json`):**
   * El campo `version` para `org.apache.logging.log4j:log4j-core` y `org.apache.logging.log4j:log4j-api` se actualiza de `2.14.1` a `2.17.1`.
   * Los identificadores PURL (`pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1`) y los hashes criptográficos del artefacto cambian correspondientemente.
2. **En el escaneo de vulnerabilidades (`trivy-sbom.json`):**
   * Los hallazgos `CVE-2021-44228` y `CVE-2021-45046` se resuelven completamente, reportando **0 vulnerabilidades CRITICAL** asociadas a Log4j.

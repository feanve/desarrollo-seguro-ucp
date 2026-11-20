# Triage de hallazgos · Laboratorio 2

**Aplicación:** OWASP Juice Shop · `http://127.0.0.1:3000`
**Alcance SAST:** `app-src/` (113 archivos TypeScript)
**Alcance DAST:** instancia local en `127.0.0.1:3000`
**Reportes:** `semgrep.sarif`, `zap.html`

---

## 1. SAST · Semgrep

### Comando ejecutado

```bash
semgrep scan \
  --config p/owasp-top-ten \
  --config p/secrets \
  --config demos/sesion-3/01-semgrep/reglas-billetera.yml \
  --metrics=off \
  --sarif -o seguridad/lab2/semgrep.sarif \
  app-src
```

**Resultado:** 601 reglas cargadas, **8 hallazgos**, todos de nivel `warning`, **0 de nivel `error`**.

> **Por qué no hay filas `ERROR`.** La plantilla del laboratorio pide triangular los hallazgos de
> severidad ERROR (máximo 15). En esta corrida Semgrep clasificó los 8 hallazgos como `warning`,
> incluida la inyección SQL. Si se hubiera usado `--severity ERROR`, el reporte habría quedado vacío
> y se habría perdido el hallazgo más grave. Se triagean los 8 `warning`.

### Tabla de triage

| Regla | Archivo:línea | ¿Verdadero o falso positivo? | Por qué | Fila ASVS |
|---|---|---|---|---|
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | `app-src/lib/insecurity.ts:54` | **Verdadero positivo** | `jwt.sign(user, privateKey, ...)` usa la llave privada RSA escrita en el código en `insecurity.ts:21`. No es un secreto de ejemplo: con esa llave cualquiera que lea el repositorio puede firmar tokens válidos para la aplicación. | **17** (13.3.1), **7** (9.1.2) |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `app-src/routes/fileServer.ts:32` | **Falso positivo** | El `sendFile` solo se alcanza si `file` no contiene `/` (`fileServer.ts:17`). Express decodifica `%2f`, `%2e%2e%2f` y `../` antes de esa comprobación: los tres responden **403**; `package.json%00.md` responde **400**. Además, `verify()` limita a `.md`/`.pdf`. No se reprodujo salida de `ftp/`; se recomienda `path.resolve` + `startsWith` como defensa en profundidad (H06, riesgo residual). | **19** (13.4.7; defensa en profundidad) |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `app-src/routes/keyServer.ts:14` | **Verdadero positivo** | Sirve cualquier archivo de `encryptionkeys/` sin autenticación. La única comprobación es que el nombre no contenga `/`, así que el material de claves queda accesible por HTTP. | **17** (13.3.1, 13.3.2) |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `app-src/routes/logfileServer.ts:14` | **Verdadero positivo** | Expone `logs/` sin autenticación. Los registros contienen correos, IP y actividad de usuarios, que son datos personales (Ley 1581). | **20** (16.4.2), **12** (14.2.6) |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `app-src/routes/quarantineServer.ts:14` | **Verdadero positivo** | Sirve archivos subidos por usuarios desde cuarentena y en el mismo origen de la aplicación. Un archivo HTML o SVG subido se ejecuta como contenido del sitio: XSS almacenado. | **15** (1.2.1), **19** (13.4.7) |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | `app-src/routes/redirect.ts:18` | **Verdadero positivo** | `isRedirectAllowed()` (`insecurity.ts:136`) valida con `url.includes(allowedUrl)`. Un atacante usa `https://github.com/juice-shop/juice-shop.malicioso.com`, que contiene la cadena permitida, y la redirección se acepta. | **15** (3.7.2) |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `app-src/routes/search.ts:23` | **Verdadero positivo** | `criteria` se interpola dentro del SQL con plantilla de cadena. Es la misma falla de la fila 14 y de la amenaza **T02** del Lab 1. Confirmación manual: `GET /rest/products/search?q=' OR '1'='1` devuelve todo el catálogo. | **14** y **22** (1.2.4) |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | `app-src/routes/userProfile.ts:65` | **Verdadero positivo** | `username = eval(code)` ejecuta el contenido de `#{...}` que el usuario puso en su nombre. Es ejecución de código en el servidor (el reto de SSTI de Juice Shop). En la build Docker el reto `usernameXssChallenge` está deshabilitado (`disabledEnv: Docker`), así que no es explotable en esta instancia; el código sigue siendo vulnerable si se habilita. | **15** (1.3.2) |

**Falsos positivos: 1 de 8.** Siete se confirmaron leyendo el código y, en el caso de la SQLi,
con una petición manual. El de `fileServer.ts:32` se descartó al probar los payloads de traversal:
la comprobación `!file.includes('/')` y la allowlist de extensiones bloquean la salida del directorio.

### Lo que Semgrep no encontró

Esto es tan importante como lo que sí encontró:

- **BOLA en el carrito** (`basket.ts:19`): no hay regla que sepa que `id` debe pertenecer al usuario.
- **Campos sensibles escribibles** (`wallet.ts:27`): el incremento de saldo con un monto del cliente no coincide con ningún patrón conocido.
- **MD5 para contraseñas** (`insecurity.ts:41`): `p/owasp-top-ten` no lo marcó.
- **La llave privada literal** (`insecurity.ts:21`): `p/secrets` reportó su *uso* en la línea 54, no el secreto en sí.
- **Cookie sin `Secure`/`HttpOnly`/`SameSite`** (`insecurity.ts:192`).
- **Ausencia de HSTS y de cabeceras de seguridad**: eso lo cubre el DAST, no el SAST.

Estos seis puntos salieron de la revisión humana de la sección 1.

---

## 2. DAST · OWASP ZAP

### Comando ejecutado

```bash
docker run --rm --network host \
  -v "$PWD/seguridad/lab2":/zap/wrk:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://127.0.0.1:3000 -r zap.html -J zap.json -I
```

**Resultado:**

```text
FAIL-NEW: 0   WARN-NEW: 7   INFO: 0   IGNORE: 0   PASS: 61
```

El JSON detalla **9 alertas**: 2 Medium, 4 Low y 3 informativas. La plantilla pide llevar a la
tabla las Medium o High, así que el triage obligatorio son las dos primeras. Las demás se revisaron
y se dejan abajo como contexto.

### Tabla de triage (Medium y High)

| Alerta | Riesgo | URL | ¿Verdadero o falso positivo? | Por qué | Fila ASVS |
|---|---|---|---|---|---|
| **Content Security Policy (CSP) Header Not Set** | **Medium** (confianza High) | `/`, `/ftp`, `/ftp/encrypt.pyc`, `/sitemap.xml` | **Verdadero positivo** | `curl -sI http://127.0.0.1:3000/` no devuelve `Content-Security-Policy`. La aplicación sirve HTML, archivos de `/ftp/` y la SPA sin ninguna directiva que limite orígenes de scripts. Esto agrava el `eval()` de `userProfile.ts:65` y el XSS de `/ftp/quarantine/`: no hay segunda barrera. | **19** (3.4.3) |
| **Cross-Domain Misconfiguration** | **Medium** (confianza Medium) | `/`, `/polyfills.js`, `/robots.txt`, `/rolldown-runtime-*.js`, `/sitemap.xml` | **Falso positivo** (con matiz de endurecimiento) | ZAP ve `Access-Control-Allow-Origin: *`. Pero la respuesta **no** incluye `Access-Control-Allow-Credentials: true`, así que el navegador no envía cookies en peticiones cruzadas y un sitio atacante no puede leer respuestas autenticadas. Los recursos marcados son públicos por diseño (JS, `robots.txt`, `sitemap.xml`). Según ASVS 3.4.2, `*` es aceptable cuando la respuesta no contiene información sensible. Aun así, lo correcto es eliminar el header o restringirlo al origen propio: es un problema de configuración, no una fuga explotable. | Sin fila directa (3.4.2, no incluido en las 25) |

### Alertas Low e informativas (revisadas, fuera del triage obligatorio)

| Alerta | Riesgo | Lectura |
|---|---|---|
| Dangerous JS Functions | Low | Detecta `eval` en los bundles de la SPA. **Refuerza** el hallazgo de Semgrep en `userProfile.ts:65`; no es un falso positivo, pero el origen ya está cubierto por la fila 15. |
| Cross-Origin-Embedder-Policy Header Missing or Invalid | Low | Falta `Cross-Origin-Embedder-Policy`. Es endurecimiento para aislamiento de procesos; no hay impacto directo demostrado en esta aplicación. |
| Cross-Origin-Opener-Policy Header Missing or Invalid | Low | Falta `Cross-Origin-Opener-Policy`. Igual que la anterior: defensa en profundidad contra tabnabbing y acceso a `window`. |
| Deprecated Feature Policy Header Set | Low | La aplicación envía `Feature-Policy: payment 'self'`, reemplazado por `Permissions-Policy`. Confirma que las cabeceras se configuran de forma manual y desactualizada. |
| Modern Web Application, Storable and Cacheable Content, Storable but Non-Cacheable Content | Informational | Contexto del escaneo (SPA, caché de estáticos). No son vulnerabilidades. |

### Lo que ZAP no puede ver

El escaneo pasivo no encontró el BOLA del carrito (`basket.ts:19`), ni el saldo manipulable
(`wallet.ts:27`), ni la SQLi (`search.ts:23`), ni la asignación de rol. ZAP no tiene sesión de
usuario ni conoce el modelo de datos: por eso el DAST se complementa con la revisión ASVS y con el
SAST, no los reemplaza.

---

## 3. Conclusión del triage

| Fuente | Hallazgos | Verdaderos positivos | Falsos positivos |
|---|:---:|:---:|:---:|
| Semgrep (SAST) | 8 | 7 | 1 |
| ZAP (DAST) — Medium/High | 2 | 1 | 1 |
| **Total** | **10** | **8** | **2** |

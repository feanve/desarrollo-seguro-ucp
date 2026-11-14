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
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `app-src/routes/fileServer.ts:32` | **Verdadero positivo** | `res.sendFile(path.resolve('ftp/', file))` usa `file` tomado de la URL. La validación de `fileServer.ts:56-57` solo exige que termine en `.md` o `.pdf`, y `cutOffPoisonNullByte` no bloquea `../`; se puede salir del directorio `ftp/`. | **19** (13.4.7) |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `app-src/routes/keyServer.ts:14` | **Verdadero positivo** | Sirve cualquier archivo de `encryptionkeys/` sin autenticación. La única comprobación es que el nombre no contenga `/`, así que el material de claves queda accesible por HTTP. | **17** (13.3.1, 13.3.2) |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `app-src/routes/logfileServer.ts:14` | **Verdadero positivo** | Expone `logs/` sin autenticación. Los registros contienen correos, IP y actividad de usuarios, que son datos personales (Ley 1581). | **20** (16.4.2), **12** (14.2.6) |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | `app-src/routes/quarantineServer.ts:14` | **Verdadero positivo** | Sirve archivos subidos por usuarios desde cuarentena y en el mismo origen de la aplicación. Un archivo HTML o SVG subido se ejecuta como contenido del sitio: XSS almacenado. | **15** (1.2.1), **19** (13.4.7) |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | `app-src/routes/redirect.ts:18` | **Verdadero positivo** | `isRedirectAllowed()` (`insecurity.ts:136`) valida con `url.includes(allowedUrl)`. Un atacante usa `https://github.com/juice-shop/juice-shop.malicioso.com`, que contiene la cadena permitida, y la redirección se acepta. | **15** (3.7.2) |
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | `app-src/routes/search.ts:23` | **Verdadero positivo** | `criteria` se interpola dentro del SQL con plantilla de cadena. Es la misma falla de la fila 14 y de la amenaza **T02** del Lab 1. Confirmación manual: `GET /rest/products/search?q=' OR '1'='1` devuelve todo el catálogo. | **14** y **22** (1.2.4) |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | `app-src/routes/userProfile.ts:65` | **Verdadero positivo** | `username = eval(code)` ejecuta el contenido de `#{...}` que el usuario puso en su nombre. Es ejecución de código en el servidor (el reto de SSTI de Juice Shop), habilitada por defecto. | **15** (1.3.2) |

**Falsos positivos: 0 de 8.** Los ocho se confirmaron leyendo el código y, en el caso de la SQLi,
con una petición manual.

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

_(Pendiente: se completa después del escaneo con `zap-baseline.py`.)_

| Alerta | Riesgo | URL | ¿Verdadero o falso positivo? | Por qué | Fila ASVS |
|---|---|---|---|---|---|
| | | | | | |

---

## 3. Conclusión del triage

| Fuente | Hallazgos | Verdaderos positivos | Falsos positivos |
|---|:---:|:---:|:---:|
| Semgrep (SAST) | 8 | 8 | 0 |
| ZAP (DAST) | pendiente | pendiente | pendiente |

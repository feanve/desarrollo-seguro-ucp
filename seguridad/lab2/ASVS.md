# Laboratorio 2 · Verificación ASVS 5.0 de OWASP Juice Shop

**Estudiante:** Felipe A Velez (`feanve`)
**Aplicación:** OWASP Juice Shop (`http://127.0.0.1:3000`, imagen `bkimminich/juice-shop:latest`)
**Código analizado:** `app-src/` (extraído de `lib/`, `models/` y `routes/`)
**Referencia:** [OWASP ASVS 5.0](https://github.com/OWASP/ASVS/tree/master/5.0/en)

> **Alcance.** La revisión humana se hizo sobre el código de `app-src/`. El escaneo dinámico se hizo
> únicamente contra la instancia local en `127.0.0.1:3000`, que es la aplicación del equipo.
> La SPA de Angular no está incluida en `app-src/`; cuando una fila depende del frontend se indica.

## 1. Revisión ASVS 5.0

| # | Capítulo | Qué verificar | Requisito ASVS | Estado | Evidencia |
|---|---|---|---|---|---|
| 1 | V6 Autenticación | Contraseñas de mínimo 8 caracteres, sin reglas de composición, contra lista de comunes | **6.2.1**, **6.2.4**, **6.2.5** | **No cumple** | `app-src/routes/changePassword.ts:19-24` solo rechaza contraseña vacía o distinta a la repetición; no hay longitud mínima ni lista de contraseñas comunes. `app-src/routes/resetPassword.ts:26-29` hace lo mismo. `app-src/models/user.ts:70-74` hashea lo que llegue, sin validar. No se cumple 6.2.1 ni 6.2.4; 6.2.5 sí se cumple porque no se exige composición. |
| 2 | V6 / V11 | Hash lento y con sal para contraseñas | **11.4.2** | **No cumple** | `app-src/lib/insecurity.ts:41` → `crypto.createHash('md5')`. Se usa en `app-src/models/user.ts:73` para toda contraseña. MD5 es rápido y sin sal: mismo password produce el mismo hash. |
| 3 | V6 | Límite de intentos o protección contra fuerza bruta | **6.3.1** | **No cumple** | `grep -Rni 'rateLimit\|express-rate\|slowDown\|brute' app-src` no devuelve ninguna coincidencia. `app-src/routes/login.ts:34` ejecuta la consulta en cada intento sin contador, bloqueo ni retardo. |
| 4 | V6 | Login y recuperación no revelan si el usuario existe | **6.3.8** | **No cumple** | El login sí es genérico (`app-src/routes/login.ts:34` y `:50` devuelven `Invalid email or password.` para ambos casos), pero la recuperación filtra: `app-src/routes/securityQuestion.ts:21-26` devuelve `{ question: ... }` si el correo existe y `{}` si no. El requisito cubre explícitamente «forgot password». |
| 5 | V7 Sesiones | La sesión expira y el cierre la invalida en el servidor | **7.3.1**, **7.4.1** | **No cumple** | `app-src/lib/insecurity.ts:54` firma con `expiresIn: '6h'`: es expiración absoluta, no por inactividad (7.3.1). No existe ruta de logout (`grep -Rni logout app-src` sin resultados) y `app-src/lib/insecurity.ts:25-30` mantiene los tokens en un `Map` en memoria: el token sigue siendo válido hasta que expira (7.4.1). |
| 6 | V7 | Cookie de sesión con `Secure`, `HttpOnly` y `SameSite` | **3.3.1**, **3.3.2**, **3.3.4** | **No cumple** | `app-src/lib/insecurity.ts:192` → `res.cookie('token', token)` y `app-src/routes/updateUserProfile.ts:42` → `res.cookie('token', updatedToken)`, ambas sin objeto de opciones. La cookie viaja sin `Secure`, sin `HttpOnly` y sin `SameSite`. |
| 7 | V9 Tokens | Firma verificada con lista fija de algoritmos | **9.1.2** | **No cumple** | `app-src/lib/insecurity.ts:52` → `expressJwt({ secret: publicKey })`, sin opción `algorithms`. `app-src/lib/insecurity.ts:55` → `jws.verify(token, publicKey)`, que toma el `alg` del encabezado. No hay allowlist ni rechazo explícito de `none`. |
| 8 | V9 | El token tiene `exp` y se validan emisor y audiencia | **9.2.1**, **9.2.3** | **No cumple** | 9.2.1 sí se cumple: `jwt.sign(..., { expiresIn: '6h' })` en `app-src/lib/insecurity.ts:54` y `jwt.verify` valida `exp` en `app-src/lib/insecurity.ts:188`. 9.2.3 no: ni `authorize` ni `verify` reciben `audience` ni `issuer`, así que cualquier token firmado con la misma llave sirve para cualquier servicio. |
| 9 | V8 Autorización | Cada consulta a un objeto filtra por dueño o permiso (BOLA) | **8.2.2** | **No cumple** | `app-src/routes/basket.ts:19` → `BasketModel.findOne({ where: { id } })` sin `UserId`. La comprobación de `app-src/routes/basket.ts:22-25` solo sirve para resolver un reto, no bloquea la respuesta. Cualquier usuario autenticado lee `/rest/basket/{id}` de otro. |
| 10 | V8 | Campos sensibles (rol, saldo, estado) no escribibles desde el cliente | **8.2.3** | **No cumple** | `app-src/routes/wallet.ts:27` → `WalletModel.increment({ balance: req.body.balance }, ...)`: el cliente elige el monto y no se verifica que el cobro se haya hecho. `app-src/models/user.ts:76-96` permite `role: 'admin'` como valor válido y ningún controlador de `app-src/` filtra ese campo. |
| 11 | V8 | Autorización en el servidor, no solo ocultando botones | **8.3.1** | **No cumple** | `security.isAuthorized()` está definido en `app-src/lib/insecurity.ts:52` pero no lo usa ninguna ruta: `grep -Rni 'isAuthorized' app-src/routes` sin resultados. Cada controlador decide por su cuenta y varios (por ejemplo `basket.ts`) no deciden nada. |
| 12 | V4 APIs | Las respuestas no devuelven más campos de los necesarios | **14.2.6** | **No cumple** | `app-src/routes/changePassword.ts:56` → `res.json({ user })` devuelve el modelo completo, incluido `password` (hash) y `role`. `app-src/routes/resetPassword.ts:46` hace lo mismo. Contraste positivo: `app-src/routes/payment.ts:32` enmascara la tarjeta con `'*'.repeat(12) + últimos 4`. |
| 13 | V4 / V2 | Paginación con límite máximo; límites de tamaño en peticiones | **2.3.2**, **2.4.1**, **4.2.5** | **No cumple** | `app-src/routes/search.ts:23` no tiene `LIMIT` ni `OFFSET`. `app-src/routes/basketItems.ts:43` acepta `quantity` negativa porque `quantityCheck` (`:87-100`) solo compara `product.quantity >= quantity`. No hay controles antiautomatización (2.4.1). Solo 4.2.5 está parcialmente cubierto: `search.ts:22` recorta `q` a 200 caracteres. |
| 14 | V1 Codificación | Consultas parametrizadas en todo acceso a datos | **1.2.4** | **No cumple** | `app-src/routes/search.ts:23` interpola `criteria` en el SQL: `` `... LIKE '%${criteria}%' ...` ``. Comparar con `app-src/routes/login.ts:34`, que ya usa `replacements` y es el patrón correcto. |
| 15 | V1 | Salida escapada según el contexto (HTML, JS, URL) | **1.2.1**, **1.2.3**, **1.3.2**, **3.7.2** | **No cumple** | Dos fallos. (a) `app-src/routes/userProfile.ts:65` ejecuta `eval(code)` sobre el `username` del usuario cuando el reto `usernameXssChallenge` está habilitado (por defecto sí): es ejecución de código controlado por el cliente. (b) `app-src/lib/insecurity.ts:136` valida la redirección con `url.includes(allowedUrl)`, así que `https://github.com/juice-shop/juice-shop.evil.com` pasa el filtro y `app-src/routes/redirect.ts:18` redirige fuera del sitio. Lo único correcto es el saneamiento de comentarios (`app-src/models/feedback.ts:44`). |
| 16 | V11 Criptografía | Datos sensibles en reposo con cifrado autenticado (o justificación) | **14.2.4**, **11.3.3** | **No cumple** | `app-src/models/index.ts:42` → `storage: 'data/juiceshop.sqlite'` sin cifrado. No hay cifrado a nivel de aplicación para correos, hashes, tarjetas ni respuestas de seguridad. No existe justificación documentada. |
| 17 | V11 / V13 | Ninguna llave, secreto o contraseña en el código ni en el historial | **13.3.1** | **No cumple** | `app-src/lib/insecurity.ts:21` contiene una llave privada RSA completa en texto plano. Además `app-src/routes/login.ts:60` incluye credenciales de usuarios de ejemplo. Semgrep `p/secrets` debe reportarlo (ver `TRIAGE.md`). |
| 18 | V12 Comunicación | TLS en todo tráfico externo; HSTS en producción | **12.1.1**, **12.2.1**, **3.4.1** | **No cumple** | `lab-env/docker-compose.yml:8` publica la aplicación solo por HTTP (`"127.0.0.1:3000:3000"`); no hay terminación TLS. La respuesta no incluye `Strict-Transport-Security` (confirmado por ZAP en `zap.html`). Aceptable para el laboratorio local, pero no para producción. |
| 19 | V13 Configuración | Debug apagado, sin trazas al usuario, cabeceras de seguridad | **13.4.2**, **3.4.4**, **16.5.1** | **No cumple** | `grep -Rni 'helmet' app-src` sin resultados: no se configuran `X-Content-Type-Options`, CSP ni `frame-ancestors`. Las rutas propagan el error con `next(error)` (por ejemplo `app-src/routes/basket.ts:34`); el manejador global está fuera de `app-src/`, pero ZAP confirma ausencia de cabeceras. |
| 20 | V16 Registro | Se registran fallos de autenticación y autorización, sin datos sensibles | **16.3.1**, **16.3.2**, **16.5.1** | **No cumple** | `app-src/lib/logger.ts:8-13` es el único logger y escribe en consola con formato `simple`. No hay registro de intentos de login fallidos ni de accesos denegados: `app-src/routes/login.ts` no registra nada y `app-src/routes/basket.ts` tampoco detecta el acceso indebido. |
| 21 | **Top 5 · T01** | El servidor recalcula precios y rechaza cantidades ≤ 0 (Lab 1, V2) | **2.3.2** | **No cumple** | El precio sí se toma de la base (`app-src/routes/order.ts:87-93`), pero la cantidad no se revalida: `app-src/routes/basketItems.ts:43` acepta `quantity: -2` y `order.ts:93` calcula `itemPrice * BasketItem.quantity`, produciendo un total negativo. |
| 22 | **Top 5 · T02** | Consultas parametrizadas en búsqueda y filtros (Lab 1, V1) | **1.2.4** | **No cumple** | `app-src/routes/search.ts:23`, misma evidencia que la fila 14. La inyección `' OR '1'='1` altera el `WHERE` y devuelve todo el catálogo. |
| 23 | **Top 5 · I01** | El `id` del token debe coincidir con el dueño del recurso; ajeno → 404 (Lab 1, V8) | **8.2.2** | **No cumple** | `app-src/routes/basket.ts:19`, misma evidencia que la fila 9. El usuario A puede leer el carrito del usuario B cambiando el `id` en la URL. |
| 24 | **Top 5 · E01** | Lista blanca de campos en el registro; `role` forzado a `customer` (Lab 1, V2/V8) | **2.2.1**, **8.2.3** | **No cumple** | `app-src/models/user.ts:76-96` acepta `role: 'admin'` como valor válido y lo asigna sin comprobar quién lo envía. El controlador de registro (`POST /api/Users`) vive en `server.ts`, que no está en `app-src/`; la evidencia es el modelo, que no impide la asignación. |
| 25 | **Top 5 · E02** | Fallo seguro si la pasarela falla: orden `FALLIDA`, sin factura (Lab 1, V16/V2) | **16.5.3**, **2.3.2** | **No cumple** | `app-src/routes/order.ts:47-57` confirma la orden y borra los ítems del carrito cuando termina de escribir el PDF, sin consultar ni verificar ningún resultado de pago. `app-src/routes/wallet.ts:27` incrementa el saldo sin cobrar la tarjeta: ante un fallo externo no hay transición a estado fallido. |

### Resumen de estados

| Estado | Cantidad | Filas |
|---|:---:|---|
| **Cumple** | 0 | — |
| **No cumple** | 25 | 1-25 |
| **No aplica** | 0 | — |
| **Total** | **25** | |

> **Sobre el nivel.** La revisión se hizo con la mentalidad de nivel 1, pero varias filas de la
> plantilla apuntan a requisitos de nivel 2 o 3 (6.3.8, 7.3.1, 9.2.3, 14.2.6, 16.5.3). Se anotaron
> igual porque son los que exige la tabla del laboratorio; el nivel exacto está en la sección 2.
> Ninguna fila quedó como «No aplica»: Juice Shop usa cookies, JWT, base de datos y API, así que
> todos los controles son exigibles.

## 2. Requisitos exactos (texto de ASVS 5.0)

| Número | Nivel | Texto |
|---|:---:|---|
| 1.2.1 | 1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. |
| 1.2.3 | 1 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). |
| 1.2.4 | 1 | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. |
| 1.3.2 | 1 | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. |
| 2.2.1 | 1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. |
| 2.3.2 | 2 | Verify that business logic limits are implemented per the application's documentation to avoid business logic flaws being exploited. |
| 2.4.1 | 2 | Verify that anti-automation controls are in place to protect against excessive calls to application functions that could lead to data exfiltration, garbage-data creation, quota exhaustion, rate-limit breaches, denial-of-service, or overuse of costly resources. |
| 3.3.1 | 1 | Verify that cookies have the 'Secure' attribute set, and if the '\__Host-' prefix is not used for the cookie name, the '\__Secure-' prefix must be used for the cookie name. |
| 3.3.2 | 2 | Verify that each cookie's 'SameSite' attribute value is set according to the purpose of the cookie, to limit exposure to user interface redress attacks and browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). |
| 3.3.4 | 2 | Verify that if the value of a cookie is not meant to be accessible to client-side scripts (such as a session token), the cookie must have the 'HttpOnly' attribute set and the same value (e.g. session token) must only be transferred to the client via the 'Set-Cookie' header field. |
| 3.4.1 | 1 | Verify that a Strict-Transport-Security header field is included on all responses to enforce an HTTP Strict Transport Security (HSTS) policy. A maximum age of at least 1 year must be defined. |
| 3.4.4 | 2 | Verify that all HTTP responses contain an 'X-Content-Type-Options: nosniff' header field. |
| 4.2.5 | 3 | Verify that, if the application (backend or frontend) builds and sends requests, it uses validation, sanitization, or other mechanisms to avoid creating URIs or HTTP request header fields which are too long to be accepted by the receiving component. |
| 6.2.1 | 1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. |
| 6.2.4 | 1 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy. |
| 6.2.5 | 1 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. |
| 6.3.1 | 1 | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. |
| 6.3.8 | 3 | Verify that valid users cannot be deduced from failed authentication challenges, such as by basing on error messages, HTTP response codes, or different response times. Registration and forgot password functionality must also have this protection. |
| 7.3.1 | 2 | Verify that there is an inactivity timeout such that re-authentication is enforced according to risk analysis and documented security decisions. |
| 7.4.1 | 1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. |
| 8.2.2 | 1 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). |
| 8.2.3 | 2 | Verify that the application ensures that field-level access is restricted to consumers with explicit permissions to specific fields to mitigate broken object property level authorization (BOPLA). |
| 8.3.1 | 1 | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. |
| 9.1.2 | 1 | Verify that only algorithms on an allowlist can be used to create and verify self-contained tokens, for a given context. The allowlist must include the permitted algorithms and must not include the 'None' algorithm. |
| 9.2.1 | 1 | Verify that, if a validity time span is present in the token data, the token and its content are accepted only if the verification time is within this validity time span. |
| 9.2.3 | 2 | Verify that the service only accepts tokens which are intended for use with that service (audience). |
| 11.3.3 | 2 | Verify that encrypted data is protected against unauthorized modification preferably by using an approved authenticated encryption method. |
| 11.4.2 | 2 | Verify that passwords are stored using an approved, computationally intensive, key derivation function, with parameter settings configured based on current guidance. |
| 12.1.1 | 1 | Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. |
| 12.2.1 | 1 | Verify that TLS is used for all connectivity between a client and external facing, HTTP-based services, and does not fall back to insecure or unencrypted communications. |
| 13.3.1 | 2 | Verify that a secrets management solution is used to securely create, store, control access to, and destroy backend secrets. Secrets must not be included in application source code or included in build artifacts. |
| 13.4.2 | 2 | Verify that debug modes are disabled for all components in production environments to prevent exposure of debugging features and information leakage. |
| 14.2.4 | 2 | Verify that controls around sensitive data related to encryption, integrity verification, retention, how the data is to be logged, access controls around sensitive data in logs, and privacy are implemented as defined in the documentation for the specific data's protection level. |
| 14.2.6 | 3 | Verify that the application only returns the minimum required sensitive data for the application's functionality. |
| 16.3.1 | 2 | Verify that all authentication operations are logged, including successful and unsuccessful attempts. |
| 16.3.2 | 2 | Verify that failed authorization attempts are logged. |
| 16.5.1 | 2 | Verify that a generic message is returned to the consumer when an unexpected or security-sensitive error occurs, ensuring no exposure of sensitive internal system data such as stack traces, queries, secret keys, and tokens. |
| 16.5.3 | 2 | Verify that the application fails gracefully and securely, including when an exception occurs, preventing fail-open conditions such as processing a transaction despite errors resulting from validation logic. |

## 3. Registro de comandos de verificación

```bash
# BOLA: usuario A pide el carrito de usuario B
grep -n "findOne({ where: { id }" app-src/routes/basket.ts

# Hash de contraseñas
grep -n "createHash" app-src/lib/insecurity.ts

# Rate limiting ausente
grep -Rni -E 'rateLimit|express-rate|slowDown|brute' app-src || echo "sin controles"

# Cookie sin atributos
grep -Rn "res.cookie" app-src

# SQL concatenado
grep -n "LIKE" app-src/routes/search.ts

# Llave privada en el código
grep -n "BEGIN RSA PRIVATE KEY" app-src/lib/insecurity.ts

# Autorización definida pero no usada
grep -Rni "isAuthorized" app-src/routes || echo "sin usos"

# eval sobre entrada del usuario
grep -rn "eval(" app-src --include='*.ts'

# Allowlist de redirección comprobada con includes()
grep -n "url.includes" app-src/lib/insecurity.ts
```

## 4. ¿Hicimos un buen trabajo?

_(Se completa al cerrar las secciones 2 y 3 del laboratorio: Semgrep y ZAP.)_

1. **¿Cuántos requisitos cumplen de los 25?** 0 de 25. Juice Shop es vulnerable por diseño; el valor del ejercicio está en la evidencia, no en el resultado. Solo se salvan controles puntuales, como el enmascarado de tarjetas en `payment.ts:32` o el saneamiento de comentarios en `feedback.ts:44`, pero no alcanzan para declarar una fila completa.
2. **¿Qué encontró la revisión humana que ninguna herramienta encontró?** Pendiente de contraste con Semgrep y ZAP.
3. **¿Qué falso positivo les hizo perder más tiempo?** Pendiente.

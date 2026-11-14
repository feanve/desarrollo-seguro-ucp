# Análisis comparativo y criterio de cierre · Laboratorio 2

**Aplicación:** OWASP Juice Shop (`http://127.0.0.1:3000`)
**Insumos:** `ASVS.md`, `TRIAGE.md`, `semgrep.sarif`, `zap.json`, `tests/test_bola_basket.py`
**Pregunta que responde:** ¿qué valor tiene cada hallazgo, por qué, y cómo se demuestra que quedó cerrado?

---

## 1. Método: de la alerta al criterio

Una herramienta no emite criterio, emite señales. El criterio se construye en cinco pasos y ninguno
se puede saltar:

| Paso | Pregunta | Evidencia que lo respalda | Ejemplo en este laboratorio |
|---|---|---|---|
| 1. Detectar | ¿Qué dijo la herramienta? | Reporte crudo (`semgrep.sarif`, `zap.json`) | Semgrep marca `search.ts:23` como `warning` |
| 2. Reproducir | ¿Puedo provocarlo yo? | Comando y salida | `GET /rest/products/search?q=' OR '1'='1` devuelve todo el catálogo |
| 3. Clasificar | ¿Es real? | Verdadero o falso positivo, con la razón | 8 de 8 en Semgrep; 1 falso positivo en ZAP |
| 4. Valorar | ¿Cuánto importa **aquí**? | Impacto × probabilidad, justificados | La SQLi es crítica; el CORS es riesgo 1 |
| 5. Decidir | ¿Corregir, mitigar, aceptar o transferir? | Requisito ASVS + control + prueba | BOLA: corregido y demostrado |

> **Regla de trabajo:** si un hallazgo no se reproduce en el paso 2, no se afirma en el paso 3.
> «Lo dice la herramienta» no es evidencia; la evidencia es la petición, el archivo y la salida.

### Por qué no se usa la severidad de la herramienta como criterio

Tres casos de este mismo escaneo lo demuestran:

| Caso | Lo que dijo la herramienta | Lo que dice el criterio |
|---|---|---|
| SQLi en `search.ts:23` | Semgrep: `warning` (ni siquiera `error`) | Riesgo **25/25**: lectura y escritura de toda la base, sin autenticación |
| `Access-Control-Allow-Origin: *` | ZAP: **Medium** | Riesgo **1/25**: falso positivo, no hay `Allow-Credentials` |
| BOLA en `basket.ts:19` | Ninguna herramienta lo vio | Riesgo **16/25**: cualquier usuario lee el carrito de otro |

La severidad de la herramienta describe el **patrón**, no el **contexto**. El criterio es lo que
convierte el patrón en una decisión.

---

## 2. Escalas usadas para valorar

### Impacto (1–5)

| Valor | Significado | Ejemplo |
|:---:|---|---|
| 1 | Sin efecto práctico | Cabecera obsoleta sin explotación conocida |
| 2 | Molestia o defensa en profundidad | Falta `Referrer-Policy` |
| 3 | Pérdida limitada o de un solo usuario | Una cantidad negativa en una orden |
| 4 | Datos de varios usuarios, fraude o lectura de archivos | Carrito ajeno, saldo, archivos del servidor |
| 5 | Control total, ejecución de código o datos masivos | SQLi, RCE, llave privada, rol admin |

### Probabilidad (1–5)

| Valor | Requisitos para explotar |
|:---:|---|
| 1 | Condiciones que no se dan en este despliegue |
| 2 | Acceso físico o privilegios administrativos |
| 3 | Usuario autenticado **y** una condición adicional (víctima, archivo, reto activo) |
| 4 | Usuario autenticado con una petición normal |
| 5 | Sin autenticación, con una petición normal |

### Riesgo y decisión

`Riesgo = Impacto × Probabilidad`

| Rango | Nivel | Decisión |
|:---:|---|---|
| 15–25 | **Crítico** | Corregir antes de exponer la aplicación |
| 10–14 | **Alto** | Corregir en la iteración actual |
| 5–9 | **Medio** | Corregir en el ciclo, no bloquea |
| 1–4 | **Bajo** | Aceptar y documentar |

---

## 3. Criterio aplicado a los hallazgos

Cada fila cita el hecho que justifica el impacto y la probabilidad. La columna **Fuente** dice quién
lo encontró: **S** Semgrep, **Z** ZAP, **H** revisión humana.

| ID | Hallazgo | Fuente | ASVS | Amenaza Lab 1 | I | P | **R** | Decisión |
|---|---|---|---|:---:|:---:|:---:|:---:|---|
| H01 | SQLi en `search.ts:23` | S + H | 1.2.4 | T02 | 5 | 5 | **25** | Corregir ya: sin auth, altera el `WHERE` |
| H02 | Llave privada JWT en `insecurity.ts:21` | S + H | 13.3.1 | — | 5 | 4 | **20** | Rotar llave y mover a secreto: con el repo se firman tokens |
| H03 | `role: 'admin'` aceptado en el registro | H | 8.2.3 | E01 | 5 | 4 | **20** | Corregir: `POST /api/Users` es público |
| H04 | Saldo acreditado con monto del cliente (`wallet.ts:27`) | H | 8.2.3 | E02 | 4 | 4 | **16** | Corregir: dinero sin pago verificado |
| H05 | BOLA del carrito (`basket.ts:19`) | H | 8.2.2 | I01 | 4 | 4 | **16** | **Corregido** y con prueba |
| H06 | Path traversal en `fileServer.ts:32` | S | 13.4.7 | — | 4 | 4 | **16** | Corregir: lectura de archivos sin auth |
| H07 | Claves servidas por `keyServer.ts:14` | S | 13.3.1 | — | 4 | 4 | **16** | Corregir: material criptográfico expuesto |
| H08 | `eval()` sobre el nombre de usuario (`userProfile.ts:65`) | S + H | 1.3.2 | — | 5 | 3 | **15** | Corregir: RCE, requiere víctima que visite el perfil |
| H09 | MD5 para contraseñas (`insecurity.ts:41`) | H | 11.4.2 | — | 5 | 3 | **15** | Migrar: requiere volcar la base para ser útil |
| H10 | Logs servidos por `logfileServer.ts:14` | S | 16.4.2 | — | 3 | 5 | **15** | Corregir: datos personales (Ley 1581) sin auth |
| H11 | XSS almacenado en `/ftp/quarantine/` | S | 1.2.1 | — | 4 | 3 | **12** | Corregir: requiere subir un archivo |
| H12 | Open redirect en `redirect.ts:18` | S + H | 3.7.2 | — | 3 | 4 | **12** | Corregir: phishing con el dominio real |
| H13 | Cantidad negativa en `basketItems.ts:43` | H | 2.3.2 | T01 | 3 | 4 | **12** | Corregir: orden con total negativo |
| H14 | Cookie sin `Secure`/`HttpOnly`/`SameSite` | H | 3.3.1, 3.3.2, 3.3.4 | — | 4 | 3 | **12** | Corregir: robo de sesión vía XSS |
| H15 | JWT sin allowlist de algoritmos ni `aud` | H | 9.1.2, 9.2.3 | — | 4 | 3 | **12** | Corregir: acepta `alg` del encabezado |
| H16 | Sin límite de intentos en el login | H | 6.3.1 | — | 3 | 4 | **12** | Corregir: fuerza bruta sin freno |
| H17 | Sin CSP (`/`, `/ftp`, `/sitemap.xml`) | Z + H | 3.4.3 | — | 2 | 4 | **8** | Mitigar: defensa en profundidad, agrava H08 y H11 |
| H18 | Sin registro de fallos de autenticación | H | 16.3.1 | — | 2 | 4 | **8** | Corregir en el ciclo: no hay trazabilidad |
| H19 | `Access-Control-Allow-Origin: *` | Z | 3.4.2 | — | 1 | 1 | **1** | **Falso positivo**: sin `Allow-Credentials`, descartar |

**Lectura del criterio.** El orden de prioridad no coincide con el orden en que las herramientas
reportan: H01 aparece como `warning`, H05 no aparece en ninguna herramienta y H19 aparece como
Medium. Un tablero ordenado por severidad de herramienta habría corregido primero el CORS y habría
dejado la SQLi para el final.

---

## 4. Comparativa de las tres fuentes

### 4.1 Cuánto encontró cada una

| Fuente | Reportes | Verdaderos positivos | Falsos positivos | Exclusivos | Tiempo de ejecución |
|---|:---:|:---:|:---:|:---:|---|
| **Semgrep** (SAST) | 8 hallazgos | 8 | 0 | **4** (`fileServer`, `keyServer`, `logfileServer`, `quarantineServer`) | ~1 min |
| **ZAP** (DAST pasivo) | 6 alertas con riesgo + 3 informativas | 5 | 1 (CORS) | **3** (`COEP`, `COOP`, `Feature-Policy`) | ~6 min |
| **Revisión humana** (ASVS) | 25 filas | 25 | 0 | **21 filas sin evidencia de herramienta** | ~2,5 h |

> El resumen de consola de ZAP dice `WARN-NEW: 7` porque suma las 6 alertas de riesgo y un aviso
> interno («ZAP warnings logged»), que no es una vulnerabilidad. El desglose real está en `zap.json`:
> 2 Medium, 4 Low y 3 informativas.

**Ningún hallazgo fue detectado por las tres fuentes a la vez.** Las coincidencias son:

| Coincidencia | Fuentes | Lectura |
|---|---|---|
| SQLi (`search.ts:23`) | Semgrep + humana | Semgrep ve el patrón; la humana confirma la explotación |
| Llave privada (`insecurity.ts:21`) | Semgrep + humana | Semgrep ve el **uso**; la humana ve el **literal** |
| Open redirect (`redirect.ts:18`) | Semgrep + humana | Ambas llegan por caminos distintos |
| CSP ausente | ZAP + humana | La humana usa la evidencia de ZAP para cerrar la fila 19 |
| `eval` | Semgrep + humana (servidor) y ZAP (bundles) | **No es el mismo punto**: Semgrep ve `userProfile.ts:65`; ZAP ve `eval` en el JS de la SPA |

### 4.2 Cobertura por clase de vulnerabilidad

| Clase | Semgrep | ZAP | Humana | Evidencia concreta |
|---|:---:|:---:|:---:|---|
| Inyección SQL | ✅ | — | ✅ | `search.ts:23`; verificado con `' OR '1'='1` |
| Ejecución de código (`eval`) | ✅ | ✅ | ✅ | `userProfile.ts:65` (servidor) y bundles (cliente) |
| Secretos en código | ✅ | — | ✅ | `insecurity.ts:21`, reportado en `:54` |
| Path traversal | ✅ | — | — | `fileServer.ts:32` |
| Open redirect | ✅ | — | ✅ | `redirect.ts:18` |
| XSS almacenado | ✅ | — | — | `/ftp/quarantine/` |
| BOLA / IDOR | — | — | ✅ | `basket.ts:19` |
| BOPLA (saldo, rol) | — | — | ✅ | `wallet.ts:27`, `user.ts:76` |
| Hash de contraseñas | — | — | ✅ | `insecurity.ts:41` |
| Cookies y sesión | — | — | ✅ | `insecurity.ts:192` |
| JWT: allowlist de algoritmo y `aud` | — | — | ✅ | `insecurity.ts:52-55` |
| JWT: llave en código | ✅ | — | ✅ | `insecurity.ts:21` |
| Cabeceras (CSP, COOP, COEP) | — | ✅ | ✅ | `zap.json` |
| TLS / HSTS | — | — | ✅ | `curl -sI`, sin `Strict-Transport-Security` |
| Lógica de negocio (cantidad) | — | — | ✅ | `basketItems.ts:43` |
| Fuerza bruta / rate limit | — | — | ✅ | `grep` sin `rateLimit` |
| Registro de eventos | — | — | ✅ | `logger.ts:8-13` |
| Exposición de archivos | ✅ | — | — | `keyServer.ts`, `logfileServer.ts` |
| CORS | — | ✅ (FP) | ✅ (descartado) | `Access-Control-Allow-Origin: *` |

### 4.3 Por qué cada herramienta ve lo que ve

**Semgrep** razona sobre el código. Ve patrones peligrosos aunque la ruta nunca se ejecute, por eso
encuentra los cuatro `sendFile` que la revisión humana pasó por alto. No puede ver:
- **Propiedad de los datos** (BOLA): no hay patrón que diga que `id` debe pertenecer al usuario.
- **Lógica de negocio**: que un saldo no puede venir del cliente no es una regla sintáctica.
- **Estado de configuración**: HSTS, CSP y CORS viven en el servidor, no en el repositorio.
- **El secreto literal**: `p/secrets` reporta el uso de la llave en la línea 54, no la llave en la 21.

**ZAP** razona sobre respuestas HTTP. Es el único que ve las cabeceras que faltan y el que mide 61
pruebas pasivas. No puede ver:
- **Nada detrás del login**: sin sesión, `/rest/basket/{id}` responde 401 y el BOLA queda invisible.
- **El modelo de datos**: no sabe que el carrito 9 pertenece a otro usuario.
- **Inyección**: el escaneo baseline es pasivo; no fuzzea `q` ni construye cargas.
- **Lógica de negocio**: no intenta una cantidad negativa ni un rol admin.

**La revisión humana** razona sobre el diseño. Es la única que encontró BOLA, saldo, rol, MD5,
cookies, rate limit y logging. Su debilidad es la opuesta: no es exhaustiva. Se le escaparon cuatro
rutas con `sendFile` que Semgrep sí encontró, y no puede repetirse igual dos veces.

### 4.4 Coste, ruido y precisión

| Fuente | Precisión | Ruido de triage | Escalable | Depende de |
|---|:---:|---|---|---|
| Semgrep | 8/8 (100 %) | Bajo: 8 hallazgos, todos reales | Sí, en CI | Reglas y lenguaje |
| ZAP | 5/6 (83 %) | Medio: 1 falso positivo entre 6, más 3 informativas | Sí, en CI | Sesión y cobertura de rutas |
| Humana | 25/25 (100 %) | Ninguno, pero caro | No | Conocimiento del revisor |

**Conclusión de la comparativa:** las tres fuentes son complementarias, no intercambiables. La unión
cubre lo que ninguna alcanza sola; la intersección es casi vacía. Un pipeline que solo corra Semgrep
y ZAP no habría encontrado el BOLA, el saldo ni el rol admin. Una revisión humana sin herramientas no
habría encontrado las cuatro rutas de `sendFile` ni las cabeceras.

---

## 5. Evidencia de cierre

### 5.1 Caso demostrado: BOLA del carrito (H05 · ASVS 8.2.2)

| Elemento | Evidencia |
|---|---|
| **Falla** | `BasketModel.findOne({ where: { id } })` en `app-src/routes/basket.ts:19` |
| **Reproducción** | Usuario A pide `/rest/basket/{id de B}` y recibe **200** con el carrito y el `UserId` de B |
| **Control** | `where: { id, UserId: user.data.id }`; ajeno e inexistente → **404**; sin token → **401** |
| **Prueba roja** | `python3 seguridad/lab2/tests/test_bola_basket.py` → `AssertionError: 200 != 404` |
| **Prueba verde** | `BASE_URL=http://127.0.0.1:3001 python3 …` → `Ran 3 tests — OK` |
| **Regresión** | Carrito propio 200, búsqueda 200, agregar ítem 200, inexistente 404, `abc` 404 |
| **Commit** | `70dac5f` en la rama `lab2/verificacion-asvs` |
| **Pull request** | https://github.com/feanve/desarrollo-seguro-ucp/pull/1 |

La prueba tiene tres casos porque el control puede fallar de tres formas: dejar pasar el carrito
ajeno (el BOLA), romper el carrito propio (falso positivo del control) o permitir el acceso sin
sesión. Una prueba que solo verifica el caso feliz no demuestra nada.

### 5.2 Catálogo de cierre de los hallazgos priorizados

| ID | Control que lo cierra | Cambio concreto | Cómo se verifica | Estado |
|---|---|---|---|---|
| H01 | Consulta parametrizada | `replacements` en `search.ts:23` | `?q=' OR '1'='1` no devuelve el catálogo | Diseñado |
| H02 | Gestión de secretos | Llave en variable de entorno + rotación | `gitleaks detect` sin hallazgos; tokens viejos inválidos | Diseñado |
| H03 | Lista blanca de campos | `UserModel.create({ email, password, role: 'customer' })` | Registro con `role: 'admin'` devuelve `customer` | Diseñado |
| H04 | Cálculo en el servidor | Monto desde el recibo del pago, no de `req.body` | Recarga sin pago no acredita saldo | Requiere pasarela |
| H05 | Filtro por dueño | `where: { id, UserId }` en `basket.ts` | `test_bola_basket.py` | **Implementado** |
| H06 | Contención de ruta | `path.resolve` + `startsWith(base)` | `curl --path-as-is /ftp/../package.json` → 403 | Diseñado |
| H07 | Retirar la ruta | No servir `encryptionkeys/` por HTTP | `GET /encryptionkeys/…` → 404 | Diseñado |
| H08 | Eliminar `eval` | `JSON.parse` o saneamiento + CSP | Nombre con `#{...}` no se ejecuta | Diseñado |
| H09 | KDF lento | `argon2id` o `bcrypt` con sal | Hash deja de ser MD5; login sigue funcionando | Requiere migración |
| H10 | Retirar la ruta | No servir `logs/` por HTTP | `GET /support/logs/…` → 404 | Diseñado |
| H11 | Cabecera `Content-Disposition` | Forzar descarga y `X-Content-Type-Options` | Un HTML subido no se renderiza | Diseñado |
| H12 | Comparación de origen | `new URL(url).origin === allowedOrigin` | `github.com.evil.com` se rechaza | Diseñado |
| H13 | Validación de rango | `Number.isInteger(q) && q > 0 && q <= 100` | `quantity: -2` → 400; total > 0 | Diseñado |
| H14 | Atributos de cookie | `{ httpOnly: true, secure: true, sameSite: 'strict' }` | `Set-Cookie` con los tres atributos | Diseñado |
| H15 | Allowlist de algoritmo | `expressJwt({ algorithms: ['RS256'], audience, issuer })` | Token con `alg: none` rechazado | Diseñado |
| H16 | Middleware de límite | `express-rate-limit` en `/rest/user/login` | El intento 11 responde 429 | Diseñado |
| H17 | CSP + `Referrer-Policy` | `helmet` en el servidor | `curl -sI` muestra `Content-Security-Policy` | Diseñado |
| H18 | Registro de eventos | Log estructurado de login fallido y 403 | El log contiene evento, usuario e IP, sin contraseña | Diseñado |
| H19 | — | Descartar el header o restringirlo al origen propio | No cambia el riesgo: falso positivo | Descartado |

> **Honestidad de alcance.** Solo H05 está implementado y demostrado. Los demás están **diseñados**:
> se sabe cuál es el control, dónde va y cómo se verifica, pero no se aplicaron. Un informe que
> declare cerrado lo que no se probó vale menos que uno que distinga «cerrado» de «planificado».

### 5.3 El patrón de un cierre demostrable

Sirve para cualquiera de los hallazgos anteriores:

1. **Reproducir** la falla con un comando o una prueba que falle (rojo).
2. **Aplicar** el control en el punto exacto, no después de cargar el dato.
3. **Probar** que el ataque falla (verde) y que el uso legítimo sigue funcionando (regresión).
4. **Cubrir el borde**: sin sesión, recurso inexistente, identificador no numérico.
5. **Guardar la evidencia**: commit, comando, salida y enlace al PR.

Una corrección sin los pasos 1 y 3 es una opinión, no una demostración.

### 5.4 Correcciones listas para aplicar

**H01 · SQLi (`app-src/routes/search.ts:23`)**

```ts
const criteria = String(req.query.q ?? '').slice(0, 200)
const [products]: any = await models.sequelize.query(
  `SELECT * FROM Products
   WHERE ((name LIKE ? OR description LIKE ?) AND deletedAt IS NULL)
   ORDER BY name`,
  { replacements: [`%${criteria}%`, `%${criteria}%`] }
)
```

Verificación: `curl -s 'http://127.0.0.1:3000/rest/products/search?q=%27%20OR%20%271%27%3D%271'`
debe devolver una lista vacía, no los 45 productos.

**H03 · Rol en el registro (`POST /api/Users`, controlador en `server.ts`)**

```ts
const { email, password, passwordRepeat } = req.body
const user = await UserModel.create({ email, password, role: 'customer' })
```

Verificación: registrar con `"role": "admin"` y comprobar que la respuesta dice `"role": "customer"`.

**H13 · Cantidad negativa (`app-src/routes/basketItems.ts:43`)**

```ts
const quantity = Number(req.body.quantity)
if (!Number.isInteger(quantity) || quantity <= 0 || quantity > 100) {
  return res.status(400).json({ status: 'error', message: 'Invalid quantity' })
}
```

Verificación: `POST /api/BasketItems` con `quantity: -2` responde 400; la orden ya no puede dar
total negativo.

**H06 · Path traversal (`app-src/routes/fileServer.ts:32`)**

```ts
const base = path.resolve('ftp')
const target = path.resolve(base, file)
if (!target.startsWith(base + path.sep)) {
  return res.status(403).end()
}
```

Verificación: `curl --path-as-is 'http://127.0.0.1:3000/ftp/../package.json'` responde 403.

**H17 · CSP (`server.ts`, fuera de `app-src/`)**

```ts
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'self'"]
    }
  },
  referrerPolicy: { policy: 'no-referrer' },
  hsts: { maxAge: 31536000, includeSubDomains: true }
}))
```

Verificación: `curl -sI http://127.0.0.1:3000/ | grep -i content-security-policy`.

### 5.5 Lo que no se debe cerrar a la ligera

| Hallazgo | Por qué no se corrige en el laboratorio |
|---|---|
| H02 (llave) | Rotarla invalida todas las sesiones y los usuarios sembrados; exige coordinar el despliegue |
| H04 (saldo) | Sin una pasarela real no hay recibo que verificar; un parche de validación daría falsa seguridad |
| H09 (MD5) | Cambiar el algoritmo exige migrar los hashes existentes en la base |
| H17 (CSP) | Una CSP mal configurada rompe la SPA; requiere probar cada directiva con la aplicación completa |

---

## 6. Guion de dos minutos para sustentar

1. **Qué se hizo:** revisión ASVS de 25 filas, Semgrep sobre `app-src` y ZAP contra `127.0.0.1:3000`.
2. **Qué encontró cada fuente:** Semgrep 8 patrones (4 exclusivos), ZAP 6 alertas (3 exclusivas y 1
   falso positivo), la revisión humana 21 filas que ninguna herramienta vio.
3. **El criterio:** se valoró por impacto × probabilidad, no por la severidad de la herramienta. La
   SQLi que Semgrep llamó `warning` es riesgo 25; el CORS que ZAP llamó Medium es riesgo 1.
4. **La comparativa:** ningún hallazgo lo vieron las tres fuentes. La unión cubre; la intersección
   es casi vacía. Por eso se usan las tres.
5. **El cierre:** se corrigió el BOLA con prueba roja/verde, regresión y PR. Los demás tienen control,
   cambio y verificación definidos, y se declaran como planificados, no como cerrados.
6. **La lección:** una herramienta no demuestra nada por sí sola; la evidencia es la reproducción, la
   prueba y la salida del comando.

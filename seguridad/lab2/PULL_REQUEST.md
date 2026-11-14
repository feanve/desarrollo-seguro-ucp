# fix(authz): exigir dueño del carrito en `GET /rest/basket/{id}`

**Pull request:** https://github.com/feanve/desarrollo-seguro-ucp/pull/1
**Rama:** `lab2/verificacion-asvs` → `main` (fork `feanve/desarrollo-seguro-ucp`)
**Laboratorio:** 2 · Sección 4: corregir una falla con su prueba

---

## 1. Requisito y amenaza

| Elemento | Valor |
|---|---|
| **Requisito ASVS 5.0** | **8.2.2** — *Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA).* |
| Complementario | **8.3.1** — la autorización se aplica en una capa de servicio confiable |
| **Amenaza del Lab 1** | **I01** — IDOR en visualización de carritos y descarga de facturas ajenas (`/rest/basket/{id}`), severidad **Alta** (riesgo 9) |
| **CWE** | CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-284 |

## 2. Descripción de la falla

`app-src/routes/basket.ts` buscaba el carrito solo por el `id` de la URL:

```ts
const id = req.params.id
const basket = await BasketModel.findOne({ where: { id }, include: [...] })
```

No comparaba ese `id` con el usuario autenticado. Cualquier sesión válida podía leer el carrito
de otra persona cambiando el número en la URL. El bloque `challengeUtils.solveIf(...)` detectaba el
acceso indebido, pero **no lo bloqueaba**.

Prueba previa al cambio:

```text
FAIL: test_carrito_ajeno_responde_404
AssertionError: 200 != 404 : BOLA: el usuario A leyó el carrito 9 del usuario B
(UserId 30) con HTTP 200: {"status":"success","data":{"id":9,...,"UserId":30,...}}
```

## 3. Cambio aplicado

`app-src/routes/basket.ts`:

```diff
-      const basket = await BasketModel.findOne({ where: { id }, include: [...] })
+      const user = security.authenticatedUsers.from(req)
       challengeUtils.solveIf(challenges.basketAccessChallenge, () => {
-        const user = security.authenticatedUsers.from(req)
         const isValidId = id && id !== 'undefined' && id !== 'null' && id !== 'NaN'
         return user && isValidId && user.bid && user?.bid != parseInt(id, 10)
       })
+
+      // Control ASVS 5.0 · 8.2.2: el carrito debe pertenecer al usuario autenticado.
+      if (user == null) {
+        res.status(401).json({ status: 'error', message: 'Unauthorized' })
+        return
+      }
+      if (!Number.isInteger(Number(id))) {
+        res.status(404).json({ status: 'error', message: 'Basket not found' })
+        return
+      }
+
+      const basket = await BasketModel.findOne({ where: { id, UserId: user.data.id }, include: [...] })
+
+      // Ajeno e inexistente responden igual: no se filtra la existencia del recurso.
+      if (basket == null) {
+        res.status(404).json({ status: 'error', message: 'Basket not found' })
+        return
+      }
```

Decisiones de diseño:

- **`404` en lugar de `403`** para un carrito ajeno: así el atacante no puede distinguir «existe pero no es mío» de «no existe», que es lo que pedía el requisito verificable del Lab 1.
- **Sin token → `401`**, coherente con el resto de la API.
- **`id` no numérico → `404`**, para no llegar nunca a la consulta.
- El filtro se aplica en la consulta (`where: { id, UserId }`), no después de traer el registro: el objeto ajeno no se carga en memoria.

## 4. Cómo ejecutar la prueba

La prueba está en `seguridad/lab2/tests/test_bola_basket.py` y solo necesita `requests`.

### 4.1 Ver el fallo (aplicación vulnerable en `:3000`)

```bash
cd /home/andru/Documentos/Repo/desarrollo-seguro-ucp-github
python3 seguridad/lab2/tests/test_bola_basket.py
```

Resultado esperado: **1 fallo**, `test_carrito_ajeno_responde_404` (`200 != 404`). Las otras dos
pruebas pasan, porque el carrito propio y el acceso sin token ya funcionaban.

### 4.2 Ver el control (misma build con la ruta corregida en `:3001`)

```bash
docker build -t juice-shop-fixed:lab2 seguridad/lab2/fix
docker run -d --name juice-shop-fixed -p 127.0.0.1:3001:3000 juice-shop-fixed:lab2

BASE_URL=http://127.0.0.1:3001 python3 seguridad/lab2/tests/test_bola_basket.py
```

Resultado esperado: **3 pruebas OK**.

La imagen `seguridad/lab2/fix` parte de `bkimminich/juice-shop:latest` y reemplaza únicamente
`/juice-shop/build/routes/basket.js` por su equivalente compilado del cambio. Es la forma de
ejecutar el control sobre la misma aplicación real que se escaneó, sin reconstruir todo Juice Shop,
cuyo `package.json` no forma parte de `app-src/`.

### 4.3 Regresión

El control no rompe el resto del flujo: con la imagen corregida se verificó

```text
GET /                                   -> 200
GET /rest/products/search?q=apple       -> 200
POST /api/BasketItems                   -> 200
GET /rest/basket/{propio}               -> 200 (con productos)
GET /rest/basket/{inexistente}          -> 404
GET /rest/basket/abc                    -> 404
GET /rest/basket/{ajeno}                -> 404
```

## 5. Cómo se encontró

La revisión humana de ASVS (fila 9 de `seguridad/lab2/ASVS.md`) leyó `basket.ts` y vio que la
consulta no filtraba por dueño. **Semgrep no lo detectó** (no tiene una regla que relacione el
objeto con el usuario) y **ZAP tampoco** (sin sesión no llega a `/rest/basket/{id}`). Es el ejemplo
que responde la pregunta de la sección 5: la revisión de diseño encontró lo que las herramientas
no pueden ver.

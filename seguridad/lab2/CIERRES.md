# Cierres adicionales con prueba

**Rama:** `lab2/cierres-adicionales`
**Alcance:** dos controles de la revisión ASVS que no cubría el PR del BOLA.
**Aplicación:** OWASP Juice Shop, misma build de `bkimminich/juice-shop:latest`.

---

## 1. Autorización por función · ASVS 8.3.1

### La falla

`GET /rest/user/authentication-details` exige sesión (sin token responde 401), pero no comprueba
el rol. Cualquier usuario `customer` recibe la lista completa de usuarios con correo, rol e IP del
último inicio de sesión:

```text
GET /rest/user/authentication-details
Authorization: Bearer <token de customer>
→ HTTP 200
{"status":"success","data":[{"id":1,"email":"admin@juice-sh.op","role":"admin", ...}]}
```

`app-src/routes/authenticatedUsers.ts:10` ejecuta `UserModel.findAll()` sin mirar quién pregunta.
`security.isAuthorized` existe en `app-src/lib/insecurity.ts:52`, pero ninguna ruta lo usa para
verificar roles.

### El control

```ts
async function retrieveUserList (req: Request, res: Response, next: NextFunction) {
  try {
    // Control ASVS 5.0 · 8.3.1: solo un administrador puede listar a todos los usuarios.
    const requester = security.authenticatedUsers.from(req)
    if (requester?.data?.role !== 'admin') {
      res.status(403).json({ status: 'error', message: 'Forbidden' })
      return
    }

    const users = await UserModel.findAll()
```

Decisiones:

- **403 y no 404**: el recurso existe y el usuario está autenticado; ocultar la ruta no aporta y
  rompería la semántica de la API.
- **El rol se lee de la sesión del servidor**, no de un campo del cuerpo ni del cliente.
- **Falla cerrado**: si la sesión no está en el mapa, no hay rol y se responde 403.

### Prueba

`seguridad/lab2/tests/test_authz_usuarios.py` → 3 casos: customer, admin y sin token.

**Rojo** (aplicación vulnerable en `:3000`):

```text
FAIL: test_customer_no_puede_listar_usuarios
AssertionError: 200 != 403 : El customer obtuvo HTTP 200: {"status":"success","data":[...]}
Ran 3 tests — FAILED (failures=1)
```

**Verde** (misma build con el control, `:3002`):

```text
test_customer_no_puede_listar_usuarios ... ok
test_admin_si_puede_listar_usuarios ... ok
test_sin_token_responde_401 ... ok
Ran 3 tests — OK
```

---

## 2. Límite de cantidad · ASVS 2.3.2

### La falla

`POST /api/BasketItems` acepta `quantity` negativa o cero. La validación de
`app-src/routes/basketItems.ts:94` solo comprueba stock:

```ts
if (!product.limitPerUser || (product.limitPerUser && product.limitPerUser >= quantity) || security.isDeluxe(req)) {
  if (product.quantity >= quantity) { // con -2, 200 >= -2 es verdadero
    next()
```

Con `quantity: -2` la orden se crea y `order.ts:93` calcula `itemPrice * quantity`, produciendo un
total negativo. Es la amenaza **T01** del Lab 1.

```text
POST /api/BasketItems  {"ProductId":1,"BasketId":11,"quantity":-2}
→ HTTP 200
{"status":"success","data":{"id":12,"quantity":-2, ...}}
```

### El control

```ts
async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  const quantityNumber = Number(quantity)
  // Control ASVS 5.0 · 2.3.2: la cantidad debe ser un entero positivo y acotado.
  if (!Number.isInteger(quantityNumber) || quantityNumber <= 0 || quantityNumber > 1000) {
    res.status(400).json({ error: 'Invalid quantity' })
    return
  }

  const product = await QuantityModel.findOne({ where: { ProductId: id } })
```

Decisiones:

- **Validar en `quantityCheck`** cubre creación y actualización: los dos middlewares
  (`quantityCheckBeforeBasketItemAddition` y `…Update`) pasan por la misma función.
- **Entero, no decimal**: una fracción de ítem tampoco es una línea de pedido válida.
- **Tope de 1000**: el límite real de stock se sigue aplicando después; el tope evita valores
  absurdos que desborden el cálculo.

### Prueba

`seguridad/lab2/tests/test_cantidad_negativa.py` → 3 casos: `-2`, `0` y `2`.
La prueba vacía el carrito antes de cada caso porque `BasketItems` tiene
`UNIQUE (ProductId, BasketId)`: un ítem residual haría fallar el segundo intento con 500 y
escondería el comportamiento real.

**Rojo** (`:3000`):

```text
FAIL: test_cantidad_negativa_rechazada
AssertionError: 200 != 400 : Se aceptó quantity=-2 con HTTP 200
FAIL: test_cantidad_cero_rechazada
AssertionError: 200 != 400 : Se aceptó quantity=0 con HTTP 200
Ran 3 tests — FAILED (failures=2)
```

**Verde** (`:3002`):

```text
test_cantidad_cero_rechazada ... ok
test_cantidad_negativa_rechazada ... ok
test_cantidad_positiva_aceptada ... ok
Ran 3 tests — OK
```

---

## 3. Cómo reproducirlo

```bash
cd /home/andru/Documentos/Repo/desarrollo-seguro-ucp-github

# 1. Rojo: aplicación vulnerable
python3 seguridad/lab2/tests/test_authz_usuarios.py
python3 seguridad/lab2/tests/test_cantidad_negativa.py

# 2. Verde: misma build con los dos controles
docker build -t juice-shop-hardened:lab2 seguridad/lab2/cierres
docker rm -f juice-shop-hardened 2>/dev/null
docker run -d --name juice-shop-hardened -p 127.0.0.1:3002:3000 juice-shop-hardened:lab2

for i in $(seq 1 30); do
  curl -s -o /dev/null http://127.0.0.1:3002 && break
  sleep 1
done

BASE_URL=http://127.0.0.1:3002 python3 seguridad/lab2/tests/test_authz_usuarios.py
BASE_URL=http://127.0.0.1:3002 python3 seguridad/lab2/tests/test_cantidad_negativa.py
```

La imagen `seguridad/lab2/cierres` reemplaza **solo** las dos rutas compiladas de estos controles.
No incluye el arreglo del BOLA: ese vive en `seguridad/lab2/fix/` y se verifica en `:3001`, para que
cada prueba aisle un control.

---

## 4. Regresión

Con la imagen endurecida en `:3002`:

| Petición | Resultado |
|---|---|
| `GET /` | 200 |
| `GET /rest/products/search?q=apple` | 200 |
| `GET /rest/basket/{propio}` | 200 |
| `POST /api/BasketItems` con `quantity: 3` | 200 |
| `GET /rest/user/authentication-details` (customer) | 403 |
| `GET /rest/user/authentication-details` (admin) | 200 |
| `GET /rest/user/authentication-details` (sin token) | 401 |

---

## 5. Lo que estos cierres no resuelven

- **El BOLA del carrito** sigue abierto en esta imagen; se corrigió en el PR del laboratorio
  (`seguridad/lab2/fix/`). Son controles independientes y se verifican por separado.
- **La cantidad negativa ya existente** en la base no se limpia: el control impide crearla, no
  corrige datos históricos. Un cierre completo incluiría una migración de datos.
- **Los roles siguen siendo asignables** en el registro (hallazgo E01). Este control protege la
  lectura de la lista, no la asignación del rol.

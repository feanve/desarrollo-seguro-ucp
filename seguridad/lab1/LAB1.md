# Laboratorio 1 · Modelo de Amenazas de la Aplicación del Equipo

**Estudiante / Integrante:** Felipe A Velez (`andru`)  
**Curso:** Desarrollo Seguro de Software · Universidad Católica de Pereira (UCP)  
**Sesión:** Sesión 2 · Modelo de amenazas con OWASP Threat Dragon y STRIDE  
**Aplicación Analizada:** OWASP Juice Shop (Desplegada localmente en `http://127.0.0.1:3000`)  
**Flujo Acotado:** Registro, Autenticación (JWT), Carrito de Compras, Checkout / Pago con Pasarela y Facturación  

---

## 1. ¿En qué estamos trabajando?

### Contexto y Alcance del Sistema
Para este laboratorio se modeló a fondo el flujo transaccional crítico de **OWASP Juice Shop**, una aplicación web moderna con arquitectura desacoplada conformada por:
- **Frontend SPA:** Single Page Application construida en Angular, ejecutada en el navegador del cliente.
- **Backend API REST:** Servicio Node.js con Express que implementa la lógica de autenticación, control de inventario, liquidación de canastas y emisión de órdenes.
- **Persistencia de Datos:** Base de datos relacional SQLite gestionada a través del ORM Sequelize.
- **Servicios Auxiliares y Terceros:** Worker de generación de facturas en formato PDF, sistema de archivos local para comprobantes descargables (`/ftp/`) y pasarela externa simulada para procesamiento de tarjetas de crédito.

### Diagrama de Flujo de Datos (DFD)
El modelo fue construido y exportado en formato **OWASP Threat Dragon 2.3+** (`modelo.json`), definiendo los siguientes componentes:

1. **Actores Externos:**
   - `Cliente Web (Navegador / SPA)`: Contexto del usuario final o de un atacante remoto que interactúa con la interfaz.
   - `Administrador (Backoffice)`: Usuario con privilegios de gestión.
   - `Pasarela de Pagos (Proveedor Externo)`: Servicio financiero externo encargado del procesamiento de cobros mediante peticiones HTTPS REST.

2. **Procesos:**
   - `API Backend REST (Node.js / Express)`: Proceso central que atiende peticiones REST, valida tokens JWT, gestiona carritos y coordina transacciones.
   - `Generador de Facturas (Worker PDF / FS)`: Proceso de fondo que compone el archivo PDF de cada orden aprobada y lo escribe en el almacenamiento.

3. **Almacenes de Datos (Data Stores):**
   - `Base de Datos Relacional (SQLite / Sequelize)`: Almacena credenciales de usuario, catálogo de productos, órdenes de compra y cupones de descuento.
   - `Almacén de Archivos (Facturas / PDF)`: Directorio del servidor donde residen los archivos `.pdf` descargables.
   - `LocalStorage del Navegador`: Almacenamiento local del lado del cliente donde se persiste el token JWT tras un login exitoso.

4. **Límites de Confianza (Trust Boundaries):**
   - **Límite 1 (`Internet | Perímetro Interno del Servidor`):** Separa al cliente (red pública no confiable) del servidor de la aplicación. Cruza todo el tráfico HTTP de entrada y salida.
   - **Límite 2 (`Backend API | Persistencia de Datos`):** Separa la lógica de aplicación del acceso a bajo nivel a la base de datos relacional y al sistema de archivos local.
   - **Límite 3 (`Backend API | Pasarela Externa (Terceros)`):** Delimita el perímetro entre el backend interno y los servicios web de terceros en Internet.

5. **Flujos de Datos Principales:**
   - **F1:** `POST /rest/user/login` (Cliente → API) | Protocolo: HTTPS | Cifrado: Sí | Red pública: Sí.
   - **F2:** `Respuesta con Token JWT` (API → Cliente) | Protocolo: HTTPS | Cifrado: Sí | Red pública: Sí.
   - **F3:** `Guardar Token en Almacén Local` (Cliente → LocalStorage) | Protocolo: DOM Storage API | Cifrado: No | Red pública: No.
   - **F4:** `POST /rest/basket/checkout` (Cliente → API) | Protocolo: HTTPS | Cifrado: Sí | Red pública: Sí.
   - **F5:** `Consultas ORM / SQL` (API → Base de Datos) | Protocolo: IPC / SQLite | Cifrado: No | Red pública: No.
   - **F6:** `POST /charges` (Cobro Pasarela) (API → Pasarela) | Protocolo: HTTPS | Cifrado: Sí | Red pública: Sí.
   - **F7:** `Respuesta / Webhook de Pago` (Pasarela → API) | Protocolo: HTTPS | Cifrado: Sí | Red pública: Sí.
   - **F8:** `Orden Aprobada / Trigger Factura` (API → Generador PDF) | Protocolo: IPC Interno | Cifrado: No | Red pública: No.
   - **F9:** `Escritura de Factura PDF` (Generador PDF → Almacén Archivos) | Protocolo: File System IO | Cifrado: No | Red pública: No.
   - **F10:** `GET /ftp/{invoice}.pdf` (Cliente → API / Almacén) | Protocolo: HTTPS | Cifrado: Sí | Red pública: Sí.

---

## 2. ¿Qué puede salir mal? (Catálogo STRIDE)

Se recorrió cada elemento del DFD aplicando la metodología **STRIDE**. Se identificaron 14 amenazas técnicas y de lógica de negocio:

> **Nota de trazabilidad:** el modelo exportado registra **22 vínculos amenaza-elemento** porque una misma amenaza se asocia a todos los elementos afectados; las **amenazas únicas son 14**.

| Letra | ID | Amenaza Identificada | Elemento Afectado | Severidad |
|---|---|---|---|---|
| **S** | S01 | Falsificación de Tokens JWT por clave débil o validación deficiente del encabezado `alg` | API Backend REST | Media |
| **S** | S02 | Suplantación mediante preguntas de seguridad triviales o públicas en el reset de contraseña | API Backend REST | Media |
| **T** | **T01** | **[LÓGICA DE NEGOCIO] Manipulación de precios y cantidades negativas en el payload de Checkout** | API Backend REST / F4 | **Alta** |
| **T** | T02 | Inyección SQL en búsqueda de catálogo y filtros de productos (`/rest/products/search`) | Flujo SQL / BD | **Alta** |
| **T** | T03 | Manipulación de interfaz mediante Stored XSS en reseñas y comentarios de productos | Frontend SPA / Cliente | Media |
| **R** | R01 | Repudio de compras completadas por carencia de bitácora transaccional inmutable | Base de Datos / API | Media |
| **R** | R02 | Repudio de modificación de credenciales y datos de despacho sin trazabilidad de IP | API Backend REST | Media |
| **I** | I01 | IDOR en visualización de carritos y descarga de facturas ajenas (`/rest/basket/{id}`) | API Backend / Almacén | **Alta** |
| **I** | I02 | Exposición de trazas internas y configuración mediante modo depuración habilitado | API Backend REST | Media |
| **I** | I03 | Divulgación masiva de credenciales y datos personales (Ley 1581) por falta de cifrado en reposo | Base de Datos (SQLite) | **Alta** |
| **D** | D01 | Saturación y fuerza bruta por carencia de Rate Limiting en autenticación y checkout | API Backend REST | Media |
| **D** | D02 | Agotamiento de memoria por consultas masivas de catálogo sin paginación máxima obligatoria | Base de Datos / API | Media |
| **E** | E01 | Asignación Masiva (*Mass Assignment*) de rol administrador en registro (`POST /api/Users`) | API Backend REST | **Alta** |
| **E** | E02 | Falla abierta y aprobación indebida ante fallos o excepciones de la pasarela de pagos | Flujo Callback / API | **Alta** |

> **Amenaza de Lógica de Negocio Destacada (T01):**  
> En el endpoint `POST /rest/basket/{id}/checkout` o al agregar ítems al carrito, un cliente intercepta la solicitud y modifica el precio unitario a un valor ínfimo (ej. $0.01) o inserta cantidades negativas en artículos costosos (ej. `-2` botellas de jugo premium y `+1` jugo básico). Al sumar las líneas en el servidor confiando en los datos recibidos del cliente, el total a pagar se reduce a cero o resulta en saldo a favor. Esta vulnerabilidad evade completamente WAFs y escáneres SAST porque la sintaxis HTTP y JSON es 100% válida.

---

## 3. ¿Qué vamos a hacer al respecto?

### Calificación de Riesgo (Impacto × Probabilidad)
Cada amenaza fue calificada bajo la fórmula:
$$\text{Riesgo} = \text{Impacto (1–3)} \times \text{Probabilidad (1–3)}$$
- **Riesgo 7–9:** Severidad **Alta (High)**.
- **Riesgo 4–6:** Severidad **Media (Medium)**.
- **Riesgo 1–3:** Severidad **Baja (Low)**.

| ID | Amenaza | Impacto | Probabilidad | Riesgo (I × P) | Severidad Threat Dragon |
|---|---|:---:|:---:|:---:|:---:|
| **T01** | Manipulación de precios y cantidades negativas en Checkout | 3 | 3 | **9** | **Alta (High)** |
| **T02** | Inyección SQL en búsqueda y filtros del catálogo | 3 | 3 | **9** | **Alta (High)** |
| **I01** | IDOR en carritos y descarga de facturas ajenas | 3 | 3 | **9** | **Alta (High)** |
| **E01** | Asignación Masiva (*Mass Assignment*) de rol `admin` en registro | 3 | 3 | **9** | **Alta (High)** |
| **E02** | Falla abierta ante excepciones o timeout de la pasarela | 3 | 3 | **9** | **Alta (High)** |
| **I03** | Divulgación de datos personales por falta de cifrado en reposo | 3 | 2 | **6** | Media (Medium) |
| **S01** | Falsificación de Tokens JWT por clave débil | 3 | 2 | **6** | Media (Medium) |
| **S02** | Suplantación por preguntas de seguridad triviales | 2 | 3 | **6** | Media (Medium) |
| **D01** | Ataques de fuerza bruta y saturación sin Rate Limiting | 2 | 3 | **6** | Media (Medium) |
| **T03** | Stored XSS en reseñas y opiniones | 2 | 2 | **4** | Media (Medium) |
| **R01** | Repudio de compras por falta de bitácora transaccional | 2 | 2 | **4** | Media (Medium) |
| **R02** | Repudio de modificación de credenciales y despacho | 2 | 2 | **4** | Media (Medium) |
| **I02** | Exposición de trazas de error con modo debug activo | 2 | 2 | **4** | Media (Medium) |
| **D02** | Agotamiento de memoria por consultas sin paginación fija | 2 | 2 | **4** | Media (Medium) |

---

### Top 5 de Mayor Riesgo y Requisitos de Seguridad Verificables

| ID | Amenaza | STRIDE | I × P | Requisito de seguridad (verificable) | ASVS 5.0 | Cómo lo verificamos |
|---|---|:---:|:---:|---|:---:|---|
| **T01** | Manipulación de precios y cantidades en el Checkout | **T** | 3 × 3 = **9** | El servidor debe ser la única fuente de verdad para precios, subtotales y descuentos; el backend debe recalcular el importe total consultando la base de datos y debe rechazar con HTTP `400 Bad Request` cualquier solicitud con cantidades $\le 0$ o precios suministrados por el cliente. | **V2**<br/>(Validación y Lógica de Negocio) | **Prueba de integración automatizada:** enviar un payload JSON con `price: 0.01` y `quantity: -2` al endpoint de checkout; verificar que la API responda con código HTTP 400 y que el saldo de la orden en la base de datos permanezca con el valor real del catálogo. |
| **T02** | Inyección SQL en búsqueda y filtros de productos | **T** | 3 × 3 = **9** | Toda consulta a la base de datos relacional debe construirse utilizando sentencias preparadas parametrizadas en el ORM (Sequelize) o sentencias SQL con placeholders obligatorios, prohibiendo estrictamente la concatenación e interpolación dinámica de cadenas. | **V1**<br/>(Codificación y Sanitización) | **Escaneo SAST y DAST:** regla de análisis estático en Semgrep (`p/sql-injection`) en el pipeline de CI/CD, sumado a una prueba dinámica con OWASP ZAP inyectando operadores SQL (`' OR '1'='1`) verificando que se devuelvan resultados literales sin alterar el plan de ejecución. |
| **I01** | IDOR en visualización de carritos y facturas ajenas | **I** | 3 × 3 = **9** | Toda consulta hacia `/rest/basket/{id}` o descarga de comprobantes en `/ftp/{invoice}.pdf` debe aplicar el principio de mediación completa: el identificador del usuario autenticado en el token JWT debe coincidir obligatoriamente con el propietario del recurso; ante una petición a un recurso ajeno o inexistente, el sistema debe responder estrictamente `404 Not Found`. | **V8**<br/>(Autorización) | **Prueba de control de acceso automatizada:** autenticar dos usuarios distintos (Usuario A y Usuario B); el Usuario A realiza una solicitud GET hacia `/rest/basket/{id_de_B}`; verificar que la respuesta retorne código de estado HTTP 404 y que no se filtre ningún dato personal o de facturación. |
| **E01** | Asignación Masiva (*Mass Assignment*) de roles en registro | **E** | 3 × 3 = **9** | El controlador de creación de cuentas (`POST /api/Users`) debe utilizar un esquema de validación estricto (DTO / Data Transfer Object) con lista blanca exclusiva para los campos `email` y `password`, forzando el rol `customer` de manera inmutable en el backend y descartando cualquier propiedad no autorizada. | **V2** (Lógica)<br/>**V8** (Autorización) | **Prueba unitaria de controlador:** enviar una petición de registro con el cuerpo `{"email":"test@ucp.edu.co", "password":"...", "role":"admin"}`; consultar el registro en SQLite y validar que la propiedad `role` persista estrictamente con el valor por defecto `customer`. |
| **E02** | Falla abierta ante excepciones de la pasarela de pagos | **E** | 3 × 3 = **9** | El procesamiento de pagos debe implementar diseño con Fallo Seguro (*Fail Closed*): ante cualquier excepción de red, timeout o código de respuesta HTTP 5xx proveniente de la pasarela externa, la orden debe transicionar inmediatamente a estado `FALLIDA` o `PENDIENTE_VERIFICACION`, impidiendo la liberación de productos o expedición de factura aprobada. | **V16** (Errores)<br/>**V2** (Lógica) | **Prueba de integración con Mock:** simular caída de la pasarela (respuesta HTTP 500 y timeout de 10 segundos); verificar que la transacción se aborte, que la orden quede registrada como `FAILED` y que no se emita el archivo PDF de factura aprobada. |

---

## 4. ¿Hicimos un buen trabajo?

### 1. ¿Qué parte del sistema quedó fuera del modelo y por qué?
Quedó fuera del alcance el aprovisionamiento de la **infraestructura base subyacente** (el demonio y socket de Docker, la configuración del kernel de Linux y el hipervisor de virtualización), así como los flujos del **pipeline de CI/CD** (GitHub Actions / runners).  
**Justificación:** Se tomó la decisión de acotar el modelo exclusivamente al **dominio de la aplicación web y su lógica de negocio transaccional** (flujo de registro, carrito, pago y facturación), dado que allí residen los mayores riesgos de diseño y las vulnerabilidades explotables directamente por usuarios externos sobre el perímetro de la API.

### 2. ¿Qué amenaza les sorprendió?
Nos sorprendió profundamente la **manipulación de lógica de negocio en el cálculo de subtotales del carrito (T01)**:  
Al admitir cantidades negativas o confiar en precios provistos por el cliente, un atacante puede reducir el total de la compra a cero o incluso generar saldos a favor sin necesidad de vulnerar la autenticación, romper el cifrado ni inyectar código. Es una falla sumamente crítica que **los escáneres de seguridad SAST y DAST automáticos pasan completamente por alto**, ya que las solicitudes HTTP cumplen formalmente con todas las especificaciones sintácticas. Esto evidencia con claridad que **el modelado de amenazas y el diseño seguro no pueden ser reemplazados por herramientas automatizadas**.

---

## Estructura de Entregables del Laboratorio

Los tres archivos requeridos por la rúbrica del curso se encuentran generados en la carpeta `seguridad/lab1/`:

```text
seguridad/lab1/
├── modelo.json    # Modelo completo exportado compatible con OWASP Threat Dragon 2.3+
├── informe.pdf    # Reporte formal en PDF con inventario DFD, catálogo STRIDE y Top 5
└── LAB1.md        # Este documento con las tablas de la Sección 3 y respuestas de la Sección 4
```

# Firma y Provenance de Artefactos · Laboratorio 3

**Herramienta:** Cosign `2.4.1` (Sigstore)  
**Artefacto firmado:** Contenedor de demostración `devseguro-ucp/lab3:demo`

---

## 1. Importancia de la Firma y Provenance

Mientras que el **SBOM** responde a la pregunta *«¿qué componentes contiene el artefacto?»*, la **firma digital y el provenance** responden a:
* *«¿Quién construyó y publicó este artefacto?»* (Autenticidad y no repudio).
* *«¿Fue modificado o suplantado el artefacto tras salir del pipeline?»* (Integridad).
* *«¿Proviene de un pipeline autorizado y de una fuente confiable?»* (Trazabilidad SLSA).

Un atacante podría inyectar un contenedor malicioso que contenga librerías idénticas en versión pero con código adulterado; la firma criptográfica previene este vector en la cadena de suministro de software.

---

## 2. Gestión Segura de Llaves

* Se generó el par de llaves mediante `cosign generate-key-pair`.
* **Llave Privada (`cosign.key`):** **NUNCA** se almacena en el repositorio de control de versiones. Está explícitamente excluida por `.gitignore` (regla `*.key`, confirmada con `git check-ignore -v seguridad/lab3/cosign.key`).
* **Llave Pública (`cosign.pub`):** Se entrega en [`seguridad/lab3/cosign.pub`](file:///home/andru/Documentos/desarrollo-seguro-ucp/seguridad/lab3/cosign.pub) como evidencia para que cualquier consumidor o entorno de despliegue pueda verificar las firmas emitidas.

---

## 3. Comparación: Firma Local vs. Firma en CI (GitHub Actions)

| Dimensión | Laboratorio (Entorno Local) | CI (GitHub Actions / Auditgate) |
|---|---|---|
| **Mecanismo de Llave** | `cosign.key` almacenada localmente en la máquina del desarrollador con passphrase opcional. | **Keyless:** Sin llaves privadas de larga duración; utiliza tokens OIDC efímeros provistos por GitHub (`id-token: write`). |
| **Identidad Criptográfica** | Quien posee el archivo físico `cosign.key` y conoce su contraseña. | La identidad del workflow en ejecución (`workflow_ref`), el commit SHA y el repositorio exacto de GitHub. |
| **Caducidad y Ciclo de Vida** | Indefinida hasta que la llave expire o sea revocada manualmente. | Efímera (minutos): el certificado Fulcio se emite para la duración estricta del job de compilación. |
| **Evidencia y Auditoría** | Archivo local `firma-verificada.json`. | Registro inmutable en el log de transparencia pública (Rekor), attestation SLSA y firma asociada en el registro OCI. |

---

## 4. Verificación de la Firma

Comando de verificación ejecutado con la llave pública:

```bash
cosign verify --key seguridad/lab3/cosign.pub devseguro-ucp/lab3:demo > seguridad/lab3/firma-verificada.json
```

La salida generada y validada se encuentra en [`firma-verificada.json`](file:///home/andru/Documentos/desarrollo-seguro-ucp/seguridad/lab3/firma-verificada.json).

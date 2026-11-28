# Laboratorio 4 · Controles para aplicaciones con LLM y agentes

**Equipo:** Valencia Vélez · **Autor:** Felipe A. Vélez (`feanve`)
**Aplicación de referencia:** PrestaUCP (préstamo de equipos) · **Sandbox:** `127.0.0.1:8099`
**Fecha:** 27 de noviembre de 2026

> **Nota de alcance.** El curso anuncia el Lab 4 en `labs/README.md` («21 nov. · Controles para
> aplicaciones con LLM y agentes»), pero **no publicó un `LAB4.md`**. Este laboratorio se construyó
> sobre las fuentes oficiales de la sesión 5: `estudio/SESION_05.md`, el deck `deck/sesion-5/` y la
> sección 6 de `proyecto/PLANTILLA.md`.

## Qué contiene

Un asistente de préstamos con RAG (recupera actas y políticas) implementado **dos veces**:

| Versión | Qué hace | Qué demuestra |
|---|---|---|
| **Vulnerable** | concatena usuario + documento en un solo prompt y ejecuta lo que el modelo proponga | LLM01, LLM02, LLM05 y LLM06 explotables |
| **Guardada** | frontera instrucción/dato, lista blanca, roles, límites de negocio, HITL, salida neutralizada y auditoría | los mismos ataques no producen efecto |

No requiere dependencias externas: Python 3.10+ con biblioteca estándar. El «modelo» es un
simulador determinista y así se declara en el informe: se valida la **arquitectura** de control, no
la obediencia de un modelo comercial concreto.

## Inicio rápido

```bash
# 1. Pruebas (18)
python3 -m unittest discover -s seguridad/lab4/tests -v

# 2. Demo interactiva
python3 -m seguridad.lab4.demo.server
# abrir http://127.0.0.1:8099

# 3. Regenerar capturas y evidencias (requiere Chrome/Chromium)
python3 seguridad/lab4/scripts/capturar.py
```

## Estructura

```
seguridad/lab4/
├── INFORME.html / INFORME.pdf   ← informe completo con las 13 capturas
├── README.md                    ← este archivo
├── demo/                        ← servidor y agentes (sin dependencias)
├── tests/test_lab4.py           ← 18 pruebas: rojo → verde
├── capturas/                    ← 13 capturas reales del demo
├── evidencias/                  ← pruebas.txt, escenarios.txt, audit.jsonl, capturas.txt
└── scripts/capturar.py          ← reproduce las capturas y la evidencia
```

## Resultados

- **18/18 pruebas OK** (`Ran 18 tests in 0.017s`).
- **7 escenarios HTTP** verificados con marcador (ver `evidencias/escenarios.txt`).
- **13 capturas** con hash en `evidencias/capturas.txt`.
- **10 eventos de auditoría** sin datos personales.
- Ataques neutralizados: borrado por escalada de rol, creación de 30 préstamos por inyección
  indirecta, fuga de documento/correo/teléfono, HTML sin neutralizar y escritura sin confirmación.

## Mapa de controles

| Riesgo OWASP LLM | Control | Dónde |
|---|---|---|
| LLM01 · Prompt injection | frontera de canal + política de ejecución | `demo/guardrails.py`, `demo/llm.py` |
| LLM02 · Fuga de información | minimización + redacción de PII | `demo/guardrails.py` |
| LLM05 · Salida insegura | escape antes de renderizar | `demo/server.py` |
| LLM06 · Agencia excesiva | lista blanca, roles, límites, HITL | `demo/agent.py` |
| Auditoría | bitácora JSONL sin PII | `demo/guardrails.py` |

El detalle, las capturas y la justificación están en **[`INFORME.html`](INFORME.html)**.

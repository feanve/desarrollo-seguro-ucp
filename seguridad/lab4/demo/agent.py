"""Agentes del laboratorio: versión vulnerable y versión con guardarraíles."""
from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import llm, store
from .guardrails import (
    Auditoria,
    Confirmaciones,
    PolicyError,
    detectar_inyeccion,
    neutralizar_html,
    redactar_fila,
    redactar_pii,
    verificar_politica,
)

BASE = Path(__file__).resolve().parents[1]
_RUTA_AUDITORIA = os.environ.get("LAB4_AUDIT_PATH") or str(BASE / "evidencias" / "audit.jsonl")
AUDITORIA = Auditoria(_RUTA_AUDITORIA)
CONFIRMACIONES = Confirmaciones(ttl_segundos=300)
USUARIO_DEMO = store.usuario_por_id(1)  # Ana Torres, estudiante


@dataclass
class Resultado:
    modo: str
    escenario: str
    mensaje: str
    documento: str
    texto: str
    prompt: str
    tool_calls: list[dict] = field(default_factory=list)
    ejecutadas: list[dict] = field(default_factory=list)
    bloqueadas: list[dict] = field(default_factory=list)
    confirmacion: dict | None = None
    inyeccion: list[str] = field(default_factory=list)
    ignoradas: list[dict] = field(default_factory=list)
    filas: list[dict] = field(default_factory=list)
    notas: list[str] = field(default_factory=list)
    request_id: str = ""


def reset(limpiar_auditoria: bool = True) -> None:
    store.reset()
    CONFIRMACIONES._datos.clear()
    if limpiar_auditoria:
        AUDITORIA.limpiar()


def _nuevo_id() -> str:
    return "req-" + secrets.token_hex(4)


def _ejecutar(nombre: str, args: dict, usuario: dict) -> dict:
    if nombre == "listar_prestamos":
        filas = store.listar_prestamos(None if args.get("todos") else usuario["id"])
        return {"filas": filas}
    if nombre == "consultar_catalogo":
        return {"catalogo": store.catalogo()}
    if nombre == "crear_prestamo":
        objetivo = store.usuario_por_nombre(str(args.get("usuario", "mi")))
        if objetivo is None:
            raise PolicyError("usuario_no_encontrado", "el usuario solicitado no existe")
        p = store.crear_prestamo(objetivo["id"], args["equipo"], args.get("dias", 7), args.get("cantidad", 1))
        return {"prestamo": p, "usuario": objetivo["nombre"], "cantidad": args.get("cantidad", 1)}
    if nombre == "eliminar_prestamo":
        ok = store.eliminar_prestamo(int(args.get("prestamo_id", 0)))
        return {"eliminado": ok, "prestamo_id": args.get("prestamo_id")}
    raise PolicyError("herramienta_no_permitida", nombre)


def _reglas_negocio(nombre: str, args: dict, usuario: dict) -> None:
    """Límites de negocio: ni el prompt ni el modelo pueden ampliarlos."""
    if nombre == "crear_prestamo":
        cantidad = int(args.get("cantidad", 1))
        if cantidad > 3:
            raise PolicyError(
                "limite_cantidad",
                f"un estudiante no puede registrar {cantidad} equipos en una sola solicitud (máx. 3)",
            )
        objetivo = store.usuario_por_nombre(str(args.get("usuario", "mi")))
        if objetivo and objetivo["id"] != usuario["id"] and usuario["rol"] != "admin":
            raise PolicyError(
                "usuario_ajeno",
                f"'{usuario['nombre']}' no puede crear préstamos a nombre de '{objetivo['nombre']}'",
            )


class VulnerableAgent:
    modo = "vulnerable"

    def handle(self, mensaje: str, documento: str, usuario: dict | None = None) -> Resultado:
        usuario = usuario or USUARIO_DEMO
        rid = _nuevo_id()
        r = llm.respond(mensaje, documento, guardado=False)
        res = Resultado(
            modo=self.modo,
            escenario="",
            mensaje=mensaje,
            documento=documento,
            texto=r["texto"],
            prompt=r["prompt"],
            tool_calls=r["tool_calls"],
            inyeccion=r["inyeccion_detectada"],
            request_id=rid,
        )
        for call in r["tool_calls"]:
            try:
                salida = _ejecutar(call["name"], call["args"], usuario)
                res.ejecutadas.append({"name": call["name"], "args": call["args"], "salida": salida})
                if "filas" in salida:
                    res.filas = salida["filas"]
            except Exception as exc:  # el agente vulnerable no contiene errores
                res.bloqueadas.append({"name": call["name"], "motivo": "error", "detalle": str(exc)})
        AUDITORIA.registrar(
            {
                "request_id": rid,
                "modo": self.modo,
                "usuario": usuario["nombre"],
                "decision": "permitido",
                "herramientas": [c["name"] for c in res.tool_calls],
                "inyeccion_detectada": res.inyeccion,
                "nota": "sin guardarraíles: la salida del modelo se ejecuta y se muestra cruda",
            }
        )
        return res


class GuardedAgent:
    modo = "guardado"

    def handle(self, mensaje: str, documento: str, usuario: dict | None = None) -> Resultado:
        usuario = usuario or USUARIO_DEMO
        rid = _nuevo_id()
        r = llm.respond(mensaje, documento, guardado=True)
        res = Resultado(
            modo=self.modo,
            escenario="",
            mensaje=mensaje,
            documento=documento,
            texto=r["texto"],
            prompt=r["prompt"],
            tool_calls=r["tool_calls"],
            inyeccion=r["inyeccion_detectada"],
            ignoradas=r["ignoradas"],
            request_id=rid,
        )

        if res.inyeccion:
            res.bloqueadas.append(
                {
                    "name": "(documento)",
                    "motivo": "inyeccion_en_datos",
                    "detalle": "el documento contiene instrucciones; se trata como dato, no como orden",
                }
            )
        for call in res.ignoradas:
            res.bloqueadas.append(
                {
                    "name": call["name"],
                    "motivo": "origen_no_confiable",
                    "detalle": "la acción venía del documento, no del usuario",
                }
            )

        for call in r["tool_calls"]:
            nombre, args = call["name"], call["args"]
            if call.get("origin") != "usuario":
                res.bloqueadas.append(
                    {"name": nombre, "motivo": "origen_no_confiable", "detalle": "no nace del canal del usuario"}
                )
                continue
            try:
                regla = verificar_politica(nombre, usuario)
                _reglas_negocio(nombre, args, usuario)

                # Minimización: un estudiante nunca recibe PII de terceros.
                if nombre == "listar_prestamos" and usuario["rol"] != "admin":
                    if args.get("todos") or args.get("incluir_pii"):
                        res.notas.append(
                            "PII minimizada: solo los préstamos del usuario y sin documento, correo ni teléfono"
                        )
                    args = {**args, "incluir_pii": False, "todos": False}

                if regla["confirmacion"]:
                    c = CONFIRMACIONES.crear(nombre, args, usuario["id"])
                    res.confirmacion = {
                        "token": c.token,
                        "herramienta": nombre,
                        "argumentos": args,
                        "nivel": regla["nivel"],
                        "expira_en": CONFIRMACIONES.ttl,
                    }
                    continue

                salida = _ejecutar(nombre, args, usuario)
                res.ejecutadas.append({"name": nombre, "args": args, "salida": salida})
                if "filas" in salida:
                    res.filas = [redactar_fila(f) for f in salida["filas"]]
            except PolicyError as exc:
                res.bloqueadas.append({"name": nombre, "motivo": exc.motivo, "detalle": exc.detalle})

        if res.filas:
            res.texto = _texto_filas(res.filas)

        # La respuesta debe decir la verdad: si algo se bloqueó, no se anuncia como hecho.
        if res.ejecutadas:
            res.texto = redactar_pii(res.texto)
        elif res.confirmacion:
            res.texto = (
                "No ejecuté la acción: es irreversible y requiere confirmación humana. "
                "Revisa la solicitud y confirma con el botón si estás de acuerdo."
            )
        elif res.bloqueadas:
            motivos = ", ".join(sorted({b["motivo"] for b in res.bloqueadas}))
            res.texto = (
                "No ejecuté la acción solicitada. El guardarraíl la detuvo: "
                f"{motivos}. El detalle está en la tabla de decisión."
            )
        else:
            res.texto = redactar_pii(res.texto)

        if res.confirmacion:
            res.notas.append("Acción irreversible detenida hasta la confirmación de una persona")
        if not res.notas:
            res.notas.append("Frontera instrucción/dato activa: el documento se trató como dato")
        if "<" in res.texto and ">" in res.texto:
            res.notas.append("Salida neutralizada: el HTML se escapó antes de renderizar")
        AUDITORIA.registrar(
            {
                "request_id": rid,
                "modo": self.modo,
                "usuario": usuario["nombre"],
                "decision": "pendiente_confirmacion" if res.confirmacion else (
                    "bloqueado" if res.bloqueadas else "permitido"
                ),
                "herramientas": [c["name"] for c in res.tool_calls],
                "ejecutadas": [e["name"] for e in res.ejecutadas],
                "bloqueadas": [b["motivo"] for b in res.bloqueadas],
                "inyeccion_detectada": res.inyeccion,
                "confirmacion": bool(res.confirmacion),
            }
        )
        return res

    def confirmar(self, token: str, usuario: dict | None = None) -> dict:
        usuario = usuario or USUARIO_DEMO
        c = CONFIRMACIONES.consumir(token, usuario["id"])
        regla = verificar_politica(c.herramienta, usuario)
        if not regla["confirmacion"]:
            raise PolicyError("no_requiere_confirmacion", "esa herramienta no usa confirmación")
        _reglas_negocio(c.herramienta, c.argumentos, usuario)
        salida = _ejecutar(c.herramienta, c.argumentos, usuario)
        AUDITORIA.registrar(
            {
                "request_id": "conf-" + token[:6],
                "modo": self.modo,
                "usuario": usuario["nombre"],
                "decision": "confirmado_por_humano",
                "herramientas": [c.herramienta],
                "ejecutadas": [c.herramienta],
                "detalle": "token de un solo uso consumido",
            }
        )
        return {"herramienta": c.herramienta, "argumentos": c.argumentos, "salida": salida}


def _texto_filas(filas: list[dict]) -> str:
    if not filas:
        return "No hay préstamos para mostrar."
    lineas = [f"Encontré {len(filas)} préstamo(s):"]
    for f in filas:
        lineas.append(f"  - #{f['id']} · {f.get('cantidad', 1)} × {f['equipo']} · {f['dias']} días · {f['estado']}")
    return "\n".join(lineas)


def neutralizar(texto: str, seguro: bool) -> str:
    return neutralizar_html(texto) if seguro else texto

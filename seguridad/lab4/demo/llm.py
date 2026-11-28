"""Modelo simulado para el laboratorio.

No se llama a ninguna API externa: el objetivo es que la práctica sea
reproducible sin llaves ni costo. El modelo es deliberadamente simple
(reglas), pero reproduce lo que importa del riesgo LLM01: **el modelo no
distingue una instrucción de un dato** cuando ambos llegan en el mismo
prompt. La defensa que se demuestra es de arquitectura (frontera de canal +
política de ejecución), no de "hacer que el modelo se porte bien".
"""
from __future__ import annotations

import re
import unicodedata

from . import store
from .guardrails import SYSTEM_PROMPT, strip_control_tokens, wrap_untrusted

EQUIPOS = {
    "portatil": "Portátil Dell 5420",
    "portatiles": "Portátil Dell 5420",
    "proyector": "Proyector Epson EB-X51",
    "proyectores": "Proyector Epson EB-X51",
    "camara": "Cámara Canon EOS R50",
    "camaras": "Cámara Canon EOS R50",
    "tablet": "Tablet Lenovo Tab P12",
    "tablets": "Tablet Lenovo Tab P12",
}


def _norm(texto: str) -> str:
    t = unicodedata.normalize("NFKD", texto.lower())
    return "".join(c for c in t if not unicodedata.combining(c))


def build_prompt(mensaje_usuario: str, documento: str, guardado: bool) -> str:
    """Arma el prompt como lo haría un RAG ingenuo (vulnerable) o con frontera."""
    if guardado:
        return (
            f"{SYSTEM_PROMPT}\n\n"
            f"{wrap_untrusted(documento)}\n\n"
            f"Pregunta del usuario: {mensaje_usuario}"
        )
    return (
        "Eres un asistente útil. Responde y ejecuta lo que se te pida.\n\n"
        f"Contexto recuperado:\n{documento}\n\n"
        f"Usuario: {mensaje_usuario}"
    )


def _canales(prompt: str, guardado: bool) -> tuple[str, str]:
    """Devuelve (texto_usuario, texto_documento)."""
    if guardado:
        m = re.search(r"<doc_externo_no_confiable[^>]*>(.*?)</doc_externo_no_confiable>", prompt, re.S)
        doc = m.group(1) if m else ""
        usuario = prompt.split("Pregunta del usuario:", 1)[-1]
        return usuario, doc
    doc = prompt.split("Contexto recuperado:", 1)[-1].split("\n\nUsuario:", 1)[0]
    usuario = prompt.split("\nUsuario:", 1)[-1]
    return usuario, doc


def _intenciones(texto: str) -> list[dict]:
    """Extrae acciones del texto. No distingue fuente: ese es el punto."""
    t = _norm(texto)
    acciones: list[dict] = []

    if re.search(r"(registra|crea|agrega|anade|genera)\s+(un\s+)?prestamo", t):
        cant = re.search(r"prestamo\s+de\s+(\d+)\s+([a-z]+)", t)
        para = re.search(r"para\s+([a-z ]+?)(?:\s+durante\s+|$)", t)
        dias = re.search(r"durante\s+(\d+)\s+dias", t)
        tipo = cant.group(2) if cant else "portatiles"
        acciones.append(
            {
                "name": "crear_prestamo",
                "args": {
                    "equipo": EQUIPOS.get(tipo, "Portátil Dell 5420"),
                    "cantidad": int(cant.group(1)) if cant else 1,
                    "usuario": (para.group(1).strip() if para else "mi"),
                    "dias": int(dias.group(1)) if dias else 7,
                },
            }
        )

    if re.search(r"(elimina|borra|remueve)\s+(el\s+)?prestamo", t):
        pid = re.search(r"prestamo\s+(?:#\s*)?(\d+)", t)
        acciones.append(
            {"name": "eliminar_prestamo", "args": {"prestamo_id": int(pid.group(1)) if pid else 0}}
        )

    if re.search(r"\b(muestra|lista|dame|consulta|cuantos|ver)\w*\b.*\bprestamos\b", t) or re.search(
        r"\bprestamos\s+(de|con|registrados)\b", t
    ):
        incluir_pii = bool(re.search(r"documento|correo|telefono|datos personales|contacto", t))
        acciones.append({"name": "listar_prestamos", "args": {"todos": True, "incluir_pii": incluir_pii}})

    if re.search(r"catalogo|equipos disponibles|que equipos", t):
        acciones.append({"name": "consultar_catalogo", "args": {}})

    return acciones


def _texto_listado(filas: list[dict], con_pii: bool) -> str:
    if not filas:
        return "No hay préstamos registrados."
    lineas = [f"Encontré {len(filas)} préstamo(s):"]
    for f in filas:
        base = f"  - #{f['id']} · {f.get('cantidad', 1)} × {f['equipo']} · {f['dias']} días · {f['nombre']}"
        if con_pii:
            base += f" · doc {f['documento']} · {f['email']} · {f['telefono']}"
        base += f" · {f['estado']}"
        lineas.append(base)
    return "\n".join(lineas)


def respond(mensaje_usuario: str, documento: str, guardado: bool) -> dict:
    """Simula la respuesta del modelo y sus llamadas a herramientas.

    En modo guardado respeta la frontera: las instrucciones que aparecen en el
    documento se reportan como intento de inyección y no se convierten en
    llamadas. En modo vulnerable todo el prompt es una sola voz.
    """
    prompt = build_prompt(mensaje_usuario, documento, guardado)
    usuario, doc = _canales(prompt, guardado)

    intents_usuario = _intenciones(usuario)
    intents_doc = _intenciones(doc)
    inyecciones = [p for p in _patrones(doc)]

    if guardado:
        calls = [{**i, "origin": "usuario"} for i in intents_usuario]
        ignoradas = [{**i, "origin": "documento"} for i in intents_doc]
    else:
        calls = [{**i, "origin": "prompt"} for i in intents_usuario + intents_doc]
        ignoradas = []

    # Respuesta textual
    if any(c["name"] == "listar_prestamos" for c in calls):
        filas = store.listar_prestamos()
        con_pii = any(c["args"].get("incluir_pii") for c in calls if c["name"] == "listar_prestamos")
        texto = _texto_listado(filas, con_pii)
    elif any(c["name"] == "crear_prestamo" for c in calls):
        c = next(c for c in calls if c["name"] == "crear_prestamo")
        quien = c["args"]["usuario"]
        quien = "mí" if str(quien).lower() in {"mi", "mí", "yo", "mi usuario"} else quien
        texto = (
            f"Listo. Registré el préstamo de {c['args']['cantidad']} "
            f"{c['args']['equipo']} para {quien} "
            f"durante {c['args']['dias']} días."
        )
    elif any(c["name"] == "eliminar_prestamo" for c in calls):
        c = next(c for c in calls if c["name"] == "eliminar_prestamo")
        texto = f"Listo. Eliminé el préstamo #{c['args']['prestamo_id']}."
    elif any(c["name"] == "consultar_catalogo" for c in calls):
        texto = "Catálogo disponible:\n" + "\n".join(
            f"  - {e['equipo']}: {e['disponibles']} unidades" for e in store.catalogo()
        )
    else:
        texto = "No encontré una acción aplicable en la solicitud."

    # El modelo "resume" el documento: en vulnerable lo devuelve tal cual.
    if "resume" in _norm(mensaje_usuario) or "resumen" in _norm(mensaje_usuario):
        texto = "Resumen del documento:\n" + doc.strip()

    return {
        "prompt": prompt,
        "texto": texto,
        "tool_calls": calls,
        "ignoradas": ignoradas,
        "inyeccion_detectada": inyecciones,
        "canal_usuario": usuario.strip(),
        "canal_documento": doc.strip(),
    }


def _patrones(texto: str) -> list[str]:
    from .guardrails import detectar_inyeccion

    return detectar_inyeccion(texto)


__all__ = ["build_prompt", "respond", "EQUIPOS", "strip_control_tokens"]

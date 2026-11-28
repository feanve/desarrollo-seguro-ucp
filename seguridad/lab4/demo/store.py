"""Almacén en memoria del asistente de préstamos (sandbox de PrestaUCP).

Datos ficticios. No hay base de datos real: el objetivo es que el laboratorio
sea reproducible con la biblioteca estándar, sin servicios externos.
"""
from __future__ import annotations

import copy
import threading
import unicodedata

LOCK = threading.RLock()

USUARIOS = [
    {
        "id": 1,
        "nombre": "Ana Torres",
        "email": "ana.torres@ucp.edu.co",
        "documento": "1094001234",
        "telefono": "+57 300 111 2233",
        "rol": "estudiante",
    },
    {
        "id": 2,
        "nombre": "Carlos Pérez",
        "email": "carlos.perez@ucp.edu.co",
        "documento": "1094005678",
        "telefono": "+57 301 444 5566",
        "rol": "estudiante",
    },
    {
        "id": 3,
        "nombre": "María Gómez",
        "email": "maria.gomez@ucp.edu.co",
        "documento": "1094009012",
        "telefono": "+57 302 777 8899",
        "rol": "admin",
    },
]

CATALOGO = [
    {"equipo": "Portátil Dell 5420", "tipo": "portatiles", "disponibles": 34},
    {"equipo": "Proyector Epson EB-X51", "tipo": "proyector", "disponibles": 6},
    {"equipo": "Cámara Canon EOS R50", "tipo": "camara", "disponibles": 4},
    {"equipo": "Tablet Lenovo Tab P12", "tipo": "tablet", "disponibles": 12},
]

_PRESTAMOS_INICIALES = [
    {"id": 1, "usuario_id": 1, "equipo": "Portátil Dell 5420", "cantidad": 1, "dias": 5, "estado": "activo"},
    {"id": 2, "usuario_id": 2, "equipo": "Cámara Canon EOS R50", "cantidad": 1, "dias": 3, "estado": "activo"},
    {"id": 3, "usuario_id": 1, "equipo": "Tablet Lenovo Tab P12", "cantidad": 1, "dias": 10, "estado": "activo"},
]

_prestamos = []
_next_id = 4


def reset() -> None:
    """Restaura el estado inicial (lo usa cada escenario y la prueba)."""
    global _prestamos, _next_id
    with LOCK:
        _prestamos = copy.deepcopy(_PRESTAMOS_INICIALES)
        _next_id = 4


def usuario_por_id(uid: int) -> dict | None:
    return next((u for u in USUARIOS if u["id"] == uid), None)


def _norm(texto: str) -> str:
    t = unicodedata.normalize("NFKD", texto.lower())
    return "".join(c for c in t if not unicodedata.combining(c)).strip()


def usuario_por_nombre(nombre: str) -> dict | None:
    n = _norm(nombre)
    if n in {"mi", "mí", "yo", "mi usuario"}:
        return usuario_por_id(1)  # sesión de demostración: Ana Torres
    for u in USUARIOS:
        if n in _norm(u["nombre"]) or _norm(u["nombre"]).split()[0] == n:
            return u
    return None


def catalogo() -> list[dict]:
    return copy.deepcopy(CATALOGO)


def listar_prestamos(usuario_id: int | None = None) -> list[dict]:
    """Devuelve préstamos enriquecidos con los datos del usuario."""
    with LOCK:
        filas = []
        for p in _prestamos:
            if usuario_id is not None and p["usuario_id"] != usuario_id:
                continue
            u = usuario_por_id(p["usuario_id"]) or {}
            filas.append(
                {
                    **p,
                    "nombre": u.get("nombre", "?"),
                    "email": u.get("email", "?"),
                    "documento": u.get("documento", "?"),
                    "telefono": u.get("telefono", "?"),
                }
            )
        return filas


def crear_prestamo(usuario_id: int, equipo: str, dias: int, cantidad: int = 1) -> dict:
    global _next_id
    with LOCK:
        p = {
            "id": _next_id,
            "usuario_id": usuario_id,
            "equipo": equipo,
            "cantidad": max(1, min(int(cantidad), 999)),
            "dias": max(1, min(int(dias), 90)),
            "estado": "activo",
        }
        _next_id += 1
        _prestamos.append(p)
        return copy.deepcopy(p)


def eliminar_prestamo(pid: int) -> bool:
    with LOCK:
        for i, p in enumerate(_prestamos):
            if p["id"] == pid:
                del _prestamos[i]
                return True
        return False


def total_prestamos() -> int:
    with LOCK:
        return len(_prestamos)


reset()

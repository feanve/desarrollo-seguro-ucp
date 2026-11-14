"""Utilidades compartidas por las pruebas de los cierres adicionales.

Solo usa la librería `requests`. La dirección base se toma de `BASE_URL`:

    python3 test_authz_usuarios.py
    BASE_URL=http://127.0.0.1:3002 python3 test_authz_usuarios.py
"""

import os

import requests

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:3000").rstrip("/")
PASSWORD = "Lab2Passw0rd!"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@juice-sh.op")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
TIMEOUT = 10


def register(email: str) -> None:
    """Crea el usuario. Si ya existe de una corrida anterior, continúa."""
    r = requests.post(
        f"{BASE_URL}/api/Users",
        json={"email": email, "password": PASSWORD, "passwordRepeat": PASSWORD},
        timeout=TIMEOUT,
    )
    if r.status_code == 201:
        return
    if r.status_code in (400, 409) and "unique" in r.text.lower():
        return
    raise RuntimeError(f"No se pudo registrar {email}: HTTP {r.status_code} {r.text[:300]}")


def login(email: str, password: str = PASSWORD) -> tuple[str, int]:
    r = requests.post(
        f"{BASE_URL}/rest/user/login",
        json={"email": email, "password": password},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    auth = r.json()["authentication"]
    return auth["token"], auth["bid"]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}

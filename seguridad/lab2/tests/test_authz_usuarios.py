"""Prueba de regresión del control ASVS 5.0 · 8.3.1 (autorización por función).

`GET /rest/user/authentication-details` listaba a todos los usuarios para
cualquier sesión válida. El control exige rol `admin` y responde 403 al resto.

Uso:
    python3 test_authz_usuarios.py
    BASE_URL=http://127.0.0.1:3002 python3 test_authz_usuarios.py

Sale con código 0 si todas las pruebas pasan y 1 si alguna falla.
"""

import unittest

import requests

from helpers import ADMIN_EMAIL, ADMIN_PASSWORD, BASE_URL, TIMEOUT, bearer, login, register

CUSTOMER = "lab2.authz.customer@ucp.local"
ENDPOINT = f"{BASE_URL}/rest/user/authentication-details"


class AuthzUsuariosTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        register(CUSTOMER)
        cls.token_customer, _ = login(CUSTOMER)
        cls.token_admin, _ = login(ADMIN_EMAIL, ADMIN_PASSWORD)

    def test_customer_no_puede_listar_usuarios(self) -> None:
        """Un customer no debe recibir la lista de usuarios."""
        r = requests.get(ENDPOINT, headers=bearer(self.token_customer), timeout=TIMEOUT)
        self.assertEqual(
            r.status_code,
            403,
            msg=f"El customer obtuvo HTTP {r.status_code}: {r.text[:300]}",
        )
        self.assertNotIn(ADMIN_EMAIL, r.text, "La respuesta filtra el correo del administrador")

    def test_admin_si_puede_listar_usuarios(self) -> None:
        """El control no debe romper la función legítima del administrador."""
        r = requests.get(ENDPOINT, headers=bearer(self.token_admin), timeout=TIMEOUT)
        self.assertEqual(r.status_code, 200, msg=f"El admin obtuvo HTTP {r.status_code}: {r.text[:300]}")
        data = r.json().get("data", [])
        self.assertIsInstance(data, list)
        self.assertIn(ADMIN_EMAIL, [u.get("email") for u in data])

    def test_sin_token_responde_401(self) -> None:
        """Sin sesión no se expone la lista."""
        r = requests.get(ENDPOINT, timeout=TIMEOUT)
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)

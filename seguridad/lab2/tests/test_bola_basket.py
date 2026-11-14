"""Prueba de regresión para el BOLA del carrito (ASVS 5.0 · 8.2.2).

Demuestra que un usuario autenticado puede leer el carrito de otro cambiando
el id en la URL de `/rest/basket/{id}`.

Uso:
    python3 test_bola_basket.py
    BASE_URL=http://127.0.0.1:3001 python3 test_bola_basket.py

Sale con código 0 si todas las pruebas pasan y 1 si alguna falla.
Solo usa la librería `requests`; no requiere pytest.
"""

import os
import unittest

import requests

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:3000").rstrip("/")
PASSWORD = "Lab2Passw0rd!"
USER_A = "lab2.bola.a@ucp.local"
USER_B = "lab2.bola.b@ucp.local"
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
    # Juice Shop responde 400 con "email must be unique" en la segunda corrida.
    if r.status_code in (400, 409) and "unique" in r.text.lower():
        return
    raise RuntimeError(f"No se pudo registrar {email}: HTTP {r.status_code} {r.text[:300]}")


def login(email: str) -> tuple[str, int]:
    r = requests.post(
        f"{BASE_URL}/rest/user/login",
        json={"email": email, "password": PASSWORD},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    auth = r.json()["authentication"]
    return auth["token"], auth["bid"]


class BolaBasketTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        register(USER_A)
        register(USER_B)
        cls.token_a, cls.bid_a = login(USER_A)
        cls.token_b, cls.bid_b = login(USER_B)

        # El dueño legítimo sí puede leer su carrito: así obtenemos el UserId de B.
        own = requests.get(
            f"{BASE_URL}/rest/basket/{cls.bid_b}",
            headers={"Authorization": f"Bearer {cls.token_b}"},
            timeout=TIMEOUT,
        )
        own.raise_for_status()
        cls.user_b = own.json()["data"]["UserId"]
        cls.user_a = requests.get(
            f"{BASE_URL}/rest/basket/{cls.bid_a}",
            headers={"Authorization": f"Bearer {cls.token_a}"},
            timeout=TIMEOUT,
        ).json()["data"]["UserId"]

    def get_basket(self, basket_id: int, token: str | None = None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return requests.get(f"{BASE_URL}/rest/basket/{basket_id}", headers=headers, timeout=TIMEOUT)

    def test_carrito_ajeno_responde_404(self) -> None:
        """A no debe poder leer el carrito de B (ni saber que existe)."""
        r = self.get_basket(self.bid_b, self.token_a)
        self.assertEqual(
            r.status_code,
            404,
            msg=f"BOLA: el usuario A leyó el carrito {self.bid_b} del usuario B "
                f"(UserId {self.user_b}) con HTTP {r.status_code}: {r.text[:300]}",
        )
        self.assertNotIn(str(self.user_b), r.text, "La respuesta filtra el UserId del dueño")

    def test_carrito_propio_responde_200(self) -> None:
        """El control no debe romper la lectura del carrito propio."""
        r = self.get_basket(self.bid_a, self.token_a)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["data"]["id"], self.bid_a)
        self.assertEqual(r.json()["data"]["UserId"], self.user_a)

    def test_sin_token_responde_401(self) -> None:
        """Sin sesión no se expone ningún carrito."""
        r = self.get_basket(self.bid_b)
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)

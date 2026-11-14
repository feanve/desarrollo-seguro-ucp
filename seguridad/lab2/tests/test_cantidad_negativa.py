"""Prueba de regresión del control ASVS 5.0 · 2.3.2 (límites de lógica de negocio).

`POST /api/BasketItems` aceptaba `quantity` negativa o cero. El control exige un
entero entre 1 y 1000 y responde 400 en cualquier otro caso.

La prueba vacía el carrito del usuario antes de cada caso: la tabla BasketItems
tiene una restricción UNIQUE (ProductId, BasketId) y un ítem residual haría
fallar el segundo intento con 500 en lugar de mostrar el comportamiento real.

Uso:
    python3 test_cantidad_negativa.py
    BASE_URL=http://127.0.0.1:3002 python3 test_cantidad_negativa.py
"""

import unittest

import requests

from helpers import BASE_URL, TIMEOUT, bearer, login, register

CUSTOMER = "lab2.cantidad@ucp.local"
PRODUCT_ID = 1


class CantidadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        register(CUSTOMER)
        cls.token, cls.bid = login(CUSTOMER)

    def setUp(self) -> None:
        """Deja el carrito sin ítems para que cada caso parta del mismo estado."""
        r = requests.get(
            f"{BASE_URL}/rest/basket/{self.bid}",
            headers=bearer(self.token),
            timeout=TIMEOUT,
        )
        if r.status_code != 200:
            return
        for producto in r.json().get("data", {}).get("Products", []):
            item_id = (producto.get("BasketItem") or {}).get("id")
            if item_id is not None:
                requests.delete(
                    f"{BASE_URL}/api/BasketItems/{item_id}",
                    headers=bearer(self.token),
                    timeout=TIMEOUT,
                )

    def add_item(self, quantity):
        return requests.post(
            f"{BASE_URL}/api/BasketItems",
            headers=bearer(self.token),
            json={"ProductId": PRODUCT_ID, "BasketId": self.bid, "quantity": quantity},
            timeout=TIMEOUT,
        )

    def test_cantidad_negativa_rechazada(self) -> None:
        """Una cantidad negativa permitiría una orden con total negativo."""
        r = self.add_item(-2)
        self.assertEqual(
            r.status_code,
            400,
            msg=f"Se aceptó quantity=-2 con HTTP {r.status_code}: {r.text[:300]}",
        )

    def test_cantidad_cero_rechazada(self) -> None:
        """Cero no es una línea de pedido válida."""
        r = self.add_item(0)
        self.assertEqual(r.status_code, 400, msg=f"Se aceptó quantity=0 con HTTP {r.status_code}")

    def test_cantidad_positiva_aceptada(self) -> None:
        """El control no debe romper el flujo normal de compra."""
        r = self.add_item(2)
        self.assertEqual(r.status_code, 200, msg=f"quantity=2 devolvió HTTP {r.status_code}: {r.text[:300]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)

from flask import Flask, request
import sqlite3

app = Flask(__name__)


@app.get("/buscar")
def buscar():
    q = request.args.get("q", "")
    con = sqlite3.connect("tienda.db")
    # ✅ Consulta parametrizada: la entrada viaja como parámetro, nunca dentro del SQL.
    filas = con.execute(
        "SELECT nombre, precio FROM productos WHERE nombre = ?", (q,)
    ).fetchall()
    return {"resultados": [{"nombre": n, "precio": p} for n, p in filas]}


if __name__ == "__main__":
    app.run()

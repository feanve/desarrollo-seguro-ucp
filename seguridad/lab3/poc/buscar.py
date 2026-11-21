"""PoC del Laboratorio 3: consulta SQL parametrizada.

Amenaza del Lab 1: inyección SQL en el buscador de usuarios.
ASVS 5.0 V1.14: usar consultas parametrizadas en todo acceso a datos.
"""
from flask import Flask, request

app = Flask(__name__)


@app.route("/buscar")
def buscar():
    nombre = request.args.get("nombre", "")
    # CORREGIDO: el valor del cliente viaja como parámetro, no como SQL.
    filas = db.execute("SELECT * FROM users WHERE name = ?", (nombre,)).fetchall()
    return {"resultados": filas}

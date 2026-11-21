"""Fixture vulnerable: DEBE ser marcado por lab3.sql-por-concatenacion."""


def buscar(cursor, nombre):
    return cursor.execute("SELECT * FROM users WHERE name = '%s'" % nombre).fetchall()

#!/usr/bin/env python3
"""Convierte los documentos del laboratorio en un HTML legible y un PDF.

El Markdown sigue siendo el entregable del repositorio. Este script genera una
vista con tablas reales para leer en el navegador o imprimir.

Uso:
    python3 seguridad/lab2/render.py
    python3 seguridad/lab2/render.py --pdf

Requiere: python3-markdown y Google Chrome (solo para --pdf).
"""

import argparse
import datetime
import pathlib
import re
import shutil
import subprocess
import sys

import markdown

BASE = pathlib.Path(__file__).resolve().parent
SALIDA_HTML = BASE / "informe.html"
SALIDA_PDF = BASE / "informe.pdf"

DOCUMENTOS = [
    ("ASVS.md", "Revisión ASVS 5.0"),
    ("TRIAGE.md", "Triage SAST y DAST"),
    ("ANALISIS.md", "Análisis comparativo y criterio de cierre"),
    ("CIERRES.md", "Cierres adicionales con prueba"),
    ("PULL_REQUEST.md", "Corrección del BOLA"),
]

CSS = """
:root {
  --texto: #1f2933;
  --suave: #52606d;
  --borde: #cbd2d9;
  --fondo-tabla: #f5f7fa;
  --acento: #0b5fff;
  --codigo: #eef2f7;
}
* { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0 auto;
  max-width: 1180px;
  padding: 2.2rem 2.4rem 5rem;
  color: var(--texto);
  font: 16px/1.55 -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  background: #fff;
}
header.portada {
  border-bottom: 3px solid var(--acento);
  margin-bottom: 2rem;
  padding-bottom: 1rem;
}
header.portada h1 { margin: 0 0 .3rem; font-size: 1.9rem; }
header.portada p { margin: .2rem 0; color: var(--suave); }
nav.indice {
  background: var(--fondo-tabla);
  border: 1px solid var(--borde);
  border-radius: 8px;
  padding: .9rem 1.2rem;
  margin-bottom: 2.4rem;
}
nav.indice strong { display: block; margin-bottom: .4rem; }
nav.indice a { color: var(--acento); text-decoration: none; margin-right: 1.1rem; }
nav.indice a:hover { text-decoration: underline; }
section.documento { margin-bottom: 3.5rem; }
section.documento > h1 {
  font-size: 1.55rem;
  border-left: 5px solid var(--acento);
  padding-left: .7rem;
  margin: 0 0 1.2rem;
}
h2 { font-size: 1.3rem; margin-top: 2.2rem; border-bottom: 1px solid var(--borde); padding-bottom: .3rem; }
h3 { font-size: 1.12rem; margin-top: 1.7rem; }
p, li { max-width: 95ch; }
a { color: var(--acento); }
code {
  background: var(--codigo);
  border-radius: 4px;
  padding: .1em .35em;
  font: .9em/1.4 "SFMono-Regular", Consolas, "Liberation Mono", monospace;
}
pre {
  background: #0f172a;
  color: #e2e8f0;
  border-radius: 8px;
  padding: 1rem 1.2rem;
  overflow-x: auto;
  font-size: .88rem;
}
pre code { background: none; color: inherit; padding: 0; }
blockquote {
  margin: 1.2rem 0;
  padding: .7rem 1rem;
  border-left: 4px solid var(--acento);
  background: var(--fondo-tabla);
  color: var(--suave);
}
div.tabla { overflow-x: auto; margin: 1rem 0 1.6rem; border: 1px solid var(--borde); border-radius: 8px; }
table { width: 100%; border-collapse: collapse; font-size: .9rem; }
th, td { padding: .55rem .7rem; text-align: left; vertical-align: top; border-bottom: 1px solid var(--borde); }
th { background: #e8eef7; font-weight: 600; white-space: normal; }
tbody tr:nth-child(even) { background: var(--fondo-tabla); }
tbody tr:last-child td { border-bottom: none; }
strong { font-weight: 600; }
footer { color: var(--suave); font-size: .85rem; border-top: 1px solid var(--borde); padding-top: 1rem; }
@media print {
  body { max-width: none; padding: 0; font-size: 10.5pt; }
  nav.indice { display: none; }
  section.documento { page-break-before: always; }
  section.documento:first-of-type { page-break-before: auto; }
  div.tabla { overflow: visible; }
  table { font-size: 8.6pt; }
  tr { page-break-inside: avoid; }
  h2, h3 { page-break-after: avoid; }
  a { color: inherit; text-decoration: none; }
  pre { white-space: pre-wrap; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
}
"""

PLANTILLA = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{titulo}</title>
<style>{css}</style>
</head>
<body>
<header class="portada">
  <h1>{titulo}</h1>
  <p>OWASP Juice Shop · Laboratorio 2 · Verificación ASVS 5.0</p>
  <p>Generado el {fecha} desde los archivos Markdown de esta carpeta.</p>
</header>
<nav class="indice">
  <strong>Contenido</strong>
  {indice}
</nav>
{cuerpo}
<footer>
  Los archivos fuente son los <code>.md</code> de <code>seguridad/lab2/</code>. Este HTML se
  regenera con <code>python3 seguridad/lab2/render.py</code>.
</footer>
</body>
</html>
"""


def convertir(texto: str) -> str:
    html = markdown.markdown(
        texto,
        extensions=["tables", "fenced_code", "toc", "sane_lists", "attr_list"],
        output_format="html5",
    )
    # Envolver cada tabla para que pueda desplazarse sin romper el diseño.
    html = html.replace("<table>", '<div class="tabla"><table>')
    html = html.replace("</table>", "</table></div>")
    return html


def main() -> int:
    parser = argparse.ArgumentParser(description="Genera informe.html y, opcionalmente, informe.pdf")
    parser.add_argument("--pdf", action="store_true", help="generar también el PDF con Chrome")
    args = parser.parse_args()

    partes = []
    indice = []
    for i, (nombre, etiqueta) in enumerate(DOCUMENTOS, 1):
        ruta = BASE / nombre
        if not ruta.exists():
            print(f"aviso: {nombre} no existe, se omite", file=sys.stderr)
            continue
        cuerpo = convertir(ruta.read_text(encoding="utf-8"))
        partes.append(f'<section class="documento" id="doc-{i}">\n{cuerpo}\n</section>')
        indice.append(f'<a href="#doc-{i}">{etiqueta}</a>')

    if not partes:
        print("error: no hay documentos para convertir", file=sys.stderr)
        return 1

    html = PLANTILLA.format(
        titulo="Laboratorio 2 · Informe de verificación",
        css=CSS,
        fecha=datetime.date.today().isoformat(),
        indice="\n  ".join(indice),
        cuerpo="\n".join(partes),
    )
    SALIDA_HTML.write_text(html, encoding="utf-8")
    print(f"HTML: {SALIDA_HTML} ({SALIDA_HTML.stat().st_size // 1024} KB)")

    if args.pdf:
        chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
        if chrome is None:
            print("error: no se encontró Chrome para generar el PDF", file=sys.stderr)
            return 1
        subprocess.run(
            [
                chrome,
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={SALIDA_PDF}",
                SALIDA_HTML.as_uri(),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print(f"PDF:  {SALIDA_PDF} ({SALIDA_PDF.stat().st_size // 1024} KB)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

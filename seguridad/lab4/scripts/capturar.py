#!/usr/bin/env python3
"""Genera las capturas y la evidencia en texto del Laboratorio 4.

Uso (desde la raíz del repositorio):

    python3 seguridad/lab4/scripts/capturar.py

Requiere Google Chrome o Chromium instalado. El servidor se levanta solo si
no está corriendo en 127.0.0.1:8099.
"""
from __future__ import annotations

import hashlib
import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

from PIL import Image

BASE = Path(__file__).resolve().parents[1]
CAPTURAS = BASE / "capturas"
EVIDENCIAS = BASE / "evidencias"
RAIZ = BASE.parents[1]
PUERTO = 8099
URL = f"http://127.0.0.1:{PUERTO}"

CHROME = next(
    (c for c in ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser") if shutil.which(c)),
    None,
)


def esperar_servidor() -> None:
    for _ in range(60):
        try:
            with urllib.request.urlopen(URL + "/health", timeout=1) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.25)
    raise SystemExit("el servidor no respondió en 15 s")


def arrancar_si_hace_falta() -> subprocess.Popen | None:
    try:
        with urllib.request.urlopen(URL + "/health", timeout=1):
            return None
    except Exception:
        pass
    env = dict(os.environ)
    proc = subprocess.Popen(
        [sys.executable, "-m", "seguridad.lab4.demo.server"],
        cwd=RAIZ,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    esperar_servidor()
    return proc


def capturar(nombre: str, url: str, alto: int = 2000) -> Path:
    destino = CAPTURAS / f"{nombre}.png"
    cmd = [
        CHROME,
        "--headless=new",
        "--disable-gpu",
        "--no-sandbox",
        "--hide-scrollbars",
        "--force-device-scale-factor=1",
        f"--window-size=1400,{alto}",
        "--virtual-time-budget=2500",
        f"--screenshot={destino}",
        url,
    ]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    recortar(destino)
    return destino


def recortar(ruta: Path) -> None:
    """Quita el fondo uniforme que queda bajo el pie de página."""
    im = Image.open(ruta).convert("RGB")
    w, h = im.size
    fondo = im.getpixel((2, h - 2))
    ultimo = h - 1
    for y in range(h - 1, 0, -4):
        fila = [im.getpixel((x, y)) for x in range(0, w, 12)]
        if any(sum(abs(a - b) for a, b in zip(px, fondo)) > 12 for px in fila):
            ultimo = min(h - 1, y + 12)
            break
    if ultimo < h - 1:
        im.crop((0, 0, w, ultimo)).save(ruta)


def generar_pruebas() -> tuple[str, str]:
    r = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "seguridad/lab4/tests", "-v"],
        cwd=RAIZ,
        capture_output=True,
        text=True,
    )
    salida = (r.stdout + r.stderr).strip()
    (EVIDENCIAS / "pruebas.txt").write_text(salida + "\n", encoding="utf-8")
    resumen = re.search(r"Ran (\d+) tests?", salida)
    estado = "OK" if r.returncode == 0 else "FALLÓ"
    n = resumen.group(1) if resumen else "?"
    doc = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>Pruebas · Lab 4</title><style>
body{{margin:0;background:#0b1220;color:#e6edf7;font:15px/1.5 -apple-system,'Segoe UI',Roboto,Arial,sans-serif}}
main{{max-width:1200px;margin:0 auto;padding:30px 34px}}
h1{{margin:0 0 4px;font-size:26px}}.sub{{color:#93a4bd;margin:0 0 18px}}
.badge{{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700;font-size:13px;
background:rgba(34,197,94,.14);color:#86efac;border:1px solid rgba(34,197,94,.45)}}
pre{{background:#0f1728;border:1px solid #233149;border-radius:12px;padding:18px;font:12.5px/1.5
'JetBrains Mono',ui-monospace,Menlo,monospace;white-space:pre-wrap;color:#cbd5e1}}
</style></head><body><main>
<h1>Pruebas del guardarraíl</h1>
<p class="sub">python3 -m unittest discover -s seguridad/lab4/tests -v ·
<span class="badge">Ran {n} tests · {estado}</span></p>
<pre>{html.escape(salida)}</pre></main></body></html>"""
    destino = EVIDENCIAS / "pruebas.html"
    destino.write_text(doc, encoding="utf-8")
    return salida, f"file://{destino}"


def evidencia_texto(escenarios: list[tuple[str, str, str]]) -> None:
    lineas = [
        "# Evidencia HTTP · Laboratorio 4",
        f"# Servidor: {URL} (solo 127.0.0.1) · datos ficticios",
        "",
    ]
    for nombre, url, marcador in escenarios:
        with urllib.request.urlopen(URL + url) as r:
            cuerpo = r.read().decode("utf-8", "replace")
        encontrado = marcador in cuerpo
        lineas.append(f"## {nombre}")
        lineas.append(f"GET {url}")
        lineas.append(f"HTTP {r.status} · {len(cuerpo)} bytes · marcador '{marcador}': {'sí' if encontrado else 'NO'}")
        lineas.append("")
    (EVIDENCIAS / "escenarios.txt").write_text("\n".join(lineas), encoding="utf-8")


def main() -> None:
    if CHROME is None:
        raise SystemExit("instala Google Chrome o Chromium para generar las capturas")
    CAPTURAS.mkdir(parents=True, exist_ok=True)
    EVIDENCIAS.mkdir(parents=True, exist_ok=True)
    proc = arrancar_si_hace_falta()
    try:
        salida, url_pruebas = generar_pruebas()
        evidencia_texto(
            [
                ("inyección directa vulnerable", "/chat?modo=vulnerable&escenario=directa", "3 → 2"),
                ("inyección indirecta vulnerable", "/chat?modo=vulnerable&escenario=indirecta", "30 × Portátil"),
                ("PII vulnerable", "/chat?modo=vulnerable&escenario=pii", "1094005678"),
                ("inyección directa guardada", "/chat?modo=guardado&escenario=directa", "rol_insuficiente"),
                ("inyección indirecta guardada", "/chat?modo=guardado&escenario=indirecta", "origen_no_confiable"),
                ("PII guardada", "/chat?modo=guardado&escenario=pii", "[documento omitido]"),
                ("HITL pendiente", "/chat?modo=guardado&escenario=hitl", "Confirmar y ejecutar"),
            ]
        )
        urllib.request.urlopen(URL + "/reset").read()  # estado limpio para las capturas
        plan = [
            ("01-portada", "/"),
            ("02-inyeccion-directa-vulnerable", "/chat?modo=vulnerable&escenario=directa"),
            ("03-inyeccion-indirecta-vulnerable", "/chat?modo=vulnerable&escenario=indirecta"),
            ("04-fuga-pii-vulnerable", "/chat?modo=vulnerable&escenario=pii"),
            ("05-salida-html-vulnerable", "/chat?modo=vulnerable&escenario=html"),
            ("06-inyeccion-directa-guardada", "/chat?modo=guardado&escenario=directa"),
            ("07-inyeccion-indirecta-guardada", "/chat?modo=guardado&escenario=indirecta"),
            ("08-fuga-pii-guardada", "/chat?modo=guardado&escenario=pii"),
            ("09-salida-html-guardada", "/chat?modo=guardado&escenario=html"),
        ]
        for nombre, ruta in plan:
            capturar(nombre, URL + ruta)
            print("captura", nombre)

        # HITL: una sola petición; el HTML se guarda fuera del repositorio porque
        # el token de confirmación (efímero) dispararía un falso positivo del
        # escáner de secretos. La evidencia queda en la captura.
        pagina = urllib.request.urlopen(URL + "/chat?modo=guardado&escenario=hitl").read().decode()
        with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as fh:
            fh.write(pagina)
            pendiente = Path(fh.name)
        try:
            capturar("10-hitl-pendiente", f"file://{pendiente}")
        finally:
            pendiente.unlink(missing_ok=True)
        m = re.search(r"/confirm\?token=([A-Za-z0-9_-]+)", pagina)
        if not m:
            raise SystemExit("no se encontró el token de confirmación")
        capturar("11-hitl-confirmado", f"{URL}/confirm?token={m.group(1)}")
        print("captura 10-11 hitl")

        capturar("13-pruebas", url_pruebas, alto=2400)
        print("pruebas:", "OK" if "OK" in salida.splitlines()[-1] else "revisar")
        capturar("12-auditoria", URL + "/audit")

        manifiesto = []
        for p in sorted(CAPTURAS.glob("*.png")):
            b = p.read_bytes()
            manifiesto.append(f"{p.name}\t{p.stat().st_size} bytes\tsha256:{hashlib.sha256(b).hexdigest()[:16]}")
        (EVIDENCIAS / "capturas.txt").write_text("\n".join(manifiesto) + "\n", encoding="utf-8")
        print(f"{len(manifiesto)} capturas en {CAPTURAS}")
    finally:
        if proc is not None:
            proc.terminate()


if __name__ == "__main__":
    main()

# Deck de la sesión 4

Fuentes del deck «Desarrollo Seguro UCP – Sesión 4»: 27 diapositivas, una por archivo, en el mismo formato que los decks de las sesiones 1, 2 y 3. `build.py` genera `deck.json` y `slides/` (`python3 build.py /_blob/<id-del-logo>`).

El hilo de la sesión es una plataforma real: **Auditgate** (`github.com/Jawy77/auditgate`), un gate determinista que bloquea solo lo nuevo en CI/CD, con agentes de IA que encuentran y priorizan sin decidir el merge. Nació como el workshop **Bunker DevSecOps** (Tribu · Hacklab Bogotá · Ethereum Bogotá · Mantishield).

| Bloque | Diapositivas |
|---|---|
| Encuadre (5:00) | `cover`, `agenda`, `repaso` |
| El problema (5:00) | `alerta`, `superficie`, `incidentes` |
| El gate determinista (5:30) | `auditgate`, `metodologia`, `diff`, `demo-scan`, `cli-ci` |
| El PR que bloquea (6:10) | `shiftleft`, `demo-pr`, `triage` |
| Cadena de suministro (7:15) | `sca`, `firma`, `privilegio`, `secretos` |
| Codify (8:15) | `codify`, `regla`, `scale` |
| Lab 3 y Entregable 1 (8:45) | `lab3`, `entregable`, `rubrica` |
| Cierre (9:50) | `trazabilidad`, `estudio`, `proxima` |

## Demos en vivo

| Slide | Comando / flujo | Dónde |
|---|---|---|
| `demo-scan` | `auditgate scan` — bloquea solo lo nuevo (15 SAST nuevos, 73 deps de deuda) | `~/Wenia/Tribu-Lab` (CLI desde `src/`) |
| `demo-pr` | Abrir un PR con una falla → el Security Gate bloquea el merge; el triage comenta | `github.com/Jawy77/auditgate-sandbox` |

> El CLI instalado por pipx (`auditgate-ci`) está desactualizado y no trae `scan`. Para la demo, correr desde el repo: `PYTHONPATH=src python3 -m auditgate scan` (o reinstalar con `pipx install "git+https://github.com/Jawy77/auditgate"`).

| Recurso | Archivo en el repositorio |
|---|---|
| `81762f76e0e02006203e5a8a9b3904d5` | Logo de la UCP (versión para fondo oscuro), tomado de ucp.edu.co; no se incluye en el repositorio |

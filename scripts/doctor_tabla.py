#!/usr/bin/env python3
"""doctor_tabla.py — versión legible del JSON de doctor (H-14 / README «bin/auditar doctor»).

Uso:
  bin/auditar doctor | python3 -I scripts/doctor_tabla.py
  python3 -I scripts/doctor_tabla.py --archivo C/herramientas.json [--corrida C]

Imprime primero las herramientas disponibles (nombre, versión y vía) y luego las que faltan, con su
`instalacion_sugerida` rotulada «comando sugerido, sin ejecutar». Con --corrida C cuenta, para cada
herramienta que falta, cuántos controles quedaron `no_evaluado` en C/estado.json con un motivo que nombra
esa herramienta («<herramienta>: …»). Es un conteo por coincidencia de texto del motivo, no una promesa de
que instalarla los vuelva evaluables.

Solo lectura: no instala nada, no ejecuta los comandos sugeridos y no modifica la corrida.
Solo biblioteca estándar.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Nombres con que una herramienta de doctor aparece en los motivos de estado.json (adaptadores/checks).
ALIAS_MOTIVO = {
    "lhci": ("lhci", "lighthouse"),
    "playwright": ("playwright", "playwright_ux"),
    "psql": ("psql", "splinter"),
    "zap.sh": ("zap.sh", "zap"),
}


def _patron(nombre):
    nombres = ALIAS_MOTIVO.get(nombre, (nombre,))
    return re.compile(r"(?<![\w.-])(?:" + "|".join(re.escape(n) for n in nombres) + r"):")


def no_evaluados_por_herramienta(estado, nombres):
    """{herramienta: nº de controles no_evaluado cuyo motivo la nombra}. Cada control cuenta una vez por herramienta."""
    controles = (estado or {}).get("controles") or []
    cuenta = {}
    for nombre in nombres:
        pat = _patron(nombre)
        cuenta[nombre] = sum(1 for c in controles if isinstance(c, dict) and c.get("estado") == "no_evaluado"
                             and pat.search(c.get("motivo") or ""))
    return cuenta


def tabla(doctor, estado=None):
    herrs = doctor.get("herramientas")
    if not isinstance(herrs, dict):
        raise ValueError("el JSON no tiene la clave «herramientas» de doctor")
    ok = sorted((n, d) for n, d in herrs.items() if isinstance(d, dict) and d.get("disponible"))
    faltan = sorted((n, d) for n, d in herrs.items() if not (isinstance(d, dict) and d.get("disponible")))
    ancho = max([len(n) for n in herrs] + [12])
    out = [f"Herramientas: {len(ok)} disponibles, {len(faltan)} faltan (de {len(herrs)}). "
           "doctor nunca instala nada.", "", f"Disponibles ({len(ok)}):"]
    for n, d in ok:
        via = f" (vía {d['via']})" if d.get("via") and d.get("via") != "path" else ""
        out.append(f"  {n.ljust(ancho)}  {d.get('version') or 's/d'}{via}")
    if not ok:
        out.append("  (ninguna)")
    cuenta = no_evaluados_por_herramienta(estado, [n for n, _ in faltan]) if estado is not None else None
    out += ["", f"Faltan ({len(faltan)}) — comando sugerido, sin ejecutar:"]
    for n, d in faltan:
        d = d if isinstance(d, dict) else {}
        estado_h = d.get("estado") or "ausente"
        extra = f" [{estado_h}: {d['detalle']}]" if estado_h != "ausente" and d.get("detalle") else (
            f" [{estado_h}]" if estado_h != "ausente" else "")
        linea = f"  {n.ljust(ancho)}  {d.get('instalacion_sugerida') or '(sin sugerencia)'}{extra}"
        if cuenta is not None:
            linea += f"  · {cuenta[n]} control(es) no_evaluado en la corrida"
        out.append(linea)
    if not faltan:
        out.append("  (ninguna)")
    if cuenta is not None:
        out += ["", "Conteo por corrida: controles no_evaluado cuyo motivo en estado.json nombra la herramienta "
                    "(coincidencia de texto; instalarla no garantiza que pasen a evaluarse)."]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Tabla legible del JSON de doctor (solo lectura).")
    ap.add_argument("--archivo", help="JSON de doctor (p. ej. C/herramientas.json); por defecto, stdin")
    ap.add_argument("--corrida", help="carpeta de corrida: cuenta controles no_evaluado por herramienta")
    a = ap.parse_args(argv)
    try:
        texto = Path(a.archivo).read_text(encoding="utf-8") if a.archivo else sys.stdin.read()
        doctor = json.loads(texto)
    except (OSError, ValueError) as e:
        print(f"doctor_tabla: no se pudo leer el JSON de doctor: {e.__class__.__name__}", file=sys.stderr)
        return 2
    estado = None
    if a.corrida:
        ruta = Path(a.corrida) / "estado.json"
        try:
            estado = json.loads(ruta.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            print(f"doctor_tabla: sin estado.json legible en {a.corrida}; se omite el conteo por corrida",
                  file=sys.stderr)
    try:
        print(tabla(doctor if isinstance(doctor, dict) else {}, estado))
    except ValueError as e:
        print(f"doctor_tabla: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

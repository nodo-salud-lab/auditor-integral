#!/usr/bin/env python3
"""comparar_corridas.py — qué cambió entre dos corridas del mismo proyecto (auditar → corregir → re-auditar).

Uso:
  comparar_corridas.py --proyecto P                 # las dos corridas más recientes de P/.auditoria/
  comparar_corridas.py --antes C1 --despues C2      # dos carpetas de corrida explícitas

Imprime en markdown (stdout): nivel global y por dominio antes y después; controles que cambiaron de estado,
agrupados por transición (fail → pass, pass → fail, X → no_evaluado…); hallazgos nuevos y resueltos por
fingerprint, mostrando solo control, severidad y archivo:línea (nunca la evidencia ni ningún valor); y un aviso
OBLIGATORIO de no comparabilidad si cambian el modo, la red (motivos «sin red») o la versión del auditor.

Lee solo gates.json, estado.json y hallazgos.jsonl (ya enmascarados) y, para modo/versión/proyecto, run.json.
Nunca lee crudo/ ni hallazgos_todos.jsonl. No escribe nada ni modifica estados: no es una fase (fail-closed).

Códigos de salida: 0 ok · 2 uso incorrecto · 4 no hay dos corridas que comparar.
Solo biblioteca estándar.
"""
import argparse
import datetime as dt
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import corrida as corrida_mod  # noqa: E402

ORDEN_DOMINIOS = ("SEG", "DAT", "COD", "UX", "INF", "ESC", "OPS")
MARCA_SIN_RED = "sin red (AUDITOR_SIN_RED)"
TOPE_LISTA = 40


def _json(ruta, defecto=None):
    try:
        d = json.loads(Path(ruta).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return defecto
    return d


def _jsonl(ruta):
    filas = []
    try:
        with open(ruta, encoding="utf-8") as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    o = json.loads(linea)
                except ValueError:
                    continue
                if isinstance(o, dict):
                    filas.append(o)
    except OSError:
        pass
    return filas


def cargar(carpeta):
    c = Path(carpeta)
    run = _json(c / "run.json", {}) or {}
    gates = _json(c / "gates.json", {}) or {}
    est = _json(c / "estado.json", {}) or {}
    controles = {x["control"]: x for x in (est.get("controles") or []) if isinstance(x, dict) and x.get("control")}
    sin_red = sum(1 for x in controles.values() if MARCA_SIN_RED in (x.get("motivo") or ""))
    return {"carpeta": c, "id": run.get("id") or c.name, "run": run, "gates": gates, "controles": controles,
            "hallazgos": _jsonl(c / "hallazgos.jsonl"), "sin_red": sin_red,
            "faltan": [n for n in ("run.json", "gates.json", "estado.json", "hallazgos.jsonl") if not (c / n).is_file()]}


def dos_mas_recientes(proyecto):
    """Las dos corridas propias más recientes de P/.auditoria (mismo criterio que corrida.ultima)."""
    proyecto = Path(proyecto).resolve()
    base = proyecto / ".auditoria"
    if base.is_symlink() or not base.is_dir():
        return []
    limite = dt.datetime.now() + dt.timedelta(minutes=1)
    cand = []
    for d in base.iterdir():
        clave = corrida_mod._corrida_propia(d, proyecto, limite)
        if clave:
            cand.append((clave, d))
    return [d for _, d in sorted(cand)[-2:]]


def avisos_no_comparables(a, b):
    avisos = []
    ma, mb = a["run"].get("modo") or a["gates"].get("modo"), b["run"].get("modo") or b["gates"].get("modo")
    if ma != mb:
        avisos.append(f"cambió el modo ({ma} → {mb}): el alcance de niveles evaluados es distinto")
    if bool(a["sin_red"]) != bool(b["sin_red"]):
        avisos.append(f"cambió la red (controles con motivo «sin red»: {a['sin_red']} → {b['sin_red']}): "
                      "lo que pasa a evaluarse o deja de evaluarse puede deberse a la red, no al código")
    va, vb = a["run"].get("auditor_version"), b["run"].get("auditor_version")
    if va != vb:
        avisos.append(f"cambió la versión del auditor ({va or 's/d'} → {vb or 's/d'}): las reglas pueden diferir")
    pa, pb = a["run"].get("proyecto"), b["run"].get("proyecto")
    if pa and pb and pa != pb:
        avisos.append("las corridas son de proyectos distintos")
    for x in (a, b):
        if x["faltan"]:
            avisos.append(f"a la corrida {x['id']} le falta {', '.join(x['faltan'])}: la comparación es incompleta")
    return avisos


def _celda_nivel(g, dominio=None):
    if dominio is None:
        d = g.get("global") or {}
    else:
        d = (g.get("dominios") or {}).get(dominio) or {}
        if not d.get("activo", True):
            return "inactivo"
    if not d:
        return "s/d"
    return f"{d.get('nivel_demostrado', 's/d')} (pot. {d.get('nivel_potencial', 's/d')})"


def _ubic(h):
    u = h.get("ubicacion") or {}
    archivo = u.get("archivo") or u.get("url") or u.get("objeto_bd") or "(sin archivo)"
    return f"{archivo}:{u['linea']}" if u.get("linea") is not None else str(archivo)


def _lista(items):
    items = list(items)
    salida = [f"- {x}" for x in items[:TOPE_LISTA]]
    if len(items) > TOPE_LISTA:
        salida.append(f"- … y {len(items) - TOPE_LISTA} más")
    return salida


def comparar(a, b):
    out = [f"# Comparación de corridas", "",
           "| | Antes | Después |", "|---|---|---|",
           f"| Corrida | {a['id']} | {b['id']} |",
           f"| Modo | {a['run'].get('modo') or 's/d'} | {b['run'].get('modo') or 's/d'} |",
           f"| Controles con motivo «sin red» | {a['sin_red']} | {b['sin_red']} |",
           f"| Versión del auditor | {a['run'].get('auditor_version') or 's/d'} | {b['run'].get('auditor_version') or 's/d'} |",
           ""]
    avisos = avisos_no_comparables(a, b)
    if avisos:
        out.append("> **Aviso: corridas no comparables directamente.** Una mejora o un empeoramiento aparente puede "
                   "deberse a estas diferencias y no a cambios en el proyecto:")
        out += [f"> - {x}" for x in avisos]
        out.append("")
    ga, gb = a["gates"], b["gates"]
    gla, glb = ga.get("global") or {}, gb.get("global") or {}
    bloq = lambda g: len({x.get("control") for x in (g.get("bloqueos") or []) if isinstance(x, dict)})
    out += ["## Nivel", "", "| Ámbito | Antes | Después |", "|---|---|---|",
            f"| Global | {_celda_nivel(ga)} | {_celda_nivel(gb)} |",
            f"| ¿Listo para datos reales? | {gla.get('listo_datos_reales', 's/d')} | {glb.get('listo_datos_reales', 's/d')} |",
            f"| Bloqueos (controles) | {bloq(gla)} | {bloq(glb)} |"]
    doms = [d for d in ORDEN_DOMINIOS if d in (ga.get("dominios") or {}) or d in (gb.get("dominios") or {})]
    for d in doms:
        out.append(f"| {d} | {_celda_nivel(ga, d)} | {_celda_nivel(gb, d)} |")
    out.append("")

    # Cambios de estado por control
    grupos = {}
    for cid in sorted(set(a["controles"]) | set(b["controles"])):
        ea = (a["controles"].get(cid) or {}).get("estado", "(ausente)")
        eb = (b["controles"].get(cid) or {}).get("estado", "(ausente)")
        if ea != eb:
            grupos.setdefault((ea, eb), []).append(cid)
    total = sum(len(v) for v in grupos.values())
    out += [f"## Controles que cambiaron de estado ({total})", ""]
    if not grupos:
        out += ["Ningún control cambió de estado.", ""]

    def prioridad(par):
        ea, eb = par
        return (0 if eb == "pass" else 1 if ea == "pass" else 2 if eb == "fail" else 3, ea, eb)

    for par in sorted(grupos, key=prioridad):
        out.append(f"### {par[0]} → {par[1]} ({len(grupos[par])})")
        out += _lista(grupos[par]) + [""]

    # Hallazgos por fingerprint (solo control, severidad y archivo:línea)
    fa = {h.get("fingerprint"): h for h in a["hallazgos"] if h.get("fingerprint")}
    fb = {h.get("fingerprint"): h for h in b["hallazgos"] if h.get("fingerprint")}
    nuevos = [fb[k] for k in fb if k not in fa]
    resueltos = [fa[k] for k in fa if k not in fb]
    orden = lambda h: (h.get("control") or "", _ubic(h))
    fmt = lambda h: f"{h.get('control') or 's/d'} · {h.get('severidad') or 's/d'} · `{_ubic(h)}`"
    out += [f"## Hallazgos nuevos ({len(nuevos)})", ""] + (_lista(fmt(h) for h in sorted(nuevos, key=orden))
                                                          or ["Ninguno."]) + [""]
    out += [f"## Hallazgos que ya no aparecen ({len(resueltos)})", "",
            "Que un hallazgo no aparezca no prueba que esté corregido: también desaparece si la herramienta no corrió "
            "o si cambió el alcance (revise el aviso de arriba y el estado del control).", ""]
    out += (_lista(fmt(h) for h in sorted(resueltos, key=orden)) or ["Ninguno."]) + [""]
    out += ["---", "Solo lectura: esta comparación no cambia ningún estado. El auditor no certifica seguridad."]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Compara dos corridas del auditor (solo lectura).")
    ap.add_argument("--proyecto", help="carpeta del proyecto: compara sus dos corridas más recientes")
    ap.add_argument("--antes", help="carpeta de la corrida anterior")
    ap.add_argument("--despues", help="carpeta de la corrida posterior")
    a = ap.parse_args(argv)
    if a.proyecto and (a.antes or a.despues):
        print("comparar_corridas: use --proyecto o --antes/--despues, no ambos", file=sys.stderr)
        return 2
    if a.proyecto:
        if not Path(a.proyecto).is_dir():
            print(f"comparar_corridas: no es una carpeta: {a.proyecto}", file=sys.stderr)
            return 2
        par = dos_mas_recientes(a.proyecto)
        if len(par) < 2:
            print(f"comparar_corridas: {a.proyecto}/.auditoria tiene {len(par)} corrida(s); hacen falta 2",
                  file=sys.stderr)
            return 4
        antes, despues = par
    elif a.antes and a.despues:
        antes, despues = Path(a.antes), Path(a.despues)
        for c in (antes, despues):
            if not (c / "run.json").is_file():
                print(f"comparar_corridas: no es una carpeta de corrida (falta run.json): {c}", file=sys.stderr)
                return 4
    else:
        print("comparar_corridas: indique --proyecto P o --antes C1 --despues C2", file=sys.stderr)
        return 2
    print(comparar(cargar(antes), cargar(despues)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

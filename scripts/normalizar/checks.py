"""Lector de los chequeos propios (crudo/check_<nombre>.json).

Formato: {"estado": "ok"|"no_evaluado"|..., "motivo": ..., "hallazgos": [{regla: "check:<n>.<sub>",
           archivo, linea, mensaje, evidencia, severidad_sugerida}],
          "checks_pass": [{regla, archivo, mensaje} | "check:<n>.<sub>", ...]}
Devuelve (registros, reglas_que_pasan). La severidad sugerida puede subir la del catálogo, no bajarla.
"""
import json
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from normalizar import comun  # noqa: E402

PREFIJO = "check:"


def nombre_check(ruta):
    stem = Path(ruta).name[:-len(".json")] if Path(ruta).name.endswith(".json") else Path(ruta).stem
    return stem[len("check_"):] if stem.startswith("check_") else stem


def _regla(regla, nombre):
    r = str(regla or "").strip()
    if r.startswith(PREFIJO):
        r = r[len(PREFIJO):]
    if not r:
        r = nombre
    elif "." not in r and r != nombre:
        r = f"{nombre}.{r}"
    return r


def leer(ruta, ctx):
    with open(ruta, encoding="utf-8") as f:
        datos = json.load(f)
    if not isinstance(datos, dict):
        raise ValueError("formato de check no reconocido (se esperaba un objeto)")
    nombre = nombre_check(ruta)
    proyecto = ctx.get("proyecto")
    meta = ctx.get("metas", {}).get(nombre) or {}
    registros = []
    for h in datos.get("hallazgos", []) or []:
        if not isinstance(h, dict):
            continue
        regla = _regla(h.get("regla"), nombre)
        registros.append({
            "herramienta": "check",
            "herramienta_fuente": nombre,
            "version": meta.get("version"),
            "regla": regla,
            "regla_fuente": PREFIJO + regla,
            "archivo": comun.normalizar_archivo(h.get("archivo"), proyecto),
            "archivo_original": h.get("archivo"),
            "linea": h.get("linea") if isinstance(h.get("linea"), int) else None,
            "snippet": h.get("evidencia") or "",
            "mensaje": h.get("mensaje") or "",
            "evidencia": (f"{h.get('mensaje')}: {h.get('evidencia')}" if h.get("mensaje") and h.get("evidencia")
                          else h.get("evidencia") or h.get("mensaje") or regla),
            "severidad_herramienta": h.get("severidad_sugerida"),
            "confianza": "alta",
            "referencias": list(h.get("referencias") or []),
            "commit": None,
        })
    pasan = set()
    for r in datos.get("checks_pass", []) or []:
        regla = r.get("regla") if isinstance(r, dict) else r  # admite {regla, archivo, mensaje} o texto
        if regla:
            pasan.add(PREFIJO + _regla(regla, nombre))
    return registros, sorted(pasan)


def estado_de(ruta):
    """(estado, motivo) que declara el propio check (p. ej. no_evaluado sin red). ("error", ...) si no se lee."""
    try:
        with open(ruta, encoding="utf-8") as f:
            datos = json.load(f)
    except (OSError, ValueError):
        return "error", "no se pudo leer el resultado del check"
    if not isinstance(datos, dict):
        return "error", "formato de check no reconocido"
    return str(datos.get("estado") or "ok"), datos.get("motivo")

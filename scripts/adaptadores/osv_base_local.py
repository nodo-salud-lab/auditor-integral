#!/usr/bin/env python3
"""osv_base_local.py — ¿hay una base OSV local ya descargada para correr osv-scanner --offline? (D1, AUDITOR_SIN_RED)

osv-scanner 2.x guarda la base por ecosistema en <RAIZ>/osv-scalibr/<Ecosistema>/all.zip y toma RAIZ de
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY (o OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY). Verificado con osv-scanner 2.7.0:
con --offline y SIN base local termina con exit 0 y 0 resultados para un lockfile (falso negativo silencioso), por eso
el adaptador no lo ejecuta si este script no encuentra una base. Nunca descarga nada ni abre conexiones.

Candidatas, en orden: las variables anteriores (si alguna está definida, solo esas: la elección del usuario manda);
si no, la caché del usuario (~/Library/Caches en macOS, ${XDG_CACHE_HOME:-~/.cache}).
Salida: JSON {"raiz": RAIZ, "ecosistemas": [...], "actualizada_utc": fecha del all.zip más reciente} y exit 0 si hay al menos un all.zip no vacío; exit 1 si no hay base.
"""
import json
import os
import sys
from pathlib import Path

VARIABLES = ("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", "OSV_SCALIBR_LOCAL_DB_CACHE_DIRECTORY")


def candidatas(env=None):
    env = os.environ if env is None else env
    explicitas = [env[v] for v in VARIABLES if env.get(v)]
    if explicitas:
        return [Path(x) for x in explicitas]
    res = []
    if env.get("HOME"):
        res.append(Path(env["HOME"]) / "Library" / "Caches")
    if env.get("XDG_CACHE_HOME"):
        res.append(Path(env["XDG_CACHE_HOME"]))
    elif env.get("HOME"):
        res.append(Path(env["HOME"]) / ".cache")
    vistas, unicas = set(), []
    for c in res:
        if str(c) not in vistas:
            vistas.add(str(c))
            unicas.append(c)
    return unicas


def buscar(env=None):
    for raiz in candidatas(env):
        base = raiz / "osv-scalibr"
        try:
            ecos = sorted(d.name for d in base.iterdir()
                          if d.is_dir() and (d / "all.zip").is_file() and (d / "all.zip").stat().st_size > 0)
        except OSError:
            continue
        if ecos:
            import datetime as dt
            mtime = max((base / e / "all.zip").stat().st_mtime for e in ecos)
            return {"raiz": str(raiz), "ecosistemas": ecos,
                    "actualizada_utc": dt.datetime.fromtimestamp(mtime, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    return None


def main():
    hallada = buscar()
    if not hallada:
        return 1
    print(json.dumps(hallada, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""resumen_crudo — estado y conteo de hallazgos crudos por herramienta (después de ejecutar_scanners.sh).

Uso: resumen_crudo.py DIR_CRUDO [--modo M] [--duracion S] [--sin-tabla]
Escribe DIR_CRUDO/resumen_scan.json e imprime una tabla por stdout. No interpreta severidades ni
controles: eso es de normalizar/. Los conteos son de hallazgos CRUDOS (antes de deduplicar/filtrar).
"""
import argparse
import datetime as dt
import json
import sys
from pathlib import Path


def _json(ruta):
    try:
        return json.loads(Path(ruta).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _sarif_resultados(ruta):
    d = _json(ruta)
    if not isinstance(d, dict):
        return None
    return [r for run in d.get("runs") or [] for r in run.get("results") or []]


def contar_gitleaks(crudo):
    detalle = {}
    for modo, archivo in (("dir", "gitleaks.json"), ("git", "gitleaks-git.json"), ("bundle", "gitleaks-bundle.json")):
        d = _json(crudo / archivo)
        if isinstance(d, list):
            detalle[modo] = len(d)
    return (sum(detalle.values()) if detalle else None), detalle


def contar_semgrep(crudo):
    res = _sarif_resultados(crudo / "semgrep.sarif")
    if res is None:
        return None, {}
    propias = sum(1 for r in res if "vibe-coding." in str(r.get("ruleId", "")))
    return len(res), {"vibe-coding": propias, "registro": len(res) - propias}


def contar_osv(crudo):
    d = _json(crudo / "osv.json")
    if not isinstance(d, dict):
        return None, {}
    vulns, paquetes = 0, 0
    for r in d.get("results") or []:
        for p in r.get("packages") or []:
            v = p.get("vulnerabilities") or []
            if v:
                paquetes += 1
                vulns += len(v)
    return vulns, {"paquetes_afectados": paquetes}


def contar_zizmor(crudo):
    res = _sarif_resultados(crudo / "zizmor.sarif")
    return (None, {}) if res is None else (len(res), {})


def contar_check(nombre):
    def contar(crudo):
        d = _json(crudo / f"check_{nombre}.json")
        if not isinstance(d, dict):
            return None, {}
        detalle = {"pases": len(d.get("checks_pass") or [])}
        if d.get("cobertura") == "parcial (fallback)":  # DECISIONES.md #6
            detalle["fallback_de"] = d.get("reemplaza")
        return len(d.get("hallazgos") or []), detalle
    return contar


HERRAMIENTAS = [
    ("gitleaks", "gitleaks", contar_gitleaks),
    ("semgrep", "semgrep", contar_semgrep),
    ("osv", "osv", contar_osv),
    ("zizmor", "zizmor", contar_zizmor),
    ("check:env_publicas", "check_env_publicas", contar_check("env_publicas")),
    ("check:registro_deps", "check_registro_deps", contar_check("registro_deps")),
    ("check:archivos_clave", "check_archivos_clave", contar_check("archivos_clave")),
    ("check:config_agentes", "check_config_agentes", contar_check("config_agentes")),
] + [(f"check:{n}", f"check_{n}", contar_check(n)) for n in (
    "datos_confidenciales",
    # fallbacks estáticos (DECISIONES.md #6): cobertura parcial; detalle «fallback_de=<herramienta real>»
    "duplicacion", "complejidad", "deps_muertas", "migraciones_sql", "dockerfile", "iac", "sbom", "workflows",
    "rls_estatico", "ux_estatico", "presupuesto_build",
    # runner opcional de tsc local (Anexo C, M-01): solo si node_modules/.bin/tsc ya existe
    "tipos",
    # F3: inventario de rutas para el revisor-autorizacion (nunca da pass por sí mismo)
    "rutas_inventario")]


def resumir(crudo, modo=None, duracion=None):
    crudo = Path(crudo)
    filas = []
    for herramienta, meta_nombre, contar in HERRAMIENTAS:
        meta = _json(crudo / f"{meta_nombre}.meta.json") or {}
        n, detalle = contar(crudo)
        filas.append({
            "herramienta": herramienta,
            "estado": meta.get("estado", "sin_meta"),
            "version": meta.get("version"),
            "hallazgos": n,
            "detalle": detalle,
            "duracion_s": meta.get("duracion_s"),
            "error": meta.get("error"),
            "meta": f"{meta_nombre}.meta.json",
        })
    return {
        "version_esquema": "1",
        "generado": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "modo": modo,
        "duracion_total_s": duracion,
        "herramientas": filas,
        "total_hallazgos_crudos": sum(f["hallazgos"] or 0 for f in filas),
    }


def tabla(resumen):
    lineas = [f"{'herramienta':<28} {'estado':<12} {'versión':<9} {'hallazgos':>9}  detalle",
              "-" * 84]
    for f in resumen["herramientas"]:
        n = "-" if f["hallazgos"] is None else str(f["hallazgos"])
        det = ", ".join(f"{k}={v}" for k, v in f["detalle"].items())
        if f["estado"] not in ("ok",) and f["error"]:
            det = (det + " · " if det else "") + f["error"][:60]
        lineas.append(f"{f['herramienta']:<28} {f['estado']:<12} {str(f['version'] or '-'):<9} {n:>9}  {det}")
    lineas.append("-" * 84)
    lineas.append(f"{'total (crudos)':<50} {resumen['total_hallazgos_crudos']:>9}"
                  + (f"  · modo {resumen['modo']}" if resumen.get("modo") else "")
                  + (f" · {resumen['duracion_total_s']} s" if resumen.get("duracion_total_s") is not None else ""))
    return "\n".join(lineas)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("crudo")
    ap.add_argument("--modo")
    ap.add_argument("--duracion", type=float)
    ap.add_argument("--sin-tabla", action="store_true")
    a = ap.parse_args(argv)
    crudo = Path(a.crudo)
    if not crudo.is_dir():
        print(f"resumen_crudo.py: no existe {crudo}", file=sys.stderr)
        return 2
    r = resumir(crudo, a.modo, a.duracion)
    (crudo / "resumen_scan.json").write_text(json.dumps(r, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not a.sin_tabla:
        print(tabla(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())

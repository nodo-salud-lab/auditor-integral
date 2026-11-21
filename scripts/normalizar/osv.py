"""Lector de osv-scanner v2 (--format json): results[].packages[].groups[] con max_severity (CVSS).

Un registro por (paquete, clase de severidad real) — pendiente §6.3 de 10-f0-f1-resultados:
  critica (CVSS ≥ 9 / GHSA CRITICAL)        → "osv:critica/<id>" → SEG-DEPS-CVE-CRIT  (N2)
  alta    (CVSS 7-8,9 / GHSA HIGH)          → "osv:alta/<id>"    → SEG-DEPS-CVE-ALTO  (N4)
  media o baja (CVSS < 7 / MODERATE, LOW)   → "osv:media/<id>" o "osv:baja/<id>" → SEG-DEPS-CVE-MEDIO (N4)
La severidad sale del CVSS (max_severity del grupo, como hace osv-scanner) y, sin CVSS, de
database_specific.severity de GitHub Advisory; sin ninguno se toma "media" (no se asume baja).
Así un paquete con 25 avisos no ocupa 25 hallazgos y el tope de 5 por (control, archivo) no
esconde paquetes. La línea citada en package-lock v2/v3 es la de la clave node_modules/<paquete>
con la versión afectada (LOCK-LINEA). Un lockfile en una ruta confidencial (config/confidencial.toml) no se lee.
"""
import json
import re
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import utiles  # noqa: E402
from normalizar import comun  # noqa: E402

sys.path.append(str(_SCRIPTS / "checks"))
import datos_confidenciales  # noqa: E402

HERRAMIENTA = "osv-scanner"
_TEXTO_SEV = {"CRITICAL": "critica", "HIGH": "alta", "MODERATE": "media", "MEDIUM": "media", "LOW": "baja"}


def severidad_cvss(valor):
    try:
        v = float(valor)
    except (TypeError, ValueError):
        return None
    if v >= 9.0:
        return "critica"
    if v >= 7.0:
        return "alta"
    if v >= 4.0:
        return "media"
    return "baja" if v > 0 else None


def _sev_grupo(grupo, vulns):
    sev = severidad_cvss(grupo.get("max_severity"))
    if sev:
        return sev
    for vid in grupo.get("ids", []):
        texto = ((vulns.get(vid) or {}).get("database_specific") or {}).get("severity")
        if texto and str(texto).upper() in _TEXTO_SEV:
            return _TEXTO_SEV[str(texto).upper()]
    return "media"  # sin dato: no se asume baja


def _puntaje(grupo):
    try:
        return float(grupo.get("max_severity"))
    except (TypeError, ValueError):
        return -1.0


def _confidencial(archivo, conf, proyecto=None):
    if not archivo or conf is None:
        return False
    archivo = str(archivo)
    if proyecto is not None and archivo.startswith(str(proyecto).rstrip("/") + "/"):
        archivo = archivo[len(str(proyecto).rstrip("/")) + 1:]
    if archivo.startswith("/"):
        return False
    return datos_confidenciales.es_confidencial(archivo, conf)


_LOCK_NPM = ("package-lock.json", "npm-shrinkwrap.json")
_VERSION_LOCK = re.compile(r'^\s*"version"\s*:\s*"([^"]*)"')


def _linea_npm(lineas, nombre, version):
    """LOCK-LINEA: línea de la clave "…node_modules/<nombre>" de package-lock v2/v3 cuya versión coincide.

    Se prefiere la entrada de nivel superior ("node_modules/<nombre>") a una copia anidada
    ("node_modules/a/node_modules/<nombre>"); una mención como dependencia de otro paquete
    ("<nombre>": "^x") nunca cuenta. Sin coincidencia de versión, la primera entrada de nivel superior.
    """
    clave = re.compile(r'^\s*"((?:[^"]*/)?node_modules/' + re.escape(nombre) + r')"\s*:\s*\{')
    candidatos = []
    for i, texto in enumerate(lineas):
        m = clave.match(texto)
        if not m:
            continue
        ver = None
        for siguiente in lineas[i + 1:i + 40]:
            mv = _VERSION_LOCK.match(siguiente)
            if mv:
                ver = mv.group(1)
                break
            if clave.match(siguiente) or re.match(r'^\s*"[^"]*node_modules/[^"]*"\s*:\s*\{', siguiente):
                break
        candidatos.append((i + 1, m.group(1) == f"node_modules/{nombre}", ver))
    if not candidatos:
        return None
    if version:
        exactos = [c for c in candidatos if c[2] == version]
        if exactos:
            return min(exactos, key=lambda c: (not c[1], c[0]))[0]
    return min(candidatos, key=lambda c: (not c[1], c[0]))[0]


def _linea_en_lockfile(proyecto, archivo, nombre, version=None):
    if not proyecto or not archivo or not nombre:
        return None
    ruta = Path(proyecto) / archivo
    if not ruta.is_file() or ruta.stat().st_size > 20_000_000:
        return None
    try:
        with open(ruta, encoding="utf-8", errors="replace") as f:
            lineas = f.read().splitlines()
    except OSError:
        return None
    if ruta.name in _LOCK_NPM:
        n = _linea_npm(lineas, nombre, version)
        if n is not None:
            return n
    marcas = (f'"node_modules/{nombre}"', f'"{nombre}":', f"{nombre}==", f'name = "{nombre}"')
    for n, linea in enumerate(lineas, 1):
        if any(m in linea for m in marcas):
            return n
    return None


_TEXTO_CLASE = {"critica": "críticos", "alta": "altos", "media": "medios o bajos"}


def _clase(sev):
    return sev if sev in ("critica", "alta") else "media"


def _registro(paquete, grupos, vulns, clase, archivo, linea, version_herr):
    grupos = sorted(grupos, key=lambda g: (-_puntaje(g), g.get("ids", [""])[0]))
    principal = grupos[0]
    pid = principal.get("ids", ["?"])[0]
    sev_max = min((_sev_grupo(g, vulns) for g in grupos), key=utiles.rango_severidad)
    alias = [a for a in principal.get("aliases", []) if a.startswith("CVE-")]
    nombre, version = paquete.get("name", "?"), paquete.get("version", "?")
    puntaje = principal.get("max_severity") or "s/d"
    otros = ", ".join(g.get("ids", ["?"])[0] for g in grupos[1:6])
    texto = (f"{nombre}@{version} ({paquete.get('ecosystem', '?')}): {len(grupos)} aviso(s) "
             f"{_TEXTO_CLASE[clase]}; máx CVSS {puntaje}: {pid}"
             f"{' (' + alias[0] + ')' if alias else ''}" + (f"; otros: {otros}" if otros else "")
             + ("…" if len(grupos) > 6 else ""))
    refs = alias[:3] + [f"https://osv.dev/vulnerability/{pid}"]
    return {
        "herramienta": "osv",
        "herramienta_fuente": HERRAMIENTA,
        "version": version_herr,
        "regla": f"{sev_max}/{pid}",
        "archivo": archivo,
        "linea": linea,
        "snippet": f"{nombre}@{version} {clase}",
        "mensaje": texto,
        "evidencia": texto,
        "severidad_herramienta": sev_max,
        "confianza": "alta",
        "referencias": refs,
        "commit": None,
    }


def leer(ruta, ctx):
    with open(ruta, encoding="utf-8") as f:
        datos = json.load(f)
    if not isinstance(datos, dict):
        raise ValueError("formato osv-scanner no reconocido")
    proyecto = ctx.get("proyecto")
    conf = ctx.get("confidencial")
    meta = ctx.get("metas", {}).get(HERRAMIENTA) or {}
    registros = []
    for res in datos.get("results", []) or []:
        archivo_original = (res.get("source") or {}).get("path")
        archivo = comun.normalizar_archivo(archivo_original, proyecto)
        if _confidencial(archivo, conf) or _confidencial(archivo_original, conf, proyecto):
            continue  # no se lee el lockfile ni se informa nada de esa ruta
        for p in res.get("packages", []) or []:
            paquete = p.get("package") or {}
            vulns = {v.get("id"): v for v in p.get("vulnerabilities", []) or [] if isinstance(v, dict)}
            grupos = [g for g in p.get("groups", []) or [] if isinstance(g, dict) and g.get("ids")]
            if not grupos:
                grupos = [{"ids": [vid], "aliases": v.get("aliases", []), "max_severity": ""} for vid, v in vulns.items()]
            clases = {}
            for g in grupos:
                clases.setdefault(_clase(_sev_grupo(g, vulns)), []).append(g)
            linea = _linea_en_lockfile(proyecto, archivo, paquete.get("name", ""), paquete.get("version"))
            for clase in ("critica", "alta", "media"):
                if clases.get(clase):
                    registros.append(_registro(paquete, clases[clase], vulns, clase, archivo, linea, meta.get("version")))
    return registros

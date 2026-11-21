"""Lector genérico de SARIF 2.1.0 (semgrep, zizmor y cualquier herramienta que emita SARIF).

- herramienta: nombre del driver canonizado (semgrep, zizmor, ...).
- regla: ruleId sin el prefijo "<herramienta>/" (zizmor/unpinned-uses → unpinned-uses).
- severidad_herramienta: solo desde la propiedad numérica security-severity (convención de
  GitHub code scanning; ≥ 9 crítica, ≥ 7 alta, ≥ 4 media). El `level` SARIF no sube la
  severidad: la fija el catálogo.
- archivo: relativo al proyecto auditado (las URIs de zizmor vienen relativas a la raíz git).
- linea_fin: endLine de la región (para la huella de contenido de la fusión; ver comun.fusionar).
"""
import json
import re
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import catalogo  # noqa: E402
from normalizar import comun  # noqa: E402

CONFIANZA = {"zizmor": "alta", "semgrep": "media"}
_CWE = re.compile(r"^(CWE-\d+)")


def canonizar(nombre):
    n = (nombre or "desconocida").strip().lower()
    for conocida in ("semgrep", "zizmor", "trivy", "checkov", "hadolint", "bandit", "bearer", "actionlint"):
        if conocida in n:
            return conocida
    return n.split()[0] if n.split() else "desconocida"


def severidad_numerica(valor):
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


def _referencias(regla):
    refs = []
    if regla.get("helpUri"):
        refs.append(regla["helpUri"])
    for tag in (regla.get("properties") or {}).get("tags", []) or []:
        m = _CWE.match(str(tag))
        if m and m.group(1) not in refs:
            refs.append(m.group(1))
    return refs


def leer(ruta, ctx):
    with open(ruta, encoding="utf-8") as f:
        datos = json.load(f)
    if not isinstance(datos, dict) or not isinstance(datos.get("runs"), list):
        raise ValueError("no es un SARIF válido (falta runs)")
    proyecto = ctx.get("proyecto")
    registros = []
    for run in datos["runs"]:
        driver = ((run.get("tool") or {}).get("driver") or {})
        herramienta = canonizar(driver.get("name"))
        meta = ctx.get("metas", {}).get(herramienta) or {}
        version = meta.get("version") or driver.get("semanticVersion") or driver.get("version")
        reglas = {r.get("id"): r for r in driver.get("rules", []) or [] if isinstance(r, dict)}
        for res in run.get("results", []) or []:
            rule_id = str(res.get("ruleId") or "desconocida")
            regla = rule_id[len(herramienta) + 1:] if rule_id.startswith(herramienta + "/") else rule_id
            # semgrep antepone la ruta (absoluta) del archivo de reglas propias: se recorta para que la
            # regla y el fingerprint no dependan de la máquina ni filtren rutas locales.
            regla = catalogo.normalizar_regla(herramienta, regla)
            meta_regla = reglas.get(rule_id, {})
            props = meta_regla.get("properties") or {}
            sev = severidad_numerica((res.get("properties") or {}).get("security-severity")
                                     or props.get("security-severity"))
            archivo, archivo_original, linea, linea_fin, snippet = None, None, None, None, ""
            locs = res.get("locations") or []
            if locs:
                fis = (locs[0] or {}).get("physicalLocation") or {}
                archivo_original = (fis.get("artifactLocation") or {}).get("uri")
                archivo = comun.normalizar_archivo(archivo_original, proyecto)
                region = fis.get("region") or {}
                linea = region.get("startLine") if isinstance(region.get("startLine"), int) else None
                linea_fin = region.get("endLine") if isinstance(region.get("endLine"), int) else None
                snippet = ((region.get("snippet") or {}).get("text")
                           or ((fis.get("contextRegion") or {}).get("snippet") or {}).get("text") or "")
            mensaje = (res.get("message") or {}).get("text") or ""
            registros.append({
                "herramienta": herramienta,
                "version": version,
                "regla": regla,
                "archivo": archivo,
                "archivo_original": archivo_original,
                "linea": linea,
                "linea_fin": linea_fin,
                "snippet": snippet,
                "mensaje": mensaje,
                "evidencia": f"{snippet.strip()} — {mensaje}" if snippet.strip() else mensaje,
                "severidad_herramienta": sev,
                "confianza": CONFIANZA.get(herramienta, "media"),
                "referencias": _referencias(meta_regla),
                "commit": None,
            })
    return registros

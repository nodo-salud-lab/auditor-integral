#!/usr/bin/env python3
"""sbom — fallback de syft (DECISIONES #6; investigacion/13 §4.14). Cobertura parcial.

Inventario de componentes desde lockfiles (sin instalar nada y sin leer node_modules):
package-lock.json (v1/v2/v3), pnpm-lock.yaml, yarn.lock, requirements*.txt y requirements*.lock (==), poetry.lock / uv.lock
(tomllib), Pipfile.lock. Escribe DIR_CRUDO/sbom.cdx.json (CycloneDX 1.5 mínimo). Licencias: solo las
que declara package-lock.json v2/v3 (campo `license`); sin ese dato la licencia queda desconocida.

Subregla                  sev     → control
  sbom_no_versionado       baja    → SEG-SBOM (no hay SBOM en el repo ni paso de CI que lo genere)
  licencia_copyleft        media   → COD-LICENCIAS (GPL/AGPL/SSPL en dependencia de producción; LGPL: baja)
  licencia_desconocida     baja    → COD-LICENCIAS (lockfile con licencias, pero el paquete no declara)
  proyecto_sin_licencia    info    → COD-LICENCIAS
Pases: ok_sbom_versionado (→ SEG-SBOM), ok_inventario (informativo: componentes inventariados; no
equivale a un SBOM versionado ni a licencias verificadas). La compatibilidad con el modelo de
distribución (propietario/SaaS) depende de la entrevista: el hallazgo copyleft lo pide verificar.
Uso: sbom.py PROYECTO DIR_CRUDO
"""
import json
import re
import sys
import tomllib
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402

NOMBRE = "sbom"
REEMPLAZA = "syft"
HERRAMIENTAS_REALES = ("syft",)
MAX_POR_SUBREGLA = 20
RE_COPYLEFT = re.compile(r"\b(A?GPL|SSPL|LGPL|EUPL|OSL|CC-BY-SA)", re.I)
RE_SBOM_ARCHIVO = re.compile(r"(\.cdx\.json|\.spdx\.json|\.spdx|bom\.json|bom\.xml)$|^sbom", re.I)
RE_SBOM_CI = re.compile(r"\b(syft|cdxgen|cyclonedx|spdx-sbom-generator|anchore/sbom-action|sbom)\b", re.I)


def _npm_lock(texto):
    datos = json.loads(texto)
    comps = []
    paquetes = datos.get("packages")
    if isinstance(paquetes, dict):
        for clave, info in paquetes.items():
            if not clave or "node_modules/" not in clave or not isinstance(info, dict) or info.get("link"):
                continue
            nombre = info.get("name") or clave.rsplit("node_modules/", 1)[-1]
            lic = info.get("license")
            if isinstance(lic, dict):
                lic = lic.get("type")
            comps.append({"eco": "npm", "nombre": nombre, "version": info.get("version"),
                          "licencia": lic if isinstance(lic, str) else None, "dev": bool(info.get("dev")),
                          "con_licencias": True})
    elif isinstance(datos.get("dependencies"), dict):  # lockfileVersion 1
        def recorrer(deps):
            for n, info in deps.items():
                if isinstance(info, dict):
                    comps.append({"eco": "npm", "nombre": n, "version": info.get("version"), "licencia": None,
                                  "dev": bool(info.get("dev")), "con_licencias": False})
                    recorrer(info.get("dependencies") or {})
        recorrer(datos["dependencies"])
    return comps


def _pnpm_lock(texto):
    comps = []
    for m in re.finditer(r"^\s{2}['\"]?/?((?:@[^/@\s'\"]+/)?[^/@\s'\":]+)[@/](\d[^:'\"\s(]*)", texto, re.M):
        comps.append({"eco": "npm", "nombre": m.group(1), "version": m.group(2), "licencia": None, "dev": False,
                      "con_licencias": False})
    return comps


def _yarn_lock(texto):
    comps = []
    for m in re.finditer(r'^"?((?:@[^@\s"/]+/)?[^@\s",]+)@[^\n]*:\n(?:[ \t]+[^\n]*\n)*?[ \t]+version:?\s+"?([^"\s]+)"?',
                         texto, re.M):
        comps.append({"eco": "npm", "nombre": m.group(1), "version": m.group(2), "licencia": None, "dev": False,
                      "con_licencias": False})
    return comps


def _requirements(texto):
    comps = []
    for linea in texto.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([^\s;#]+)", linea)
        if m:
            comps.append({"eco": "pypi", "nombre": m.group(1).lower(), "version": m.group(3), "licencia": None,
                          "dev": False, "con_licencias": False})
    return comps


def _toml_lock(texto):
    datos = tomllib.loads(texto)
    return [{"eco": "pypi", "nombre": str(p.get("name", "")).lower(), "version": p.get("version"), "licencia": None,
             "dev": False, "con_licencias": False} for p in datos.get("package", []) if isinstance(p, dict) and p.get("name")]


def _pipfile_lock(texto):
    datos = json.loads(texto)
    comps = []
    for seccion, dev in (("default", False), ("develop", True)):
        for n, info in (datos.get(seccion) or {}).items():
            v = (info or {}).get("version", "") if isinstance(info, dict) else ""
            comps.append({"eco": "pypi", "nombre": n.lower(), "version": v.lstrip("="), "licencia": None, "dev": dev,
                          "con_licencias": False})
    return comps


LECTORES = [
    (lambda n: n == "package-lock.json" or n == "npm-shrinkwrap.json", _npm_lock),
    (lambda n: n == "pnpm-lock.yaml", _pnpm_lock),
    (lambda n: n == "yarn.lock", _yarn_lock),
    # Ronda 6 (integración, DECISIONES.md #12): requirements.lock (pip-compile/rye, formato ==) como requirements*.txt;
    # detectar_stack y archivos_clave ya lo reconocían como lockfile.
    (lambda n: re.fullmatch(r"requirements[\w.-]*\.(txt|lock)", n) is not None, _requirements),
    (lambda n: n in ("poetry.lock", "uv.lock"), _toml_lock),
    (lambda n: n == "Pipfile.lock", _pipfile_lock),
]


def purl(c):
    if c["eco"] == "npm":
        return f"pkg:npm/{quote(c['nombre'], safe='/')}@{quote(str(c['version'] or ''), safe='')}"
    return f"pkg:pypi/{quote(c['nombre'], safe='')}@{quote(str(c['version'] or ''), safe='')}"


def analizar(proyecto, crudo=None):
    proyecto = Path(proyecto)
    comps, fuentes = [], []
    for p in fb.recorrer(proyecto):
        lector = next((f for cond, f in LECTORES if cond(p.name)), None)
        if lector is None:
            continue
        texto = comun.leer(p, limite=50_000_000)
        if texto is None:
            continue
        try:
            nuevos = lector(texto)
        except (ValueError, tomllib.TOMLDecodeError):
            continue
        fuentes.append(fb.rel(proyecto, p))
        comps.extend(dict(c, fuente=fb.rel(proyecto, p)) for c in nuevos)
    if not fuentes:
        return fb.resultado(REEMPLAZA, estado="no_evaluado", motivo="no hay lockfiles ni requirements con versiones "
                            "fijas: no se puede inventariar (requiere syft)")
    unicos = {}
    for c in comps:
        unicos.setdefault((c["eco"], c["nombre"], c["version"]), c)
    componentes = sorted(unicos.values(), key=lambda c: (c["eco"], c["nombre"], str(c["version"])))
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"tools": [{"name": "auditor-integral check:sbom", "version": comun.VERSION_CHECKS}],
                        "properties": [{"name": "auditor:cobertura", "value": fb.COBERTURA},
                                       {"name": "auditor:fuentes", "value": ", ".join(fuentes)}]},
           "components": []}
    for c in componentes:
        comp = {"type": "library", "name": c["nombre"], "version": c["version"] or "", "purl": purl(c)}
        if c["licencia"]:
            clave = "id" if re.fullmatch(r"[A-Za-z0-9.+-]+", c["licencia"]) else "name"
            comp["licenses"] = [{"license": {clave: c["licencia"]}}]
        if c["dev"]:
            comp["scope"] = "optional"
        bom["components"].append(comp)
    hallazgos, pases = [], []
    # SEG-SBOM: SBOM versionado o generado en CI
    versionado = [fb.rel(proyecto, p) for p in fb.recorrer(proyecto, {".json", ".xml", ".spdx"})
                  if RE_SBOM_ARCHIVO.search(p.name) and p.name not in ("package.json",)]
    ci = []
    for p in fb.recorrer(proyecto, {".yml", ".yaml"}, desde=".github/workflows"):
        texto = comun.leer(p) or ""
        if RE_SBOM_CI.search(texto):
            ci.append(fb.rel(proyecto, p))
    if versionado or ci:
        pases.append(fb.pase(NOMBRE, "sbom_versionado", "SBOM en el repo o generado en CI: " + ", ".join((versionado + ci)[:3])))
    else:
        hallazgos.append(comun.hallazgo(NOMBRE, "sbom_no_versionado", None, None, "No hay SBOM versionado (*.cdx.json, "
                                        "*.spdx.json) ni paso de CI que lo genere (syft/cdxgen).",
                                        f"{len(componentes)} componentes inventariados desde {', '.join(fuentes[:3])}", "baja"))
    # COD-LICENCIAS
    copyleft, desconocida = [], []
    for c in componentes:
        if c["dev"]:
            continue
        if c["licencia"] and RE_COPYLEFT.search(c["licencia"]):
            copyleft.append(c)
        elif c["con_licencias"] and (not c["licencia"] or c["licencia"].upper().startswith(("UNLICENSED", "SEE LICENSE"))):
            desconocida.append(c)
    for c in copyleft[:MAX_POR_SUBREGLA]:
        sev = "baja" if re.match(r"LGPL", c["licencia"], re.I) else "media"
        hallazgos.append(comun.hallazgo(NOMBRE, "licencia_copyleft", c["fuente"], None,
                                        f"Dependencia de producción con licencia copyleft ({c['licencia']}): verificar "
                                        "compatibilidad con el modelo de distribución declarado (propietario/SaaS).",
                                        f"{c['nombre']}@{c['version']} ({c['licencia']})", sev))
    for c in desconocida[:MAX_POR_SUBREGLA]:
        hallazgos.append(comun.hallazgo(NOMBRE, "licencia_desconocida", c["fuente"], None,
                                        "Dependencia de producción sin licencia declarada en el lockfile.",
                                        f"{c['nombre']}@{c['version']}", "baja"))
    resto = len(desconocida) - MAX_POR_SUBREGLA
    if resto > 0:
        hallazgos.append(comun.hallazgo(NOMBRE, "licencia_desconocida", None, None, f"… y {resto} dependencias más sin "
                                        "licencia declarada.", f"{resto} más", "baja"))
    tiene_licencia = any(p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING"))
                         for p in proyecto.iterdir() if p.is_file())
    pkg = proyecto / "package.json"
    if not tiene_licencia and pkg.is_file():
        try:
            tiene_licencia = bool(json.loads(pkg.read_text(encoding="utf-8")).get("license"))
        except (OSError, ValueError, AttributeError):
            pass
    if not tiene_licencia:
        hallazgos.append(comun.hallazgo(NOMBRE, "proyecto_sin_licencia", None, None, "El repositorio no declara licencia "
                                        "(LICENSE* ni campo license en package.json).", "sin LICENSE", "info"))
    con_lic = sum(1 for c in componentes if c["licencia"])
    pases.append(fb.pase(NOMBRE, "inventario", f"{len(componentes)} componentes inventariados en sbom.cdx.json; "
                         f"{con_lic} con licencia declarada en el lockfile"))
    if crudo:  # al final: el SBOM propio no debe contarse como "SBOM versionado" del proyecto
        comun.escribir_json(Path(crudo) / "sbom.cdx.json", bom)
    return fb.resultado(REEMPLAZA, hallazgos, pases)


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))

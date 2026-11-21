"""Infraestructura común de los fallbacks estáticos (DECISIONES.md #6; investigacion/13-fallbacks-herramientas.md).

Un fallback es un chequeo propio (mismo contrato que comun.py) que cubre PARCIALMENTE un control
cuando falta la herramienta real. Diferencias con un chequeo normal:

- Salida: además de {check, version, estado, motivo, hallazgos, checks_pass} lleva
  `reemplaza` (herramienta real) y `cobertura` = "parcial (fallback)".
- Solo corre si la herramienta real está ausente según `herramientas.json` de doctor
  (DIR_CORRIDA/herramientas.json, es decir, el padre de DIR_CRUDO; o la ruta de la variable
  AUDITOR_HERRAMIENTAS_JSON). Si la herramienta real está disponible → estado "no_evaluado" con
  motivo, sin hallazgos (orden: herramienta real > fallback; evita fingerprints duplicados).
  Sin herramientas.json se asume ausente y el fallback corre.
- Los pases llevan subregla con prefijo `ok_` (p. ej. check:dockerfile.ok_tag_latest): un fallback
  es herramienta parcial, así que el catálogo debe mapear cada pase de forma explícita y solo
  cuando el fallback cubre el control por completo (ver investigacion/propuestas/fallbacks_integracion.md).
- Recorrido: excluye siempre comun.DIRS_EXCLUIDOS (node_modules, dist, ...) y lo confidencial
  (Decisión 3): config/confidencial.toml (o AUDITOR_CONFIDENCIAL) con la regla de coincidencia de
  datos_confidenciales.es_confidencial (carpetas a cualquier profundidad y globs de nombre de archivo,
  p. ej. *.dcm; ronda 6: en las carpetas_ambiguas —pacientes, patients— solo cuentan los archivos de
  datos, y el código de esas carpetas se recorre y analiza), unida SIEMPRE a los defaults datos-reales/, datos-abiertos/, node_modules/, dist/.
  Nada de eso se lee. presupuesto_build es la única excepción para dist/ (nunca para node_modules).
- Estados: "ok", "no_aplica" (no hay nada que analizar: el control queda no_aplica por la
  herramienta), "no_evaluado", "parcial" (corrió solo una parte), "error".
"""
import json
import os
import re
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402

try:  # fuente única de la regla de coincidencia confidencial (carpetas a cualquier profundidad + globs)
    import datos_confidenciales as _dc  # noqa: E402
except Exception:  # noqa: BLE001 — sin el módulo quedan los defaults y las listas leídas aquí
    _dc = None

RAIZ_AUDITOR = Path(__file__).resolve().parent.parent.parent
CONFIDENCIAL = RAIZ_AUDITOR / "config" / "confidencial.toml"
UMBRALES = RAIZ_AUDITOR / "config" / "umbrales.toml"
COBERTURA = "parcial (fallback)"
EXCLUSIONES_DEFECTO = ("datos-reales", "datos-abiertos", "node_modules", "dist")
SIEMPRE_EXCLUIDOS = ("node_modules",)
CLAVES_LISTA = ("excluir", "exclusiones", "carpetas", "rutas", "directorios", "patrones", "confidenciales")

rel = comun.rel
leer = comun.leer
hallazgo = comun.hallazgo


def _normalizar_patron(p):
    p = str(p).strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    for suf in ("/**/*", "/**", "/*", "/"):
        if p.endswith(suf):
            p = p[: -len(suf)]
    while p.startswith("**/"):
        p = p[3:]
    return p.strip("/")


def _listas(nodo):
    """Listas de cadenas bajo claves conocidas, a cualquier profundidad del TOML."""
    if isinstance(nodo, dict):
        for k, v in nodo.items():
            if isinstance(v, list) and str(k).lower() in CLAVES_LISTA:
                yield [x for x in v if isinstance(x, str)]
            elif isinstance(v, (dict, list)):
                yield from _listas(v)
    elif isinstance(nodo, list):
        for x in nodo:
            yield from _listas(x)


def cargar_exclusiones(ruta=None):
    """Conjunto de nombres de carpeta (sin '/') o rutas relativas (con '/') que nunca se recorren.

    Lee config/confidencial.toml si existe (formato tolerante: cualquier lista de cadenas bajo
    claves excluir/exclusiones/carpetas/rutas/directorios/patrones/confidenciales, en la raíz o en
    tablas) y la une SIEMPRE con los defaults (más restrictivo: unión, nunca reemplazo).
    """
    ruta = Path(ruta or os.environ.get("AUDITOR_CONFIDENCIAL") or CONFIDENCIAL)
    excl = set(EXCLUSIONES_DEFECTO)
    try:
        if ruta.is_file():
            with open(ruta, "rb") as f:
                datos = tomllib.load(f)
            for lista in _listas(datos):
                for p in lista:
                    n = _normalizar_patron(p)
                    if n and "*" not in n:
                        excl.add(n)
    except (OSError, tomllib.TOMLDecodeError):
        pass  # config ilegible: se quedan los defaults (fail-safe)
    return frozenset(excl)


def excluido(rel_posix, exclusiones):
    partes = rel_posix.split("/")
    for e in exclusiones:
        if "/" in e:
            if rel_posix == e or rel_posix.startswith(e + "/"):
                return True
        elif e in partes:
            return True
    return False


def cargar_confidencial(ruta=None):
    """Configuración en el formato de datos_confidenciales ({carpetas, archivos}) o None si no se puede leer."""
    if _dc is None:
        return None
    try:
        return _dc.cargar(ruta)
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return None


def recorrer(proyecto, extensiones=None, nombres=None, confidencial=None, permitir=(), desde=None):
    """Como comun.recorrer, más exclusiones confidenciales. `permitir`: carpetas excluidas por
    defecto que este fallback sí debe recorrer (p. ej. "dist" en presupuesto_build); node_modules
    nunca se permite. `desde`: subcarpeta inicial (relativa o absoluta)."""
    proyecto = Path(proyecto)
    excl = set(cargar_exclusiones(confidencial)) - (set(permitir) - set(SIEMPRE_EXCLUIDOS))
    conf_dc = cargar_confidencial(confidencial)

    def fuera(r):
        return excluido(r, excl) or (conf_dc is not None and _dc.es_confidencial(r, conf_dc))

    dirs_excl = (set(comun.DIRS_EXCLUIDOS) - set(permitir)) | set(SIEMPRE_EXCLUIDOS)
    inicio = proyecto if desde is None else (proyecto / desde)
    if not inicio.is_dir():
        return
    for raiz, dirs, archivos in os.walk(inicio):
        r = Path(raiz)
        sub = []
        for d in sorted(dirs):
            p = r / d
            if d in dirs_excl or p.is_symlink():
                continue
            if fuera(p.relative_to(proyecto).as_posix()):
                continue
            sub.append(d)
        dirs[:] = sub
        for a in sorted(archivos):
            p = r / a
            if p.is_symlink() or fuera(p.relative_to(proyecto).as_posix()):
                continue
            if extensiones is not None and p.suffix.lower() not in extensiones:
                continue
            if nombres is not None and a not in nombres:
                continue
            yield p


def umbral(clave, defecto, ruta=None):
    """umbral.<clave>.valor de config/umbrales.toml (o el default si falta)."""
    ruta = UMBRALES if ruta is None else Path(ruta)
    try:
        with open(ruta, "rb") as f:
            datos = tomllib.load(f)
        v = datos.get("umbral", {}).get(clave, {}).get("valor")
        return v if isinstance(v, (int, float)) else defecto
    except (OSError, tomllib.TOMLDecodeError):
        return defecto


def ruta_herramientas(crudo):
    env = os.environ.get("AUDITOR_HERRAMIENTAS_JSON")
    if env:
        return Path(env)
    return Path(crudo).resolve().parent / "herramientas.json" if crudo else None


def herramienta_real_disponible(crudo, nombres):
    """Nombre de la primera herramienta real disponible según herramientas.json, o None."""
    ruta = ruta_herramientas(crudo)
    if not ruta or not ruta.is_file():
        return None
    try:
        datos = json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    herrs = datos.get("herramientas") if isinstance(datos, dict) else None
    if not isinstance(herrs, dict):
        return None
    for n in nombres:
        info = herrs.get(n)
        if isinstance(info, dict) and info.get("disponible") is True:
            return n
    return None


def pase(nombre, subregla, mensaje, archivo=None):
    """Pase de un fallback: subregla con prefijo ok_ (mapeo explícito en el catálogo)."""
    sub = subregla if subregla.startswith("ok_") else f"ok_{subregla}"
    return comun.pase(nombre, sub, mensaje, archivo)


def resultado(reemplaza, hallazgos=None, checks_pass=None, estado="ok", motivo=None):
    res = comun.resultado(hallazgos, checks_pass, estado, motivo)
    res["reemplaza"] = reemplaza
    res["cobertura"] = COBERTURA
    return res


def main(nombre, reemplaza, reales, analizar, argv=None):
    """CLI: <script> PROYECTO DIR_CRUDO. Omite el análisis si la herramienta real está disponible."""
    def envoltura(proyecto, crudo=None):
        real = herramienta_real_disponible(crudo, reales)
        if real:
            return resultado(reemplaza, estado="no_evaluado",
                             motivo=f"omitido: la herramienta real ({real}) está disponible según herramientas.json")
        return analizar(proyecto, crudo=crudo)
    return comun.main_check(nombre, envoltura, argv, argumentos=lambda p, c: {"crudo": c})


# --- utilidades de texto compartidas ------------------------------------------------------------
def linea_en(texto, indice):
    return texto.count("\n", 0, indice) + 1


def evidencia_linea(texto, n):
    return comun.linea_texto(texto, n).strip()


RE_ESPACIOS = re.compile(r"\s+")

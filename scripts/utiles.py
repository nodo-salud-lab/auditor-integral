"""Utilidades comunes de las fases deterministas (normalizar, estado, gates, score, informe).

- E/S JSON estable (claves ordenadas, UTF-8, salto final) para que dos corridas sobre el
  mismo crudo produzcan los mismos bytes (criterio F1-3).
- Lectura de run.json y de las banderas del perfil (perfil.json o, en su defecto,
  perfil_tecnico.json con las banderas de entrevista en null: no se asume la respuesta).
- Índice de controles con la severidad contextual aplicada.

Solo biblioteca estándar.
"""
import datetime as dt
import json
import os
import re
import tomllib
from pathlib import Path

import catalogo

RAIZ = Path(__file__).resolve().parent.parent
ORDEN_DOMINIOS = ("SEG", "DAT", "COD", "UX", "INF", "ESC", "OPS")
NIVELES = ("N0", "N1", "N2", "N3", "N4", "N5")
SEVERIDADES_DESC = ("critica", "alta", "media", "baja", "info")
LIMITE_MODO = {"rapido": "N2", "estandar": "N4", "profundo": "N5"}

BANDERAS_ARCHIVOS = ("baas", "ssr_serverless", "llm", "pagos", "emails", "docker", "iac", "k8s",
                     "movil", "pwa", "multi_idioma", "agente_ia", "servidor", "bd")
# Banderas detectadas por archivos que perfil.json puede omitir (añadidas después del esquema original):
# si faltan en perfil.json, se toman de perfil_tecnico.json (Anexo C del brazo C, AUD-INF).
BANDERAS_COMPLEMENTO_TECNICO = ("servidor", "bd")
BANDERAS_ENTREVISTA = ("datos_personales", "salud", "menores", "ue", "datos_reales_cargados",
                       "usuarios_3m", "usuarios_12m")


# --------------------------------------------------------------------------- E/S
def leer_json(ruta, defecto=None):
    try:
        with open(ruta, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return defecto


def volcar_json(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def escribir_json(ruta, obj):
    ruta = Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    tmp = ruta.with_name(ruta.name + ".tmp")
    tmp.write_text(volcar_json(obj), encoding="utf-8")
    os.replace(tmp, ruta)


def leer_jsonl(ruta):
    ruta = Path(ruta)
    if not ruta.is_file():
        return []
    return [json.loads(l) for l in ruta.read_text(encoding="utf-8").splitlines() if l.strip()]


def escribir_jsonl(ruta, filas):
    ruta = Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    texto = "".join(json.dumps(f, ensure_ascii=False, sort_keys=True) + "\n" for f in filas)
    tmp = ruta.with_name(ruta.name + ".tmp")
    tmp.write_text(texto, encoding="utf-8")
    os.replace(tmp, ruta)


_RE_FIN_DE_LINEA = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]")


def una_linea(texto):
    """Texto en una sola línea: todo carácter de control o separador de línea (\\r, \\n, VT, FF, NEL, U+2028/2029)
    pasa a espacio. En CommonMark un \\r solo ya corta la línea (F3-C adv.: rompía el código en línea)."""
    return _RE_FIN_DE_LINEA.sub(" ", str(texto))


def md_literal(texto):
    """Texto ajeno (repo auditado, herramientas, LLM) como literal Markdown: sin HTML (< y > como entidades), sin
    enlaces ni imágenes ([ y ] escapados) y sin cerrar código en línea (` → ')."""
    return (str(texto).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace("[", "\\[").replace("]", "\\]").replace("`", "'"))


def escribir_texto(ruta, texto):
    ruta = Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)
    tmp = ruta.with_name(ruta.name + ".tmp")
    tmp.write_text(texto, encoding="utf-8")
    os.replace(tmp, ruta)


def leer_toml(ruta):
    with open(ruta, "rb") as f:
        return tomllib.load(f)


# --------------------------------------------------------------------------- corrida
def leer_run(corrida):
    return leer_json(Path(corrida) / "run.json", {}) or {}


def modo_corrida(corrida):
    modo = leer_run(corrida).get("modo")
    return modo if modo in LIMITE_MODO else "estandar"


def fecha_referencia(corrida):
    """Fecha (AAAA-MM-DD) de la corrida según run.json; hoy si no hay. Sirve para vencimientos."""
    inicio = leer_run(corrida).get("inicio")
    if isinstance(inicio, str) and len(inicio) >= 10:
        return inicio[:10]
    return dt.date.today().isoformat()


def cargar_perfil(corrida):
    """Perfil para evaluar condiciones: {"banderas": {...}, "origen": "perfil"|"perfil_tecnico"|"vacio"}.

    perfil.json (entrevista) tiene prioridad. Sin él, las banderas detectables salen de
    perfil_tecnico.json y las de entrevista quedan en null (desconocidas).
    """
    corrida = Path(corrida)
    perfil = leer_json(corrida / "perfil.json")
    tecnico = leer_json(corrida / "perfil_tecnico.json")
    if isinstance(perfil, dict) and isinstance(perfil.get("banderas"), dict):
        banderas = dict(perfil["banderas"])
        for b in BANDERAS_COMPLEMENTO_TECNICO:
            if b not in banderas:
                banderas[b] = tecnico.get(b) if isinstance(tecnico, dict) else None
        return {"banderas": banderas, "origen": "perfil"}
    banderas = {b: None for b in BANDERAS_ARCHIVOS + BANDERAS_ENTREVISTA}
    if isinstance(tecnico, dict):
        for b in BANDERAS_ARCHIVOS:
            if b in tecnico:
                banderas[b] = tecnico[b]
        return {"banderas": banderas, "origen": "perfil_tecnico"}
    return {"banderas": banderas, "origen": "vacio"}


def indice_controles(perfil=None, cat=None):
    """{id: control} de TODO el catálogo; los aplicables llevan la severidad contextual
    y el campo `aplicabilidad` (aplica | desconocida); los demás, aplicabilidad = no_aplica."""
    cat = cat if cat is not None else catalogo.cargar_catalogo()
    perfil = perfil or {"banderas": {}}
    aplicables = {c["id"]: c for c in catalogo.controles_aplicables(perfil, "N5", catalogo=cat)}
    indice = {}
    for c in cat:
        if c["id"] in aplicables:
            indice[c["id"]] = aplicables[c["id"]]
        else:
            copia = dict(c)
            copia["aplicabilidad"] = "no_aplica"
            indice[c["id"]] = copia
    return indice


def orden_catalogo(cat=None):
    cat = cat if cat is not None else catalogo.cargar_catalogo()
    return {c["id"]: i for i, c in enumerate(cat)}


def num_nivel(nivel):
    return NIVELES.index(nivel)


def rango_severidad(sev):
    """0 = crítica (más grave) ... 4 = info."""
    return SEVERIDADES_DESC.index(sev) if sev in SEVERIDADES_DESC else len(SEVERIDADES_DESC)


def max_severidad(a, b):
    return a if rango_severidad(a) <= rango_severidad(b) else b


# --------------------------------------------------------------------------- metas de herramientas
ALIAS_HERRAMIENTA = {"osv": "osv-scanner", "osv_scanner": "osv-scanner", "semgrep oss": "semgrep"}
ESTADOS_META = ("ok", "parcial", "error", "ausente", "timeout", "no_aplica", "no_evaluado", "sin_red")


def canon_herramienta(nombre):
    n = str(nombre or "").strip().lower()
    if n.startswith("check_"):
        n = n[len("check_"):]
    elif n.startswith("check:"):
        n = n[len("check:"):]
    return ALIAS_HERRAMIENTA.get(n, n)


def cargar_metas(crudo):
    """{herramienta_canonica: meta} desde crudo/*.meta.json (meta = {herramienta, version, estado, ...}).

    Si hay varios meta de la misma herramienta (p. ej. gitleaks repo e historial), gana el peor
    estado (error/timeout/ausente sobre ok), para no declarar `pass` con una corrida incompleta.
    """
    metas = {}
    crudo = Path(crudo)
    if not crudo.is_dir():
        return metas
    for ruta in sorted(crudo.glob("*.meta.json")):
        m = leer_json(ruta)
        if not isinstance(m, dict):
            continue
        nombre = canon_herramienta(m.get("herramienta") or ruta.name[:-len(".meta.json")])
        estado = m.get("estado") if m.get("estado") in ESTADOS_META else "error"
        m = dict(m, estado=estado)
        previo = metas.get(nombre)
        if previo is None or (previo["estado"] == "ok" and estado != "ok"):
            metas[nombre] = m
    return metas

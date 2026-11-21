"""Construcción, fusión y tope de hallazgos (PLAN_MAESTRO §3.5).

Registro intermedio (lo produce cada lector: gitleaks.py, sarif.py, osv.py, checks.py):
    {herramienta, herramienta_fuente?, version, regla, archivo, linea, snippet, mensaje,
     evidencia?, severidad_herramienta, confianza, referencias, commit}

construir()  registro → hallazgo (control por catalogo.control_por_regla; severidad = la del
             catálogo, que la herramienta puede subir pero no bajar; evidencia enmascarada ≤ 300;
             fingerprint = sha256(control|archivo_normalizado|regla|snippet_normalizado)).
fusionar()   (1) mismo fingerprint → uno; (2) mismo (control, archivo, línea) Y además la misma regla, o
             herramientas distintas con la misma huella de contenido → un hallazgo con fuente múltiple; la
             confianza sube un escalón si hay > 1 herramienta. Reglas distintas de UNA misma herramienta en la
             misma línea son defectos distintos y no se fusionan (pendiente §6.2 de 10-f0-f1-resultados;
             criterio de GitHub code scanning: una alerta por regla y ubicación). Huella de contenido: sha256
             del texto normalizado de las líneas de la región (como primaryLocationLineHash de GitHub); la
             calcula normalizar/run.py leyendo el archivo (nunca en rutas confidenciales) y, si no hay
             proyecto, se usa el snippet de la herramienta. Los grupos se arman sin encadenar: cada hallazgo
             entra al primer grupo con el que es compatible con TODOS sus miembros.
limitar()    máximo N instancias por (control, archivo); la última lleva instancias_extra ("y N más").
ordenar()    orden estable (dominio, orden del catálogo, archivo, línea, fingerprint).
"""
import hashlib
import re
import sys
import urllib.parse
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import catalogo  # noqa: E402
import enmascarar  # noqa: E402
import utiles  # noqa: E402

MAX_EVIDENCIA = 300
MAX_INSTANCIAS = 5
CONFIANZAS = ("baja", "media", "alta")
_RUTA_REMEDIACIONES = utiles.RAIZ / "plantillas" / "remediaciones.toml"
_REMEDIACIONES = None
_HEX = re.compile(r"^[0-9a-f]{7,40}$")
# fingerprint → huella de contenido (sha256 del texto normalizado de la región). Lo llena construir().
_CONTENIDO = {}


# --------------------------------------------------------------------------- rutas
def normalizar_archivo(uri, proyecto=None):
    """Ruta POSIX relativa al proyecto (o la mejor aproximación posible). None si no hay ruta."""
    if uri is None or uri == "":
        return None
    r = str(uri)
    if r.startswith("file://"):
        r = urllib.parse.unquote(r[len("file://"):])
    r = r.replace("\\", "/")
    proyecto = Path(proyecto) if proyecto else None
    absoluta = r.startswith("/")
    if absoluta and proyecto is not None:
        for base in {str(proyecto), str(proyecto.resolve()) if proyecto.exists() else str(proyecto)}:
            b = base.rstrip("/") + "/"
            if r.startswith(b):
                r, absoluta = r[len(b):], False
                break
    partes = [p for p in r.split("/") if p not in ("", ".")]
    if not partes:
        return None
    rel = "/".join(partes)
    if proyecto is not None and proyecto.is_dir() and not (proyecto / rel).exists():
        for i in range(1, len(partes)):
            candidato = "/".join(partes[i:])
            if (proyecto / candidato).exists():
                return candidato
    return ("/" + rel) if absoluta else rel


# --------------------------------------------------------------------------- construcción
def _remediaciones():
    global _REMEDIACIONES
    if _REMEDIACIONES is None:
        try:
            _REMEDIACIONES = utiles.leer_toml(_RUTA_REMEDIACIONES).get("remediacion", {})
        except OSError:
            _REMEDIACIONES = {}
    return _REMEDIACIONES


def remediacion(control):
    texto = _remediaciones().get(control["id"])
    if not texto:
        texto = f"Corregir el incumplimiento de «{control['titulo']}» y volver a auditar."
    return enmascarar.recortar(texto, 600)


def _colapsar(texto):
    return re.sub(r"\s+", " ", texto or "").strip()


def huella_contenido(texto):
    t = _colapsar(texto)
    return hashlib.sha256(t.encode("utf-8")).hexdigest() if t else None


def huella(control, archivo, regla, snippet):
    base = f"{control}|{archivo or ''}|{regla}|{snippet}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def _lista_catalogo(indice):
    return list(indice.values())


def construir(reg, indice, secretos=()):
    """Registro intermedio → hallazgo (dict según hallazgo.schema.json) o None si no mapea."""
    herramienta = reg["herramienta"]
    regla = str(reg.get("regla") or "")
    archivo = normalizar_archivo(reg.get("archivo"), None)
    control_id = catalogo.control_por_regla(herramienta, regla, catalogo=_lista_catalogo(indice), archivo=archivo)
    if control_id is None:
        return None
    c = indice[control_id]
    snippet = _colapsar(enmascarar.enmascarar_texto(reg.get("snippet") or "", secretos))
    evidencia_bruta = reg.get("evidencia") or reg.get("snippet") or reg.get("mensaje") or ""
    evidencia = enmascarar.recortar(_colapsar(enmascarar.enmascarar_texto(evidencia_bruta, secretos)), MAX_EVIDENCIA)
    severidad = c["severidad_base"]
    if reg.get("severidad_herramienta") in utiles.SEVERIDADES_DESC:
        severidad = utiles.max_severidad(severidad, reg["severidad_herramienta"])
    fp = huella(control_id, archivo, regla, snippet or _colapsar(enmascarar.enmascarar_texto(reg.get("mensaje") or "", secretos)))
    contenido = reg.get("contenido_hash") or huella_contenido(snippet)
    if contenido:
        _CONTENIDO[fp] = contenido
    linea = reg.get("linea")
    linea = linea if isinstance(linea, int) and not isinstance(linea, bool) and linea >= 0 else None
    commit = reg.get("commit")
    commit = commit.lower() if isinstance(commit, str) and _HEX.match(commit.lower()) else None
    refs = []
    for r in reg.get("referencias") or []:
        r = enmascarar.recortar(str(r), 300)
        if r and r not in refs:
            refs.append(r)
    version = reg.get("version")
    fuente = {"herramienta": str(reg.get("herramienta_fuente") or herramienta)[:60],
              "version": str(version)[:60] if version else None,
              "regla": (str(reg.get("regla_fuente") or regla)[:200]) or None}
    confianza = reg.get("confianza") if reg.get("confianza") in CONFIANZAS else "media"
    esfuerzo = c.get("esfuerzo") if c.get("esfuerzo") in ("XS", "S", "M", "L", "XL") else None
    return {
        "id": "H-" + fp[:12],
        "control": control_id,
        "alias": list(c.get("alias", [])),
        "dominio": c["dominio"],
        "etapa": c["etapa"],
        "gate": c["gate"],
        "severidad": severidad,
        "confianza": confianza,
        "metodo": "determinista",
        "fuente": [fuente],
        "ubicacion": {"archivo": archivo, "linea": linea, "url": None, "objeto_bd": None, "commit": commit},
        "evidencia": evidencia,
        "fingerprint": fp,
        "estado_hallazgo": "abierto",
        "triage": None,
        "remediacion": remediacion(c),
        "referencias": refs,
        "esfuerzo": esfuerzo,
    }


# --------------------------------------------------------------------------- fusión
def _subir_confianza(conf, pasos=1):
    i = min(CONFIANZAS.index(conf) + pasos, len(CONFIANZAS) - 1)
    return CONFIANZAS[i]


def _clave_fuente(f):
    return (f["herramienta"], f.get("regla") or "", f.get("version") or "")


def _unir(grupo):
    """Une hallazgos equivalentes. Base: el de herramienta alfabéticamente primera."""
    grupo = sorted(grupo, key=lambda h: (_clave_fuente(h["fuente"][0]), h["ubicacion"]["commit"] is not None,
                                         h["fingerprint"]))
    base = dict(grupo[0])
    base["ubicacion"] = dict(base["ubicacion"])
    fuentes = {}
    for h in grupo:
        for f in h["fuente"]:
            fuentes.setdefault(_clave_fuente(f), f)
    base["fuente"] = [fuentes[k] for k in sorted(fuentes)]
    sev = base["severidad"]
    conf = base["confianza"]
    refs = []
    for h in grupo:
        sev = utiles.max_severidad(sev, h["severidad"])
        if CONFIANZAS.index(h["confianza"]) > CONFIANZAS.index(conf):
            conf = h["confianza"]
        refs += [r for r in h.get("referencias", []) if r not in refs]
    herramientas = {f["herramienta"] for f in base["fuente"]}
    if len(herramientas) > 1:
        conf = _subir_confianza(conf, len(herramientas) - 1)
    base["severidad"] = sev
    base["confianza"] = conf
    base["referencias"] = sorted(refs)
    base["fingerprint"] = min(h["fingerprint"] for h in grupo)
    base["id"] = "H-" + base["fingerprint"][:12]
    extra = sum(h.get("instancias_extra", 0) for h in grupo)
    if extra:
        base["instancias_extra"] = extra
    return base


def _contenidos(h, contenidos):
    c = contenidos.get(h["fingerprint"])
    return {c} if c else set()


def _compatibles(a, b, contenidos):
    """a y b (en el mismo control, archivo y línea) son el mismo defecto."""
    reglas_a = {(f["herramienta"], f.get("regla") or "") for f in a["fuente"]}
    reglas_b = {(f["herramienta"], f.get("regla") or "") for f in b["fuente"]}
    if reglas_a & reglas_b:
        return True  # misma regla de la misma herramienta
    herr_a = {x for x, _ in reglas_a}
    herr_b = {x for x, _ in reglas_b}
    if herr_a & herr_b:
        return False  # la misma herramienta con otra regla: otro defecto
    return bool(_contenidos(a, contenidos) & _contenidos(b, contenidos))


def _agrupar_sin_encadenar(grupo, contenidos):
    orden = sorted(grupo, key=lambda h: ([_clave_fuente(f) for f in h["fuente"]], h["fingerprint"]))
    clusters = []
    for h in orden:
        for cl in clusters:
            if all(_compatibles(h, m, contenidos) for m in cl):
                cl.append(h)
                break
        else:
            clusters.append([h])
    return clusters


def fusionar(hallazgos, contenidos=None):
    contenidos = _CONTENIDO if contenidos is None else contenidos
    por_fp = {}
    for h in hallazgos:
        por_fp.setdefault(h["fingerprint"], []).append(h)
    paso1 = []
    for g in por_fp.values():
        paso1.append(_unir(g) if len(g) > 1 else g[0])
    por_lugar, sueltos = {}, []
    for h in paso1:
        u = h["ubicacion"]
        if u.get("archivo") and u.get("linea") is not None:
            por_lugar.setdefault((h["control"], u["archivo"], u["linea"]), []).append(h)
        else:
            sueltos.append(h)
    paso2 = list(sueltos)
    for clave in sorted(por_lugar):
        for cl in _agrupar_sin_encadenar(por_lugar[clave], contenidos):
            paso2.append(_unir(cl) if len(cl) > 1 else cl[0])
    return sorted(paso2, key=lambda h: h["fingerprint"])


def es_critico_n1(h):
    return h.get("severidad") == "critica" and h.get("gate") == "N1"


def limitar(hallazgos, maximo=MAX_INSTANCIAS):
    """Tope de `maximo` instancias por (control, archivo) para el informe y el texto que va al LLM.
    Los críticos de N1 NUNCA se descartan (ronda 1: con el tope se perdía D06, la 6.ª instancia de SEG-SECRETO-REPO en
    .env): se guardan todos y el resto de instancias completa el cupo hasta `maximo`. Las descartadas se cuentan en
    `instancias_extra` del último guardado."""
    grupos = {}
    for h in hallazgos:
        grupos.setdefault((h["control"], h["ubicacion"].get("archivo") or ""), []).append(h)
    salida = []
    for clave in sorted(grupos):
        orden = lambda h: (h["ubicacion"].get("linea") is None, h["ubicacion"].get("linea") or 0, h["fingerprint"])  # noqa: E731
        g = sorted(grupos[clave], key=orden)
        criticos = [h for h in g if es_critico_n1(h)]
        otros = [h for h in g if not es_critico_n1(h)]
        cupo = max(0, maximo - len(criticos))
        elegidos = {id(h) for h in criticos + otros[:cupo]}
        guardados = [dict(h) for h in g if id(h) in elegidos]
        descartados = [h for h in g if id(h) not in elegidos]
        if descartados:
            ultimo = guardados[-1]
            ultimo["instancias_extra"] = ultimo.get("instancias_extra", 0) + len(descartados) + sum(
                h.get("instancias_extra", 0) for h in descartados)
        salida += guardados
    return salida


def ordenar(hallazgos, orden=None):
    orden = orden or utiles.orden_catalogo()
    dom = {d: i for i, d in enumerate(utiles.ORDEN_DOMINIOS)}
    return sorted(hallazgos, key=lambda h: (dom.get(h["dominio"], 99), orden.get(h["control"], 9999),
                                            h["ubicacion"].get("archivo") or "",
                                            h["ubicacion"].get("linea") if h["ubicacion"].get("linea") is not None else -1,
                                            h["fingerprint"]))

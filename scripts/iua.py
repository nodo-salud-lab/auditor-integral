#!/usr/bin/env python3
"""IUA — Índice de Usabilidad Automatizado 0-100 → iua.json (PLAN_MAESTRO §5.1; DECISIONES.md #1 y #2).
No es SUS: es determinista, no usa LLM y no reemplaza la medición con usuarios reales.

Uso:  iua.py DIR_CORRIDA   |   iua.py --corrida DIR_CORRIDA

Entradas (todas opcionales; lo que falte deja su componente en `no_evaluado`):
  crudo/axe*.json           resultado(s) de axe-core: {violations, passes, incomplete, inapplicable} o lista
                            de ellos (una por página). Cada regla: {id, impact, tags}.
  crudo/lighthouse*.json    LHR de Lighthouse (o lista de corridas): categories.performance.score (0-1) y/o
                            audits.<métrica>.score.
  crudo/playwright_ux.json  sonda Playwright: {"teclado": {interactivos, alcanzables_foco_visible},
                            "responsive": {viewports: [{ancho, scroll_horizontal}], objetivos_total, objetivos_24px},
                            "estados": {llamadas, con_estados_visibles}, "limpieza": {tipos_error: [...]},
                            "axe": [...] (opcional, mismo formato que axe.json)}.
  hallazgos_todos.jsonl     hallazgos de fallbacks UX estáticos (check ux_estatico / presupuesto_build, o con
                            `cobertura` "parcial ..."): se informan por componente como cobertura parcial.
  Un <nombre>.meta.json con estado distinto de "ok" invalida el crudo de esa herramienta.

Componentes (pesos entre componentes: config/pesos.toml [iua.componentes], ESTIMACIÓN del plan):
  accesibilidad      fórmula de Lighthouse: 100 × Σ w(r)·[r pasa] / Σ w(r) sobre reglas axe en passes ∪
                     violations (sin incomplete ni inapplicable), pass/fail por regla sin crédito parcial;
                     w por impacto axe: critical 10, serious 7, moderate 3, minor 1 si tiene etiqueta WCAG A/AA
                     (0 si no), experimental 0 ([iua.accesibilidad_lighthouse]). Con varias páginas, una regla
                     falla si falla en alguna (peor caso; ESTIMACIÓN). Reglas sin impacto conocido: excluidas
                     y listadas.
  rendimiento        puntaje Performance de Lighthouse × 100, mediana de corridas; si falta la categoría,
                     media ponderada de las métricas FCP 10 / SI 10 / LCP 25 / TBT 30 / CLS 25
                     ([iua.rendimiento]), renormalizada si faltan métricas (se avisa).
  teclado            % de elementos interactivos alcanzables con Tab y con foco visible.
  responsive_tactil  % de viewports sin scroll horizontal × % de objetivos táctiles ≥ 24 px.
  robustez_estados   % de llamadas con estado de carga, vacío y error visibles ante 500/timeout forzado.
  limpieza           100 − 20 × tipos de error distintos (consola y errores técnicos visibles), piso 0.

IUA = Σ peso·puntaje / Σ peso sobre los componentes medidos; se informa con su cobertura (peso medido /
peso total). Un fallback estático nunca da puntaje (solo detecta fallos, no mide la proporción): el
componente queda `parcial_fallback` y no entra en el IUA. Bandas ([umbral.iua_bandas], Lighthouse):
0-49 pobre · 50-89 mejorable · 90-100 bueno. Con cobertura < umbral.iua_cobertura_minima_banda (0,70) la
banda se omite (banda = null, banda_omitida = true; el informe la muestra en gris): Anexo C, IUA-BANDA.
"""
import argparse
import json
import re
import statistics
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import utiles  # noqa: E402

RUTA_PESOS = utiles.RAIZ / "config" / "pesos.toml"
RUTA_UMBRALES = utiles.RAIZ / "config" / "umbrales.toml"

COMPONENTES = ("accesibilidad", "teclado", "responsive_tactil", "robustez_estados", "rendimiento", "limpieza")
# Auditorías de Lighthouse de cada métrica de rendimiento (claves de [iua.rendimiento]: peso_<clave>).
METRICAS_LH = {"fcp": "first-contentful-paint", "si": "speed-index", "lcp": "largest-contentful-paint",
               "tbt": "total-blocking-time", "cls": "cumulative-layout-shift"}
# Controles del catálogo cuyos hallazgos de fallback informan cada componente (ESTIMACIÓN de mapeo,
# según investigacion/13-fallbacks-herramientas.md §4.10-4.11).
CONTROL_COMPONENTE = {
    "UX-AXE-CRIT": "accesibilidad", "UX-AXE-SERIOUS": "accesibilidad", "UX-A11Y-ESTATICA": "accesibilidad",
    "UX-LANG": "accesibilidad", "UX-FORMULARIOS": "accesibilidad",
    "UX-TECLADO": "teclado", "UX-FOCO-OCULTO": "teclado",
    "UX-REFLOW": "responsive_tactil", "UX-TACTIL": "responsive_tactil",
    "UX-ESTADOS": "robustez_estados",
    "UX-LIGHTHOUSE": "rendimiento", "UX-LCP-LAB": "rendimiento",
    "UX-ERRORES-VISIBLES": "limpieza",
}
FALLBACKS_UX = ("ux_estatico", "presupuesto_build")
COBERTURA_FALLBACK = "parcial (fallback)"
ETIQUETA_WCAG_A_AA = re.compile(r"^wcag\d*aa?$")
NOMBRES_BANDA = ("pobre", "mejorable", "bueno")  # Lighthouse: Poor / Needs Improvement / Good
FUENTE_COMPONENTE = {"accesibilidad": "axe-core", "rendimiento": "lighthouse", "teclado": "playwright_ux",
                     "responsive_tactil": "playwright_ux", "robustez_estados": "playwright_ux",
                     "limpieza": "playwright_ux"}


# Valores por defecto = los adoptados en config/ (solo se usan si falta el archivo de configuración).
COMPONENTES_DEFECTO = {"accesibilidad": 25, "teclado": 15, "responsive_tactil": 15, "robustez_estados": 15,
                       "rendimiento": 15, "limpieza": 15}
RENDIMIENTO_DEFECTO = {"fcp": 10, "si": 10, "lcp": 25, "tbt": 30, "cls": 25}


# --------------------------------------------------------------------------- configuración
def _toml(ruta):
    try:
        return utiles.leer_toml(ruta), True
    except OSError:
        return {}, False


def cargar_config():
    pesos, ok_p = _toml(RUTA_PESOS)
    umbrales, ok_u = _toml(RUTA_UMBRALES)
    p = pesos.get("iua", {})
    acc = p.get("accesibilidad_lighthouse", {})
    rend = p.get("rendimiento", {})
    limp = p.get("limpieza", {})
    bandas = umbrales.get("umbral", {}).get("iua_bandas", {})
    comps = p.get("componentes") or COMPONENTES_DEFECTO
    return {
        "config": "ok" if ok_p and ok_u else "ausente: valores por defecto del código",
        "componentes": {k: comps.get(k, 0) for k in COMPONENTES},
        "acc": {"critical": acc.get("peso_critical", 10), "serious": acc.get("peso_serious", 7),
                "moderate": acc.get("peso_moderate", 3), "minor_wcag": acc.get("peso_minor_wcag", 1),
                "minor_bp": acc.get("peso_minor_best_practice", 0), "experimental": acc.get("peso_experimental", 0)},
        "rendimiento": {k: rend.get(f"peso_{k}", RENDIMIENTO_DEFECTO[k]) for k in METRICAS_LH},
        "penalizacion_limpieza": limp.get("penalizacion_por_tipo", 20),
        "base_limpieza": limp.get("base", 100),
        "bandas": list(bandas.get("valor", [50, 90])),
        "cobertura_minima_banda": umbrales.get("umbral", {}).get("iua_cobertura_minima_banda", {}).get("valor", 0.7),
        "origen_bandas": bandas.get("origen", "propuesta"),
        "fuente_bandas": bandas.get("fuente", ""),
        "origen_componentes": p.get("origen", "propuesta"),
    }


# --------------------------------------------------------------------------- utilidades
def _r(x):
    return None if x is None else round(float(x), 1)


def _pct(num, den):
    return 100.0 * num / den if den else None


def _sin(motivo):
    return {"puntaje": None, "motivo": motivo}


def banda(valor, cortes):
    if valor is None:
        return None
    i = sum(1 for c in sorted(cortes) if valor >= c)
    return NOMBRES_BANDA[min(i, len(NOMBRES_BANDA) - 1)]


# --------------------------------------------------------------------------- componentes
def peso_regla(impacto, tags, cfg):
    tags = [str(t) for t in (tags or [])]
    if impacto is None:
        return None
    a = cfg["acc"]
    if "experimental" in tags:
        return a["experimental"]
    if impacto == "minor":
        return a["minor_wcag"] if any(ETIQUETA_WCAG_A_AA.match(t) for t in tags) else a["minor_bp"]
    return a.get(impacto)


def accesibilidad(paginas, cfg):
    reglas = {}  # id -> {"falla": bool, "impact": str|None, "tags": set}
    n = 0
    for pag in paginas:
        if not isinstance(pag, dict):
            continue
        n += 1
        for clave, falla in (("violations", True), ("passes", False)):
            for r in pag.get(clave) or []:
                if not isinstance(r, dict) or not r.get("id"):
                    continue
                d = reglas.setdefault(str(r["id"]), {"falla": False, "impact": None, "tags": set()})
                d["falla"] = d["falla"] or falla
                if r.get("impact") and (falla or d["impact"] is None):
                    d["impact"] = r["impact"]
                d["tags"].update(str(t) for t in (r.get("tags") or []))
    w_total = w_pass = 0.0
    sin_impacto, evaluadas, fallidas = [], 0, []
    for rid in sorted(reglas):
        d = reglas[rid]
        w = peso_regla(d["impact"], d["tags"], cfg)
        if w is None:
            sin_impacto.append(rid)
            continue
        evaluadas += 1
        w_total += w
        if d["falla"]:
            fallidas.append(rid)
        else:
            w_pass += w
    res = {"puntaje": _r(_pct(w_pass, w_total)) if w_total > 0 else None, "paginas": n,
           "reglas_evaluadas": evaluadas, "reglas_fallidas": fallidas, "reglas_sin_impacto": sin_impacto}
    if not n:
        res["motivo"] = "sin resultados de axe (requiere sonda Playwright/axe)"
    elif res["puntaje"] is None:
        res["motivo"] = "ninguna regla axe con peso > 0 en passes/violations"
    return res


def rendimiento(lhrs, cfg):
    cats, por_metrica = [], {}
    for l in lhrs:
        if not isinstance(l, dict):
            continue
        l = l.get("lhr", l) if isinstance(l.get("lhr"), dict) else l
        s = ((l.get("categories") or {}).get("performance") or {}).get("score")
        if isinstance(s, (int, float)) and not isinstance(s, bool):
            cats.append(float(s))
        for k, audit in METRICAS_LH.items():
            v = ((l.get("audits") or {}).get(audit) or {}).get("score")
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                por_metrica.setdefault(k, []).append(float(v))
    if cats:
        return {"puntaje": _r(100.0 * statistics.median(cats)), "corridas": len(cats),
                "metodo": "categoria_lighthouse"}
    pesos = cfg["rendimiento"]
    usadas = {k: statistics.median(v) for k, v in por_metrica.items() if pesos.get(k)}
    den = sum(pesos[k] for k in usadas)
    if not den:
        return dict(_sin("sin resultados de Lighthouse (requiere LHCI)"), corridas=len(lhrs))
    res = {"puntaje": _r(100.0 * sum(pesos[k] * v for k, v in usadas.items()) / den),
           "corridas": max(len(v) for v in por_metrica.values()), "metodo": "metricas_ponderadas",
           "metricas_faltantes": sorted(k for k in pesos if pesos[k] and k not in usadas)}
    if res["metricas_faltantes"]:
        res["nota"] = "métricas faltantes: pesos renormalizados sobre las disponibles (ESTIMACIÓN)"
    return res


def teclado(d):
    if not isinstance(d, dict):
        return _sin("sin datos de la sonda de teclado (Tab-loop Playwright)")
    total, ok = d.get("interactivos") or 0, d.get("alcanzables_foco_visible") or 0
    if not total:
        return _sin("la sonda no encontró elementos interactivos")
    return {"puntaje": _r(_pct(min(ok, total), total)), "interactivos": total, "alcanzables_foco_visible": ok}


def responsive_tactil(d):
    if not isinstance(d, dict) or not d.get("viewports"):
        return _sin("sin datos de viewports (sonda Playwright)")
    vps = [v for v in d["viewports"] if isinstance(v, dict)]
    sin_scroll = sum(1 for v in vps if v.get("scroll_horizontal") is False)
    f_vp = sin_scroll / len(vps) if vps else 0.0
    total, ok = d.get("objetivos_total") or 0, d.get("objetivos_24px") or 0
    res = {"viewports": [v.get("ancho") for v in vps], "viewports_sin_scroll": sin_scroll,
           "objetivos_total": total, "objetivos_24px": ok}
    if total:
        res["puntaje"] = _r(100.0 * f_vp * min(ok, total) / total)
    else:
        res["puntaje"] = _r(100.0 * f_vp)
        res["nota"] = "sin objetivos táctiles medidos: solo se usa el factor de viewports"
    return res


def robustez_estados(d):
    if not isinstance(d, dict):
        return _sin("sin datos de estados forzados (page.route 500/timeout)")
    total, ok = d.get("llamadas") or 0, d.get("con_estados_visibles") or 0
    if not total:
        return _sin("la sonda no interceptó llamadas de red")
    return {"puntaje": _r(_pct(min(ok, total), total)), "llamadas": total, "con_estados_visibles": ok}


def limpieza(d, cfg):
    if not isinstance(d, dict) or not isinstance(d.get("tipos_error"), list):
        return _sin("sin datos de consola ni de errores visibles (sonda Playwright)")
    tipos = sorted({str(t) for t in d["tipos_error"]})
    p = max(0.0, cfg["base_limpieza"] - cfg["penalizacion_limpieza"] * len(tipos))
    return {"puntaje": _r(p), "tipos_error": len(tipos)}


# --------------------------------------------------------------------------- fallbacks
def _es_fallback(h):
    if "parcial" in str(h.get("cobertura") or ""):
        return True
    for f in h.get("fuente") or []:
        if str(f.get("herramienta") or "") in FALLBACKS_UX:
            return True
        if any(str(f.get("regla") or "").startswith(f"check:{n}.") for n in FALLBACKS_UX):
            return True
    return False


def hallazgos_fallback(hallazgos):
    por_comp = {}
    for h in hallazgos or []:
        comp = CONTROL_COMPONENTE.get(h.get("control"))
        if not comp or h.get("estado_hallazgo", "abierto") != "abierto" or not _es_fallback(h):
            continue
        por_comp.setdefault(comp, []).append(h)
    return por_comp


# --------------------------------------------------------------------------- índice
def calcular(datos, cfg, motivos_entrada=None):
    motivos_entrada = motivos_entrada or {}
    pw = datos.get("playwright") or {}
    paginas_axe = list(datos.get("axe") or []) + list(pw.get("axe") or [])
    crudos = {
        "accesibilidad": accesibilidad(paginas_axe, cfg),
        "rendimiento": rendimiento(datos.get("lighthouse") or [], cfg),
        "teclado": teclado(pw.get("teclado")),
        "responsive_tactil": responsive_tactil(pw.get("responsive")),
        "robustez_estados": robustez_estados(pw.get("estados")),
        "limpieza": limpieza(pw.get("limpieza"), cfg),
    }
    fb = hallazgos_fallback(datos.get("hallazgos"))
    componentes = {}
    num = peso_medido = 0.0
    peso_total = sum(cfg["componentes"].values())
    medidos = parciales = 0
    for comp in COMPONENTES:
        r = dict(crudos[comp])
        puntaje = r.pop("puntaje")
        motivo_propio = r.pop("motivo", None)
        motivo = motivos_entrada.get(comp) or motivo_propio
        peso = cfg["componentes"][comp]
        fbs = fb.get(comp, [])
        if puntaje is not None:
            estado, cobertura = "medido", "completa"
            medidos += 1
            num += peso * puntaje
            peso_medido += peso
            motivo = None
        elif fbs:
            estado, cobertura = "parcial_fallback", COBERTURA_FALLBACK
            parciales += 1
            motivo = (f"{motivo or 'sin sonda dinámica'}; {len(fbs)} hallazgo(s) de fallback estático: "
                      "detectan fallos pero no miden la proporción (sin puntaje)")
        else:
            estado, cobertura = "no_evaluado", None
        componentes[comp] = {
            "estado": estado, "puntaje": puntaje, "peso": peso, "banda": banda(puntaje, cfg["bandas"]),
            "fuente": FUENTE_COMPONENTE[comp] if estado == "medido" else (
                ", ".join(sorted({f.get("herramienta") for h in fbs for f in h.get("fuente") or []
                                  if f.get("herramienta")})) if fbs else None),
            "cobertura": cobertura, "motivo": motivo, "hallazgos_fallback": len(fbs),
            "controles_fallback": sorted({h["control"] for h in fbs}), "detalle": r,
        }
    valor = _r(num / peso_medido) if peso_medido else None
    fraccion = round(peso_medido / peso_total, 3) if peso_total else 0.0
    minima = cfg.get("cobertura_minima_banda", 0.7)
    omitida = valor is not None and fraccion < minima
    return {
        "version_esquema": "1",
        "iua": valor,
        # Anexo C (IUA-BANDA): con cobertura < umbral.iua_cobertura_minima_banda la banda se omite (gris).
        "banda": None if omitida else banda(valor, cfg["bandas"]),
        "banda_omitida": omitida,
        "banda_motivo": (f"cobertura {fraccion:.2f} del peso < {minima:.2f}".replace(".", ",") +
                         " (umbral.iua_cobertura_minima_banda): la banda se omite porque un IUA parcial no es "
                         "comparable con uno completo") if omitida else None,
        "parcial": medidos < len(COMPONENTES),
        "cobertura": {"peso_medido": peso_medido if peso_medido % 1 else int(peso_medido),
                      "peso_total": peso_total,
                      "fraccion": fraccion,
                      "componentes_medidos": medidos, "componentes_total": len(COMPONENTES),
                      "componentes_parcial_fallback": parciales},
        "componentes": componentes,
        "bandas": {"cortes": cfg["bandas"], "nombres": list(NOMBRES_BANDA), "origen": cfg["origen_bandas"],
                   "fuente": cfg["fuente_bandas"]},
        "origen_pesos_componentes": cfg["origen_componentes"],
        "config": cfg.get("config", "ok"),
        "nota": ("IUA determinista, no es SUS ni lo reemplaza. Pesos entre componentes: ESTIMACIÓN (PLAN_MAESTRO "
                 "§5.1); accesibilidad y rendimiento con fórmulas de Lighthouse. El IUA se calcula solo sobre los "
                 "componentes medidos: léalo junto a su cobertura."),
    }


# --------------------------------------------------------------------------- E/S de corrida
def _leer_crudo(crudo, patron, nombre_meta):
    """Lee crudo/<patron> (sin .meta.json). Devuelve (lista de objetos, motivo si no se pudo usar)."""
    meta = utiles.leer_json(crudo / f"{nombre_meta}.meta.json")
    if isinstance(meta, dict) and meta.get("estado") not in (None, "ok"):
        return [], f"{nombre_meta}: {meta.get('estado')}" + (f" ({meta.get('error')})" if meta.get("error") else "")
    objetos, invalidos = [], []
    for ruta in sorted(crudo.glob(patron)) if crudo.is_dir() else []:
        if ruta.name.endswith(".meta.json") or not ruta.is_file():
            continue
        d = utiles.leer_json(ruta)
        if d is None:
            invalidos.append(ruta.name)
        elif isinstance(d, list):
            objetos.extend(x for x in d if isinstance(x, dict))
        elif isinstance(d, dict) and isinstance(d.get("resultados"), list):
            objetos.extend(x for x in d["resultados"] if isinstance(x, dict))
        elif isinstance(d, dict) and isinstance(d.get("corridas"), list):
            objetos.extend(x for x in d["corridas"] if isinstance(x, dict))
        elif isinstance(d, dict):
            objetos.append(d)
    motivo = f"{nombre_meta}: JSON inválido ({', '.join(invalidos)})" if invalidos and not objetos else None
    return objetos, motivo


def cargar_entradas(corrida):
    corrida = Path(corrida)
    crudo = corrida / "crudo"
    axe, m_axe = _leer_crudo(crudo, "axe*.json", "axe")
    lh, m_lh = _leer_crudo(crudo, "lighthouse*.json", "lighthouse")
    pw_lista, m_pw = _leer_crudo(crudo, "playwright_ux.json", "playwright_ux")
    pw = pw_lista[0] if pw_lista else {}
    hallazgos = utiles.leer_jsonl(corrida / "hallazgos_todos.jsonl") or utiles.leer_jsonl(corrida / "hallazgos.jsonl")
    motivos = {}
    if m_axe and not pw.get("axe"):
        motivos["accesibilidad"] = m_axe
    if m_lh:
        motivos["rendimiento"] = m_lh
    if m_pw:
        for comp in ("teclado", "responsive_tactil", "robustez_estados", "limpieza"):
            motivos[comp] = m_pw
    return {"axe": axe, "lighthouse": lh, "playwright": pw, "hallazgos": hallazgos}, motivos


def generar(corrida):
    corrida = Path(corrida)
    datos, motivos = cargar_entradas(corrida)
    r = calcular(datos, cargar_config(), motivos)
    utiles.escribir_json(corrida / "iua.json", r)
    return r


def main(argv=None):
    ap = argparse.ArgumentParser(description="Índice de Usabilidad Automatizado → iua.json")
    ap.add_argument("corrida_pos", nargs="?", metavar="DIR_CORRIDA")
    ap.add_argument("--corrida")
    a = ap.parse_args(argv)
    corrida = a.corrida or a.corrida_pos
    if not corrida or not Path(corrida).is_dir():
        print("iua.py: indique una carpeta de corrida existente", file=sys.stderr)
        return 2
    r = generar(corrida)
    c = r["cobertura"]
    print(f"iua: {r['iua'] if r['iua'] is not None else 'sin datos'} · componentes medidos "
          f"{c['componentes_medidos']}/{c['componentes_total']} (peso {c['peso_medido']}/{c['peso_total']})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

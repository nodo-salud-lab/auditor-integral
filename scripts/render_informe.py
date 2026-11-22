#!/usr/bin/env python3
"""Informe por plantilla, SIN LLM (criterio F1-5) → informe.md, hoja-de-ruta.md, merged.sarif.

Uso:  render_informe.py DIR_CORRIDA   |   render_informe.py --corrida DIR_CORRIDA

Lee estado.json, gates.json, score.json e iua.json (los genera si faltan), hallazgos.jsonl, normalizacion.json
y run.json; calcula roadmap.json; rellena plantillas/informe.md.tmpl y hoja-de-ruta.md.tmpl con
string.Template. Todo texto final pasa otra vez por enmascarar.py con los secretos conocidos de la
corrida (defensa en profundidad: criterio F1-2). merged.sarif es SARIF 2.1.0 mínimo (subible a
GitHub code scanning), una entrada por instancia (hallazgos_todos.jsonl).
"""
import argparse
import re
import string
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import enmascarar  # noqa: E402
import estado as estado_mod  # noqa: E402
import gates as gates_mod  # noqa: E402
import iua as iua_mod  # noqa: E402
import roadmap as roadmap_mod  # noqa: E402
import score as score_mod  # noqa: E402
import utiles  # noqa: E402

PLANTILLAS = utiles.RAIZ / "plantillas"
VERSION_AUDITOR = "0.2.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
NIVEL_SARIF = {"critica": "error", "alta": "error", "media": "warning", "baja": "note", "info": "note"}
COBERTURA_FALLBACK = "parcial (fallback)"
NOMBRE_DOMINIO = {"SEG": "Seguridad", "DAT": "Datos/BD", "COD": "Código", "UX": "Usabilidad/frontend",
                  "INF": "Infra/despliegue", "ESC": "Escala/carga", "OPS": "Operación/legal"}


def _celda(texto):
    return utiles.una_linea(texto).replace("|", "\\|")


def _codigo(texto):
    return "`" + utiles.una_linea(texto).replace("`", "'") + "`"


def _pct(x):
    return f"{round(x * 100)} %"


def _asegurar(corrida):
    if not (corrida / "gates.json").is_file() or not (corrida / "estado.json").is_file():
        gates_mod.generar(corrida)
    if not (corrida / "score.json").is_file():
        score_mod.generar(corrida)
    if not (corrida / "iua.json").is_file():
        iua_mod.generar(corrida)
    return roadmap_mod.generar(corrida)


ETIQUETA_FP_HUMANO = "descartado por verificación humana"   # = veredictos.ETIQUETA_FP_HUMANO (H-2)
TEXTOS_BLOQUEO = {"secreto_vivo": "secreto expuesto (se presume vivo) → N0",
                  "datos_reales_expuestos": "datos reales expuestos → N0",
                  "bloquea_global": "control que bloquea el nivel global → máximo N1",
                  "critico_seg_dat": "crítico abierto en SEG/DAT → máximo N1"}


def _nota_ia(b):
    """DECISIONES.md #10: texto fijo (no del LLM) para un bloqueo que depende de un juicio de IA pendiente."""
    return f" ({gates_mod.NOTA_PENDIENTE_IA})" if b.get("pendiente_ia") else ""


def _fp_ia_pendientes(hallazgos, triage=None):
    """{control: n} de hallazgos críticos/altos que la IA marcó falso_positivo SIN verificación humana. estado.efectivo
    ya no los cuenta, pero no están descartados: el número del bloqueo los muestra aparte para no ocultarlos."""
    res = {}
    triage = triage or {}
    for h in hallazgos or []:
        fp = (h.get("estado_hallazgo") == "falso_positivo"
              or ((triage.get(h.get("id")) or {}).get("veredicto") == "falso_positivo"))
        if fp and h.get("severidad") in ("critica", "alta") and not h.get("verificacion_humana"):
            res[h.get("control")] = res.get(h.get("control"), 0) + 1
    return res


def _seccion_bloqueos(g, indice, hallazgos=None, triage=None):
    bloqueos = g["global"]["bloqueos"]
    fp_ia = _fp_ia_pendientes(hallazgos, triage)
    if not bloqueos:
        return "Sin bloqueos del nivel global."
    lineas = ["**Bloqueos del nivel global:**", ""]
    vistos = set()
    for b in bloqueos:  # ya vienen ordenados: el tope más bajo primero
        if b["control"] in vistos:
            continue
        vistos.add(b["control"])
        titulo = indice.get(b["control"], {}).get("titulo", b["control"])
        n_fp = fp_ia.get(b["control"], 0)
        extra = (f" más {n_fp} con posible falso positivo de la IA pendiente de verificación humana (no se descartan; "
                 f"{len(b['hallazgos']) + n_fp} en total)" if n_fp else "")
        # R6: una entrada por control; todos sus motivos en la misma línea (el primero es el más estricto)
        motivos = "; ".join(TEXTOS_BLOQUEO.get(t, t) for t in (b.get("tipos") or [b["tipo"]]))
        lineas.append(f"- {b['control']} ({_celda(titulo)}): {motivos}{_nota_ia(b)}; "
                      f"{len(b['hallazgos'])} hallazgo(s){extra}.")
    return "\n".join(lineas)


def _linea_bloqueo_item(i):
    """«Bloqueo: …» de un ítem de la hoja de ruta cuyo bloqueo depende de un juicio de IA pendiente (o None)."""
    b = i.get("bloqueo")
    if not b:
        return None
    tipos = "; ".join(TEXTOS_BLOQUEO.get(t, t) for t in b.get("tipos") or [])
    return f"Bloqueo: {tipos} (tope {b.get('tope')}){_nota_ia(b)}"


def _bloqueos_dueno(g, indice=None):
    """Línea «Bloqueos» del resumen del dueño, en lenguaje llano: cuenta controles únicos y cada código va con su
    nombre legible (R6)."""
    indice = indice or {}
    bloqueos = g["global"]["bloqueos"]
    if not bloqueos:
        return "ninguno"
    por_control = {}
    for b in bloqueos:
        por_control.setdefault(b["control"], b)   # el primero es el de tope más bajo
    partes = [f"{cid} «{_celda((indice.get(cid) or {}).get('titulo', cid))}» → {b['tope']}{_nota_ia(b)}"
              for cid, b in por_control.items()]
    return f"{len(partes)}: " + "; ".join(partes)


NOTA_NO_EVALUADO = ("«No evaluado» significa «no revisado», no «está bien»: un control sin revisar no suma a favor "
                    "y el nivel no sube hasta revisarlo.")


def nota_no_evaluado(estados, indice):
    """R6: línea fija junto al nivel global (informe y resumen del dueño) con cuántos controles quedaron sin revisar y
    cuántos por falta de red o por juicio de la IA pendiente (un control puede estar en ambos grupos)."""
    pend = _pendientes(estados)
    sin_red = sum(1 for e in pend if "sin red" in (e.get("motivo") or "") or "AUDITOR_SIN_RED" in (e.get("motivo") or ""))
    juicio = sum(1 for e in pend if clasificar_pendiente(e, indice, {})[0] == "juicio_ia")
    return (f"{NOTA_NO_EVALUADO} En esta corrida quedaron {len(pend)} control(es) sin revisar; de ellos, {sin_red} "
            f"por falta de red y {juicio} a la espera del juicio de la IA (un control puede estar en ambos grupos).")


def _tabla_dominios(g, s, hallazgos):
    filas = []
    for d in utiles.ORDEN_DOMINIOS:
        dg = g["dominios"].get(d, {})
        ds = s["dominios"].get(d)
        crit = sum(1 for h in hallazgos if h["dominio"] == d and h["severidad"] == "critica" and h["estado_hallazgo"] == "abierto")
        alt = sum(1 for h in hallazgos if h["dominio"] == d and h["severidad"] == "alta" and h["estado_hallazgo"] == "abierto")
        if not dg.get("activo"):
            filas.append(f"| {d} | — | — | — | — | — | {crit} | {alt} | sin controles aplicables |")
            continue
        if ds and ds["puntaje"] is not None:
            puntaje = f"{ds['puntaje']:g}/100" + (" (gris: insuficiente)" if ds["gris"] else "")
        else:
            puntaje = "— (insuficiente)"
        cob = _pct(ds["cobertura"]) if ds else "—"
        letra = (ds or {}).get("letra") or "—"
        nota = dg.get("leyenda") or ""
        filas.append(f"| {d} | {dg['nivel_demostrado']} | {dg['nivel_potencial']} | {letra} | {puntaje} | {cob} | {crit} | {alt} | {_celda(nota)} |")
    return "\n".join(filas)


def _puntaje_global(s):
    gl = s["global"]
    texto = f"{gl['puntaje']:g}/100" if gl["puntaje"] is not None else "—"
    texto += f" · letra {gl.get('letra') or '—'}"
    texto += f" · cobertura {_pct(gl['cobertura'])}" + (" (gris: insuficiente)" if gl["gris"] else "")
    return texto


def _metodo_puntaje(s):
    p = s.get("pesos") or {}
    nombres = {"critica": "crítica", "alta": "alta", "media": "media", "baja": "baja"}
    pesos = ", ".join(f"{nombres[k]} {str(p[k]).replace('.', ',').removesuffix(',0')}"
                      for k in nombres if k in p)
    metodo = s["global"].get("metodo") or "—"
    return f"pesos por severidad {pesos} (origen: {s.get('origen_pesos', 's/d')}); agregación global: {metodo}"


def _bandas_texto(cortes, nombres):
    limites = [0] + sorted(cortes)
    partes = []
    for i, nombre in enumerate(nombres[:len(limites)]):
        hasta = limites[i + 1] - 1 if i + 1 < len(limites) else 100
        partes.append(f"{limites[i]:g}-{hasta:g} {nombre}")
    return " · ".join(partes)


def _seccion_iua(r):
    c = r["cobertura"]
    if r["iua"] is not None and r.get("banda_omitida"):
        valor = (f"IUA: {r['iua']:g}/100 (banda omitida, en gris: {r.get('banda_motivo') or 'cobertura insuficiente'})")
    elif r["iua"] is not None:
        valor = f"IUA: {r['iua']:g}/100 ({r['banda']})"
    else:
        valor = "IUA: sin datos (ningún componente medido)"
    lineas = [
        f"{valor} · cobertura {_pct(c['fraccion'])} del peso · {c['componentes_medidos']}/{c['componentes_total']} "
        f"componentes medidos" + (f"; {c['componentes_parcial_fallback']} solo con fallback estático (cobertura parcial)"
                                  if c.get("componentes_parcial_fallback") else "") + ".",
        "",
        "| Componente | Estado | Puntaje | Peso | Fuente | Cobertura | Nota |",
        "|---|---|---|---|---|---|---|",
    ]
    orden = [c for c in iua_mod.COMPONENTES if c in r["componentes"]]
    orden += sorted(c for c in r["componentes"] if c not in orden)
    for nombre in orden:
        comp = r["componentes"][nombre]
        puntaje = f"{comp['puntaje']:g}/100" if comp["puntaje"] is not None else "—"
        notas = [comp.get("motivo") or comp.get("detalle", {}).get("nota") or ""]
        if comp["estado"] == "medido" and comp.get("hallazgos_fallback"):
            notas.append(f"además {comp['hallazgos_fallback']} hallazgo(s) de fallback estático")
        if comp.get("detalle", {}).get("reglas_sin_impacto"):
            notas.append("reglas axe sin impacto, excluidas: " + ", ".join(comp["detalle"]["reglas_sin_impacto"]))
        nota = "; ".join(n for n in notas if n)
        lineas.append(f"| {nombre} | {comp['estado']} | {puntaje} | {comp['peso']:g} | {_celda(comp.get('fuente') or '—')} "
                      f"| {comp.get('cobertura') or '—'} | {_celda(nota)} |")
    b = r["bandas"]
    lineas += [
        "",
        f"Bandas ({b['origen']}, Lighthouse): {_bandas_texto(b['cortes'], b['nombres'])}. Accesibilidad con la fórmula de "
        "Lighthouse (pesos por impacto axe 10/7/3/1) y rendimiento con el puntaje Performance de Lighthouse; pesos entre "
        "componentes **ESTIMACIÓN** (plan §5.1). El IUA se calcula solo con los componentes medidos: léalo con su cobertura.",
        "",
        "SUS: sin datos de usuarios. El IUA no lo reemplaza.",
    ]
    return "\n".join(lineas)


def _tabla_cobertura(g):
    filas = []
    for n, v in g["cobertura_por_nivel"].items():
        estado = "verificado" if v["verificado"] else f"{n} no verificado"
        filas.append(f"| {n} | {v['aplicables']} | {v['evaluados']} | {_pct(v['cobertura'])} | {estado} |")
    return "\n".join(filas)


HERR_SONDA = frozenset({"zap", "k6", "nuclei", "headers", "playwright", "playwright_ux", "axe", "pa11y-ci", "lighthouse",
                        "web-vitals", "pg_stat_statements", "pgbench", "dos_usuarios", "anon_negativa", "stripe-cli",
                        "promptfoo", "garak"})


def _resuelve_no_demostrable(control):
    """Qué fase resolvería un control no demostrable en estático: F3 (revisores LLM), F4 (sondas) o entrevista."""
    herrs = control.get("herramientas", [])
    res = []
    if control.get("metodo") == "llm" or any(estado_mod.es_agente_llm(h) for h in herrs):
        res.append("F3")
    if any(h in HERR_SONDA for h in herrs):
        res.append("F4")
    if (control.get("metodo") == "manual" or any(h in estado_mod.COMPONENTES_ENTREVISTA | estado_mod.COMPONENTES_MANUALES
                                                for h in herrs) or control.get("aviso_legal")):
        res.append("entrevista")
    return res or ["F3"]  # solo reglas estáticas parciales: lo resuelve el juicio de un revisor


def _seccion_no_demostrable(estados, indice):
    """Cuántos controles quedaron no_evaluado por «no demostrable en estático» y qué los resolvería."""
    nd = [e for e in estados if e["estado"] == "no_evaluado"
          and (indice.get(e["control"]) or {}).get("evidencia_pass") == "no_demostrable_estatico"]
    if not nd:
        return "Ningún control aplicable quedó `no_evaluado` por «no demostrable en estático»."
    grupos = {"F3": [], "F4": [], "entrevista": []}
    for e in sorted(nd, key=lambda x: x["control"]):
        for fase in _resuelve_no_demostrable(indice[e["control"]]):
            grupos[fase].append(e["control"])
    nombres = {"F3": "F3 revisores LLM (juicio: autorización, arquitectura, flujo)",
               "F4": "F4 sondas dinámicas (navegador, DAST, carga)",
               "entrevista": "entrevista con el creador / evidencia manual"}
    lineas = [f"**{len(nd)} controles** aplicables quedaron `no_evaluado` por **no demostrable en estático** "
              "(`evidencia_pass = no_demostrable_estatico`): ninguna herramienta estática los cubre completos, así que "
              "su ausencia de hallazgos no es evidencia (sin «pases vacíos»). Sus hallazgos sí cuentan como fail. "
              "Los resolvería:", ""]
    for fase in ("F3", "F4", "entrevista"):
        if grupos[fase]:
            lineas.append(f"- {nombres[fase]}: {len(grupos[fase])} — {', '.join(grupos[fase])}")
    return "\n".join(lineas)


def fallbacks_de_corrida(corrida):
    """{check: herramienta real que reemplaza} de los fallbacks (DECISIONES.md #6) presentes en crudo/.
    Un fallback se reconoce por `cobertura: "parcial (fallback)"` en su check_<nombre>.json."""
    res = {}
    crudo = Path(corrida) / "crudo"
    if not crudo.is_dir():
        return res
    for p in sorted(crudo.glob("check_*.json")):
        if p.name.endswith(".meta.json"):
            continue
        d = utiles.leer_json(p, {}) or {}
        if isinstance(d, dict) and d.get("cobertura") == COBERTURA_FALLBACK:
            res[p.name[len("check_"):-len(".json")]] = d.get("reemplaza") or "herramienta real"
    return res


# --------------------------------------------------------------------------- remediación por perfil (Anexo C, AUD-REM)
RE_CSP_META = re.compile(r"""<meta[^>]+http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*>""", re.I)
RE_CSP_CONTENT = re.compile(r"""content\s*=\s*(["'])(.*?)\1""", re.I | re.S)
FUENTES_LOCALES = {"'self'", "'none'", "blob:", "data:"}
REMEDIACION_LOCAL = {
    "OPS-ERROR-TRACKING": (
        "Registrar los errores en un registro local en el dispositivo (tipo de error, módulo, versión y fecha, "
        "sin datos del paciente ni contenido de archivos), visible para el usuario y exportable a mano para soporte. "
        "Un servicio externo de seguimiento de errores obligaría a abrir connect-src a un tercero y a revisar la "
        "transferencia de datos de salud antes de hacerlo."),
}


def csp_connect_solo_self(proyecto):
    """True si la CSP del index.html (fuente o del build ya existente en dist/, build/ u out/: Vite puede
    inyectarla al construir) limita connect-src (o, sin él, default-src) a orígenes locales."""
    texto = ""
    for rel in ("index.html", "dist/index.html", "build/index.html", "out/index.html"):
        ruta = Path(proyecto) / rel
        if ruta.is_symlink() or not ruta.is_file():
            continue
        try:
            texto += ruta.read_text(encoding="utf-8", errors="replace")[:200_000] + "\n"
        except OSError:
            continue
    veredictos = []  # una CSP con un origen externo (o sin connect/default-src) anula a las demás
    for meta in RE_CSP_META.findall(texto):
        m = RE_CSP_CONTENT.search(meta)
        if not m:
            continue
        directivas = {}
        for parte in m.group(2).split(";"):
            tokens = parte.split()
            if tokens:
                directivas[tokens[0].lower()] = tokens[1:]
        fuentes = directivas.get("connect-src", directivas.get("default-src"))
        veredictos.append(bool(fuentes) and all(f.lower() in FUENTES_LOCALES for f in fuentes))
    return bool(veredictos) and all(veredictos)


def remediacion_por_perfil(control, texto, banderas, csp_restrictiva):
    """Remediación ajustada al perfil: en salud o con CSP connect-src local, nada de servicios externos."""
    if control in REMEDIACION_LOCAL and ((banderas or {}).get("salud") is True or csp_restrictiva):
        return REMEDIACION_LOCAL[control]
    return texto


def _texto_ia(texto, maximo=300):
    """Razón escrita por la IA → literal Markdown de una línea: enmascarada, recortada, sin HTML, enlaces, código en
    línea roto ni celdas de tabla (F3-C adv.: hubo inyección de Markdown/HTML)."""
    t = enmascarar.recortar(enmascarar.enmascarar_texto(" ".join(utiles.una_linea(texto or "").split())), maximo)
    # sin autolinks de GFM (https://…, www.…, correo): el enlace queda como texto inerte, p. ej. https[:]//…
    t = _RE_ESQUEMA.sub(r"\1[:]//", t)
    t = _RE_WWW.sub(r"\1[.]", t)
    t = _RE_CORREO.sub(r"\1[@]", t)
    return _celda(utiles.md_literal(t)).rstrip(". ") or "sin razón"


_RE_ESQUEMA = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*):/+")
_RE_WWW = re.compile(r"(?i)\b(www)\.")
_RE_CORREO = re.compile(r"([\w.+-])@(?=[\w-]+\.[\w-])")


def _aviso_triage(t, lugar):
    """Advertencia bajo un hallazgo grave que la IA marcó falso_positivo o incierto (None en otro caso)."""
    t = t or {}
    quien = "auditor" if t.get("modelo") == "auditor" else "triage-fp"
    if t.get("veredicto") == "falso_positivo":
        return (f"  ⚠ La IA lo marcó como posible falso positivo ({quien}): {_texto_ia(t.get('razon'))}. "
                "Requiere verificación humana antes de actuar.")
    if t.get("veredicto") == "incierto":
        donde = "revisarlo" if str(lugar).startswith("(sin archivo)") else f"revisar {_codigo(lugar)}"
        if t.get("modelo") == "auditor":  # entrada sintética de veredictos.py: la IA nunca vio este hallazgo
            return ("  ⚠ No revisado por la IA (quedó fuera del digest de triage por el tope de tokens). Cuenta como "
                    f"verdadero (fail-closed); una persona puede {donde} antes de aplicar la remediación.")
        return (f"  ⚠ La IA no pudo confirmarlo ni descartarlo ({quien}, incierto): {_texto_ia(t.get('razon'))}. "
                f"Por eso cuenta como verdadero (fail-closed); una persona puede {donde} antes de aplicar la "
                "remediación.")
    return None


def _seccion_hallazgos(hallazgos, indice, fallbacks=None, triage=None, estados=None):
    """estados: {control: estado}. La remediación condicional sigue la misma regla que roadmap.calcular: solo si el
    control NO está en fail (con otro hallazgo efectivo manda la remediación del catálogo; el aviso ⚠ se mantiene)."""
    fallbacks = fallbacks or {}
    triage = triage or {}
    estados = estados or {}
    graves = [h for h in hallazgos if h["severidad"] in ("critica", "alta") and h["estado_hallazgo"] == "abierto"]
    if not graves:
        return "No hay hallazgos críticos ni altos abiertos en lo que se pudo evaluar."
    bloques, actual = [], None
    # Hallazgos distintos del mismo control (p. ej. reglas distintas en la misma línea, que no se fusionan)
    # se agrupan como instancias bajo un solo encabezado.
    n_inst = {}
    for h in graves:
        n_inst[h["control"]] = n_inst.get(h["control"], 0) + 1 + h.get("instancias_extra", 0)
    for h in graves:
        if h["control"] != actual:
            actual = h["control"]
            c = indice.get(actual, {})
            bloques.append(f"\n### {actual} — {_celda(c.get('titulo', actual))} ({h['severidad']} · {h['gate']}"
                           f" · {n_inst[actual]} instancia(s))\n")
            est = estados.get(actual)
            marcados = roadmap_mod.graves_marcados_fp(actual, graves, triage) if est != "fail" else []
            if marcados:  # F3-C: la IA marcó todas las instancias como posible FP → remediación condicional
                cond = roadmap_mod.remediacion_condicional(
                    dict(c, id=actual), min((x["severidad"] for x in marcados), key=utiles.rango_severidad),
                    [roadmap_mod._lugar(x) for x in marcados], h.get("remediacion"), est)
                bloques.append("Remediación (condicional: la IA marcó todas las instancias como posible falso "
                               f"positivo): {cond}\n")
            else:
                bloques.append(f"Remediación: {h.get('remediacion') or 'ver catálogo'}\n")
        u = h["ubicacion"]
        lugar = u.get("archivo") or "(sin archivo)"
        if u.get("linea") is not None:
            lugar += f":{u['linea']}"
        fuentes = ", ".join(f"{f['herramienta']}:{f.get('regla')}" for f in h["fuente"])
        extra = f" (y {h['instancias_extra']} más)" if h.get("instancias_extra") else ""
        fb = sorted({fallbacks[f["herramienta"]] for f in h["fuente"] if f["herramienta"] in fallbacks})
        if fb and all(f["herramienta"] in fallbacks for f in h["fuente"]):
            extra += f" · cobertura parcial (fallback de {', '.join(fb)})"
        bloques.append(f"- {_codigo(lugar)} · confianza {h['confianza']} · método {h['metodo']} · {_celda(fuentes)}{extra}\n"
                       f"  Evidencia: {_codigo(h['evidencia'])}")
        aviso = _aviso_triage(triage.get(h.get("id")), lugar)
        if aviso:
            bloques.append(aviso)
    return "\n".join(bloques).strip()


MAX_UBIC_MENORES = 5
MAX_EVID_MENORES = 160


def _seccion_menores(hallazgos, indice):
    """6d (ronda 7, DECISIONES.md #12 adenda 2): hallazgos abiertos de severidad media, baja o info. La sección 6
    solo lista críticos y altos; sin esto, lo que un check deja visible con severidad menor (p. ej. RLS deny-all,
    reconstrucción SQLite, PII no tabular, FK sin índice) llegaba a hallazgos.jsonl pero no al informe.
    Una línea por control con severidad, nivel, ubicaciones (máx. MAX_UBIC_MENORES) y evidencia corta."""
    orden = {"media": 0, "baja": 1, "info": 2}
    menores = [h for h in hallazgos if h.get("severidad") in orden and h.get("estado_hallazgo") == "abierto"]
    if not menores:
        return "No hay hallazgos abiertos de severidad media, baja ni info."
    por_control = {}
    for h in menores:
        por_control.setdefault(h["control"], []).append(h)
    lineas = []
    for cid, hs in sorted(por_control.items(), key=lambda kv: (min(orden[h["severidad"]] for h in kv[1]),
                                                                  utiles.num_nivel(kv[1][0].get("gate") or "N5"), kv[0])):
        sev = min((h["severidad"] for h in hs), key=lambda x: orden[x])
        n = sum(1 + h.get("instancias_extra", 0) for h in hs)
        lugares = []
        for h in hs[:MAX_UBIC_MENORES]:
            u = h.get("ubicacion") or {}
            lugar = u.get("archivo") or "(sin archivo)"
            if u.get("linea") is not None:
                lugar += f":{u['linea']}"
            lugares.append(_codigo(lugar))
        resto = f" y {len(hs) - MAX_UBIC_MENORES} más" if len(hs) > MAX_UBIC_MENORES else ""
        evid = utiles.una_linea(hs[0].get("evidencia") or "")
        if len(evid) > MAX_EVID_MENORES:
            evid = evid[:MAX_EVID_MENORES - 1] + "…"
        titulo = _celda((indice.get(cid) or {}).get("titulo", cid))
        lineas.append(f"- **{cid}** — {titulo} ({sev} · {hs[0].get('gate', 's/d')} · {n} instancia(s)): "
                      f"{', '.join(lugares)}{resto}" + (f". Evidencia: {_codigo(evid)}" if evid else ""))
    return (f"{len(menores)} hallazgo(s) abiertos de severidad media, baja o info (detalle completo en "
            "`hallazgos.jsonl`; remediación en la hoja de ruta o el catálogo):\n\n" + "\n".join(lineas))


def _seccion_no_evaluados(estados, indice):
    pendientes = [e for e in estados if e["estado"] in ("no_evaluado", "manual_pendiente")]
    if not pendientes:
        return "Todos los controles aplicables se evaluaron."
    filas = ["| Control | Nivel | Estado | Motivo | Cómo habilitarlo |", "|---|---|---|---|---|"]
    for e in sorted(pendientes, key=lambda x: (utiles.num_nivel(indice[x["control"]]["gate"]), x["control"])):
        motivo = e.get("motivo") or ""
        if roadmap_mod.es_motivo_fp_ia(motivo):
            como = "verificación humana del hallazgo que la IA marcó como posible falso positivo (ver sección 6)"
        elif "no demostrable en análisis estático" in motivo:
            como = "F3 revisores / F4 sondas / entrevista (no demostrable en estático)"
        elif "juicio LLM" in motivo:
            como = "modo estándar con juicio LLM (F3)"
        elif "modo" in motivo and "alcance" in motivo:
            como = "--modo estandar o profundo"
        elif e["estado"] == "manual_pendiente" or "entrevista" in motivo:
            como = "entrevista / evidencia manual"
        else:
            como = "instalar o habilitar la herramienta (`bin/auditar doctor` o `/auditor-integral:auditar-doctor`)"
        filas.append(f"| {e['control']} | {indice[e['control']]['gate']} | {e['estado']} | {_celda(motivo)} | {como} |")
    return f"{len(pendientes)} controles aplicables sin evaluar:\n\n" + "\n".join(filas)


def _seccion_legal(estados, indice):
    texto = ("El auditor señala riesgo; no afirma cumplimiento de la Ley 19.628, la Ley 20.584 ni la Ley 21.719 "
             "(DECISIONES.md #4: lo legal no bloquea el nivel, pero siempre se avisa y lo verifica el creador). "
             "Detalle y normas en el bloque «Aviso legal» al inicio del informe.")
    lineas = [texto, ""]
    for e in estados:
        if (indice.get(e["control"]) or {}).get("aviso_legal") and e["estado"] != "no_aplica":
            lineas.append(f"- **Aviso** {e['control']}: {e['estado']}" + (f" — {e['motivo']}" if e.get("motivo") else ""))
    return "\n".join(lineas).strip()


def _herramientas(resumen, fallbacks=None):
    fallbacks = fallbacks or {}
    herr = resumen.get("herramientas") or {}
    if not herr:
        return "sin metadatos de herramientas"

    def estado(k, v):
        if k in fallbacks:
            return f"{v.get('estado')}; fallback de {fallbacks[k]}, cobertura parcial"
        return str(v.get("estado"))
    return ", ".join(f"{k} {v.get('version') or 's/v'} ({estado(k, v)})" for k, v in sorted(herr.items()))


def _seccion_grupos(rm):
    salida = []
    for g in rm["grupos"]:
        items = [i for i in rm["items"] if i["grupo"] == g["id"]]
        salida.append(f"## {g['titulo']}\n")
        if not items:
            salida.append("Nada en este grupo.\n")
            continue
        for i in items:
            salida.append(
                f"{i['orden']}. **{i['control']}** — {_celda(i['titulo'])} ({i['severidad']} · {i['gate']} · esfuerzo {i['esfuerzo']}"
                + (" · bloquea el nivel global" if i["bloquea_global"] else "") + ")\n"
                f"   - Qué falla: {i['estado']}" + (f" ({_celda(i['motivo'])})" if i.get("motivo") else "")
                + (f"; {i['hallazgos']} hallazgo(s)" if i["hallazgos"] else "") + "\n"
                f"   - Qué hacer: {_celda(i['que_hacer'])}\n"
                + (f"   - {_linea_bloqueo_item(i)}\n" if i.get("bloqueo") else "")
                + f"   - Cómo se verifica: {_celda(i['verificacion'])}\n"
                f"   - Referencia: {_celda(i.get('referencia') or '—')}\n")
    return "\n".join(salida).strip()


def sarif(hallazgos, indice):
    usados = sorted({h["control"] for h in hallazgos})
    reglas = [{"id": cid, "name": cid,
               "shortDescription": {"text": indice.get(cid, {}).get("titulo", cid)},
               "properties": {"dominio": indice.get(cid, {}).get("dominio"), "gate": indice.get(cid, {}).get("gate")}}
              for cid in usados]
    resultados = []
    for h in hallazgos:
        r = {"ruleId": h["control"], "level": NIVEL_SARIF.get(h["severidad"], "warning"),
             "message": {"text": h["evidencia"] or h["control"]},
             "partialFingerprints": {"auditorIntegral/v1": h["fingerprint"]},
             "properties": {"severidad": h["severidad"], "confianza": h["confianza"], "id": h["id"],
                            "fuente": [f"{f['herramienta']}:{f.get('regla')}" for f in h["fuente"]]}}
        u = h["ubicacion"]
        if u.get("archivo") and not u["archivo"].startswith("/"):
            loc = {"physicalLocation": {"artifactLocation": {"uri": u["archivo"]}}}
            if isinstance(u.get("linea"), int) and u["linea"] >= 1:
                loc["physicalLocation"]["region"] = {"startLine": u["linea"]}
            r["locations"] = [loc]
        resultados.append(r)
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "auditor-integral", "version": VERSION_AUDITOR,
                                          "informationUri": "https://github.com/", "rules": reglas}},
                      "results": resultados}]}


TITULO_AVISO_LEGAL = "⚠ Aviso legal — verificación del creador"


def _seccion_aviso_legal(estados, indice, perfil, corrida):
    """Bloque destacado al inicio del informe (DECISIONES.md #4). Nunca afirma cumplimiento."""
    perfil_json = utiles.leer_json(Path(corrida) / "perfil.json")
    decl = gates_mod.estado_mod.declaracion_sin_datos(perfil, corrida, perfil_json)
    pendientes = [e for e in estados if indice.get(e["control"], {}).get("aviso_legal") and e["estado"] != "no_aplica"]
    b = perfil.get("banderas") or {}
    titulo = f"## {TITULO_AVISO_LEGAL}\n"
    if decl and not pendientes:
        return (f"{titulo}\n> **GUÍA.** {gates_mod.estado_mod.DECLARACION_SIN_DATOS} (perfil.json, registrada el "
                f"{decl.get('fecha') or 'sin fecha'}): los controles legales quedan `no_aplica`. Si el proyecto "
                "empieza a tratar datos de personas, repita la entrevista. El auditor no afirma cumplimiento "
                "de ninguna ley.")
    if not pendientes:
        return ""
    if b.get("datos_personales") is True or b.get("salud") is True or b.get("menores") is True:
        situacion = "El creador declaró que el proyecto trata datos personales"
        situacion += " y de salud." if b.get("salud") is True else "."
    else:
        situacion = ("No se sabe si el proyecto trata datos personales (la entrevista no lo respondió o la respuesta "
                     "es contradictoria): se avisa por precaución.")
    filas = ["| Control | Nivel de referencia | Estado | Qué verificar |", "|---|---|---|---|"]
    for e in sorted(pendientes, key=lambda x: (utiles.num_nivel(indice[x["control"]]["gate"]), x["control"])):
        c = indice[e["control"]]
        filas.append(f"| {e['control']} | {c['gate']} | {e['estado']} | {_celda(c.get('titulo', e['control']))} |")
    leyes = ["- Ley 19.628, sobre protección de la vida privada (tratamiento de datos personales).",
             "- Ley 21.719, que regula la protección y el tratamiento de los datos personales: **re-verificar su "
             "vigencia y sus plazos de entrada en vigor en BCN** (https://www.bcn.cl/leychile) a la fecha de uso; "
             "el auditor no la da por vigente ni por no vigente."]
    if b.get("salud") is True:
        leyes.append("- Ley 20.584, derechos y deberes de los pacientes (ficha clínica y confidencialidad): el "
                     "creador declaró datos de salud.")
    elif b.get("salud") is None:
        leyes.append("- Ley 20.584, derechos y deberes de los pacientes: solo si el proyecto trata datos de salud "
                     "(no declarado en la entrevista).")
    return "\n".join([
        titulo,
        "> **GUÍA.** Lo legal no bloquea el nivel (DECISIONES.md #4), pero se avisa siempre. El auditor **no afirma "
        "cumplimiento** de ninguna ley: indica qué debe verificar una persona. Estos controles quedan en "
        "`manual_pendiente` hasta que el creador confirme la verificación (o `fail` si hay evidencia en contra).",
        "", situacion, "", *filas, "", "Normas que conviene revisar (Chile):", "", *leyes, "",
        "Sugerencia: revisión por una persona con formación jurídica (o la persona delegada de protección de datos "
        "de la institución) antes de cargar datos reales. Si el creador declara que el proyecto no usa datos "
        "personales, la declaración queda registrada con su fecha y estos controles pasan a `no_aplica`."])


def _aviso_sus(estados, indice):
    """Aviso en la hoja de ruta (DECISIONES.md #5): sin SUS con usuarios reales, N4 no se otorga."""
    for e in estados:
        if indice.get(e["control"], {}).get("exigido_sin_condicion") and e["estado"] not in ("pass", "no_aplica"):
            return (f"\n\n## Aviso — SUS exigido para N4 (DECISIONES.md #5)\n\n**{e['control']}** — "
                    f"{_celda(indice[e['control']].get('titulo', e['control']))}: {e['estado']}"
                    + (f". {_celda(e['motivo'])}." if e.get("motivo") else
                       ". N4 no se otorga sin SUS promedio >= 68 medido con usuarios reales, también en "
                       "herramientas internas."))
    return ""


# ------------------------------------------------------------------------------------------------------------------
# F3-B: secciones fáciles para el desarrollador y el dueño («Qué hizo el auditor», «Qué falta», «Qué hacer ahora»).
# Las llena este script sin LLM. Los juicios de la IA solo se cuentan si validan contra veredicto.schema.json; el texto
# del redactor-dueno solo se usa si pasa validar_redaccion (fail-closed: si no, plantilla).
# ------------------------------------------------------------------------------------------------------------------
SONDAS_APP = {"playwright_ux", "lhci", "lighthouse", "axe", "k6", "headers", "zap", "nuclei", "anon_negativa",
              "dos_usuarios"}
PREGUNTAS_CORTAS = {
    1: "qué hace y para quién", 2: "flujos principales", 3: "datos personales, de salud, de menores o de la UE",
    4: "pagos y proveedor", 5: "IA dentro de la app", 6: "envío de emails", 7: "dónde está publicada y staging",
    8: "usuarios a 3 y 12 meses", 9: "usuarios o datos reales cargados", 10: "cuentas a nombre del creador",
    11: "backups y prueba de restauración", 12: "RTO y RPO", 13: "tope de gasto", 14: "administradores y MFA",
    15: "política de privacidad", 16: "qué haría ante una clave filtrada"}
GRUPOS_PENDIENTES = (
    ("instalar", "Instalar o habilitar herramientas"),
    ("entrevista", "Responder preguntas de la entrevista"),
    ("levantar_app", "Levantar la app (sondas dinámicas, F4; solo con confirmación)"),
    ("fp_ia", "Posible falso positivo de la IA por verificar"),
    ("verificacion_humana", "Verificación humana"),
    ("juicio_ia", "Juicio de la IA pendiente"),
    ("modo", "Cambiar de modo"),
    ("reintentar", "La herramienta falló: reintentar"),
    ("evidencia", "Falta evidencia positiva (fail-closed)"),
)
_RE_HERR_FALTA = re.compile(r"([\w.+-]+): (?:herramienta ausente|sin datos de la herramienta)")
_RE_HERR_FALLO = re.compile(r"([\w.+-]+): (?:timeout de la herramienta|la herramienta terminó con error)")
_ESFUERZO_SML = {"XS": "S", "S": "S", "M": "M", "L": "L", "XL": "L"}


def _pregunta_por_bandera():
    datos = utiles.leer_toml(utiles.RAIZ / "catalogo" / "perfil_riesgo.toml") or {}
    return {b["nombre"]: b.get("pregunta") for b in datos.get("bandera", []) if b.get("pregunta")}


def _lista_corta(ids, maximo=8):
    ids = list(ids)
    texto = ", ".join(ids[:maximo])
    return texto + (f" y {len(ids) - maximo} más" if len(ids) > maximo else "")


def clasificar_pendiente(e, indice, preguntas=None):
    """(categoría, detalle) de un control no_evaluado/manual_pendiente según lo que lo resolvería."""
    import catalogo
    motivo = e.get("motivo") or ""
    c = indice.get(e["control"]) or {}
    herrs = c.get("herramientas") or []
    if roadmap_mod.es_motivo_fp_ia(motivo):   # F3-C adv.: no hay evidencia que registrar ni /auditar-informe
        return "fp_ia", None
    if e.get("estado") == "manual_pendiente" or "aviso legal" in motivo or "verificación manual" in motivo \
            or "SUS" in motivo:
        return "verificacion_humana", None
    if "fuera del alcance del modo" in motivo:
        return "modo", None
    if "entrevista" in motivo:
        preguntas = preguntas if preguntas is not None else _pregunta_por_bandera()
        nombres = [n.strip() for n in motivo.split("entrevista:", 1)[1].split(",")] if "entrevista:" in motivo else []
        if not nombres:
            try:
                nombres = sorted(catalogo.nombres_en_condicion(c.get("condicion", "siempre")))
            except catalogo.ErrorCondicion:
                nombres = []
        return "entrevista", sorted({preguntas[n] for n in nombres if preguntas.get(n)})
    if any(h in SONDAS_APP for h in herrs) and ("sin datos de la herramienta" in motivo or "herramienta ausente" in motivo
                                                or "no demostrable" in motivo):
        return "levantar_app", None
    if "juicio LLM" in motivo or ("no demostrable" in motivo and any(estado_mod.es_agente_llm(h) for h in herrs)):
        return "juicio_ia", sorted(h for h in herrs if estado_mod.es_agente_llm(h))
    fallidas = _RE_HERR_FALLO.findall(motivo)
    if fallidas:
        return "reintentar", sorted(set(fallidas))
    faltan = _RE_HERR_FALTA.findall(motivo)
    if faltan:
        return "instalar", sorted(set(faltan))
    return "evidencia", None


def _pendientes(estados):
    return [e for e in estados if e.get("estado") in ("no_evaluado", "manual_pendiente")]


def seccion_que_falta(estados, indice, herramientas_json=None):
    pend = _pendientes(estados)
    if not pend:
        return "Nada pendiente: todos los controles aplicables se evaluaron."
    preguntas = _pregunta_por_bandera()
    instal = (herramientas_json or {}).get("herramientas") or {}
    grupos = {}
    for e in sorted(pend, key=lambda x: (utiles.num_nivel((indice.get(x["control"]) or {}).get("gate", "N5")),
                                         x["control"])):
        cat, det = clasificar_pendiente(e, indice, preguntas)
        grupos.setdefault(cat, []).append((e["control"], det))
    salida = [f"{len(pend)} controles sin evaluar, agrupados por lo que los resolvería (el detalle por control está "
              "en «Lo que NO se evaluó»)."]
    como_general = {
        "levantar_app": "levantar la app en local y autorizar las sondas (F4); nunca contra producción.",
        "fp_ia": "una persona revisa a mano el archivo:línea de la sección 6; si es real, aplica la remediación del "
                 "catálogo; si no, deja constancia escrita. El auditor no tiene forma de registrar esa verificación: "
                 "el control sigue no_evaluado hasta que una corrida nueva ya no encuentre el hallazgo.",
        "verificacion_humana": "una persona registra la evidencia (avisos legales, SUS con usuarios reales, controles "
                               "manuales) y regenera el informe: " + roadmap_mod.comando("informe") + ".",
        "juicio_ia": roadmap_mod.comando("juicio", "estandar") + " (o profundo) con los subagentes de F3; cada "
                     "juicio requiere verificación humana.",
        "modo": "corrida nueva en modo profundo (o estandar) para evaluar niveles superiores: "
                + roadmap_mod.comando("auditar", "profundo") + ".",
        "evidencia": "la herramienta corrió, pero no dejó evidencia positiva suficiente para pass (fail-closed); "
                     "revisar a mano o agregar el check."}
    for cat, titulo in GRUPOS_PENDIENTES:
        filas = grupos.get(cat)
        if not filas:
            continue
        salida.append(f"\n**{titulo}** ({len(filas)})\n")
        if cat in ("instalar", "reintentar"):
            # Una línea por conjunto de herramientas alternativas (cualquiera de ellas desbloquea esos controles).
            por_conjunto = {}
            for cid, det in filas:
                por_conjunto.setdefault(tuple(det or ["(herramienta sin nombre)"]), []).append(cid)
            orden = sorted(por_conjunto.items(), key=lambda x: (-len(x[1]), x[0]))
            for herrs, ids in orden[:10]:
                alternativas = " o ".join(f"`{h}`" for h in herrs)
                cmds = [f"{_codigo(instal[h]['instalacion_sugerida'])}" for h in herrs
                        if cat == "instalar" and (instal.get(h) or {}).get("instalacion_sugerida")]
                salida.append(f"- {alternativas} → {len(ids)} control(es): {_lista_corta(ids, 6)}."
                              + (f" Comando sugerido, sin ejecutar: {' / '.join(cmds)}." if cmds else ""))
            if len(orden) > 10:
                resto = sum(len(ids) for _, ids in orden[10:])
                salida.append(f"- … y {len(orden) - 10} conjunto(s) más de herramientas ({resto} control(es)).")
            salida.append("- Cómo: " + (roadmap_mod.comando("doctor") + " muestra qué falta y el comando de "
                                        "instalación sugerido (no se instala nada sin su confirmación)."
                                        if cat == "instalar" else
                                        "corrida nueva (" + roadmap_mod.comando("auditar") + "); si se repite, "
                                        "revisar el timeout con " + roadmap_mod.comando("doctor") + "."))
        elif cat == "entrevista":
            por_preg = {}
            for cid, det in filas:
                for p in det or [0]:
                    por_preg.setdefault(p, []).append(cid)
            for p, ids in sorted(por_preg.items()):
                etiqueta = f"pregunta {p} ({PREGUNTAS_CORTAS.get(p, 's/d')})" if p else "preguntas E0/E5 sin bandera asociada (verificación por entrevista)"
                salida.append(f"- {etiqueta} → {_lista_corta(ids)}.")
            salida.append("- Cómo: responder la entrevista (" + roadmap_mod.comando("perfil") + ") y luego "
                          "regenerar el informe (" + roadmap_mod.comando("informe") + "). Sin respuesta no se "
                          "asume nada.")
        else:
            salida.append(f"- {_lista_corta([cid for cid, _ in filas])}.")
            salida.append(f"- Cómo: {como_general[cat]}")
    return "\n".join(salida).strip()


EFECTO_DESCARTA = "descarta el hallazgo (falso positivo con razón y ubicación)"   # texto de veredictos.ajustar
EFECTO_FP_GRAVE = ("posible falso positivo: el hallazgo NO se descarta del informe (sigue en la sección 6 con aviso; "
                   "requiere verificación humana)")
_RE_FILA_HID = re.compile(r"^\| [^|]*\((H-[0-9a-f]+)\) \|")


def efecto_fp_graves(texto, hallazgos):
    """Tabla 6b: un falso positivo sobre un hallazgo crítico/alto abierto NO desaparece de la sección 6 (fail-closed),
    así que su efecto no puede decir «descarta el hallazgo» (F3-C adv.). Solo cambia el texto mostrado."""
    graves = {h.get("id") for h in hallazgos if h.get("severidad") in ("critica", "alta")
              and h.get("estado_hallazgo", "abierto") == "abierto"}
    salida = []
    for linea in texto.split("\n"):
        m = _RE_FILA_HID.match(linea)
        if m and m.group(1) in graves and f"| {EFECTO_DESCARTA} |" in linea:
            linea = linea.replace(f"| {EFECTO_DESCARTA} |", f"| {EFECTO_FP_GRAVE} |", 1)
        salida.append(linea)
    return "\n".join(salida)


def leer_veredictos(corrida):
    """(válidos, descartados) de <corrida>/veredictos.jsonl; solo cuentan las líneas que validan contra el schema."""
    import json
    import validar_schema
    ruta = Path(corrida) / "veredictos.jsonl"
    if not ruta.is_file():
        return [], 0
    schema = utiles.leer_json(utiles.RAIZ / "schemas" / "veredicto.schema.json")
    validos, malos = [], 0
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        if not linea.strip():
            continue
        try:
            v = json.loads(linea)
        except ValueError:
            malos += 1
            continue
        if isinstance(v, dict) and schema and not validar_schema.validar(v, schema):
            validos.append(v)
        else:
            malos += 1
    return validos, malos


def veredictos_de_corrida(corrida):
    """(juicios, descartados) coherentes con «Decisiones de la IA» (F3-A).

    Si veredictos.py ya corrió (existe decisiones_ia.json), cuentan solo los veredictos APLICADOS por las reglas
    duras y los descartados por schema o por reglas. Si decisiones_ia.json existe pero no se puede leer, no se
    cuenta ningún juicio (fail-closed) y todas las líneas de veredictos.jsonl se informan como descartadas.
    Sin decisiones_ia.json se usa la lectura por schema (leer_veredictos).
    """
    import veredictos as veredictos_mod
    ruta = Path(corrida) / veredictos_mod.DECISIONES
    if not ruta.exists():
        return leer_veredictos(corrida)
    dec = utiles.leer_json(ruta)
    if not isinstance(dec, dict) or not isinstance(dec.get("aplicadas"), list):
        validos, malos = leer_veredictos(corrida)
        return [], max(1, len(validos) + malos)
    aplicadas = [a for a in dec["aplicadas"] if isinstance(a, dict) and {"agente", "control", "veredicto"} <= set(a)]
    descartadas = dec.get("descartadas") if isinstance(dec.get("descartadas"), list) else []
    return aplicadas, len(descartadas) + (len(dec["aplicadas"]) - len(aplicadas))


def _tokens(datos):
    """(total, {fase: n}) de tokens.json con formato tolerante; None si no se puede leer sin inventar."""
    if not isinstance(datos, dict):
        return None

    def num(x):
        if isinstance(x, bool):
            return None
        if isinstance(x, int):
            return x
        if isinstance(x, dict):
            return num(x.get("total", x.get("tokens")))
        return None
    crudas = next((datos[k] for k in ("por_fase", "fases", "por_agente") if isinstance(datos.get(k), dict)), {})
    fases = {k: num(v) for k, v in crudas.items() if num(v) is not None}
    total = num(datos.get("total", datos.get("total_tokens")))
    if total is None and fases:
        total = sum(fases.values())
    return None if total is None else (total, fases)


def _conteo_pendientes(pend, indice):
    cuenta = {}
    for e in pend:
        cat = clasificar_pendiente(e, indice)[0]
        cuenta[cat] = cuenta.get(cat, 0) + 1
    return cuenta


MOTIVO_NO_REGISTRADO = "motivo no registrado"
MAX_MOTIVO = 200


def motivos_herramientas(corrida):
    """{herramienta canónica: motivo real} de crudo/: el campo «error» del .meta.json o, si falta, el «motivo» de la
    salida del check (check_<nombre>.json). Sin inventar: lo que no tiene motivo no aparece."""
    crudo = Path(corrida) / "crudo"
    res = {}
    for nombre, m in utiles.cargar_metas(crudo).items():
        if isinstance(m.get("error"), str) and m["error"].strip():
            res[nombre] = m["error"].strip()
    if crudo.is_dir():
        for p in sorted(crudo.glob("check_*.json")):
            if p.name.endswith(".meta.json"):
                continue
            nombre = utiles.canon_herramienta(p.name[:-len(".json")])
            d = utiles.leer_json(p, {}) or {}
            if nombre not in res and isinstance(d, dict) and isinstance(d.get("motivo"), str) and d["motivo"].strip():
                res[nombre] = d["motivo"].strip()
    # F3-C adv.: enmascarar con los secretos de la corrida ANTES de que _no_corrio recorte (nunca medio secreto)
    secretos = enmascarar.secretos_de_corrida(corrida)
    return {k: enmascarar.enmascarar_texto(v, secretos) for k, v in res.items()}


def _no_corrio(k, v, motivos):
    """«nombre (estado: motivo real)»; si el estado es no_evaluado no se usa el texto genérico «p. ej. sin red»."""
    est = v.get("estado")
    texto = "no evaluado" if est == "no_evaluado" else estado_mod.TEXTO_ESTADO_HERR.get(est, est)
    motivo = (motivos or {}).get(k) or (motivos or {}).get(utiles.canon_herramienta(k)) or MOTIVO_NO_REGISTRADO
    motivo = enmascarar.recortar(enmascarar.enmascarar_texto(" ".join(str(motivo).split())), MAX_MOTIVO)
    return f"{k} ({texto}: {utiles.md_literal(motivo)})"  # texto de la herramienta = dato: sin enlaces ni HTML


ESTADOS_CORRIO = ("ok", "parcial")


def _parcial(k, motivos):
    motivo = (motivos or {}).get(k) or (motivos or {}).get(utiles.canon_herramienta(k)) or MOTIVO_NO_REGISTRADO
    motivo = enmascarar.recortar(enmascarar.enmascarar_texto(" ".join(str(motivo).split())), MAX_MOTIVO)
    return f" (parcial: {utiles.md_literal(motivo)})"


def es_sintetico(v):
    """True si la entrada de decisiones_ia.aplicadas la generó el auditor (tope de triage), no un juicio de la IA."""
    return v.get("agente") == "auditor" and v.get("modelo") is None


def seccion_que_hizo(resumen, estados, indice, veredictos, tokens, modo, descartados=0, motivos=None):
    herr = (resumen or {}).get("herramientas") or {}
    # R6: una herramienta en «parcial» (p. ej. semgrep sin red: solo reglas locales) SÍ corrió y puede originar
    # hallazgos y bloqueos: va en la lista de las que corrieron, marcada como parcial con su motivo.
    corrieron = [f"{k} {v.get('version') or 's/v'}" + (_parcial(k, motivos) if v.get("estado") == "parcial" else "")
                 for k, v in sorted(herr.items()) if v.get("estado") in ESTADOS_CORRIO]
    no_corrieron = [_no_corrio(k, v, motivos) for k, v in sorted(herr.items())
                    if v.get("estado") not in ESTADOS_CORRIO + ("no_aplica",)]
    sin_objeto = [k for k, v in sorted(herr.items()) if v.get("estado") == "no_aplica"]
    lineas = [f"- **Herramientas que corrieron ({len(corrieron)}):** {', '.join(corrieron) or 'ninguna'}."]
    if no_corrieron:
        lineas.append(f"- **No corrieron ({len(no_corrieron)}):** {', '.join(no_corrieron)}.")
    if sin_objeto:
        lineas.append(f"- **Sin nada que analizar:** {', '.join(sin_objeto)}.")
    # Las entradas del agente 'auditor' (modelo nulo) son sintéticas: veredictos.py las agrega por cada hallazgo grave
    # que el tope de tokens dejó fuera del digest de triage. No son juicios de la IA y no se cuentan como tales.
    sin_juzgar = [v for v in veredictos or [] if es_sintetico(v)]
    veredictos = [v for v in veredictos or [] if not es_sintetico(v)]
    if veredictos:
        por_agente = {}
        for v in veredictos:
            por_agente.setdefault(v["agente"], []).append(v)
        lineas.append(f"- **Qué revisó la IA ({len(veredictos)} juicios):**")
        for ag, vs in sorted(por_agente.items()):
            cuenta = {}
            for v in vs:
                cuenta[v["veredicto"]] = cuenta.get(v["veredicto"], 0) + 1
            detalle = ", ".join(f"{k} {n}" for k, n in sorted(cuenta.items()))
            controles = _lista_corta(sorted({v["control"] for v in vs}), 6)
            lineas.append(f"  - `{ag}`: {len(vs)} ({detalle}) sobre {controles}.")
        humanos = sum(1 for v in veredictos if v.get("requiere_verificacion_humana"))
        lineas.append(f"  - {humanos} juicio(s) marcados «requiere verificación humana». Todo juicio de la IA es una "
                      "opinión: el nivel lo calcula `gates.py` y la IA nunca convierte un `fail` en `pass`.")
    else:
        lineas.append("- **Qué revisó la IA:** La IA no emitió juicios en esta corrida: todo el resultado sale de "
                      "scripts y escáneres deterministas.")
    if sin_juzgar:
        lineas.append(f"  - {len(sin_juzgar)} hallazgo(s) crítico(s)/alto(s) **no juzgados** por la IA: quedaron fuera del "
                      "digest de triage por el tope de tokens. Cuentan como verdaderos (fail-closed).")
    if descartados:
        lineas.append(f"  - {descartados} línea(s) de `veredictos.jsonl` descartadas por no validar contra el schema "
                      "o las reglas duras de `veredictos.py` (ninguna cambió un estado a favor; ver «Decisiones de "
                      "la IA»).")
    pend = _pendientes(estados)
    if pend:
        cuenta = _conteo_pendientes(pend, indice)
        titulos = dict(GRUPOS_PENDIENTES)
        partes = "; ".join(f"{titulos[c].split(' (')[0].lower()}: {cuenta[c]}" for c, _ in GRUPOS_PENDIENTES
                           if c in cuenta)
        lineas.append(f"- **No se pudo evaluar:** {len(pend)} controles ({partes}). Ver «Qué falta».")
    n_pass = sum(1 for e in estados if e.get("estado") == "pass")
    n_fail = sum(1 for e in estados if e.get("estado") == "fail")
    lineas.append(f"- **Resultado de lo evaluado:** {n_pass} en pass y {n_fail} en fail.")
    tok = _tokens(tokens)
    if tok is None:
        lineas.append("- **Tokens LLM:** no medido (`tokens.json` ausente o ilegible: `medir_tokens.py` no corrió "
                      "o no encontró transcripts con usage).")
    else:
        total, fases = tok
        pres = ((utiles.leer_toml(utiles.RAIZ / "config" / "presupuesto_tokens.toml") or {}).get("total") or {})
        pres = pres.get(modo) or {}
        techo = pres.get("techo_duro")
        aviso = " **Supera el techo duro.**" if isinstance(techo, int) and total > techo else ""
        lineas.append(f"- **Tokens LLM medidos:** {total} (meta del modo {modo}: {pres.get('meta', 's/d')}; "
                      f"techo duro: {techo if techo is not None else 's/d'}; metas = ESTIMACIÓN de diseño).{aviso}")
        if fases:
            lineas.append("  - Por fase: " + ", ".join(f"{k} {n}" for k, n in sorted(fases.items())) + ".")
    return "\n".join(lineas)


def _ubicacion_de(control, hallazgos):
    for h in sorted((h for h in hallazgos if h.get("control") == control),
                    key=lambda h: utiles.rango_severidad(h.get("severidad", "media"))):
        u = h.get("ubicacion") or {}
        if u.get("archivo"):
            return u["archivo"] + (f":{u['linea']}" if u.get("linea") is not None else "")
    return None


def seccion_que_hacer(rm, hallazgos, siguiente, maximo=10, por_que=None, excluir=(), primeros=()):
    """Hoja de ruta corta: críticos, luego lo que falla para el siguiente nivel, luego lo que falta evaluar.
    excluir: controles que la portada ya listó en «Qué hacer hoy» (R10: no se repiten; un ítem con bloqueo pendiente
    de IA se muestra igual, DECISIONES.md #10).
    primeros: orden de los bloqueos de la portada (R10d): dentro del Paso 1 esos controles van primero y en ese orden,
    así el ítem 1 coincide con «Lo primero» de la cabecera. Solo reordena el Paso 1 (roadmap.json no cambia)."""
    items = [i for i in (rm or {}).get("items") or []
             if i["control"] not in excluir or (i.get("bloqueo") or {}).get("pendiente_ia")]
    if not items and excluir:
        return "Nada más por ahora: lo urgente está en «Qué hacer hoy», en la portada."
    if not items:
        return "Nada urgente: no hay críticos abiertos ni controles pendientes del siguiente nivel."
    por_que = por_que or {}
    criticos = [i for i in items if i["estado"] == "fail" and i["severidad"] == "critica"]
    pos = {c: k for k, c in enumerate(primeros)}
    criticos.sort(key=lambda i: pos.get(i["control"], len(pos)))   # estable: el resto conserva el orden del roadmap
    fallas = [i for i in items if i["estado"] == "fail" and i["severidad"] != "critica"]
    pend = [i for i in items if i["estado"] != "fail"]
    pasos = (("Paso 1 — Críticos (antes que cualquier otra cosa)", criticos),
             (f"Paso 2 — Para llegar a {siguiente}", fallas),
             (f"Paso 3 — Habilitar la evaluación de {siguiente} (ver «Qué falta»)", pend))
    salida, n = [], 0
    for titulo, grupo in pasos:
        cupo = max(0, maximo - n) if maximo else len(grupo)
        # DECISIONES.md #10: un ítem con bloqueo pendiente de IA nunca se recorta (fija el tope global).
        mostrados = [i for k, i in enumerate(grupo) if k < cupo or i.get("bloqueo")]
        if not mostrados:
            continue
        salida.append(f"\n**{titulo}:**\n")
        for i in mostrados:
            n += 1
            esf = _ESFUERZO_SML.get(i.get("esfuerzo"), i.get("esfuerzo") or "M")
            donde = _ubicacion_de(i["control"], hallazgos)
            salida.append(f"{n}. **{i['control']}** — {_celda(i['titulo'])} · esfuerzo **{esf}**"
                          + (f" · en {_codigo(donde)}" if donde else ""))
            if por_que.get(i["control"]):
                salida.append(f"   - Por qué importa: {_celda(por_que[i['control']])}")
            if i["estado"] == "fail":
                salida.append(f"   - Hacer: {_celda(i['que_hacer'])}")
            else:
                salida.append(f"   - Qué falta: {_celda(i.get('motivo') or i['estado'])}")
                if i.get("revision_ia"):  # F3-C: verificación humana concreta, luego la remediación condicional
                    salida.append(f"   - Hacer: {_celda(i['que_hacer'])}")
            if i.get("bloqueo"):   # DECISIONES.md #10: bloqueo visible, etiquetado como juicio de IA pendiente
                salida.append(f"   - {_linea_bloqueo_item(i)}")
            salida.append(f"   - Verificar: {_celda(i['verificacion'])}")
    if len(items) > n:
        salida.append(f"\n… y {len(items) - n} más en `hoja-de-ruta.md`.")
    if excluir:
        salida.insert(0, "Lo listado en «Qué hacer hoy» (portada) no se repite aquí.")
    return "\n".join(salida).strip()


def validar_redaccion(r, rm, revisados=None):
    """(True, None) si el texto del redactor-dueno se puede usar; si no, (False, motivo). No admite controles nuevos.
    R10: tampoco admite palabras prohibidas de la portada y, si se da revisados=(r, a), el resumen debe decir «r de a»
    (cuántos puntos se revisaron de los que aplican)."""
    if not isinstance(r, dict):
        return False, "no es un objeto JSON"
    if set(r) != {"agente", "resumen", "por_que_importa", "modelo"}:
        return False, "claves distintas de agente, resumen, por_que_importa y modelo"
    if r["agente"] != "redactor-dueno":
        return False, "agente distinto de redactor-dueno"
    if not isinstance(r["modelo"], str) or not 0 < len(r["modelo"]) <= 80:
        return False, "modelo inválido"
    if not isinstance(r["resumen"], str) or not r["resumen"].strip():
        return False, "resumen vacío"
    if len(r["resumen"].split()) > 200 or len(r["resumen"]) > 1600:
        return False, "resumen de más de 200 palabras"
    if not isinstance(r["por_que_importa"], dict):
        return False, "por_que_importa no es un objeto"
    for texto in [r["resumen"], *[t for t in r["por_que_importa"].values() if isinstance(t, str)]]:
        prohibidas = palabras_prohibidas(texto)
        if prohibidas:
            return False, f"usa palabras prohibidas ({', '.join(prohibidas)})"
    if revisados is not None and f"{revisados[0]} de {revisados[1]}" not in r["resumen"]:
        return False, f"el resumen no dice cuántos puntos se revisaron («{revisados[0]} de {revisados[1]}»)"
    controles = {i["control"] for i in (rm or {}).get("items") or []}
    for cid, texto in r["por_que_importa"].items():
        if cid not in controles:
            return False, f"{cid} no está en la hoja de ruta"
        if not isinstance(texto, str) or not texto.strip() or len(texto.split()) > 25 or len(texto) > 300:
            return False, f"«por qué importa» de {cid} vacío o de más de 25 palabras"
    return True, None


def secciones_dueno(valores, rm, estados, indice, veredictos, herr_ok, redaccion, motivo_red, siguiente, hallazgos,
                    excluir=()):
    """Valores de resumen-dueno.md.tmpl: lenguaje llano; el texto del redactor solo si validó."""
    pend = _pendientes(estados)
    criticos = sum(1 for i in rm["items"] if i["estado"] == "fail" and i["severidad"] == "critica")
    if redaccion:
        resumen = _celda(redaccion["resumen"].strip())
        nota = (f"Texto redactado por IA (redactor-dueno, modelo {_celda(redaccion['modelo'])}) a partir del informe: "
                "requiere verificación humana.")
    else:
        resumen = (f"Nivel demostrado: {valores['nivel_demostrado']} ({valores['hito']}). ¿Listo para datos reales? "
                   f"{valores['listo_datos_reales']}. Hay {criticos} problema(s) crítico(s) abierto(s) y {len(pend)} "
                   "punto(s) que no se pudieron revisar.")
        nota = (f"Texto del redactor descartado ({motivo_red}); se usa el texto de plantilla." if motivo_red
                else "Texto generado por plantilla, sin IA.")
    ia = (f"La IA revisó {len(veredictos)} punto(s) acotados; sus opiniones requieren verificación humana."
          if veredictos else "La IA no participó: todo salió de herramientas automáticas.")
    hizo = (f"Revisó el proyecto con {len(herr_ok)} herramienta(s) automática(s)"
            + (f" ({', '.join(herr_ok)})" if herr_ok else "") + f". {ia} No pudo revisar {len(pend)} punto(s).")
    llano = {"instalar": "instalar herramientas que faltan", "entrevista": "responder preguntas sobre el proyecto",
             "levantar_app": "probar la app funcionando (con su permiso)",
             "fp_ia": "revisar a mano un posible falso positivo de la IA (ver «Qué hacer ahora»)",
             "verificacion_humana": "revisión de una persona (incluye avisos legales)",
             "juicio_ia": "revisión asistida por IA", "modo": "una auditoría más completa",
             "reintentar": "repetir herramientas que fallaron", "evidencia": "evidencia que hoy no alcanza"}
    cuenta = _conteo_pendientes(pend, indice)
    falta = "\n".join(f"- {llano[c]}: {cuenta[c]} punto(s)" for c, _ in GRUPOS_PENDIENTES if c in cuenta) \
        or "- Nada pendiente."
    hacer = seccion_que_hacer(rm, hallazgos, siguiente, maximo=5, por_que=(redaccion or {}).get("por_que_importa"),
                              excluir=excluir)
    # R10: el texto del redactor (si validó) va debajo de la portada; nunca reemplaza el estado ni los números.
    texto_redactor = f"{resumen}\n\n" if redaccion else ""
    return {"resumen": resumen, "nota_redactor": nota, "que_hizo_dueno": hizo, "que_falta_dueno": falta,
            "que_hacer_dueno": hacer, "texto_redactor": texto_redactor}


def _lit(t):
    """Texto escrito por una persona en el repo auditado: literal Markdown (sin HTML, enlaces ni tablas rotas)."""
    return utiles.md_literal(utiles.una_linea(str(t or ""))).replace("|", "\\|")


def descartes_humanos_ruta(r):
    """Hoja de ruta: controles que salen del plan porque una persona verificó el falso positivo (H-2)."""
    if not r or not (r.get("aplicadas") or r.get("ignoradas") or r.get("huerfanas")):
        return ("Ninguno. Una persona puede registrar un falso positivo verificado en un JSON (por ejemplo "
                "`.auditor-integral/fp-verificados.json`, formato en la sección 6c del informe); se aplica solo si el "
                "operador corre la auditoría con `--fp-verificados RUTA`.")
    lineas = [f"- {_lit(a.get('control'))}: {ETIQUETA_FP_HUMANO} ({_lit(a.get('quien'))}, {_lit(a.get('fecha'))})"
              f" en {_lit(', '.join(a.get('ubicaciones') or [])) or 'sin archivo'}: {_lit(a.get('conclusion'))}. "
              "No es pass: deja de bloquear el nivel." for a in r.get("aplicadas") or []]
    n_av = len(r.get("ignoradas") or []) + len(r.get("huerfanas") or [])
    if n_av:
        lineas.append(f"- {n_av} entrada(s) del archivo no se aplicaron (incompletas, inválidas o huérfanas): ver la "
                      "sección 6c del informe.")
    return "\n".join(lineas)


def descartes_humanos_dueno(r):
    """Resumen del dueño: una línea en lenguaje llano (H-2)."""
    aplicadas = (r or {}).get("aplicadas") or []
    n_av = len((r or {}).get("ignoradas") or []) + len((r or {}).get("huerfanas") or [])
    if not aplicadas and not n_av:
        return "ninguna."
    texto = (f"{len(aplicadas)} alarma(s) que una persona revisó y registró como falsa(s) ("
             + "; ".join(f"{_lit(a.get('control'))}: {_lit(a.get('quien'))}, {_lit(a.get('fecha'))}"
                         for a in aplicadas[:5])
             + ("; …" if len(aplicadas) > 5 else "") + "). No cuentan como aprobadas; solo dejan de frenar el nivel."
             if aplicadas else "ninguna aplicada.")
    if n_av:
        texto += f" {n_av} registro(s) no se aplicaron (incompletos o ya no coinciden): ver el informe, sección 6c."
    return texto


# ------------------------------------------------------------------------------------------------------------------
# R10: portada para la persona dueña («primero el dueño»). Solo reordena y traduce datos que ya existen en gates.json,
# estado.json, hallazgos.jsonl, score.json, normalizacion.json y roadmap.json: no cambia el estado, el nivel, los
# bloqueos ni listo_datos_reales. Es plantilla (sin IA). Nunca imprime `evidencia`: solo archivo:línea.
# ------------------------------------------------------------------------------------------------------------------
from checks import comun as _checks_comun  # noqa: E402  (criterio único de «código de test»)

ESTADO_ARREGLAR, ESTADO_CONFIRMAR, ESTADO_AMBAR, ESTADO_GRIS = "arreglar", "confirmar", "ambar", "gris"
# R10c: carpeta sin código reconocible y sin bloqueos (color gris): no se habla como si hubiera una app revisada.
ESTADO_SIN_CODIGO = "sin_codigo"
ETIQUETA_SIN_CODIGO = "NO HAY CÓDIGO QUE AUDITAR"
ETIQUETA_ARREGLAR = "HAY QUE ARREGLAR YA"
ETIQUETA_CONFIRMAR = "HAY QUE CONFIRMAR HOY (posible falsa alarma)"
ETIQUETA_GRIS = "NO PUDIMOS REVISAR LO ESENCIAL"
ETIQUETA_NIVEL = "SIN BLOQUEOS Y NIVEL {nd} DEMOSTRADO"
ETIQUETA_PARCIAL = "SIN BLOQUEOS ENCONTRADOS, REVISIÓN PARCIAL"
VARIANTES_PORTADA = ("informe", "dueno", "hoja")
PRUEBA_FIRME, PRUEBA_POR_CONFIRMAR, PRUEBA_POR_CONFIRMAR_IA = "firme", "por_confirmar", "por_confirmar_ia"
RAZON_PRUEBA = {
    PRUEBA_POR_CONFIRMAR: "aparece solo en archivos de prueba y el detector no está seguro",
    PRUEBA_POR_CONFIRMAR_IA: "la IA cree que puede ser falsa alarma; no se descarta hasta que lo mire una persona"}
# R10b: en CONFIRMAR la única acción de cada bloqueo es confirmarlo (la regla «si es real, cámbiala hoy» va en
# «Cómo confirmarlo»). R10c: en ARREGLAR un bloqueo por confirmar se confirma primero y, si es real, se arregla
# (ACCION_CONFIRMAR_ARREGLAR), con el mismo bloque «Cómo confirmarlo».
ACCION_CONFIRMAR = "Confírmalo hoy"
ACCION_CONFIRMAR_ARREGLAR = "Confirma hoy si es real ({razon}); si lo es, {accion}"
# R10b: estados de normalizacion.json que significan «la herramienta no corrió» (para avisar en P1 y en GRIS).
HERR_NO_CORRIO = ("ausente", "timeout", "error")
HERR_P1 = ("gitleaks", "semgrep")   # herramientas cuya ausencia se avisa en P1 de ARREGLAR/CONFIRMAR
TEXTO_SIN_CODIGO = "No encontramos código que auditar: revisa que la carpeta sea la correcta"
# Palabras que la portada (y el texto del redactor-dueno) no puede usar: sugieren aprobación sin evidencia o son jerga.
PALABRAS_PROHIBIDAS = ("seguro", "segura", "aprobado", "limpio", "sin problemas", "está bien", "verificado", "OK",
                       "verde", "pass", "fail", "no_evaluado", "gate", "control")
# Excepciones exactas (frases fijas de la plantilla que niegan o acotan; «no está seguro» habla del detector).
FRASES_PERMITIDAS = ("Esto NO significa que la app sea segura", "no certifica seguridad",
                     "no significa que esté bien", "el detector no está seguro")
VERBOS_ACCION_DUENO = ("Cambia", "Saca", "Quita", "Protege", "Agrega", "Crea", "Revisa", "Reemplaza", "Elimina",
                       "Responde", "Permite", "Corre", "Confírmalo", "Confirma")
ACCION_SIN_TEXTO = "Ver el detalle en el informe técnico."
TITULO_SIN_TEXTO = "Un punto del informe técnico"
_RE_EMOJI = re.compile("[☀-➿⬀-⯿️\U0001F000-\U0001FAFF]")
_RE_CODIGO_MD = re.compile(r"`[^`\n]*`")
_RE_CODIGO_CONTROL = re.compile(r"\b(?:SEG|DAT|COD|UX|INF|ESC|OPS)-[A-Z0-9]")
# un `código` que es exactamente un id de control (p. ej. `SEG-SECRETO-REPO`) sigue contando como código de control;
# cualquier otro `código` (rutas como `data/DAT-2024-pacientes.csv`) se quita antes de buscar (R10b, defecto 1).
_RE_ID_CONTROL = re.compile(r"(?:SEG|DAT|COD|UX|INF|ESC|OPS)(?:-[A-Z0-9]+)+")
_REMEDIACION_GENERICA = ("Cumplir «", "Corregir el incumplimiento")
NOMBRE_SEVERIDAD = (("critica", "Crítica"), ("alta", "Alta"), ("media", "Media"), ("baja", "Baja"),
                    ("info", "Informativa"))
NOMBRE_MODO = {"rapido": "rápido", "estandar": "estándar", "profundo": "profundo"}
CATS_NO_DEMOSTRABLE_N = ("levantar_app", "juicio_ia", "verificacion_humana", "entrevista")
# MOTIVO_LLANO: (clave, singular, plural) de por qué un punto grave quedó sin revisar; el orden es el de desempate.
MOTIVOS_LLANOS = (
    ("sin_red", "sin internet", "sin internet"),
    ("fp_ia", "con una alarma de la que la IA dudó (debe mirarla una persona)",
     "con alarmas de las que la IA dudó (debe mirarlas una persona)"),
    ("juicio_ia", "necesita revisión con IA", "necesitan revisión con IA"),
    ("levantar_app", "necesita la app funcionando", "necesitan la app funcionando"),
    ("base_datos", "necesita acceso a la base de datos", "necesitan acceso a la base de datos"),
    ("instalar", "necesita una herramienta que falta en este equipo",
     "necesitan una herramienta que falta en este equipo"),
    ("reintentar", "quedó así porque una herramienta no terminó a tiempo o falló: repite la auditoría",
     "quedaron así porque una herramienta no terminó a tiempo o falló: repite la auditoría"),
    ("no_demostrable", "no se puede demostrar mirando el código", "no se pueden demostrar mirando el código"),
    ("entrevista", "necesita tus respuestas sobre la app", "necesitan tus respuestas sobre la app"),
    ("persona", "debe revisarlo una persona", "debe revisarlos una persona"),
    ("evidencia", "se revisó pero la herramienta no dejó la prueba que se pide para darlo por bueno",
     "se revisaron pero las herramientas no dejaron la prueba que se pide para darlos por buenos"),
)
HERR_BASE_DATOS = ("splinter", "esquema_resumen")
LLANO_PENDIENTE = {"instalar": "instalar herramientas que faltan", "entrevista": "responder preguntas sobre la app",
                   "levantar_app": "auditar con la app en marcha", "fp_ia": "que una persona mire alarmas que la IA dudó",
                   "verificacion_humana": "la revisión de una persona", "juicio_ia": "la revisión asistida por IA",
                   "modo": "una auditoría más completa",
                   "reintentar": "repetir la auditoría, porque una herramienta no terminó a tiempo o falló",
                   "evidencia": "más pruebas de las que hoy hay"}


class PortadaInvalida(ValueError):
    """La portada no cumple sus reglas (palabras prohibidas, códigos en la variante dueno, línea P4.b ausente)."""


def plural(n, singular, plural_):
    return singular if n == 1 else plural_


def _minuscula(t):
    return t[:1].lower() + t[1:] if t and not t.startswith("`") and not t[:2].isupper() else t


def _sin_punto(t):
    return (t or "").rstrip().rstrip(".")


def palabras_prohibidas(texto):
    """Palabras prohibidas presentes en `texto` (fuera de `código` y de las frases permitidas), más «emoji»."""
    t = _RE_CODIGO_MD.sub(" ", texto or "")
    for f in FRASES_PERMITIDAS:
        t = t.replace(f, " ")
    hallado = [p for p in PALABRAS_PROHIBIDAS
               if re.search(r"(?<![\w-])" + re.escape(p) + r"(?![\w-])", t, re.IGNORECASE)]
    if _RE_EMOJI.search(t):
        hallado.append("emoji")
    return hallado


def _texto_apto(texto, defecto):
    texto = utiles.una_linea(texto or "").strip()
    return texto if texto and not palabras_prohibidas(texto) else defecto


def titulo_dueno(cid, indice):
    c = indice.get(cid) or {}
    return _sin_punto(_texto_apto(c.get("titulo_dueno") or c.get("titulo"), TITULO_SIN_TEXTO))


# R10c: controles cuyo titulo_dueno del catálogo cubre varios casos; la subregla del hallazgo (fuente[].regla, la que
# escribió el check) dice cuál ocurrió. Se usan el título y la acción de cada caso presente (unidos con «y» /
# «Además,», en el orden de este diccionario: lo más urgente primero); sin ningún caso reconocido, los textos neutrales
# del catálogo.
TITULOS_POR_REGLA = {
    "check:archivos_clave.env_comiteado": (
        "El archivo `.env` con valores reales está guardado en el repositorio",
        "Saca `.env` del repositorio, agrégalo a `.gitignore` y cambia las claves que tenía: quedaron en el historial."),
    "check:archivos_clave.env_no_ignorado": (
        "El archivo `.env` con valores reales no está excluido del repositorio",
        "Agrega `.env` a `.gitignore` antes del próximo commit."),
    "check:archivos_clave.env_ejemplo_ausente": (
        "Falta un archivo de ejemplo de configuración (`.env.example`)",
        "Crea `.env.example` con los nombres de las variables y valores inventados."),
}


def titulo_accion_por_caso(cid, hs, indice, remediaciones=None):
    """(título, acción) del dueño para un control con sus hallazgos `hs`: los casos concretos que traen los hallazgos
    (subreglas de TITULOS_POR_REGLA); sin ninguno, los textos del catálogo."""
    reglas = {str((f or {}).get("regla") or "") for h in hs or [] if h.get("control") in (None, cid)
              for f in h.get("fuente") or []}
    casos = [TITULOS_POR_REGLA[r] for r in TITULOS_POR_REGLA if r in reglas]
    if not casos:
        return titulo_dueno(cid, indice), accion_dueno(cid, indice, remediaciones)
    titulo = casos[0][0] + "".join(f" y {_minuscula(t)}" for t, _ in casos[1:])
    accion = casos[0][1] + "".join(f" Además, {_minuscula(a)}" for _, a in casos[1:])
    return _sin_punto(_texto_apto(titulo, TITULO_SIN_TEXTO)), _texto_apto(accion, ACCION_SIN_TEXTO)


def accion_dueno(cid, indice, remediaciones=None):
    """accion_dueno del catálogo; si falta, la primera frase de la remediación; con la genérica, el informe técnico."""
    c = indice.get(cid) or {}
    if c.get("accion_dueno"):
        return _texto_apto(c["accion_dueno"], ACCION_SIN_TEXTO)
    rem = utiles.una_linea((remediaciones or {}).get(cid) or "").strip()
    if not rem or rem.startswith(_REMEDIACION_GENERICA):
        return ACCION_SIN_TEXTO
    primera = re.split(r"(?<=[.:;])\s", rem, maxsplit=1)[0].rstrip(".:;") + "."
    return _texto_apto(primera, ACCION_SIN_TEXTO)


def _remediaciones_catalogo():
    try:
        return (utiles.leer_toml(utiles.RAIZ / "plantillas" / "remediaciones.toml") or {}).get("remediacion") or {}
    except OSError:
        return {}


def motivo_llano(e, indice):
    """Clave de MOTIVOS_LLANOS de un control sin revisar (la primera regla que se cumple)."""
    motivo = e.get("motivo") or ""
    cat, det = clasificar_pendiente(e, indice, {})
    if "AUDITOR_SIN_RED" in motivo or "sin red" in motivo:
        return "sin_red"
    if roadmap_mod.es_motivo_fp_ia(motivo):
        return "fp_ia"
    if "juicio LLM" in motivo or cat == "juicio_ia":
        return "juicio_ia"
    if cat == "levantar_app":
        return "levantar_app"
    if cat == "reintentar":   # R10b: timeout o fallo de una herramienta instalada; antes que no_demostrable/evidencia
        return "reintentar"
    if cat == "instalar" and any(h in HERR_BASE_DATOS for h in det or []):
        return "base_datos"
    if cat == "instalar":
        return "instalar"
    if (indice.get(e["control"]) or {}).get("evidencia_pass") == "no_demostrable_estatico":
        return "no_demostrable"
    if cat == "entrevista":
        return "entrevista"
    if e.get("estado") == "manual_pendiente":
        return "persona"
    return "evidencia"


def _conteo_motivos(claves):
    cuenta = {}
    for k in claves:
        cuenta[k] = cuenta.get(k, 0) + 1
    orden = [m[0] for m in MOTIVOS_LLANOS]
    return sorted(cuenta.items(), key=lambda kv: (-kv[1], orden.index(kv[0]) if kv[0] in orden else 99))


def _texto_motivos(conteo):
    textos = {k: (s, p) for k, s, p in MOTIVOS_LLANOS}
    return ", ".join(f"{n} {plural(n, *textos[k])}" for k, n in conteo)


def prueba_bloqueo(b, hs):
    """ESTIMACIÓN de si un bloqueo puede ser falsa alarma. Nunca cambia conteos, estado, nivel ni listo."""
    if b.get("pendiente_ia"):
        return PRUEBA_POR_CONFIRMAR_IA
    archivos = [(h.get("ubicacion") or {}).get("archivo") for h in hs]
    if (hs and not any(h.get("confianza") == "alta" for h in hs) and all(archivos)
            and all(_checks_comun.es_test(a) for a in archivos)):
        return PRUEBA_POR_CONFIRMAR
    return PRUEBA_FIRME


def _regla_generica(hs):
    return any(str((f or {}).get("regla") or "").startswith("generic") for h in hs for f in h.get("fuente") or [])


def _lugar_h(h):
    u = h.get("ubicacion") or {}
    if not u.get("archivo"):
        return None
    return u["archivo"] + (f":{u['linea']}" if u.get("linea") is not None else "")


def _clave_lugar(h):
    u = h.get("ubicacion") or {}
    linea = u.get("linea") if isinstance(u.get("linea"), int) else 10 ** 9
    return (u.get("archivo") is None, u.get("archivo") or "", linea)


def sin_codigo(perfil_tecnico):
    """True si detectar_stack (perfil_tecnico.json) no reconoció nada que auditar: sin lenguajes, frameworks,
    ecosistemas, Docker, IaC, Kubernetes ni CI, y sin truncar el recorrido. Sin perfil_tecnico → False (no se
    afirma nada que la corrida no registró)."""
    p = perfil_tecnico if isinstance(perfil_tecnico, dict) else None
    if not p or "lenguajes" not in p:
        return False
    if (p.get("limites") or {}).get("truncado"):
        return False
    return not (p.get("lenguajes") or p.get("frameworks") or p.get("ecosistemas")
                or any(p.get(k) for k in ("docker", "iac", "k8s", "ci")))


def datos_portada(g, estados, hallazgos, s, resumen, rm, indice, modo="estandar", corrida_id="s/d",
                  proyecto="proyecto", remediaciones=None, perfil_tecnico=None, herramientas_json=None):
    """Todos los números y textos de la portada, derivados solo de los archivos de la corrida."""
    remediaciones = _remediaciones_catalogo() if remediaciones is None else remediaciones
    vacio = sin_codigo(perfil_tecnico)
    gl = g["global"]
    por_control = {e["control"]: e for e in estados}
    est = {e["control"]: e.get("estado") for e in estados}
    aplicables = [e for e in estados if e.get("estado") != "no_aplica"]
    revisados = [e for e in aplicables if e.get("estado") in ("pass", "fail")]
    sin_revisar = [e for e in aplicables if e.get("estado") in ("no_evaluado", "manual_pendiente")]
    cob_s = ((s or {}).get("global") or {}).get("cobertura")
    cob = round(len(revisados) / len(aplicables), 3) if aplicables else 0.0
    inv1 = isinstance(cob_s, (int, float)) and not isinstance(cob_s, bool) and cob == cob_s
    inv2 = True
    por_dom = {}
    for e in aplicables:
        c = indice.get(e["control"])
        if c is None or c.get("aviso_legal"):
            continue
        d = por_dom.setdefault(c["dominio"], [0, 0])
        d[0] += 1
        d[1] += e.get("estado") in ("pass", "fail")
    for d, dg in (g.get("dominios") or {}).items():
        niv = (dg or {}).get("niveles") or {}
        tot = [sum(v.get("aplicables", 0) for v in niv.values()), sum(v.get("evaluados", 0) for v in niv.values())]
        if tot != por_dom.pop(d, [0, 0]):
            inv2 = False
    if any(v != [0, 0] for v in por_dom.values()):
        inv2 = False

    # bloqueos: un control por bloqueo, tope más bajo primero y luego el orden de roadmap.json
    pos_rm = {i["control"]: k for k, i in enumerate((rm or {}).get("items") or [])}
    por_id = {h.get("id"): h for h in hallazgos}
    bloqueos, vistos = [], set()
    for k, b in enumerate(gl.get("bloqueos") or []):
        if b["control"] in vistos:
            continue
        vistos.add(b["control"])
        hs = [por_id[i] for i in b.get("hallazgos") or [] if i in por_id] or \
             [h for h in hallazgos if h.get("control") == b["control"]]
        prueba = prueba_bloqueo(b, hs)
        con_archivo = sorted((h for h in hs if _lugar_h(h)), key=_clave_lugar)
        extra = len(con_archivo) - 1 if con_archivo else 0
        archivos_extra = {(h.get("ubicacion") or {}).get("archivo") for h in con_archivo[1:]}
        titulo_b, accion_b = titulo_accion_por_caso(b["control"], hs, indice, remediaciones)
        bloqueos.append({"control": b["control"], "tope": b.get("tope"), "orden": (
            utiles.num_nivel(b.get("tope") or "N5"), pos_rm.get(b["control"], 10 ** 6), k),
            "tipos": b.get("tipos") or [b.get("tipo")], "prueba": prueba, "generica": _regla_generica(hs),
            "lugar": _lugar_h(con_archivo[0]) if con_archivo else None, "extra": extra,
            "extra_archivo": archivos_extra.pop() if extra and len(archivos_extra) == 1 else None,
            "titulo": titulo_b, "accion": accion_b})
    bloqueos.sort(key=lambda b: b["orden"])
    en_bloqueo = {b["control"] for b in bloqueos}

    # puntos graves («que pueden frenar el uso»)
    graves = []
    for e in estados:
        c = indice.get(e["control"]) or {}
        if c.get("aviso_legal") or e.get("estado") == "no_aplica":
            continue
        if (c.get("bloquea_global") or e["control"] in gates_mod.CONTROLES_SECRETO or e["control"] in en_bloqueo
                or (c.get("dominio") in gates_mod.DOMINIOS_BLOQUEO_CRITICO and c.get("severidad_base") == "critica")):
            graves.append(e)
    g_problema = [e for e in graves if e["control"] in en_bloqueo or e.get("estado") == "fail"]
    g_comprobados = [e for e in graves if e.get("estado") == "pass" and e["control"] not in en_bloqueo]
    g_sin_revisar = [e for e in graves if e["control"] not in en_bloqueo
                     and e.get("estado") in ("no_evaluado", "manual_pendiente")]
    motivos_graves = {e["control"]: motivo_llano(e, indice) for e in g_sin_revisar}
    herr_reintentar = sorted({x for e in g_sin_revisar if motivos_graves[e["control"]] == "reintentar"
                              for x in (clasificar_pendiente(e, indice, {})[1] or [])})

    # temas (un tema = un control con hallazgos abiertos; aviso = cada hallazgo)
    temas, hs_abiertos = {}, {}
    for h in hallazgos:
        if h.get("estado_hallazgo", "abierto") != "abierto":
            continue
        hs_abiertos.setdefault(h["control"], []).append(h)
        t = temas.setdefault(h["control"], {"control": h["control"], "sev": "info", "avisos": 0, "en_prueba": 0})
        if utiles.rango_severidad(h.get("severidad")) < utiles.rango_severidad(t["sev"]):
            t["sev"] = h.get("severidad")
        t["avisos"] += 1
        archivo = (h.get("ubicacion") or {}).get("archivo")
        t["en_prueba"] += bool(archivo and _checks_comun.es_test(archivo))
    n_fail = sum(1 for e in estados if e.get("estado") == "fail")
    inv_temas = len(temas) == n_fail
    filas = {sev: [sum(1 for t in temas.values() if t["sev"] == sev),
                   sum(t["avisos"] for t in temas.values() if t["sev"] == sev)] for sev, _ in NOMBRE_SEVERIDAD}
    otros = sorted((t for t in temas.values() if t["control"] not in en_bloqueo),
                   key=lambda t: (utiles.rango_severidad(t["sev"]),
                                  utiles.num_nivel((indice.get(t["control"]) or {}).get("gate") or "N5"),
                                  -t["avisos"], t["control"]))
    for t in otros:
        t["titulo"], t["accion"] = titulo_accion_por_caso(t["control"], hs_abiertos.get(t["control"]), indice,
                                                          remediaciones)

    # nivel siguiente (P5)
    nd = gl["nivel_demostrado"]
    sig = utiles.NIVELES[utiles.num_nivel(nd) + 1] if utiles.num_nivel(nd) < 5 else None
    n_sig = None
    if sig:
        niv = [((dg or {}).get("niveles") or {}).get(sig) or {} for dg in (g.get("dominios") or {}).values()]
        pend = sorted({c for v in niv for c in v.get("pendientes") or []})
        fallidos = sorted({c for v in niv for c in v.get("fallidos") or []})
        ne = [c for c in pend if (indice.get(c) or {}).get("evidencia_pass") == "no_demostrable_estatico"
              or (c in por_control and clasificar_pendiente(por_control[c], indice, {})[0] in CATS_NO_DEMOSTRABLE_N)]
        n_sig = {"nivel": sig, "aplicables": sum(v.get("aplicables", 0) for v in niv),
                 "evaluados": sum(v.get("evaluados", 0) for v in niv), "fallidos": fallidos, "pendientes": pend,
                 "no_demostrables": ne}

    herr = (resumen or {}).get("herramientas") or {}
    # R10c: herramientas que faltan en este equipo (doctor: herramientas.json; o «ausente» en normalizacion.json)
    doctor = (herramientas_json or {}).get("herramientas") or {}
    ausentes = {k for k, v in doctor.items() if isinstance(v, dict) and (v.get("estado") == "ausente"
                                                                       or v.get("disponible") is False)}
    ausentes |= {k for k, v in herr.items() if (v or {}).get("estado") == "ausente"}
    herr_instalar = sorted({x for e in g_sin_revisar if motivos_graves[e["control"]] == "instalar"
                            for x in (clasificar_pendiente(e, indice, {})[1] or [])} & ausentes)
    gitleaks_estado = (herr.get("gitleaks") or {}).get("estado")
    gitleaks_ok = gitleaks_estado in ESTADOS_CORRIO
    herr_no_corrio = [k for k in HERR_P1 if (herr.get(k) or {}).get("estado") in HERR_NO_CORRIO]
    sin_red = (any("AUDITOR_SIN_RED" in (e.get("motivo") or "") for e in estados)
               or any((v or {}).get("estado") == "sin_red" for v in herr.values()))

    # estado (una sola regla)
    faltas_gris = []
    if bloqueos:
        estado = ESTADO_ARREGLAR if any(b["prueba"] == PRUEBA_FIRME for b in bloqueos) else ESTADO_CONFIRMAR
    else:
        if not gitleaks_ok:
            faltas_gris.append("gitleaks")
        if est.get("SEG-SECRETO-REPO") not in ("pass", "fail"):
            faltas_gris.append("secreto")
        if len(g_comprobados) + len(g_problema) == 0:
            faltas_gris.append("graves")
        # R10c: sin código y sin bloqueos el estado es propio (nunca «revisión parcial» de una app que no hay)
        estado = ESTADO_SIN_CODIGO if vacio else ESTADO_GRIS if faltas_gris else ESTADO_AMBAR
    if estado == ESTADO_ARREGLAR:
        # R10c: «Empieza por el 1» y «Lo primero» apuntan al mismo bloqueo: los firmes primero (solo reordena)
        bloqueos.sort(key=lambda b: (b["prueba"] != PRUEBA_FIRME, b["orden"]))
    if estado == ESTADO_SIN_CODIGO:
        etiqueta = ETIQUETA_SIN_CODIGO
    elif estado == ESTADO_ARREGLAR:
        etiqueta = ETIQUETA_ARREGLAR
    elif estado == ESTADO_CONFIRMAR:
        etiqueta = ETIQUETA_CONFIRMAR
    elif estado == ESTADO_GRIS:
        etiqueta = ETIQUETA_GRIS
    elif utiles.num_nivel(nd) >= 1:
        etiqueta = ETIQUETA_NIVEL.format(nd=nd)
    else:
        etiqueta = ETIQUETA_PARCIAL

    pend_todos = _pendientes(estados)
    cuenta_pend = _conteo_pendientes(pend_todos, indice)
    orden_cat = [c for c, _ in GRUPOS_PENDIENTES]
    ampliar = sorted(cuenta_pend.items(), key=lambda kv: (-kv[1], orden_cat.index(kv[0]) if kv[0] in orden_cat
                                                          else 99))[:3]
    herr_pend = {x for e in pend_todos if clasificar_pendiente(e, indice, {})[0] == "instalar"
                 for x in (clasificar_pendiente(e, indice, {})[1] or [])}
    return {
        "proyecto": proyecto, "corrida": corrida_id, "modo": modo, "sin_red": sin_red, "estado": estado,
        "etiqueta": etiqueta, "faltas_gris": faltas_gris, "nivel_demostrado": nd, "nivel_siguiente": n_sig,
        "gitleaks_estado": gitleaks_estado, "herr_no_corrio": herr_no_corrio, "herr_reintentar": herr_reintentar,
        "sin_codigo": vacio, "herr_instalar": herr_instalar,
        "ampliar_ausentes": sorted(herr_pend & ausentes), "ampliar_otras": bool(herr_pend - ausentes),
        "hito_siguiente": f"{sig} ({gates_mod.HITOS[sig]})" if sig else None,
        "listo": gl.get("listo_datos_reales"), "bloqueos": bloqueos,
        "revisados": len(revisados), "aplicables": len(aplicables), "cobertura": cob,
        "invariantes_ok": inv1 and inv2, "invariante_temas": inv_temas,
        "n_avisos_legales": len(gl.get("avisos_legales") or []),
        "n_descartes": len(gl.get("descartes_humanos") or []),
        "graves_aplican": len(graves), "graves_con_problema": len(g_problema),
        "graves_comprobados": len(g_comprobados), "graves_sin_revisar": len(g_sin_revisar),
        "motivos_graves": motivos_graves, "filas_temas": filas, "otros_temas": otros, "n_fail": n_fail,
        "ampliar": ampliar, "titulos": {cid: titulo_dueno(cid, indice) for cid in motivos_graves},
        "titulos_fallidos": [titulo_accion_por_caso(c, hs_abiertos.get(c), indice, remediaciones)[0]
                             for c in (n_sig or {}).get("fallidos", [])],
    }


def _linea_bloqueo(n, b, variante, confirmar=False):
    codigo = f" (`{b['control']}`)" if variante == "informe" else ""
    lugar = ""
    if b["lugar"]:
        lugar = f": {_codigo(b['lugar'])}"
        if b["extra"]:
            donde = f" en {_codigo(b['extra_archivo'])}" if b["extra_archivo"] else ""
            lugar += f" (y {b['extra']} {plural(b['extra'], 'lugar', 'lugares')} más{donde})"
    generica = (" (regla genérica del detector)" if variante == "informe" and b["generica"] else "")
    if b["prueba"] == PRUEBA_FIRME:
        accion = _celda(b["accion"])
    elif confirmar:
        # R10b: en CONFIRMAR la única acción es confirmar; «si es real, cámbiala hoy» va en «Cómo confirmarlo»
        accion = f"{ACCION_CONFIRMAR} ({RAZON_PRUEBA[b['prueba']]})."
    else:
        # R10c: en ARREGLAR, un bloqueo por confirmar no se ordena arreglar sin más: primero se confirma
        accion = ACCION_CONFIRMAR_ARREGLAR.format(razon=RAZON_PRUEBA[b["prueba"]],
                                                  accion=_minuscula(_celda(b["accion"])))
    return f"{n}. **{_celda(b['titulo'])}**{codigo}{lugar} — {accion}{generica}"


def _lista_y(items, maximo=4):
    items = list(items)
    if len(items) > maximo:
        items = items[:maximo] + [f"{len(items) - maximo} más"]
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " y " + items[-1]


def _se_revisan(n, cuales="de esos puntos"):
    return f"así se {plural(n, 'revisa', 'revisan')} {n} {cuales}"


def _lineas_ambar(d, variante="informe"):
    """P2 en ÁMBAR: una línea por grupo de MOTIVO_LLANO de los graves sin revisar (de mayor a menor). R10c: el verbo
    es para el dueño y la línea dice qué se gana («así se revisan N»)."""
    conteo = _conteo_motivos(d["motivos_graves"].values())
    informe = variante == "informe"
    lineas = []
    for k, (motivo, n) in enumerate(conteo, 1):
        titulos = "; ".join(f"«{_celda(d['titulos'][c])}»" for c, m in sorted(d["motivos_graves"].items())
                            if m == motivo)
        reint = d.get("herr_reintentar") or []
        inst = d.get("herr_instalar") or []
        texto = {
            "sin_red": ("**Vuelve a correr la auditoría con internet** ("
                        + ("quien te ayuda con la parte técnica: sin la opción `--sin-red`" if informe
                           else "pídeselo a quien te ayuda con la parte técnica")
                        + f"): {_se_revisan(n)}."),
            "juicio_ia": (f"**Vuelve a correr la auditoría con revisión asistida por IA**: {_se_revisan(n)}. Lo que "
                          "diga la IA lo confirma una persona."),
            "no_demostrable": (f"**Pide a quien te ayuda que confirme a mano** que no "
                               f"{plural(n, 'pase esto', 'pasen estas cosas')}: {titulos}. Leyendo el código no se "
                               "puede demostrar."),
            "reintentar": (f"**Repite la auditoría, con más tiempo si hace falta**: {_se_revisan(n)}. "
                           + plural(len(reint) or 1, "Una herramienta del auditor no terminó a tiempo o falló",
                                    "Algunas herramientas del auditor no terminaron a tiempo o fallaron")
                           + (f" ({', '.join(reint)})." if informe and reint else ".")),
            "base_datos": (f"**Da acceso de solo lectura a la base de datos en la próxima auditoría**: "
                           f"{_se_revisan(n)}."),
            "levantar_app": f"**Pide que la próxima auditoría se haga con la app en marcha**: {_se_revisan(n)}.",
            "instalar": ((f"**Pide a quien te ayuda que instale {_lista_y(inst)}**" if inst else
                          "**Pide a quien te ayuda que habilite las herramientas que esta vez no corrieron**")
                         + (" (`bin/auditar doctor` muestra cuáles faltan)" if informe else "")
                         + f": {_se_revisan(n)}."),
            "fp_ia": f"**Pide que una persona mire las alarmas de las que la IA dudó**: {_se_revisan(n)}.",
            "entrevista": f"**Responde las preguntas sobre tu app**: {_se_revisan(n)}.",
            # R10d: concordancia con un solo punto («de este punto»)
            "persona": f"**Pide que una persona revise {plural(n, 'este punto', 'estos puntos')}**: {titulos}.",
            "evidencia": f"**Pide una revisión a mano de {plural(n, 'este punto', 'estos puntos')}**: {titulos}.",
        }[motivo]
        lineas.append(f"{k}. {texto}")
    return lineas


def _llano_ampliar(cat, d):
    """Texto de «Lo que más ampliaría la revisión» para una categoría. R10c: «instalar» solo nombra herramientas que de
    verdad faltan en este equipo (doctor o normalizacion.json); sin ninguna ausente no se pide instalar."""
    if cat != "instalar":
        return LLANO_PENDIENTE.get(cat, cat)
    aus, otras = d.get("ampliar_ausentes") or [], d.get("ampliar_otras")
    if aus:
        return f"instalar {_lista_y(aus)}" + (", y habilitar otras herramientas que esta vez no corrieron"
                                              if otras else "")
    return "habilitar herramientas que esta vez no corrieron"


def _texto_gris(d):
    que = {"gitleaks": "no se pudo usar la herramienta que busca claves secretas",
           "secreto": "la búsqueda de claves secretas en el proyecto no terminó",
           "graves": "ninguno de los puntos que pueden frenar el uso quedó revisado"}
    # R10c: si gitleaks no corrió, que la búsqueda de claves no terminara es la misma causa (no se repite)
    faltas = [f for f in d["faltas_gris"] if not (f == "secreto" and "gitleaks" in d["faltas_gris"])]
    return "; ".join(que[f] for f in faltas)


def _accion_gris(d):
    """Lo que sigue a «vuelve a correr la auditoría» en GRIS."""
    if "gitleaks" in d["faltas_gris"]:
        # R10b: solo se pide instalar si falta; si está instalada y no terminó a tiempo o falló, se repite
        if d.get("gitleaks_estado") in ("timeout", "error"):
            return "con más tiempo (gitleaks está instalada, pero no terminó a tiempo o falló)"
        return "después de instalar gitleaks (`brew install gitleaks`)"
    return "después de revisar el detalle técnico"


def _codigos_de_control(cuerpo):
    """Texto donde buscar códigos de control: fuera de `código`, más los `código` que son exactamente un id de control
    (una ruta como `data/DAT-2024-pacientes.csv` no es un código de control)."""
    ids = [m.group(0)[1:-1] for m in _RE_CODIGO_MD.finditer(cuerpo) if _RE_ID_CONTROL.fullmatch(m.group(0)[1:-1])]
    return _RE_CODIGO_MD.sub(" ", cuerpo) + "\n" + " ".join(ids)


def validar_portada(texto, estado, variante, proyecto=None):
    """Lanza PortadaInvalida si la portada rompe sus reglas (fail-closed: mejor un error que un texto engañoso)."""
    # el nombre del proyecto (dato del dueño) solo aparece en el título: se excluye de la revisión de palabras
    cuerpo = "\n".join(" " if l.startswith("## Portada — ") else l for l in texto.splitlines())
    prohibidas = palabras_prohibidas(cuerpo)
    if prohibidas:
        raise PortadaInvalida(f"palabras prohibidas en la portada ({variante}): {', '.join(prohibidas)}")
    if variante in ("dueno", "hoja") and _RE_CODIGO_CONTROL.search(_codigos_de_control(cuerpo)):
        raise PortadaInvalida(f"la variante {variante} no puede llevar códigos de control")
    if (variante != "hoja" and estado == ESTADO_AMBAR
            and not any(l.startswith("- Puntos que pueden frenar el uso:") for l in texto.splitlines())):
        raise PortadaInvalida("en ÁMBAR la portada debe decir cuántos puntos graves quedaron sin revisar (P4.b)")
    return texto


# R10d: un solo título para la tabla de gravedades en todos los estados (con bloqueos, la tabla los incluye) y una nota
# cuando la fila «Crítica» es 0 (un 0 no dice nada de lo que no se pudo revisar).
TITULO_TABLA_PROBLEMAS = "### Problemas encontrados, por gravedad"
NOTA_SIN_CRITICOS = "Ninguno de gravedad crítica en lo revisado."
# R10d: en NO HAY CÓDIGO QUE AUDITAR solo se listan hallazgos reales de claves o datos personales
CONTROLES_SECRETO_PII = tuple(gates_mod.CONTROLES_SECRETO) + ("DAT-PII-REPO", "DAT-PII-TEST")


def _lineas_temas(temas, variante):
    lineas = []
    for t in temas:
        prueba = f", {t['en_prueba']} en archivos de prueba" if t["en_prueba"] else ""
        codigo = f" (`{t['control']}`)" if variante == "informe" else ""
        lineas.append(f"- **{_celda(t['titulo'])}**{codigo} ({t['avisos']} "
                      f"{plural(t['avisos'], 'aviso', 'avisos')}{prueba}) — {_celda(t['accion'])}")
    return lineas


def _probados(e1, f1):
    """«se probaron N y …» del nivel siguiente, con concordancia (R10d: con 0 fallidos no se dice «fallaron 0»)."""
    if e1 == 0:
        return "todavía no se probó ninguno"
    if f1 == 0:
        return "se probó 1 y salió bien" if e1 == 1 else f"se probaron {e1} y todos salieron bien"
    if e1 == 1:
        return "se probó 1 y falló"
    if f1 == e1:
        return f"se probaron {e1} y los {e1} fallaron"
    return f"se probaron {e1} y {plural(f1, 'falló', 'fallaron')} {f1}"


def _sin_revisar_nivel(p1, ne1):
    """Cuántos de los puntos sin revisar del nivel siguiente no se pueden probar leyendo el código (R10d:
    concordancia; nunca «de los 1» ni «0 no se pueden»)."""
    if p1 == 1:
        return f"el que quedó sin revisar {'no ' if ne1 else ''}se puede probar leyendo el código"
    if ne1 == 0:
        return f"los {p1} sin revisar se pueden probar leyendo el código"
    if ne1 == p1:
        return f"ninguno de los {p1} sin revisar se puede probar leyendo el código"
    return f"de los {p1} sin revisar, {ne1} no {plural(ne1, 'se puede', 'se pueden')} probar leyendo el código"


def _linea_listo(d, estado, nd):
    listo = {"SI": "SÍ"}.get(d["listo"], d["listo"] or "s/d")
    if d["listo"] == "NO":
        motivo = {ESTADO_ARREGLAR: ", por los problemas de arriba, que impiden usar la app.",
                  ESTADO_CONFIRMAR: ", hasta confirmar la alarma.",
                  ESTADO_SIN_CODIGO: ": no se auditó ninguna app."}.get(
            estado, ": no por un bloqueo; falta demostrar "
            + ("lo mínimo." if utiles.num_nivel(nd) < 1 else "el nivel N2."))
    elif d["listo"] == "CONDICIONAL":
        motivo = ": con condiciones (ver «1. Veredicto» en `informe.md`)."
    else:
        motivo = "."
    return f"¿Lista para datos reales de personas? **{listo}**{motivo}"


def _resto_sin_codigo(d, variante, nd):
    """R10d: en NO HAY CÓDIGO QUE AUDITAR, después de P1 y «Qué hacer hoy» no van cifras de cobertura ni la tabla de
    problemas con recomendaciones de app: solo los hallazgos reales de claves o datos personales (si los hay) y una
    línea con el nivel, la respuesta sobre datos reales y el aviso legal."""
    out = []
    reales = [t for t in d["otros_temas"] if t["control"] in CONTROLES_SECRETO_PII]
    if reales:
        out += ["### Lo que sí encontramos en esta carpeta", "", *_lineas_temas(reales, variante), ""]
    linea = (f"Nivel demostrado: **{nd} de N5** (sin código, no dice nada sobre una app). "
             + _linea_listo(d, ESTADO_SIN_CODIGO, nd))
    nl = d["n_avisos_legales"]
    if nl:
        donde = "más abajo" if variante == "informe" else "en `informe.md`"
        linea += (f" Hay {nl} {plural(nl, 'punto legal', 'puntos legales')} que siempre revisa una persona (ver "
                  f"«Aviso legal» {donde}).")
    return out + [linea, ""]


def _intro_ambar(d):
    """Primera frase de «Qué hacer hoy» en ÁMBAR: sin bloqueos, pero sin callar los temas de gravedad alta."""
    if not d["invariante_temas"]:
        return "No hay bloqueos que arreglar hoy."
    crit, alta = d["filas_temas"]["critica"][0], d["filas_temas"]["alta"][0]
    n = crit + alta
    if not n:
        return "No hay bloqueos ni problemas de gravedad alta o crítica que arreglar hoy."
    grav = "alta o crítica" if crit else "alta"
    # R10d: «gravedad …» solo para remitir a la tabla de gravedades (no compite con «impiden usar la app» de P1)
    return (f"No hay bloqueos que arreglar hoy; hay {n} {plural(n, 'problema', 'problemas')} de gravedad {grav} "
            "en la tabla de abajo.")


def render_portada(d, variante="informe"):
    if variante not in VARIANTES_PORTADA:
        raise ValueError(f"variante desconocida: {variante}")
    estado, nd = d["estado"], d["nivel_demostrado"]
    rojo = estado in (ESTADO_ARREGLAR, ESTADO_CONFIRMAR)
    vacio = bool(d.get("sin_codigo"))
    por_confirmar = rojo and any(b["prueba"] != PRUEBA_FIRME for b in d["bloqueos"])
    bl = d["bloqueos"]
    nb = len(bl)
    primero = None
    p2 = []
    if rojo:
        for n, b in enumerate(bl[:5], 1):
            p2.append(_linea_bloqueo(n, b, variante, confirmar=estado == ESTADO_CONFIRMAR))
        if nb > 5:
            resto = "; ".join(_minuscula(_celda(b["titulo"])) for b in bl[5:])
            p2.append(f"\nY {nb - 5} más: {resto}. Lista completa en `hoja-de-ruta.md`.")
        if por_confirmar:   # R10c: también en ARREGLAR cuando hay al menos un bloqueo por confirmar
            if variante == "informe":
                falsa = ("- Si es un valor inventado para pruebas: pide que se registre como falsa alarma "
                         "(`.auditor-integral/fp-verificados.json`, con nombre, fecha y razón) y vuelve a correr con "
                         "`--fp-verificados`.")
            else:
                falsa = ("- Si es un valor inventado para pruebas: pídele a quien te ayuda con la parte técnica que la "
                         "registre como falsa alarma (con nombre, fecha y razón) y vuelve a correr la auditoría.")
            p2 += ["", "**Cómo confirmarlo:**",
                   "- Si es una clave o dato real: **cámbiala en el servicio hoy mismo**, luego sácala del archivo.",
                   falsa]
        if estado == ESTADO_CONFIRMAR:
            primero = (f"confirma hoy si «{_celda(bl[0]['titulo'])}» es real (ver «Cómo confirmarlo» en "
                       "`resumen-dueno.md`)")
        else:
            firme = next(b for b in bl if b["prueba"] == PRUEBA_FIRME)
            # R10e: la cabecera de la hoja va sola: nombra el problema y dónde, no solo la acción
            donde = f" ({_codigo(firme['lugar'])})" if firme["lugar"] else ""
            primero = (f"«{_celda(firme['titulo'])}»{donde}: "
                       f"{_minuscula(_sin_punto(firme['accion']))}")
        if vacio:
            primero += f"; además, {_minuscula(TEXTO_SIN_CODIGO)}"
    elif estado == ESTADO_SIN_CODIGO:
        # R10b (defecto 3): sin código reconocible no se habla como si hubiera una app revisada
        p2 = ["1. **Revisa que la carpeta sea la correcta** y vuelve a correr la auditoría sobre la carpeta que tiene "
              "el código de la app."]
        primero = "revisa que la carpeta sea la correcta (no encontramos código que auditar)"
    elif estado == ESTADO_AMBAR:
        lineas = _lineas_ambar(d, "dueno" if variante == "hoja" else variante)
        intro = _intro_ambar(d)
        if lineas:
            p2 = [f"{intro} Lo primero es ampliar la revisión de los puntos que pueden frenar el uso:", *lineas]
            primero = _minuscula(_sin_punto(re.sub(r"^\d+\. ", "", lineas[0]).replace("**", "")))
            # R10c: fuera de la lista, «de esos puntos» no tiene a qué referirse: se dice de cuáles
            primero = re.sub(r"(?: \([^)]*\))?: (así se \w+ \d+) de esos puntos(?:\..*)?$",
                             lambda m: f" ({m.group(1)} de los {d['graves_sin_revisar']} puntos que pueden frenar el "
                                       "uso y que quedaron sin revisar)", primero)
        else:
            p2 = [f"{intro} Los puntos que pueden frenar el uso que aplican a tu app quedaron revisados; lo siguiente "
                  "es ampliar el resto de la revisión (ver «Qué pudimos revisar»)."]
            primero = "ampliar el resto de la revisión (ver «Qué pudimos revisar»)"
    else:
        p2 = [f"Vuelve a correr la auditoría {_accion_gris(d)}."]
        primero = f"vuelve a correr la auditoría {_accion_gris(d)}"

    if variante == "hoja":
        hito = d["hito_siguiente"] or "ninguno (ya está en el nivel más alto)"
        texto = (f"**Estado: {d['etiqueta']}.** Lo primero: {primero}.\n"
                 f"Nivel demostrado: {nd} (dato secundario; ver «Portada» en `informe.md`). Siguiente hito: {hito}.")
        return validar_portada(texto, estado, variante, d["proyecto"])

    # P1
    if estado == ESTADO_ARREGLAR:
        k = sum(1 for b in bl if b["prueba"] != PRUEBA_FIRME)
        conf = (f" ({plural(k, 'uno', str(k))} hay que {plural(k, 'confirmarlo', 'confirmarlos')} primero)"
                if k else "")
        # R10d: el grupo de bloqueos se nombra «problemas que impiden usar la app» / «bloqueos», nunca «graves»
        # (en P3 «gravedad alta» es otra cosa: la columna de la tabla)
        frase = (f"Encontramos {plural(nb, 'un problema', f'{nb} problemas')} que hay que arreglar antes "
                 f"de usar la app con personas reales{conf}. Empieza por el 1.")
        # R10c: solo con una clave firme (si está por confirmar, lo cubre «Cómo confirmarlo»)
        if any("secreto_vivo" in (b["tipos"] or []) and b["prueba"] == PRUEBA_FIRME for b in bl):
            frase += (" Cambiar una clave en su servicio es más urgente que borrarla del archivo: quien ya la copió "
                      "puede seguir usándola.")
    elif estado == ESTADO_CONFIRMAR:
        frase = (f"Encontramos {plural(nb, 'una alarma que, si es real, impide', f'{nb} alarmas que, si son reales, impiden')}"
                 f" usar la app; {plural(nb, 'podría ser una falsa alarma', 'podrían ser falsas alarmas')}, pero no "
                 f"podemos {plural(nb, 'descartarla sola. Revísala hoy', 'descartarlas solas. Revísalas hoy')}. "
                 f"Mientras nadie {plural(nb, 'la', 'las')} confirme, "
                 f"{plural(nb, 'cuenta como un bloqueo', 'cuentan como bloqueos')}.")
    elif estado == ESTADO_SIN_CODIGO:
        frase = (f"{TEXTO_SIN_CODIGO} (o el código está en un lenguaje que el auditor no reconoce). Sin código no hay "
                 "conclusión posible sobre ninguna app.")
        if d["faltas_gris"]:
            frase += f" Además, {_texto_gris(d)}."
    elif estado == ESTADO_AMBAR:
        frase = ("No encontramos problemas que impidan usar la app en lo que pudimos revisar. **Esto NO significa que "
                 "la app sea "
                 f"segura**: de los {d['graves_aplican']} puntos que pueden frenar el uso, comprobamos "
                 f"{d['graves_comprobados']} y **{d['graves_sin_revisar']} "
                 f"{plural(d['graves_sin_revisar'], 'quedó', 'quedaron')} sin revisar**.")
    else:
        frase = f"No pudimos revisar ni lo más básico ({_texto_gris(d)}). No hay conclusión posible."
    if rojo and vacio:
        frase = f"{TEXTO_SIN_CODIGO}. {frase}"
    if rojo and d.get("herr_no_corrio"):
        frase += f" Además, no pudimos usar {' ni '.join(d['herr_no_corrio'])}: los problemas pueden ser más."
    out = [f"## Portada — {d['proyecto']}", "", f"**Estado: {d['etiqueta']}**", "", frase, "",
           "### Qué hacer hoy", "", *p2, ""]

    if estado == ESTADO_SIN_CODIGO:
        out += _resto_sin_codigo(d, variante, nd)
        modo = NOMBRE_MODO.get(d["modo"], d["modo"])
        out += ["---", f"Corrida `{d['corrida']}` · modo {modo}{' · sin internet' if d['sin_red'] else ''} · generado "
                "por plantilla, sin IA. Este resumen no certifica seguridad. **GUÍA**."]
        return validar_portada("\n".join(out), estado, variante, d["proyecto"])

    # P3 (R10d: un solo título en todos los estados; la tabla incluye los bloqueos de arriba)
    out += [TITULO_TABLA_PROBLEMAS, ""]
    if not d["invariante_temas"]:
        out += ["Sin dato: los archivos de la corrida no cuadran (ver el informe técnico).", ""]
    else:
        out += ["| Gravedad | Temas | Avisos |", "|---|---|---|"]
        for sev, nombre in NOMBRE_SEVERIDAD:
            temas, avisos = d["filas_temas"][sev]
            if sev != "critica" and temas == 0:
                continue
            if sev == "critica" and rojo and temas:
                nombre += " (los de arriba)" if not any(t["sev"] == "critica" for t in d["otros_temas"]) \
                    else " (incluye los de arriba)"
            out.append(f"| {nombre} | {temas} | {avisos} |")
        if d["filas_temas"]["critica"][0] == 0:
            # R10b/R10d: un 0 en «Crítica» no dice que no haya nada crítico en lo que no se revisó
            out += ["", NOTA_SIN_CRITICOS]
        out += ["", "Un «aviso» es cada lugar donde apareció un problema; un mismo tema puede repetirse muchas "
                "veces."]
        if d["otros_temas"]:
            out += ["", f"Los más importantes{' después de los de arriba' if rojo else ''}:"]
            out += _lineas_temas(d["otros_temas"][:3], variante)
        out.append("")

    # P4
    out += ["### Qué pudimos revisar", ""]
    if d["invariantes_ok"]:
        nl = d["n_avisos_legales"]
        # R10c: los avisos legales son parte de los que aplican (el denominador), no de los revisados
        legal = (f" De esos {d['aplicables']}, {nl} {plural(nl, 'es un aviso legal', 'son avisos legales')} que "
                 "siempre revisa una persona." if nl else "")
        out.append(f"- Revisamos **{d['revisados']} de {d['aplicables']}** puntos que aplican a tu app "
                   f"({_pct(d['cobertura'])}).{legal}")
    else:
        out.append("- Cobertura: sin dato (los archivos de la corrida no cuadran; ver informe técnico).")
    conteo = _conteo_motivos(d["motivos_graves"].values())
    detalle = f" ({_texto_motivos(conteo)})" if conteo else ""
    out.append(f"- Puntos que pueden frenar el uso: aplican {d['graves_aplican']}; con problema "
               f"{d['graves_con_problema']}; comprobados sin problema {d['graves_comprobados']}; **sin revisar "
               f"{d['graves_sin_revisar']}**{detalle}.")
    if d["ampliar"]:
        partes = [f"{_llano_ampliar(c, d)} ({n}{' ' + plural(n, 'punto', 'puntos') if k == 0 else ''})"
                  for k, (c, n) in enumerate(d["ampliar"])]
        unidas = partes[0] if len(partes) == 1 else ", ".join(partes[:-1]) + " y " + partes[-1]
        out.append(f"- Lo que más ampliaría la revisión: {unidas}.")
    out.append("- Que algo no se haya revisado no significa que esté bien.")
    if d["n_descartes"]:
        n = d["n_descartes"]
        out.append(f"- {n} {plural(n, 'alarma la marcó', 'alarmas las marcó')} una persona como "
                   f"{plural(n, 'falsa', 'falsas')}; no cuentan como revisadas.")
    out.append("")

    # P5
    out += ["### El nivel (dato secundario)", ""]
    nivel = [f"Nivel demostrado: **{nd} de N5**. El nivel solo sube con pruebas a favor: lo que no se pudo revisar "
             "cuenta como no demostrado. No es una nota de calidad de la app."]
    ns = d["nivel_siguiente"]
    if ns:
        e1, f1, p1, ne1 = ns["evaluados"], len(ns["fallidos"]), len(ns["pendientes"]), len(ns["no_demostrables"])
        linea = (f"Para {ns['nivel']} hacen falta {ns['aplicables']} {plural(ns['aplicables'], 'punto', 'puntos')}: "
                 f"{_probados(e1, f1)}")
        if p1:
            linea += "; " + _sin_revisar_nivel(p1, ne1)
        nivel.append(linea + ".")
        if ne1 and d["modo"] in ("rapido", "estandar"):
            nivel.append(f"Por eso, en este modo el nivel no pasa de {nd} aunque se arregle todo lo encontrado.")
    if estado == ESTADO_ARREGLAR:
        nivel.append(f"En tu caso, además, hay {plural(nb, 'un problema abierto que impide', 'problemas abiertos que impiden')}"
                     " usar la app.")
    elif estado == ESTADO_CONFIRMAR:
        nivel.append(f"En tu caso, además, hay {plural(nb, 'una alarma por confirmar que podría impedir', 'alarmas por confirmar que podrían impedir')}"
                     " usar la app.")
    elif estado == ESTADO_AMBAR:
        f1 = len((ns or {}).get("fallidos") or [])
        if f1:
            nivel.append(f"En tu caso no hay bloqueos, pero hay {f1} {plural(f1, 'problema que', 'problemas que')} "
                         f"también {plural(f1, 'impide', 'impiden')} {ns['nivel']}: "
                         + "; ".join(_minuscula(_celda(t)) for t in d["titulos_fallidos"]) + ".")
        else:
            nivel.append("En tu caso no hay bloqueos: lo que falta es poder revisar esos puntos.")
    else:
        nivel.append("En tu caso falta revisar lo más básico.")
    out.append(" ".join(nivel))
    out.append("")
    out += [_linea_listo(d, estado, nd), ""]

    # P6 y P7
    if d["n_avisos_legales"]:
        nl = d["n_avisos_legales"]
        donde = "justo abajo" if variante == "informe" else "en `informe.md`"
        out += ["### Aviso legal", "",
                f"{nl} {plural(nl, 'punto legal que debe', 'puntos legales que debe')} revisar una persona (ver "
                f"«Aviso legal» {donde}). El auditor no certifica cumplimiento legal.", ""]
    modo = NOMBRE_MODO.get(d["modo"], d["modo"])
    out += ["---", f"Corrida `{d['corrida']}` · modo {modo}{' · sin internet' if d['sin_red'] else ''} · generado "
            "por plantilla, sin IA. Este resumen no certifica seguridad. **GUÍA**."]
    return validar_portada("\n".join(out), estado, variante, d["proyecto"])


def portada_reemplazo(d, variante, motivo):
    """Portada mínima cuando la normal no pasa validar_portada (R10b): fail-closed (el texto que rompió las reglas no
    se muestra) pero visible (el dueño recibe igual sus tres archivos, con el estado y las cifras de la corrida)."""
    if variante == "hoja":
        return (f"**Estado: {d['etiqueta']}.** Lo primero: lee «1. Veredicto» en `informe.md` (el resumen de la "
                f"portada no se pudo armar).\nNivel demostrado: {d['nivel_demostrado']} (dato secundario).")
    nb = len(d["bloqueos"])
    out = [f"## Portada — {d['proyecto']}", "", f"**Estado: {d['etiqueta']}**", "",
           "No pudimos armar el resumen de esta portada sin romper sus reglas de redacción, así que no lo mostramos. "
           "Lee el informe técnico (`informe.md`, desde «1. Veredicto»).", ""]
    if nb:
        out += [f"Hay {nb} {plural(nb, 'problema que impide usar la app (abierto o por confirmar)', 'problemas que impiden usar la app (abiertos o por confirmar)')}"
                " (ver «Bloqueos» en `informe.md`).", ""]
    out += [f"- Puntos que pueden frenar el uso: aplican {d['graves_aplican']}; con problema "
            f"{d['graves_con_problema']}; comprobados sin problema {d['graves_comprobados']}; **sin revisar "
            f"{d['graves_sin_revisar']}**.",
            "- Que algo no se haya revisado no significa que esté bien.", "",
            f"¿Lista para datos reales de personas? **{ {'SI': 'SÍ'}.get(d['listo'], d['listo'] or 's/d') }**.", ""]
    if variante == "informe":
        out += [f"Motivo técnico: {_codigo(utiles.una_linea(str(motivo)))}.", ""]
    out += ["---", f"Corrida `{d['corrida']}` · generado por plantilla, sin IA. Este resumen no certifica seguridad. "
            "**GUÍA**."]
    return "\n".join(out)


def _portada_o_reemplazo(d, variante, avisos):
    try:
        return render_portada(d, variante)
    except PortadaInvalida as e:
        avisos.append(f"{variante}: {e}")
        return portada_reemplazo(d, variante, e)


def _cargar_portada(corrida):
    corrida = Path(corrida)
    rm = utiles.leer_json(corrida / "roadmap.json") or _asegurar(corrida)
    run = utiles.leer_run(corrida)
    estado = utiles.leer_json(corrida / "estado.json")
    perfil = utiles.cargar_perfil(corrida)
    import veredictos as veredictos_mod
    hallazgos = veredictos_mod.marcar_fp_humanos(corrida, utiles.leer_jsonl(corrida / "hallazgos.jsonl"))
    return datos_portada(utiles.leer_json(corrida / "gates.json"), estado["controles"], hallazgos,
                         utiles.leer_json(corrida / "score.json"),
                         utiles.leer_json(corrida / "normalizacion.json", {}) or {}, rm,
                         utiles.indice_controles(perfil), estado.get("modo") or "estandar", run.get("id") or "s/d",
                         Path(run.get("proyecto") or ".").name or "proyecto",
                         perfil_tecnico=utiles.leer_json(corrida / "perfil_tecnico.json"),
                         herramientas_json=utiles.leer_json(corrida / "herramientas.json", {}) or {})


def portada(corrida, variante="informe", datos=None):
    """Portada de la corrida (variante informe, dueno u hoja), enmascarada con los secretos de la corrida."""
    datos = datos if datos is not None else _cargar_portada(corrida)
    return enmascarar.enmascarar_texto(render_portada(datos, variante), enmascarar.secretos_de_corrida(corrida))


def generar(corrida):
    corrida = Path(corrida)
    rm = _asegurar(corrida)
    run = utiles.leer_run(corrida)
    estado = utiles.leer_json(corrida / "estado.json")
    g = utiles.leer_json(corrida / "gates.json")
    s = utiles.leer_json(corrida / "score.json")
    r_iua = utiles.leer_json(corrida / "iua.json")
    resumen = utiles.leer_json(corrida / "normalizacion.json", {}) or {}
    perfil = utiles.cargar_perfil(corrida)
    indice = utiles.indice_controles(perfil)
    import veredictos as veredictos_mod
    # H-2: los hallazgos que una persona registró como falsos positivos verificados salen de la sección 6 y de los
    # conteos (quedan en la 6c); merged.sarif conserva todas las instancias.
    hallazgos = veredictos_mod.marcar_fp_humanos(corrida, utiles.leer_jsonl(corrida / "hallazgos.jsonl"))
    todos = utiles.leer_jsonl(corrida / "hallazgos_todos.jsonl") or hallazgos
    secretos = enmascarar.secretos_de_corrida(corrida)
    proyecto = Path(run.get("proyecto") or ".").name or "proyecto"
    gl = g["global"]
    nd = gl["nivel_demostrado"]
    sig = utiles.NIVELES[min(utiles.num_nivel(nd) + 1, 5)]
    fallbacks = fallbacks_de_corrida(corrida)
    csp_local = csp_connect_solo_self(run["proyecto"]) if run.get("proyecto") else False
    banderas = perfil.get("banderas") or {}
    for h in hallazgos:
        if h.get("remediacion"):
            h["remediacion"] = remediacion_por_perfil(h.get("control"), h["remediacion"], banderas, csp_local)
        if h.get("control") in roadmap_mod.CONTROLES_REMEDIACION_SECRETO and h.get("remediacion"):
            # R6: rotar + git filter-repo solo si el secreto está versionado (decide con TODAS las instancias)
            h["remediacion"] = roadmap_mod.remediacion_secreto(
                h["control"], [x for x in todos if x.get("control") == h["control"]], h["remediacion"])
    for i in rm["items"]:
        if not i.get("revision_ia"):  # la remediación condicional ya trae el texto del hallazgo
            i["que_hacer"] = remediacion_por_perfil(i["control"], i["que_hacer"], banderas, csp_local)

    valores = {
        "proyecto": proyecto, "corrida": run.get("id") or "s/d", "commit": run.get("commit7") or ("sin commits" if run.get("es_repo_git") else "sin-git"),
        "modo": estado.get("modo") or "estandar", "version_auditor": VERSION_AUDITOR,
        # R10c: el valor interno del modo (estandar) va en los comandos; en el texto visible, con tilde (estándar)
        "modo_visible": NOMBRE_MODO.get(estado.get("modo") or "estandar", estado.get("modo") or "estandar"),
        "nivel_demostrado": nd, "nivel_potencial": gl["nivel_potencial"], "hito": gl["hito"],
        "listo_datos_reales": gl["listo_datos_reales"], "cuello": ", ".join(gl["cuello_de_botella"]) or "—",
        "nota_no_evaluado": nota_no_evaluado(estado["controles"], indice),
        "bloqueos": _seccion_bloqueos(g, indice, hallazgos, roadmap_mod.triage_de_corrida(corrida)),
        "tabla_dominios": _tabla_dominios(g, s, hallazgos),
        "puntaje_global": _puntaje_global(s),
        "metodo_puntaje": _metodo_puntaje(s),
        "seccion_iua": _seccion_iua(r_iua),
        "tabla_cobertura": _tabla_cobertura(g),
        "no_demostrable": _seccion_no_demostrable(estado["controles"], indice),
        "hallazgos": _seccion_hallazgos(hallazgos, indice, fallbacks, roadmap_mod.triage_de_corrida(corrida),
                                        {e["control"]: e["estado"] for e in estado["controles"]}),
        "hallazgos_menores": _seccion_menores(hallazgos, indice),
        "no_evaluados": _seccion_no_evaluados(estado["controles"], indice),
        "avisos_legales": _seccion_legal(estado["controles"], indice),
        "aviso_legal": _seccion_aviso_legal(estado["controles"], indice, perfil, corrida),
        "n_items_ruta": str(len(rm["items"])),
        "herramientas": _herramientas(resumen, fallbacks),
        "perfil_origen": perfil["origen"],
        "n_hallazgos": str(len(hallazgos)), "n_hallazgos_todos": str(len(todos)),
        "n_sin_mapear": str(len(resumen.get("sin_mapear", []))),
        "umbral_cobertura": _pct(s.get("umbral_cobertura", 0.7)),
        "descartes_humanos": veredictos_mod.seccion_fp_humanos(corrida),
        # cabecera: cuántos descartes humanos se aplicaron y de qué archivo (o por qué no), siempre visible
        "aviso_descartes": veredictos_mod.aviso_fp_humanos(corrida, estado["controles"]),
    }
    # F3-B: «Qué hizo el auditor», «Qué falta», «Qué hacer ahora» (informe, resumen del dueño y hoja de ruta).
    veredictos, descartados = veredictos_de_corrida(corrida)
    herr_json = utiles.leer_json(corrida / "herramientas.json", {}) or {}
    valores["que_hizo"] = seccion_que_hizo(resumen, estado["controles"], indice, veredictos,
                                           utiles.leer_json(corrida / "tokens.json"), valores["modo"], descartados,
                                           motivos=motivos_herramientas(corrida))
    valores["que_falta"] = seccion_que_falta(estado["controles"], indice, herr_json)
    valores["decisiones_ia"] = efecto_fp_graves(veredictos_mod.seccion_informe(corrida), hallazgos)
    # R10: portada (misma fuente de datos para las tres variantes)
    datos_p = datos_portada(g, estado["controles"], hallazgos, s, resumen, rm, indice, valores["modo"],
                            valores["corrida"], proyecto,
                            perfil_tecnico=utiles.leer_json(corrida / "perfil_tecnico.json"),
                            herramientas_json=herr_json)
    avisos_portada = []   # R10b: una portada que no pasa la validación se reemplaza (nunca deja sin informe)
    valores["portada"] = _portada_o_reemplazo(datos_p, "informe", avisos_portada)
    listados = ({b["control"] for b in datos_p["bloqueos"][:5]}
                if datos_p["estado"] in (ESTADO_ARREGLAR, ESTADO_CONFIRMAR) else set())
    # R10d: el Paso 1 sigue el orden de los bloqueos de la portada (firmes primero en ARREGLAR)
    primeros = [b["control"] for b in datos_p["bloqueos"]]
    valores["que_hacer"] = seccion_que_hacer(rm, hallazgos, sig, primeros=primeros)
    redaccion, motivo_red = None, None
    if (corrida / "redaccion-dueno.json").is_file():
        cruda = utiles.leer_json(corrida / "redaccion-dueno.json")
        ok, motivo_red = validar_redaccion(cruda, rm, (datos_p["revisados"], datos_p["aplicables"]))
        redaccion = cruda if ok else None
    herr_ok = [k + (" (parcial)" if v.get("estado") == "parcial" else "")
               for k, v in sorted((resumen.get("herramientas") or {}).items()) if v.get("estado") in ESTADOS_CORRIO]
    dueno = dict(valores, **secciones_dueno(valores, rm, estado["controles"], indice, veredictos, herr_ok, redaccion,
                                            motivo_red, sig, hallazgos, excluir=listados),
                 bloqueos_dueno=_bloqueos_dueno(g, indice), portada=_portada_o_reemplazo(datos_p, "dueno", avisos_portada),
                 descartes_dueno=descartes_humanos_dueno(veredictos_mod.leer_fp_humanos(corrida)))
    informe = string.Template((PLANTILLAS / "informe.md.tmpl").read_text(encoding="utf-8")).substitute(valores)
    resumen_dueno = string.Template((PLANTILLAS / "resumen-dueno.md.tmpl").read_text(encoding="utf-8")).substitute(dueno)
    ruta = string.Template((PLANTILLAS / "hoja-de-ruta.md.tmpl").read_text(encoding="utf-8")).substitute({
        "proyecto": proyecto, "nivel_demostrado": nd, "hito": gl["hito"], "hito_siguiente": f"{sig}: {gates_mod.HITOS[sig]}",
        "cabecera_portada": _portada_o_reemplazo(datos_p, "hoja", avisos_portada),
        "modo": valores["modo"], "que_hacer_ahora": seccion_que_hacer(rm, hallazgos, sig, maximo=None, primeros=primeros),
        "grupos": _seccion_grupos(rm) + _aviso_sus(estado["controles"], indice),
        "descartes_humanos": descartes_humanos_ruta(veredictos_mod.leer_fp_humanos(corrida))})
    utiles.escribir_texto(corrida / "informe.md", enmascarar.enmascarar_texto(informe, secretos))
    utiles.escribir_texto(corrida / "resumen-dueno.md", enmascarar.enmascarar_texto(resumen_dueno, secretos))
    utiles.escribir_texto(corrida / "hoja-de-ruta.md", enmascarar.enmascarar_texto(ruta, secretos))
    utiles.escribir_json(corrida / "merged.sarif", enmascarar.enmascarar_obj(sarif(todos, indice), secretos))
    for a in avisos_portada:
        print(f"render_informe: AVISO: la portada no pasó su validación ({enmascarar.enmascarar_texto(a, secretos)}); "
              "se escribió una portada de reemplazo que remite al informe técnico", file=sys.stderr)
    return informe


def main(argv=None):
    ap = argparse.ArgumentParser(description="Informe por plantilla (sin LLM)")
    ap.add_argument("corrida_pos", nargs="?", metavar="DIR_CORRIDA")
    ap.add_argument("--corrida")
    a = ap.parse_args(argv)
    corrida = a.corrida or a.corrida_pos
    if not corrida or not Path(corrida).is_dir():
        print("render_informe.py: indique una carpeta de corrida existente", file=sys.stderr)
        return 2
    generar(corrida)
    print(f"informe: {Path(corrida) / 'informe.md'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

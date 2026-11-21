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


def seccion_que_hacer(rm, hallazgos, siguiente, maximo=10, por_que=None):
    """Hoja de ruta corta: críticos, luego lo que falla para el siguiente nivel, luego lo que falta evaluar."""
    items = list((rm or {}).get("items") or [])
    if not items:
        return "Nada urgente: no hay críticos abiertos ni controles pendientes del siguiente nivel."
    por_que = por_que or {}
    criticos = [i for i in items if i["estado"] == "fail" and i["severidad"] == "critica"]
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
    return "\n".join(salida).strip()


def validar_redaccion(r, rm):
    """(True, None) si el texto del redactor-dueno se puede usar; si no, (False, motivo). No admite controles nuevos."""
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
    controles = {i["control"] for i in (rm or {}).get("items") or []}
    for cid, texto in r["por_que_importa"].items():
        if cid not in controles:
            return False, f"{cid} no está en la hoja de ruta"
        if not isinstance(texto, str) or not texto.strip() or len(texto.split()) > 25 or len(texto) > 300:
            return False, f"«por qué importa» de {cid} vacío o de más de 25 palabras"
    return True, None


def secciones_dueno(valores, rm, estados, indice, veredictos, herr_ok, redaccion, motivo_red, siguiente, hallazgos):
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
    hacer = seccion_que_hacer(rm, hallazgos, siguiente, maximo=5, por_que=(redaccion or {}).get("por_que_importa"))
    return {"resumen": resumen, "nota_redactor": nota, "que_hizo_dueno": hizo, "que_falta_dueno": falta,
            "que_hacer_dueno": hacer}


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
    valores["que_hacer"] = seccion_que_hacer(rm, hallazgos, sig)
    redaccion, motivo_red = None, None
    if (corrida / "redaccion-dueno.json").is_file():
        cruda = utiles.leer_json(corrida / "redaccion-dueno.json")
        ok, motivo_red = validar_redaccion(cruda, rm)
        redaccion = cruda if ok else None
    herr_ok = [k + (" (parcial)" if v.get("estado") == "parcial" else "")
               for k, v in sorted((resumen.get("herramientas") or {}).items()) if v.get("estado") in ESTADOS_CORRIO]
    dueno = dict(valores, **secciones_dueno(valores, rm, estado["controles"], indice, veredictos, herr_ok, redaccion,
                                            motivo_red, sig, hallazgos), bloqueos_dueno=_bloqueos_dueno(g, indice),
                 descartes_dueno=descartes_humanos_dueno(veredictos_mod.leer_fp_humanos(corrida)))
    informe = string.Template((PLANTILLAS / "informe.md.tmpl").read_text(encoding="utf-8")).substitute(valores)
    resumen_dueno = string.Template((PLANTILLAS / "resumen-dueno.md.tmpl").read_text(encoding="utf-8")).substitute(dueno)
    ruta = string.Template((PLANTILLAS / "hoja-de-ruta.md.tmpl").read_text(encoding="utf-8")).substitute({
        "proyecto": proyecto, "nivel_demostrado": nd, "hito": gl["hito"], "hito_siguiente": f"{sig}: {gates_mod.HITOS[sig]}",
        "modo": valores["modo"], "que_hacer_ahora": seccion_que_hacer(rm, hallazgos, sig, maximo=None),
        "grupos": _seccion_grupos(rm) + _aviso_sus(estado["controles"], indice),
        "descartes_humanos": descartes_humanos_ruta(veredictos_mod.leer_fp_humanos(corrida))})
    utiles.escribir_texto(corrida / "informe.md", enmascarar.enmascarar_texto(informe, secretos))
    utiles.escribir_texto(corrida / "resumen-dueno.md", enmascarar.enmascarar_texto(resumen_dueno, secretos))
    utiles.escribir_texto(corrida / "hoja-de-ruta.md", enmascarar.enmascarar_texto(ruta, secretos))
    utiles.escribir_json(corrida / "merged.sarif", enmascarar.enmascarar_obj(sarif(todos, indice), secretos))
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

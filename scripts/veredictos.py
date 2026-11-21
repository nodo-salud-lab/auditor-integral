#!/usr/bin/env python3
"""Veredictos del LLM (veredictos.jsonl) → estado/gates con reglas duras (F3; PLAN_MAESTRO §3.1, §3.3, §10 F3).

Cada línea de <corrida>/veredictos.jsonl se valida contra schemas/veredicto.schema.json y contra estas reglas
(fail-closed: ante la duda, la decisión de la IA NO se aplica):
  (a) Un fail determinista solo cambia con un veredicto `falso_positivo` sobre su hallazgo (hallazgo_id) con razón
      no vacía y una ubicación archivo:línea en el MISMO archivo del hallazgo, que además estaba en el digest que vio
      el agente. Un 'pass' nunca borra un hallazgo. Un falso positivo de un hallazgo CRÍTICO o ALTO
      (SEVERIDADES_FP_HUMANO) nunca deja el control en un estado OK (pass ni no_aplica por alcance 0): queda
      no_evaluado (requiere verificación humana), o fail si hay otro hallazgo efectivo; uno medio/bajo sí puede
      descartarse sin verificación humana (decisión F3-C, 18-11-2026). Si otro veredicto dice verdadero/incierto sobre el
      mismo hallazgo, gana ese (no se aplica el falso positivo).
      Un 'fail' con hallazgo_id de un hallazgo del MISMO control que estaba en el digest del agente es una
      confirmación ('verdadero'): no baja severidad ni produce pass. Si no es confirmable (otro control, fuera de su
      digest, inexistente), cuenta como indicio del control (hallazgo de IA); de triage-fp se descarta.
  (b) 'incierto' cuenta como verdadero: sobre un hallazgo, lo confirma (gates.py ya no lo trata como pendiente de
      triage); sobre un control (sin hallazgo_id), crea un hallazgo de método llm → fail. Los críticos/altos que el
      digest de triage dejó fuera por el tope anti-desborde (incierto_por_tope) quedan 'incierto'.
  (c) Un control `llm` o `mixto` pasa a pass SOLO con un veredicto 'pass' de un agente que el catálogo declara como
      componente del control, con ≥ 1 ubicación archivo:línea que existe en el proyecto (relativa, dentro del
      proyecto, no confidencial, sin node_modules/lockfile/.env, línea ≤ largo del archivo), con `metodo` no vacío,
      sin requiere_verificacion_humana, con el digest de su juicio completo (digest/indice.json), sin hallazgos
      efectivos y sin veredictos fail/incierto del mismo control. En mixto, además, la parte determinista tiene que
      haber corrido (estado.py: rama «parte determinista sin hallazgos»). Un control determinista nunca pasa por IA.
  (d) Una línea inválida (JSON, schema o reglas) se descarta con su motivo; si nombra un control del dominio del
      agente, ese control queda no_evaluado (un pass se degrada) y el motivo lo dice.
  (e) Nunca toca controles de otro dominio que el declarado por el tipo de juicio (DOMINIOS_JUICIO) ni controles
      de los que el agente no es componente: esas líneas se descartan sin efecto sobre el control.
  (f) Juez omitido: si digest/indice.json marca un digest con omitir_juez=true (nada que juzgar) y su agente no
      emitió veredictos, los controles llm/mixto de ese digest quedan no_evaluado con motivo «juez omitido: <motivo>»
      (determinista, 0 tokens; registrado en decisiones_ia.json → jueces_omitidos). Un digest omitido nunca
      sostiene un pass. Igual con lanzar=false (el modo no lanza ese juez): motivo «juez no lanzado: …». La lista de
      controles sale de indice.json → digests.<j>.controles (si la clave existe, aunque sea []), luego del digest,
      luego del catálogo.
Las decisiones aplicadas y descartadas van a <corrida>/decisiones_ia.json; los fail/incierto de control, a
hallazgos_ia.jsonl: un hallazgo por ubicación validada (máx. TOPE_UBICACIONES por veredicto; el truncado se
informa), fingerprint estable por control+archivo+línea (valida contra hallazgo.schema.json; metodo "llm"; la
severidad es la del catálogo y la IA solo puede subirla). Todo texto del LLM se enmascara antes de escribirse. Sin veredictos.jsonl no se escribe nada y se
borran decisiones_ia.json y hallazgos_ia.jsonl viejos. El informe lo muestra en «Decisiones de la IA», aparte de
las deterministas (seccion_informe).

Falsos positivos verificados por una PERSONA (H-2, DECISIONES.md #11, pendiente de confirmar por Enzo): archivo JSON
que escribe la persona (por convención <proyecto>/.auditor-integral/fp-verificados.json, o uno fuera del proyecto; la
IA y los agentes nunca lo escriben) y que SOLO se aplica si el operador lo autoriza con
`bin/auditar … --fp-verificados RUTA` (variable AUDITOR_FP_VERIFICADOS). Un fp-verificados.json que trae el propio
repositorio auditado, sin esa autorización, es una autoatestación del repo: no descarta nada y el informe lo avisa.
El informe y la hoja de ruta recalculan el registro en cada report (leer_fp_humanos) y nunca confían en
<corrida>/fp_humanos.json tal como está en disco; si no coincide con el recálculo, lo avisan. Formato:
  {"version": "1", "entradas": [{"control": "SEG-SECRETO-BUNDLE", "huella": "H-xxxxxxxxxxxx",   # id o fingerprint
                                 "ubicacion": "dist/a.js:5",                                    # opcional
                                 "quien": "Nombre Apellido", "fecha": "AAAA-MM-DD",
                                 "conclusion": "por qué no es un problema real"}]}
Reglas (fail-closed; cargar_fp_humanos / aplicar_fp_humanos / ajustar_fp_humanos):
- Entrada incompleta (falta control, huella, quien, fecha o conclusion), con fecha inválida o futura (respecto de la
  corrida), con «quien» que nombra a la IA o a un agente, duplicada, o con el archivo como enlace simbólico, no
  legible o > 256 KiB: se ignora con aviso.
- Coincide por huella estable (fingerprint de contenido o id H-…) y control; si trae ubicación, también debe
  coincidir archivo:línea. Un hallazgo NUEVO distinto en la misma línea tiene otra huella: no se descarta. Una huella
  que ya no coincide con ningún hallazgo de la corrida se avisa como entrada huérfana.
- Efecto: el hallazgo queda falso_positivo con verificacion_humana {quien, fecha, conclusion}; los veredictos de la IA
  sobre ese hallazgo se descartan (prevalece la persona; tampoco cuentan como FP grave de la IA). Si el control ya no
  tiene hallazgos efectivos y quedaba pass o no_aplica, toma estado no_aplica con motivo «descartado por
  verificación humana (quién, fecha)» y el campo descarte_humano: NO es pass (no suma puntaje), pero deja de bloquear
  las compuertas (cuenta como OK igual que no_aplica). Si quedaba no_evaluado / manual_pendiente / fail por otra
  causa, no cambia: solo se anota al final del motivo. Registro: <corrida>/fp_humanos.json (informe 6c, hoja de ruta
  y resumen del dueño). veredictos.jsonl no puede crear ni modificar esta verificación.

Uso:  veredictos.py DIR_CORRIDA   (valida, aplica y recalcula estado.json + gates.json)
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
if str(_SCRIPTS / "checks") not in sys.path:
    sys.path.insert(0, str(_SCRIPTS / "checks"))

import datos_confidenciales  # noqa: E402
import digest as digest_mod  # noqa: E402
import enmascarar  # noqa: E402
import utiles  # noqa: E402
import validar_schema  # noqa: E402

SCHEMA = utiles.RAIZ / "schemas" / "veredicto.schema.json"
SCHEMA_HALLAZGO = utiles.RAIZ / "schemas" / "hallazgo.schema.json"
ARCHIVO = "veredictos.jsonl"
DECISIONES = "decisiones_ia.json"
HALLAZGOS_IA = "hallazgos_ia.jsonl"
JUICIO = {"revisor-autorizacion": "autorizacion", "revisor-arquitectura": "arquitectura", "triage-fp": "triage",
          "revisor-ux": "ux"}
TODOS = ("SEG", "DAT", "COD", "UX", "INF", "ESC", "OPS")
DOMINIOS_JUICIO = {
    "revisor-autorizacion": ("SEG", "DAT", "COD"),            # IDOR/BOLA/BFLA, auth en cliente, RLS, tests de authz
    "revisor-arquitectura": ("SEG", "DAT", "COD", "INF", "OPS"),  # STRIDE, transacciones, plataforma, abuso de lógica
    "revisor-ux": ("UX",),
    "triage-fp": TODOS,                                      # solo sobre hallazgos (hallazgo_id), de cualquier dominio
    "redactor-dueno": (),                                    # solo redacta: nunca emite veredictos
}
VEREDICTOS_HALLAZGO = ("verdadero", "falso_positivo", "incierto")
CONFIRMAN = ("verdadero", "incierto", "fail")   # sobre un hallazgo, 'fail' = confirmación (verdadero)
TOPE_UBICACIONES = 5                             # hallazgos de IA por veredicto (uno por ubicación)
VENTANA_FP = max(list(digest_mod.CONTEXTO_LINEAS.values()) + [digest_mod.CONTEXTO_DEFECTO])  # ±líneas del fragmento
# Regla (a): un falso positivo de la IA sobre un hallazgo de estas severidades nunca deja el control en pass
# (no_evaluado hasta verificación humana). Medio/bajo quedan fuera a propósito: el triage puede descartarlos.
SEVERIDADES_FP_HUMANO = ("critica", "alta")
RE_UBIC = re.compile(r"^(.+):([0-9]+)$")


def _recortar(texto, n=300):
    return enmascarar.recortar(texto, n)


class Contexto:
    def __init__(self, corrida, indice, hallazgos):
        self.corrida = Path(corrida)
        run = utiles.leer_run(self.corrida)
        p = run.get("proyecto")
        self.proyecto = Path(p).resolve() if p and Path(p).is_dir() else None
        self.indice = indice
        self.hallazgos = {h["id"]: h for h in hallazgos}
        self.secretos = enmascarar.secretos_de_corrida(self.corrida)
        self.conf = datos_confidenciales.cargar()
        self.fecha = utiles.fecha_referencia(self.corrida)
        ind = utiles.leer_json(self.corrida / "digest" / "indice.json")
        self.indice_digest = ind if isinstance(ind, dict) else None
        self.en_digest = {}
        for j in digest_mod.JUICIOS:
            d = utiles.leer_json(self.corrida / "digest" / f"{j}.json")
            self.en_digest[j] = {x.get("id") for x in (d or {}).get("hallazgos", []) if isinstance(x, dict)}
        perfil = utiles.leer_json(self.corrida / "perfil.json")
        self.pendientes = pendientes_entrevista(perfil)

    def texto(self, t, n=300):
        return _recortar(enmascarar.enmascarar_texto(str(t or ""), self.secretos), n)

    def ubicacion_existe(self, u):
        """(archivo, línea) si la cita apunta a una línea real de un archivo legible del proyecto; None si no."""
        m = RE_UBIC.match(str(u or ""))
        if not m or self.proyecto is None:
            return None
        linea = int(m.group(2))
        # sin enlaces simbólicos en ningún componente ni rutas confidenciales/prohibidas; ruta canónica (F3-C adv.)
        seguro = digest_mod.ruta_segura(self.proyecto, m.group(1), self.conf) if linea >= 1 else None
        if seguro is None:
            return None
        rel, real = seguro
        try:
            with open(real, encoding="utf-8", errors="replace") as f:
                n = sum(1 for _ in f)
        except OSError:
            return None
        return (rel, linea) if linea <= n else None

    def digest_completo(self, agente):
        juicio = JUICIO.get(agente)
        if self.indice_digest is None or juicio is None:
            return False, "no hay digest/indice.json (el juicio no se hizo sobre un digest acotado)"
        m = (self.indice_digest.get("digests") or {}).get(juicio) or {}
        if m.get("omitir_juez"):
            return False, f"juez omitido: {m.get('motivo_omision') or 'sin motivo declarado'}"
        if m.get("completo") is True:
            return True, None
        return False, f"digest de {juicio} incompleto: {'; '.join(m.get('motivos_incompleto') or ['sin registro'])}"


def pendientes_entrevista(perfil):
    """{control: [preguntas sin respuesta]} desde perfil.json → pendientes_entrevista (perfil.py)."""
    res = {}
    if not isinstance(perfil, dict):
        return res
    for preg, info in sorted((perfil.get("pendientes_entrevista") or {}).items()):
        for c in (info or {}).get("controles", []) if isinstance(info, dict) else []:
            res.setdefault(c, []).append(str(preg))
    return res


def _es_sintetica(a):
    """Entrada de `aplicadas` que agrega el auditor (agente 'auditor', modelo nulo) por un hallazgo grave que el tope de
    tokens dejó fuera del digest de triage: no es un juicio de la IA."""
    return a.get("agente") == "auditor" and a.get("modelo") is None


def _efectivos_por_control(hallazgos, fecha):
    import estado as estado_mod  # import diferido: estado.py importa este módulo dentro de generar()
    res = {}
    for h in hallazgos:
        if estado_mod.efectivo(h, fecha):
            res.setdefault(h["control"], []).append(h["id"])
    return res


def _hallazgo_ia(v, c, ubic, ctx):
    sev = c.get("severidad_base") or "media"
    if v.get("severidad_propuesta"):
        sev = utiles.max_severidad(sev, v["severidad_propuesta"])
    # estable por control+archivo+línea: la misma ubicación de dos veredictos (o corridas) es el mismo hallazgo
    base = f"ia|{v['control']}|{ubic[0] if ubic else ''}|{ubic[1] if ubic else ''}"
    fp = hashlib.sha256(base.encode("utf-8")).hexdigest()
    h = {"id": f"H-{fp[:16]}", "control": v["control"], "alias": list(c.get("alias") or [])[:10],
         "dominio": c["dominio"], "etapa": c.get("etapa", "E2"), "gate": c["gate"], "severidad": sev,
         "confianza": "media", "metodo": "llm",
         "fuente": [{"herramienta": v["agente"], "version": None, "regla": f"ia:{v['veredicto']}"}],
         "ubicacion": {"archivo": ubic[0] if ubic else None, "linea": ubic[1] if ubic else None},
         "evidencia": ctx.texto(f"IA ({v['veredicto']}): {v['razon']}"), "fingerprint": fp,
         "estado_hallazgo": "abierto", "triage": None, "esfuerzo": c.get("esfuerzo")}
    return h


def _leer_lineas(corrida):
    ruta = Path(corrida) / ARCHIVO
    if not ruta.is_file():
        return None
    return ruta.read_text(encoding="utf-8", errors="replace").splitlines()


def evaluar(corrida, indice, hallazgos):
    """Valida y clasifica los veredictos. None si no hay veredictos.jsonl. Devuelve
    {hallazgos, hallazgos_ia, pases, forzar, fp_criticos, fp_graves, aplicadas, descartadas, triage}.
    fp_criticos: {control: [ids]} solo críticos (compatibilidad); fp_graves: críticos y altos (decide la regla a)."""
    lineas = _leer_lineas(corrida)
    if lineas is None:
        return None
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    schema_h = json.loads(SCHEMA_HALLAZGO.read_text(encoding="utf-8"))
    ctx = Contexto(corrida, indice, hallazgos)
    aplicadas, descartadas, forzar = [], [], {}
    vistos = set()
    por_hallazgo = {}     # id → [(n, v)]
    por_control = {}      # control → [(n, v)] (sin hallazgo_id, o fail con hallazgo_id no confirmable)
    notas = {}            # n → nota (fail con hallazgo_id tratado como indicio del control)
    agentes_vistos = set()

    def descartar(n, v, motivo, forzar_control=False):
        reg = {"linea": n, "motivo": _recortar(motivo, 300)}
        if isinstance(v, dict):
            for k in ("agente", "control", "hallazgo_id", "veredicto"):
                if isinstance(v.get(k), str):
                    reg[k] = ctx.texto(v[k], 80)
        descartadas.append(reg)
        if forzar_control and isinstance(v, dict) and v.get("control") in indice:
            forzar.setdefault(v["control"], f"veredicto de IA descartado (línea {n}): {motivo}")

    def en_su_dominio(v):
        """(ok, motivo) de la regla (e); solo si ok se puede forzar no_evaluado sobre el control."""
        agente, cid = v.get("agente"), v.get("control")
        c = indice.get(cid)
        if agente not in DOMINIOS_JUICIO or c is None:
            return False, "agente o control desconocido"
        if c["dominio"] not in DOMINIOS_JUICIO[agente]:
            return False, f"fuera del dominio del juicio: {agente} no juzga controles {c['dominio']}"
        if agente != "triage-fp" and agente not in (c.get("herramientas") or []):
            return False, f"{agente} no es componente del control {cid} en el catálogo"
        return True, None

    for n, linea in enumerate(lineas, 1):
        if not linea.strip():
            continue
        try:
            v = json.loads(linea)
        except ValueError:
            descartar(n, None, "JSON inválido")
            continue
        if not isinstance(v, dict):
            descartar(n, None, "la línea no es un objeto JSON")
            continue
        if isinstance(v.get("agente"), str):
            agentes_vistos.add(v["agente"])
        clave = json.dumps(v, sort_keys=True, ensure_ascii=False)
        if clave in vistos:
            continue  # línea duplicada
        vistos.add(clave)
        errores = validar_schema.validar(v, schema)
        dominio_ok, motivo_dominio = en_su_dominio(v) if isinstance(v.get("control"), str) else (False, None)
        if errores:
            descartar(n, v, "no valida contra veredicto.schema.json: " + "; ".join(errores[:3]), dominio_ok)
            continue
        if v["agente"] == "redactor-dueno":
            descartar(n, v, "el redactor-dueno solo redacta: no emite veredictos")
            continue
        c = indice.get(v["control"])
        if c is None:
            descartar(n, v, "control inexistente en el catálogo")
            continue
        if c.get("aplicabilidad") == "no_aplica":
            descartar(n, v, "el control no aplica a este perfil")
            continue
        if not dominio_ok:
            descartar(n, v, motivo_dominio)
            continue
        if not v["razon"].strip():
            descartar(n, v, "razón vacía", True)
            continue
        hid = v.get("hallazgo_id")
        if hid and v["veredicto"] == "fail":
            h = ctx.hallazgos.get(hid)
            if h is None:
                nota = f"hallazgo {hid} inexistente en esta corrida"
            elif h["control"] != v["control"]:
                nota = f"el hallazgo {hid} es de {h['control']}, no de {v['control']}"
            elif hid not in ctx.en_digest.get(JUICIO.get(v["agente"]), set()):
                nota = f"el hallazgo {hid} no estaba en el digest de {JUICIO.get(v['agente'])}"
            else:
                por_hallazgo.setdefault(hid, []).append((n, v))   # fail = confirmación (verdadero)
                continue
            if v["agente"] == "triage-fp":
                descartar(n, v, f"{nota}: triage-fp solo confirma hallazgos de su digest", True)
            else:
                notas[n] = f"{nota}: se trata como indicio del control"
                por_control.setdefault(v["control"], []).append((n, v))
            continue
        if hid:
            h = ctx.hallazgos.get(hid)
            if v["veredicto"] not in VEREDICTOS_HALLAZGO:
                descartar(n, v, f"sobre un hallazgo solo valen {', '.join(VEREDICTOS_HALLAZGO)}; un 'pass' nunca "
                                "borra un hallazgo (regla a)", True)
            elif h is None:
                descartar(n, v, f"hallazgo {hid} inexistente en esta corrida", True)
            elif h["control"] != v["control"]:
                descartar(n, v, f"el hallazgo {hid} es de {h['control']}, no de {v['control']}", True)
            else:
                por_hallazgo.setdefault(hid, []).append((n, v))
            continue
        if v["veredicto"] in VEREDICTOS_HALLAZGO[:2]:
            descartar(n, v, f"'{v['veredicto']}' exige hallazgo_id", True)
            continue
        if v["agente"] == "triage-fp":
            descartar(n, v, "triage-fp solo juzga hallazgos (hallazgo_id)", True)
            continue
        por_control.setdefault(v["control"], []).append((n, v))

    # --- hallazgos: triage y falsos positivos (reglas a y b) ---------------------------------------------------
    ajustados = {hid: dict(h) for hid, h in ctx.hallazgos.items()}
    fp_criticos = {}   # solo críticos (clave histórica; decide la etiqueta «crítico» del motivo)
    fp_graves = {}     # críticos y altos: SEVERIDADES_FP_HUMANO
    triage = {}
    for hid in sorted(por_hallazgo):
        h = ajustados[hid]
        lista = por_hallazgo[hid]
        if h.get("verificacion_humana"):
            # H-2: una persona ya lo registró como falso positivo verificado: la IA no lo reabre ni lo «descarta»
            # (su FP no cuenta como grave pendiente) y un fail/verdadero de la IA tampoco lo revive.
            vh = h["verificacion_humana"]
            for n, v in lista:
                descartar(n, v, f"el hallazgo ya fue descartado por verificación humana ({vh.get('quien')}, "
                                f"{vh.get('fecha')}): prevalece la persona")
            continue
        confirman = [(n, v) for n, v in lista if v["veredicto"] in CONFIRMAN]
        for n, v in lista:
            if v["veredicto"] != "falso_positivo":
                continue
            juicio = JUICIO.get(v["agente"])
            u = h.get("ubicacion") or {}
            citas = [RE_UBIC.match(x) for x in v.get("ubicaciones") or []]
            # mismo archivo y, si el hallazgo tiene línea, dentro de la ventana que mostró el digest (F3-C adv.):
            # una línea inventada o lejana no es la ubicación del hallazgo
            mismo = [m for m in citas if m and _canon(m.group(1)) == _canon(u.get("archivo"))
                     and int(m.group(2)) >= 1 and (not isinstance(u.get("linea"), int)
                                                   or abs(int(m.group(2)) - u["linea"]) <= VENTANA_FP)]
            if confirman:
                descartar(n, v, "otro veredicto confirma el hallazgo (verdadero/incierto gana: fail-closed)")
            elif hid not in ctx.en_digest.get(juicio, set()):
                descartar(n, v, f"el hallazgo no estaba en el digest de {juicio}: el agente no lo vio")
            elif not u.get("archivo"):
                descartar(n, v, "el hallazgo no tiene archivo: un falso positivo exige citar archivo:línea")
            elif not mismo:
                cerca = (f" a ±{VENTANA_FP} líneas de la {u['linea']}" if isinstance(u.get("linea"), int) else "")
                descartar(n, v, f"falso_positivo sin ubicación archivo:línea en {u.get('archivo')}{cerca} (regla a)")
            else:
                h["estado_hallazgo"] = "falso_positivo"
                triage[hid] = {"veredicto": "falso_positivo", "razon": ctx.texto(v["razon"]), "modelo": v["modelo"]}
                if h.get("severidad") == "critica":
                    fp_criticos.setdefault(h["control"], []).append(hid)
                if h.get("severidad") in SEVERIDADES_FP_HUMANO:
                    fp_graves.setdefault(h["control"], []).append(hid)
                aplicadas.append(_aplicada(n, v, ctx, "descarta el hallazgo (falso positivo con razón y ubicación)"))
                break
        if hid not in triage and confirman:
            n, v = sorted(confirman, key=lambda x: (x[1]["veredicto"] == "incierto", x[0]))[0]
            triage[hid] = {"veredicto": "incierto" if v["veredicto"] == "incierto" else "verdadero",
                           "razon": ctx.texto(v["razon"]), "modelo": v["modelo"]}
            for n2, v2 in confirman:
                aplicadas.append(_aplicada(n2, v2, ctx, "confirma el hallazgo" + (
                    " (fail con hallazgo_id = verdadero)" if v2["veredicto"] == "fail" else "")))
    ind_triage = ((ctx.indice_digest or {}).get("digests") or {}).get("triage") or {}
    corte = _corte_triage(ctx.indice_digest, ind_triage)
    for hid in ind_triage.get("incierto_por_tope") or []:
        if hid in ajustados and hid not in triage and not ajustados[hid].get("verificacion_humana"):
            triage[hid] = {"veredicto": "incierto", "razon": f"no juzgado: {corte}", "modelo": "auditor"}
            aplicadas.append({"linea": None, "agente": "auditor", "control": ajustados[hid]["control"],
                              "hallazgo_id": hid, "veredicto": "incierto",
                              "razon": f"no juzgado: {corte} (§3.4.5); cuenta como verdadero",
                              "ubicaciones": [], "modelo": None, "efecto": "confirma el hallazgo"})
    for hid, t in triage.items():
        ajustados[hid]["triage"] = t

    # --- controles: pass / fail / incierto / no_evaluado (reglas b, c) --------------------------------------
    efectivos = _efectivos_por_control(ajustados.values(), ctx.fecha)
    pases, hallazgos_ia = {}, {}
    for cid in sorted(por_control):
        c = indice[cid]
        lista = por_control[cid]
        negativos = [(n, v) for n, v in lista if v["veredicto"] in ("fail", "incierto")]
        for n, v in negativos:
            validas = []
            for x in v.get("ubicaciones") or []:
                u = ctx.ubicacion_existe(x)
                if u and u not in validas:
                    validas.append(u)
            truncadas = max(0, len(validas) - TOPE_UBICACIONES)
            nuevos = [_hallazgo_ia(v, c, u, ctx) for u in (validas[:TOPE_UBICACIONES] or [None])]
            if any(validar_schema.validar(h, schema_h) for h in nuevos):
                descartar(n, v, "no se pudo construir un hallazgo válido", True)
                continue
            for h in nuevos:
                previo = hallazgos_ia.get(h["id"])
                if previo is None:
                    hallazgos_ia[h["id"]] = h
                else:  # misma ubicación de otro veredicto: un solo hallazgo, con la severidad mayor
                    previo["severidad"] = utiles.max_severidad(previo["severidad"], h["severidad"])
            efecto = f"fail del control ({'incierto = verdadero' if v['veredicto'] == 'incierto' else 'fail'})"
            if n in notas:
                efecto += f"; {notas[n]}"
            if truncadas:
                efecto += (f"; {truncadas} ubicación(es) válida(s) truncada(s) por el tope de {TOPE_UBICACIONES} "
                           "hallazgos por veredicto")
            aplicadas.append(_aplicada(n, v, ctx, efecto, hallazgo_ia=[h["id"] for h in nuevos],
                                       truncadas=truncadas))
        for n, v in lista:
            if v["veredicto"] == "no_evaluado":
                forzar.setdefault(cid, f"la IA no pudo evaluar (línea {n}): {ctx.texto(v['razon'], 120)}")
                aplicadas.append(_aplicada(n, v, ctx, "sin cambio: el control queda no_evaluado"))
                continue
            if v["veredicto"] != "pass":
                continue
            motivo = None
            ubics = [ctx.ubicacion_existe(x) for x in v.get("ubicaciones") or []]
            if c.get("metodo") not in ("llm", "mixto"):
                motivo = "control determinista: la IA no puede declarar pass (regla c)"
            elif efectivos.get(cid):
                motivo = ("el control tiene fail determinista: solo un falso_positivo con razón y archivo:línea "
                          "sobre cada hallazgo puede cambiarlo (regla a)")
            elif negativos:
                motivo = "otro veredicto del mismo control es fail/incierto (gana el fail)"
            elif not (v.get("metodo") or "").strip():
                motivo = "pass sin método declarado (regla c)"
            elif not ubics:
                motivo = "pass sin ubicaciones archivo:línea (regla c)"
            elif not all(ubics):
                motivo = "pass con ubicaciones inexistentes, fuera del proyecto, confidenciales o prohibidas (regla c)"
            elif v.get("requiere_verificacion_humana"):
                motivo = "el agente marcó requiere verificación humana: no hay pass"
            else:
                ok, mot = ctx.digest_completo(v["agente"])
                if not ok:
                    motivo = mot
                elif cid in ctx.pendientes:
                    motivo = f"falta respuesta a la pregunta {', '.join(ctx.pendientes[cid])} de la entrevista"
            if motivo:
                descartar(n, v, motivo, not (efectivos.get(cid) or negativos))
                continue
            if cid not in pases:
                pases[cid] = {"agente": v["agente"], "modelo": v["modelo"], "linea": n,
                              "motivo": _recortar(f"pass por juicio de IA ({v['agente']}, {v['modelo']}; método: "
                                                  f"{ctx.texto(v['metodo'], 60)}; evidencia: "
                                                  f"{', '.join(v['ubicaciones'][:3])}): {ctx.texto(v['razon'], 120)}")}
                aplicadas.append(_aplicada(n, v, ctx, "pass por juicio de IA"))
    omitidos = jueces_omitidos(ctx, indice, agentes_vistos)
    for o in omitidos:
        for cid in o["controles"]:
            forzar.setdefault(cid, o["motivo"])
    for cid in list(pases):
        if cid in forzar:
            del pases[cid]
    return {"hallazgos": [ajustados[h["id"]] for h in hallazgos],
            "hallazgos_ia": [hallazgos_ia[k] for k in sorted(hallazgos_ia)], "pases": pases,
            "forzar": forzar, "fp_criticos": fp_criticos, "fp_graves": fp_graves, "triage": dict(sorted(triage.items())),
            "aplicadas": aplicadas, "descartadas": descartadas, "omitidos": omitidos}


def _canon(rel):
    """Ruta relativa sin componentes vacíos ni «.» (para comparar la cita con el archivo del hallazgo)."""
    return "/".join(p for p in str(rel or "").split("/") if p not in ("", "."))


def _corte_triage(indice_digest, ind_triage):
    """Por qué un crítico/alto quedó fuera del digest de triage, sin afirmar un corte que no ocurrió: el anti-desborde
    de TOPE solo si entraron TOPE graves; si no, el tope de tokens del digest (que comparte con la cuota de FP)."""
    inc = ind_triage.get("incluidos") or {}
    dentro = sum(x for x in (inc.get("criticos"), inc.get("altos")) if isinstance(x, int))
    if dentro >= digest_mod.TOPE:
        return f"quedó fuera del digest de triage por el anti-desborde de {digest_mod.TOPE} críticos/altos"
    tope = (indice_digest or {}).get("tope_tokens")
    return ("quedó fuera del digest de triage por el tope de "
            + (f"{tope} tokens" if isinstance(tope, int) else "tokens") + " (compartido con la cuota de candidatos a FP)")


def jueces_omitidos(ctx, indice, agentes_vistos):
    """Regla (f): [{juicio, agente, motivo, controles}] de los digests cuyo agente no emitió ninguna línea y que
    (1) tienen omitir_juez=true (nada que juzgar / falta la entrada esencial) o (2) tienen lanzar=false (el modo no
    lanza ese juez; solo si el índice trae la clave). Controles, en este orden: indice.json → digests.<j>.controles si
    la clave existe (aunque sea []), si no digest/<j>.json → controles si existe, si no el catálogo
    (digest.controles_de); solo llm/mixto aplicables. Nunca produce pass ni toca un fail."""
    res = []
    ind = ctx.indice_digest or {}
    digests = ind.get("digests") or {}
    jm = ind.get("jueces_modo") if isinstance(ind.get("jueces_modo"), dict) else {}
    modo = jm.get("modo")
    permitidos = set(jm.get("lanzar") or []) | set(jm.get("condicionales") or [])
    for juicio in sorted(digests):
        m = digests[juicio]
        if not isinstance(m, dict):
            continue
        if m.get("omitir_juez") is True:
            motivo = f"juez omitido: {ctx.texto(m.get('motivo_omision') or 'sin motivo declarado', 200)}"
        elif m.get("lanzar") is False:
            if juicio in permitidos:
                motivo = "juez no lanzado: indice.json marca lanzar=false"
            else:
                motivo = (f"juez no lanzado: el modo {ctx.texto(modo or 'sin registro', 20)} no lanza este juez "
                          "(config/presupuesto_tokens.toml [jueces])")
        else:
            continue
        agente = m.get("agente") or {v: k for k, v in JUICIO.items()}.get(juicio)
        if agente not in JUICIO or agente in agentes_vistos:
            continue
        lista = m.get("controles")
        if not isinstance(lista, list):
            d = utiles.leer_json(ctx.corrida / "digest" / f"{juicio}.json")
            lista = d.get("controles") if isinstance(d, dict) else None
        if not isinstance(lista, list):
            lista = digest_mod.controles_de(agente, indice)
        ids = sorted({x.get("id") if isinstance(x, dict) else x for x in lista} - {None})
        ids = [cid for cid in ids if cid in indice and indice[cid].get("aplicabilidad") != "no_aplica"
               and indice[cid].get("metodo") in ("llm", "mixto")]
        res.append({"juicio": juicio, "agente": agente, "motivo": motivo, "controles": ids})
    return res


def _aplicada(n, v, ctx, efecto, hallazgo_ia=None, truncadas=0):
    reg = {"linea": n, "agente": v["agente"], "control": v["control"], "hallazgo_id": v.get("hallazgo_id"),
           "veredicto": v["veredicto"], "razon": ctx.texto(v["razon"]),
           "ubicaciones": [ctx.texto(u, 200) for u in (v.get("ubicaciones") or [])][:5],
           "metodo": ctx.texto(v.get("metodo"), 120) if v.get("metodo") else None,
           "modelo": ctx.texto(v["modelo"], 80), "efecto": efecto,
           "requiere_verificacion_humana": bool(v.get("requiere_verificacion_humana"))}
    if hallazgo_ia:
        reg["hallazgo_ia"] = hallazgo_ia[0]
        reg["hallazgos_ia"] = list(hallazgo_ia)
    if truncadas:
        reg["ubicaciones_truncadas"] = truncadas
    return reg


ESTADOS_OK_FP = ("pass", "no_aplica")   # = gates.OK_DEMOSTRADO: estados que cuentan como cumplidos


def ajustar(controles, res):
    """Post-proceso sobre el estado calculado: degrada pass por veredictos inválidos/no_evaluado (regla d) y por
    falsos positivos críticos o altos (regla a). Nunca convierte nada en pass.

    Regla (a): si el FP de la IA quitó el único hallazgo efectivo, estado.calcular puede dejar el control en pass o,
    con alcance 0 de la herramienta completa, en no_aplica (sin_alcance del catálogo). Ambos cuentan como OK en gates,
    así que los dos se degradan a no_evaluado; un fail (otro hallazgo efectivo) no se toca. El motivo del FP va
    primero para que el recorte a 300 caracteres no lo borre (render_informe/roadmap lo reconocen por su texto)."""
    criticos = res.get("fp_criticos") or {}
    graves = res.get("fp_graves") or {}
    for reg in controles:
        cid = reg["control"]
        ids = graves.get(cid) or criticos.get(cid)   # res sin fp_graves (anterior a F3-C alto): solo críticos
        motivo_fp = None
        if ids:
            etiqueta = "crítico" if cid in criticos else "alto"
            motivo_fp = (f"falso positivo {etiqueta} según IA ({', '.join(ids[:3])}): requiere verificación "
                         "humana; no hay pass sin ella")
            if reg["estado"] == "no_evaluado" and (reg.get("motivo") or "").startswith(motivo_fp):
                continue   # ya ajustado (idempotente): ni la rama forzar ni la FP vuelven a anteponer nada
        if ids and reg["estado"] in ESTADOS_OK_FP:
            reg.update(estado="no_evaluado", herramienta=None, motivo=None)   # el motivo FP se pone abajo
        if cid in res.get("forzar", {}):
            motivo = res["forzar"][cid]
            if reg["estado"] == "pass":
                reg.update(estado="no_evaluado", herramienta=None, motivo=_recortar(motivo))
            elif reg["estado"] == "no_evaluado":
                previo = reg.get("motivo") or ""
                reg["motivo"] = _recortar(f"{motivo}; {previo}" if previo else motivo)
        # D2 (investigacion/18, DECISIONES.md #10): el control puede quedar no_evaluado por OTRA causa (herramienta
        # sin datos, cobertura parcial, veredicto forzado). gates.py solo reconoce el bloqueo pendiente_ia si el motivo
        # EMPIEZA por la frase FP (roadmap.es_motivo_fp_ia), así que va primero y el motivo previo queda detrás; el
        # recorte a 300 corta por el final. Un fail (otro hallazgo efectivo) no se toca; manual_pendiente tampoco.
        if motivo_fp and reg["estado"] == "no_evaluado":
            previo = reg.get("motivo") or ""
            reg["motivo"] = _recortar(f"{motivo_fp}; {previo}" if previo else motivo_fp)


def ajustar_pendientes(controles, perfil):
    """Pregunta de la entrevista sin respuesta → sus controles no quedan en pass (perfil.json)."""
    pend = pendientes_entrevista(perfil)
    for reg in controles:
        if reg["control"] in pend and reg["estado"] == "pass":
            reg.update(estado="no_evaluado", herramienta=None, motivo=_recortar(
                f"falta respuesta a la pregunta {', '.join(pend[reg['control']])} de la entrevista (perfil.json): "
                "no se asume la respuesta"))


def registrar(corrida, res, controles):
    """Escribe decisiones_ia.json y hallazgos_ia.jsonl (o los borra si no hay veredictos)."""
    corrida = Path(corrida)
    if res is None:
        for n in (DECISIONES, HALLAZGOS_IA):
            (corrida / n).unlink(missing_ok=True)
        return
    final = {c["control"]: c for c in controles}
    for a in res["aplicadas"]:
        reg = final.get(a["control"])
        a["estado_final"] = reg["estado"] if reg else None
        if a["veredicto"] == "pass" and reg and reg["estado"] != "pass":
            a["efecto"] = (f"pass de IA sin efecto: el control quedó {reg['estado']} (la parte determinista no "
                           "corrió, otra regla lo impidió o hay pendientes)")
    omitidos = [{"juicio": o["juicio"], "agente": o["agente"], "motivo": o["motivo"],
                 "controles": [{"control": cid, "veredicto": "no_evaluado", "motivo": o["motivo"],
                                "estado_final": (final.get(cid) or {}).get("estado")} for cid in o["controles"]]}
                for o in res.get("omitidos") or []]
    datos = {"version_esquema": "1",
             "resumen": {"aplicadas": len(res["aplicadas"]), "descartadas": len(res["descartadas"]),
                         # aplicadas = juicios de la IA + entradas sintéticas del auditor (graves fuera del digest de
                         # triage por el tope: cuentan como verdaderos). Se informan por separado.
                         "aplicadas_ia": sum(1 for a in res["aplicadas"] if not _es_sintetica(a)),
                         "sin_juzgar_por_tope": sum(1 for a in res["aplicadas"] if _es_sintetica(a)),
                         "pases_ia": sorted(c for c, x in final.items() if x.get("herramienta") in JUICIO
                                            and x["estado"] == "pass"),
                         "hallazgos_ia": len(res["hallazgos_ia"]),
                         "jueces_omitidos": [o["juicio"] for o in omitidos]},
             "aplicadas": res["aplicadas"], "descartadas": res["descartadas"], "triage": res["triage"],
             "jueces_omitidos": omitidos}
    utiles.escribir_json(corrida / DECISIONES, datos)
    utiles.escribir_jsonl(corrida / HALLAZGOS_IA, res["hallazgos_ia"])


def hallazgos_para_gates(corrida, hallazgos):
    """Hallazgos con el triage de la IA aplicado + hallazgos_ia (para gates.py y el informe)."""
    corrida = Path(corrida)
    hallazgos = marcar_fp_humanos(corrida, hallazgos)
    dec = utiles.leer_json(corrida / DECISIONES)
    if not isinstance(dec, dict):
        return hallazgos
    triage = dec.get("triage") or {}
    res = []
    for h in hallazgos:
        t = triage.get(h["id"])
        if t and not h.get("verificacion_humana"):
            h = dict(h, triage=t)
            if t.get("veredicto") == "falso_positivo":
                h["estado_hallazgo"] = "falso_positivo"
        res.append(h)
    return res + utiles.leer_jsonl(corrida / HALLAZGOS_IA)


# --- H-2: falsos positivos verificados por una persona (DECISIONES.md #11) -------------------------------------
FP_HUMANO_REL = ".auditor-integral/fp-verificados.json"   # en la raíz del proyecto auditado; lo escribe la persona
FP_HUMANOS = "fp_humanos.json"                            # registro en la corrida (lo escribe estado.py)
TOPE_FP_HUMANO_BYTES = 256 * 1024
CAMPOS_FP_HUMANO = ("control", "huella", "quien", "fecha", "conclusion")
RE_HUELLA = re.compile(r"^(H-[0-9a-f]{6,64}|[0-9a-f]{16,64})$")
RE_CONTROL = re.compile(r"^(SEG|DAT|COD|UX|INF|ESC|OPS)-[A-Z0-9+-]+$")
# «quien» debe ser una persona: se rechazan la IA, modelos y agentes del auditor (fail-closed ante una entrada que la
# propia IA hubiera escrito firmando como ella).
RE_QUIEN_IA = re.compile(r"(?i)(^|[^a-z0-9])(ia|ai|llm|gpt[-a-z0-9]*|claude[-a-z0-9]*|anthropic|openai|gemini|"
                         r"modelo|model|agente|agent|bot|subagente|auditor(-integral)?|triage-fp|revisor-[a-z-]+|"
                         r"redactor-dueno)($|[^a-z0-9])")
ETIQUETA_FP_HUMANO = "descartado por verificación humana"
RE_QUIEN = re.compile(r"^[^\W\d_](?:[^\W\d_]|[ .,'’-]){1,119}$")   # nombre: va a motivos de estado.json e informes


def _fecha_iso(x):
    if not isinstance(x, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", x):
        return None
    try:
        return dt.date.fromisoformat(x)
    except ValueError:
        return None


# Quién autoriza el registro: el OPERADOR del auditor (bin/auditar --fp-verificados RUTA → esta variable), nunca el
# repositorio auditado. Un fp-verificados.json que trae el propio proyecto es una autoatestación del repo (lo pudo
# versionar su autor o escribirlo cualquier proceso): sin la autorización explícita del operador NO se aplica, solo se
# avisa (revisión adversarial, 2026-11-20).
ENV_FP_HUMANO = "AUDITOR_FP_VERIFICADOS"
MOTIVO_SIN_AUTORIZAR = (f"el proyecto trae {FP_HUMANO_REL}, pero NO se aplicó: un registro dentro del repositorio "
                        "auditado no prueba que lo haya escrito una persona. El operador del auditor debe "
                        "autorizarlo con 'bin/auditar … --fp-verificados RUTA' (DECISIONES.md #11)")


def fuente_fp_humanos():
    """Ruta del registro que autorizó el operador (--fp-verificados → AUDITOR_FP_VERIFICADOS), o None."""
    v = os.environ.get(ENV_FP_HUMANO, "").strip()
    return Path(v) if v else None


def _nombre_fuente(ruta, proyecto):
    """Nombre del registro para informes y avisos: relativo al proyecto si está dentro; si no, solo el nombre
    del archivo (no se escriben rutas absolutas de la máquina del operador)."""
    try:
        if proyecto is not None:
            return Path(os.path.abspath(ruta)).relative_to(os.path.abspath(proyecto)).as_posix()
    except ValueError:
        pass
    return f"(fuera del proyecto) {Path(ruta).name}"


def cargar_fp_humanos(proyecto, fecha_ref=None, secretos=(), ruta=None):
    """(entradas_validas, ignoradas, existe) del registro de falsos positivos verificados por una persona.
    ruta=None: <proyecto>/.auditor-integral/fp-verificados.json (función pura; quien decide si se APLICA es
    _registro_fp). ignoradas: [{entrada, motivo}] (entrada = nº 1-based o None si es el archivo entero). Nunca lanza."""
    if ruta is None:
        if proyecto is None:
            return [], [], False
        carpeta = Path(proyecto) / ".auditor-integral"
        ruta = carpeta / "fp-verificados.json"
        nombre = FP_HUMANO_REL
        if not (carpeta.exists() or carpeta.is_symlink()):
            return [], [], False
        if carpeta.is_symlink() or ruta.is_symlink():
            return [], [{"entrada": None, "motivo": f"{nombre} es (o está bajo) un enlace simbólico: se ignora"}], True
        if not ruta.exists():
            return [], [], False
    else:
        ruta = Path(ruta)
        nombre = _nombre_fuente(ruta, proyecto)
        if ruta.is_symlink() or ruta.parent.is_symlink():
            return [], [{"entrada": None, "motivo": f"{nombre} es (o está bajo) un enlace simbólico: se ignora"}], True
        if not ruta.exists():
            return [], [{"entrada": None, "motivo": f"{nombre} no existe: no se descarta nada"}], True
    if not ruta.is_file():
        return [], [{"entrada": None, "motivo": f"{nombre} no es un archivo regular: se ignora"}], True
    try:
        if ruta.stat().st_size > TOPE_FP_HUMANO_BYTES:
            return [], [{"entrada": None, "motivo": f"{nombre} supera {TOPE_FP_HUMANO_BYTES} bytes: se ignora"}], True
        datos = json.loads(ruta.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeDecodeError):
        return [], [{"entrada": None, "motivo": f"{nombre} no es JSON legible: se ignora entero"}], True
    entradas = datos.get("entradas") if isinstance(datos, dict) else None
    if not isinstance(entradas, list):
        return [], [{"entrada": None, "motivo": f"{nombre} no tiene la lista «entradas»: se ignora"}], True
    limite = _fecha_iso(fecha_ref) if fecha_ref else None

    def txt(t, n):
        return _recortar(enmascarar.enmascarar_texto(utiles.una_linea(str(t)).strip(), secretos), n)

    validas, ignoradas, vistas = [], [], set()
    for i, e in enumerate(entradas, 1):
        if not isinstance(e, dict):
            ignoradas.append({"entrada": i, "motivo": "no es un objeto"})
            continue
        faltan = [k for k in CAMPOS_FP_HUMANO if not (isinstance(e.get(k), str) and e[k].strip())]
        if faltan:
            ignoradas.append({"entrada": i, "motivo": f"entrada incompleta: falta {', '.join(faltan)}"})
            continue
        control, huella = e["control"].strip(), e["huella"].strip()
        fecha = _fecha_iso(e["fecha"].strip())
        if not RE_CONTROL.match(control):
            ignoradas.append({"entrada": i, "motivo": "control con formato inválido"})
        elif not RE_HUELLA.match(huella):
            ignoradas.append({"entrada": i, "motivo": "huella inválida (use el id H-… del informe o el fingerprint)"})
        elif fecha is None:
            ignoradas.append({"entrada": i, "motivo": "fecha inválida (formato AAAA-MM-DD, fecha real)"})
        elif limite is not None and fecha > limite:
            ignoradas.append({"entrada": i, "motivo": f"fecha posterior a la corrida ({fecha_ref})"})
        elif not RE_QUIEN.match(e["quien"].strip()):
            ignoradas.append({"entrada": i, "motivo": "«quien» debe ser un nombre de persona (letras, espacios, . , ' -; "
                                                      "máx. 120)"})
        elif RE_QUIEN_IA.search(e["quien"]):
            ignoradas.append({"entrada": i, "motivo": "«quien» nombra a la IA o a un agente: solo vale una persona"})
        elif "ubicacion" in e and e["ubicacion"] is not None and not (
                isinstance(e["ubicacion"], str) and RE_UBIC.match(e["ubicacion"].strip())):
            ignoradas.append({"entrada": i, "motivo": "ubicación inválida (formato archivo:línea)"})
        elif (control, huella) in vistas:
            ignoradas.append({"entrada": i, "motivo": "entrada duplicada (misma huella y control): vale la primera"})
        else:
            vistas.add((control, huella))
            ubic = e.get("ubicacion").strip() if isinstance(e.get("ubicacion"), str) else None
            validas.append({"entrada": i, "control": control, "huella": huella, "ubicacion": ubic,
                            "quien": txt(e["quien"], 120), "fecha": fecha.isoformat(),
                            "conclusion": txt(e["conclusion"], 300)})
    return validas, ignoradas, True


def _lugar_h(h):
    u = h.get("ubicacion") or {}
    if not u.get("archivo"):
        return None
    return f"{_canon(u['archivo'])}:{u['linea']}" if isinstance(u.get("linea"), int) else _canon(u["archivo"])


def _coincide_huella(h, huella):
    return huella in (h.get("id"), h.get("fingerprint"))


def _proyecto_de(corrida):
    p = utiles.leer_run(corrida).get("proyecto")
    return Path(p) if p and Path(p).is_dir() else None


def hay_registro_fp(corrida):
    """¿Puede haber descartes humanos en esta corrida? (fuente autorizada o archivo en el proyecto)."""
    proyecto = _proyecto_de(corrida)
    return fuente_fp_humanos() is not None or bool(
        proyecto and ((proyecto / ".auditor-integral").exists() or (proyecto / ".auditor-integral").is_symlink()))


def _registro_fp(corrida, hallazgos):
    """(hallazgos_marcados, registro|None) SIN escribir nada. Es la única fuente de verdad del descarte humano: la usan
    estado.py (aplicar_fp_humanos) y, en cada report, el informe y la hoja de ruta (leer_fp_humanos), que nunca
    confían en <corrida>/fp_humanos.json tal como está en disco (la corrida es zona de escritura de la IA)."""
    corrida = Path(corrida)
    proyecto = _proyecto_de(corrida)
    fuente = fuente_fp_humanos()
    if fuente is None:
        _, _, en_proyecto = cargar_fp_humanos(proyecto)
        if not en_proyecto:
            return hallazgos, None
        return hallazgos, {"version_esquema": "1", "archivo": FP_HUMANO_REL, "autorizado": False, "aplicadas": [],
                           "ignoradas": [{"entrada": None, "motivo": MOTIVO_SIN_AUTORIZAR}], "huerfanas": []}
    validas, ignoradas, _ = cargar_fp_humanos(proyecto, utiles.fecha_referencia(corrida),
                                              enmascarar.secretos_de_corrida(corrida), ruta=fuente)
    res = [dict(h) for h in hallazgos]
    aplicadas, huerfanas = [], []
    for e in validas:
        mismos = [h for h in res if _coincide_huella(h, e["huella"])]
        del_control = [h for h in mismos if h.get("control") == e["control"]]
        motivo = None
        if not mismos:
            motivo = ("la huella ya no coincide con ningún hallazgo de esta corrida (¿se corrigió o cambió el "
                      "código?): no se descarta nada")
            if e["ubicacion"]:
                otros = [h for h in res if h.get("control") == e["control"] and _lugar_h(h) == _canon_ubic(e["ubicacion"])]
                if otros:
                    motivo = (f"en {e['ubicacion']} hay un hallazgo distinto ({', '.join(sorted(h['id'] for h in otros)[:3])}): "
                              "no se descarta; requiere una verificación nueva")
        elif not del_control:
            motivo = f"la huella es de otro control ({mismos[0].get('control')}), no de {e['control']}: no se descarta"
        else:
            if e["ubicacion"]:
                fuera = [h for h in del_control if _lugar_h(h) != _canon_ubic(e["ubicacion"])]
                if fuera:
                    motivo = (f"la ubicación registrada ({e['ubicacion']}) ya no coincide con la del hallazgo "
                              f"({_lugar_h(fuera[0]) or 'sin archivo'}): no se descarta; vuelva a verificar")
        if motivo:
            huerfanas.append({"entrada": e["entrada"], "control": e["control"], "huella": e["huella"],
                              "motivo": motivo})
            continue
        vh = {"quien": e["quien"], "fecha": e["fecha"], "conclusion": e["conclusion"]}
        for h in del_control:
            h["estado_hallazgo"] = "falso_positivo"
            h["verificacion_humana"] = vh
        aplicadas.append({"entrada": e["entrada"], "control": e["control"], "huella": e["huella"],
                          "hallazgos": sorted({h["id"] for h in del_control}),
                          "ubicaciones": sorted({x for x in (_lugar_h(h) for h in del_control) if x}),
                          "severidades": sorted({h.get("severidad") for h in del_control if h.get("severidad")},
                                                key=utiles.rango_severidad),
                          **vh})
    registro = {"version_esquema": "1", "archivo": _nombre_fuente(fuente, proyecto), "autorizado": True,
                "aplicadas": aplicadas, "ignoradas": ignoradas, "huerfanas": huerfanas}
    return res, registro


def _n_graves(registro):
    return sum(1 for a in (registro or {}).get("aplicadas") or []
               if {"critica", "alta"} & set(a.get("severidades") or []))


def aplicar_fp_humanos(corrida, hallazgos):
    """(hallazgos, registro). Marca falso_positivo + verificacion_humana los hallazgos que la persona registró (solo
    desde la fuente que autorizó el operador) y escribe <corrida>/fp_humanos.json como constancia (lo borra si no hay
    registro). Siempre avisa por stderr cuántos descartes se aplicaron y de qué archivo. registro=None sin archivo."""
    corrida = Path(corrida)
    res, registro = _registro_fp(corrida, hallazgos)
    if registro is None:
        (corrida / FP_HUMANOS).unlink(missing_ok=True)
        return hallazgos, None
    utiles.escribir_json(corrida / FP_HUMANOS, registro)
    if registro["autorizado"]:
        print(f"fp-verificados: {len(registro['aplicadas'])} descarte(s) humano(s) aplicado(s) "
              f"({_n_graves(registro)} de severidad crítica/alta) desde {registro['archivo']}, autorizado por el "
              "operador (--fp-verificados); no son pass", file=sys.stderr)
    for x in registro["ignoradas"]:
        print(f"fp-verificados: entrada {x['entrada'] or '(archivo)'} ignorada: {x['motivo']}", file=sys.stderr)
    for x in registro["huerfanas"]:
        print(f"fp-verificados: entrada {x['entrada']} huérfana ({x['control']}): {x['motivo']}", file=sys.stderr)
    return res, registro


def _canon_ubic(u):
    m = RE_UBIC.match(str(u or "").strip())
    return f"{_canon(m.group(1))}:{int(m.group(2))}" if m else None


def _clave_registro(r):
    if not isinstance(r, dict) or not isinstance(r.get("aplicadas"), list):
        return None
    return sorted((str(a.get("control")), str(a.get("huella")), tuple(sorted(map(str, a.get("hallazgos") or []))))
                  for a in r["aplicadas"] if isinstance(a, dict))


def leer_fp_humanos(corrida):
    """Registro de descartes humanos RECALCULADO desde la fuente autorizada (nunca el <corrida>/fp_humanos.json tal como
    está: la corrida es zona de escritura de la IA). Si el archivo de la corrida no coincide con el recálculo, el
    registro trae «discrepancia» (el informe lo avisa). None si no hay nada que mostrar."""
    corrida = Path(corrida)
    hallazgos = utiles.leer_jsonl(corrida / "hallazgos_todos.jsonl") or utiles.leer_jsonl(corrida / "hallazgos.jsonl")
    _, r = _registro_fp(corrida, hallazgos)
    en_disco = utiles.leer_json(corrida / FP_HUMANOS) if (corrida / FP_HUMANOS).exists() else None
    if en_disco is not None and _clave_registro(en_disco) != _clave_registro(r or {"aplicadas": []}):
        r = dict(r) if r else {"version_esquema": "1", "archivo": FP_HUMANO_REL, "autorizado": False,
                               "aplicadas": [], "ignoradas": [], "huerfanas": []}
        r["discrepancia"] = (f"<corrida>/{FP_HUMANOS} no coincide con el registro recalculado desde la fuente "
                             "autorizada: se ignora (pudo editarse a mano o corresponder a otra autorización); "
                             "este informe usa solo el recálculo")
    return r


def marcar_fp_humanos(corrida, hallazgos):
    """Copia de los hallazgos con la verificación humana recalculada aplicada (roadmap, informe)."""
    r = leer_fp_humanos(corrida)
    if not r:
        return hallazgos
    por_id = {}
    for a in r["aplicadas"]:
        if isinstance(a, dict):
            for hid in a.get("hallazgos") or []:
                por_id.setdefault(hid, {"quien": a.get("quien"), "fecha": a.get("fecha"),
                                        "conclusion": a.get("conclusion")})
    res = []
    for h in hallazgos:
        vh = por_id.get(h.get("id"))
        res.append(dict(h, estado_hallazgo="falso_positivo", verificacion_humana=vh) if vh else h)
    return res


def controles_sin_respaldo(registro, controles):
    """Controles que estado.json trae como descarte_humano sin una entrada aplicada en el registro recalculado."""
    con = {a.get("control") for a in (registro or {}).get("aplicadas") or [] if isinstance(a, dict)}
    return sorted(c["control"] for c in controles or [] if c.get("descarte_humano") and c["control"] not in con)


def aviso_fp_humanos(corrida, controles):
    """Línea de cabecera del informe: cuántos descartes humanos se aplicaron, de qué archivo y si algo no cuadra."""
    r = leer_fp_humanos(corrida)
    sin_respaldo = controles_sin_respaldo(r, controles)
    partes = []
    if r and r.get("autorizado") and r["aplicadas"]:
        partes.append(f"> **Descartes humanos aplicados: {len(r['aplicadas'])}** ({_n_graves(r)} de severidad "
                      f"crítica o alta), desde `{_celda(r.get('archivo'))}`, autorizado por el operador con "
                      "`--fp-verificados`. No son pass: ver sección 6c.")
    elif r and not r.get("autorizado") and any(x.get("motivo") == MOTIVO_SIN_AUTORIZAR for x in r["ignoradas"]):
        partes.append(f"> **El proyecto trae `{FP_HUMANO_REL}` y NO se aplicó**: un registro dentro del repositorio "
                      "auditado no prueba que lo haya escrito una persona. Los hallazgos siguen abiertos (sección 6c).")
    if r and r.get("discrepancia"):
        partes.append(f"> **Aviso:** {_celda(r['discrepancia'])}.")
    if sin_respaldo:
        partes.append(f"> **Aviso:** estado.json trae descartes humanos que este informe no pudo re-verificar "
                      f"({_celda(', '.join(sin_respaldo[:10]))}). Vuelva a correr `auditar gates` (o `all`) con "
                      "`--fp-verificados` o sin él; mientras tanto, no confíe en el nivel de esos controles.")
    return "\n>\n".join(partes)


def ajustar_fp_humanos(controles, registro, indice):
    """Estado propio del control cuyos hallazgos descartó una persona (ver docstring del módulo). Nunca produce pass."""
    if not registro:
        return
    por_control = {}
    for a in registro.get("aplicadas") or []:
        por_control.setdefault(a["control"], []).append(a)
    for reg in controles:
        lista = por_control.get(reg["control"])
        c = indice.get(reg["control"]) or {}
        if not lista or c.get("aplicabilidad") == "no_aplica" or c.get("aviso_legal"):
            continue
        firmas = sorted({f"{a['quien']}, {a['fecha']}" for a in lista})
        etiqueta = f"{ETIQUETA_FP_HUMANO} ({'; '.join(firmas[:2])}{'; …' if len(firmas) > 2 else ''})"
        ids = sorted({hid for a in lista for hid in a["hallazgos"]})
        if reg["estado"] in ESTADOS_OK_FP:
            reg.update(estado="no_aplica", herramienta=None, motivo=_recortar(
                f"{etiqueta}: {lista[0]['conclusion']} — no es pass; deja de bloquear el nivel"))
            reg["descarte_humano"] = {"quien": lista[0]["quien"], "fecha": lista[0]["fecha"],
                                      "conclusion": lista[0]["conclusion"], "hallazgos": ids[:20],
                                      "entradas": len(lista)}
        else:
            # fail (quedan otros hallazgos), no_evaluado o manual_pendiente por otra causa: no cambia el estado; la nota
            # va al FINAL para no tapar un motivo que gates.py lee por su inicio (bloqueo pendiente_ia).
            previo = reg.get("motivo") or ""
            nota = f"{len(ids)} hallazgo(s) {etiqueta}; el control sigue {reg['estado']} por otra causa"
            reg["motivo"] = _recortar(f"{previo}; {nota}" if previo else nota)


def seccion_fp_humanos(corrida, md=True):
    """Markdown de la sección 6c del informe (y base de la hoja de ruta)."""
    r = leer_fp_humanos(corrida)
    formato = ("Para registrar uno, la **persona** que lo verificó escribe un archivo JSON (por ejemplo "
               f"`{FP_HUMANO_REL}`, o uno fuera del proyecto) con `{{\"version\": \"1\", \"entradas\": "
               "[{\"control\": …, \"huella\": \"H-…\" (id de la sección 6), \"ubicacion\": \"archivo:línea\" "
               "(opcional), \"quien\": …, \"fecha\": \"AAAA-MM-DD\", \"conclusion\": …}]}` y el **operador** vuelve "
               "a correr la auditoría con `--fp-verificados RUTA` (sin ese flag no se aplica, aunque el archivo esté en "
               "el proyecto). La IA y los agentes nunca escriben ese archivo ni pasan el flag por su cuenta; un control "
               "descartado así no queda en pass (no suma puntaje), solo deja de bloquear el nivel. Una entrada cuya "
               "huella ya no coincide se avisa como huérfana.")
    if not r:
        return "No hay falsos positivos verificados por una persona en esta corrida. " + formato
    partes = []
    if r["aplicadas"]:
        partes.append("| Control | Hallazgos | Ubicación | Quién | Fecha | Conclusión |\n|---|---|---|---|---|---|")
        for a in r["aplicadas"]:
            partes.append(f"| {_celda(a.get('control'))} | {_celda(', '.join(a.get('hallazgos') or []))} | "
                          f"{_celda(', '.join(a.get('ubicaciones') or [])) or '—'} | {_celda(a.get('quien'))} | "
                          f"{_celda(a.get('fecha'))} | {_celda(a.get('conclusion'))} |")
    else:
        partes.append("Ninguna entrada se aplicó.")
    avisos = ([f"- entrada {x.get('entrada') or '(archivo)'} ignorada: {_celda(x.get('motivo'))}" for x in r["ignoradas"]]
              + [f"- entrada {x.get('entrada')} huérfana ({_celda(x.get('control'))}, {_celda(x.get('huella'))}): "
                 f"{_celda(x.get('motivo'))}" for x in r["huerfanas"]])
    if r.get("discrepancia"):
        avisos.append(f"- {_celda(r['discrepancia'])}")
    if avisos:
        partes.append(f"\n**Avisos del registro `{_celda(r.get('archivo') or FP_HUMANO_REL)}` ({len(avisos)}).** "
                      "No descartaron nada:\n")
        partes.extend(avisos)
    partes.append("\n" + formato)
    return "\n".join(partes)


def _celda(t):
    """Texto de IA o del repo auditado como literal Markdown: sin tablas rotas, enlaces ni HTML (F3-C adv.)."""
    return utiles.md_literal(str(t or "")).replace("|", "\\|").replace("\n", " ")


def seccion_informe(corrida):
    """Markdown de «Decisiones de la IA», separado de las decisiones deterministas."""
    dec = utiles.leer_json(Path(corrida) / DECISIONES)
    if not isinstance(dec, dict):
        return ("No hubo veredictos de IA en esta corrida (no existe veredictos.jsonl): todos los estados de este "
                "informe son deterministas.")
    partes = ["**BORRADOR — juicio de IA.** Estas decisiones las tomó un modelo sobre un digest acotado y ya "
              "enmascarado; los scripts las validaron con reglas duras (un fail determinista solo cambia con "
              "falso_positivo + razón + archivo:línea; 'incierto' cuenta como verdadero; un pass exige evidencia "
              "archivo:línea y método). Requieren verificación humana."]
    ap = dec.get("aplicadas") or []
    if ap:
        partes.append("\n| Control | Agente | Veredicto | Efecto | Estado final | Evidencia | Razón |\n"
                      "|---|---|---|---|---|---|---|")
        for a in ap:
            ref = f" ({a['hallazgo_id']})" if a.get("hallazgo_id") else ""
            partes.append(f"| {a['control']}{ref} | {_celda(a.get('agente'))} | {a['veredicto']} | "
                          f"{_celda(a.get('efecto'))} | {a.get('estado_final') or '—'} | "
                          f"{_celda(', '.join(a.get('ubicaciones') or [])) or '—'} | {_celda(a.get('razon'))} |")
    else:
        partes.append("\nNinguna decisión de la IA se aplicó.")
    om = dec.get("jueces_omitidos") or []
    if om:
        partes.append("\n**Jueces omitidos o no lanzados (0 tokens).** El digest no traía nada que juzgar, le "
                      "faltaba su entrada esencial o el modo no lanza ese juez; sus controles quedan no_evaluado "
                      "(nunca pass):\n")
        for o in om:
            ctrls = ", ".join(x.get("control", "") for x in o.get("controles") or []) or "—"
            partes.append(f"- {_celda(o.get('agente'))} ({_celda(o.get('motivo'))}): {_celda(ctrls)}")
    de = dec.get("descartadas") or []
    if de:
        partes.append(f"\n**Veredictos descartados ({len(de)}).** No cambiaron ningún estado a favor; si nombraban un "
                      "control del dominio del agente, ese control quedó no_evaluado.\n")
        for d in de:
            partes.append(f"- línea {d.get('linea')}: {_celda(d.get('control') or 's/control')} "
                          f"({_celda(d.get('agente') or 's/agente')}) — {_celda(d.get('motivo'))}")
    return "\n".join(partes)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Valida y aplica veredictos.jsonl; recalcula estado y gates")
    ap.add_argument("corrida_pos", nargs="?", metavar="DIR_CORRIDA")
    ap.add_argument("--corrida")
    a = ap.parse_args(argv)
    corrida = a.corrida or a.corrida_pos
    if not corrida or not Path(corrida).is_dir():
        print("veredictos.py: indique una carpeta de corrida existente", file=sys.stderr)
        return 2
    if not (Path(corrida) / ARCHIVO).is_file():
        print(f"veredictos.py: no existe {ARCHIVO} en la corrida (los subagentes no emitieron veredictos)",
              file=sys.stderr)
        return 2
    import gates
    g = gates.generar(corrida)
    dec = utiles.leer_json(Path(corrida) / DECISIONES) or {}
    r = dec.get("resumen") or {}
    print(f"veredictos: {r.get('aplicadas_ia', r.get('aplicadas', 0))} juicios de IA aplicados, "
          f"{r.get('sin_juzgar_por_tope', 0)} graves sin juzgar por el tope de triage (cuentan como verdaderos), "
          f"{r.get('descartadas', 0)} descartados, "
          f"pass por IA: {', '.join(r.get('pases_ia') or []) or 'ninguno'}; global demostrado "
          f"{g['global']['nivel_demostrado']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Estado por control de una corrida → estado.json (PLAN_MAESTRO §3.5; valida contra estado.schema.json).

Uso:  estado.py DIR_CORRIDA   |   estado.py --corrida DIR_CORRIDA

Reglas (en este orden, para cada control del catálogo con la severidad contextual del perfil):
  no_aplica         la condición del control es falsa para el perfil.
  fail              ≥ 1 hallazgo efectivo: abierto, o aceptado sin aceptación válida (falta la
                    firma, venció, o es crítico de N1, que nunca se acepta). falso_positivo no cuenta.
  no_evaluado       gate fuera del alcance del modo (rapido ≤ N2, estandar ≤ N4, profundo ≤ N5).
  manual_pendiente  método manual.
  no_evaluado       método llm ("juicio LLM no ejecutado en F1"); componente de entrevista sin
                    respuesta; herramienta ausente, con error, timeout o sin red; o mixto con agente
                    LLM cuya parte determinista no tuvo hallazgos (falta el juicio).
  pass              solo con evidencia positiva, según `evidencia_pass` del control (sin «pases vacíos»):
                    - "ausencia_suficiente": una herramienta completa del control corrió ok sin hallazgos Y
                      analizó ≥ 1 objeto relevante (`alcance_requerido` = ["herramienta.clave"], leído de
                      meta.alcance). Alcance 0 → `sin_alcance` (no_aplica | no_evaluado) con
                      `motivo_sin_alcance` (p. ej. SEG-SECRETO-BUNDLE «sin bundle»); alcance no registrado →
                      no_evaluado (fail-closed). `alcance_condicional` = [{requiere, si, motivo}]: si la clave `si`
                      es > 0 (p. ej. gitleaks.commits), `requiere` (gitleaks.historial) también debe ser > 0; si `si`
                      no está registrada y `requiere` no es > 0 → no_evaluado (fail-closed).
                      Ronda 2: `alcance_excluyente` = [{clave, motivo}]: si la clave (p. ej.
                      semgrep.fuentes_sin_reglas) es > 0, hay objetos relevantes que la herramienta no cubre →
                      no_evaluado (nunca pass), aunque el alcance requerido sea > 0.
                    - "checks_pass" (default si falta el campo, fail-closed; también con el antiguo
                      `exige_checks_pass = true`): solo vale un pase explícito en checks_pass; que la
                      herramienta corra ok deja no_evaluado. Ronda 2: con `pases_requeridos` (patrones fnmatch)
                      hace falta un pase para CADA uno (lógica AND); si falta alguno → no_evaluado con la lista.
                    - "no_demostrable_estatico": nunca pasa en análisis estático; queda no_evaluado con el
                      motivo MOTIVO_NO_DEMOSTRABLE (lo resolverían F3 revisores, F4 sondas o la entrevista).
                    En las tres, un hallazgo sigue dando fail.
                    Ronda 3: `pass_contradicho_por` = [{control, motivo}]: si ese otro control tiene hallazgos
                    efectivos en la corrida, este no queda en pass (no_evaluado con el motivo); p. ej. una inyección
                    SQL (DAT-SQL-CONCATENADO) contradice el pass de SEG-SAST-INY. Una clave de `alcance_excluyente`
                    no registrada bloquea el pass (fail-closed).
`herramientas` del catálogo son alternativas ("la primera disponible"): basta una que haya
corrido ok; los agentes LLM y la entrevista, en cambio, son componentes requeridos.
Excepción (corrección post-verificación): las `herramientas_parciales` del control solo cubren una
parte (p. ej. semgrep en SEG-SECRETO-BUNDLE detecta service_role, no sk_live/AKIA en dist/): sus
hallazgos producen fail, pero no bastan para declarar pass; hace falta una herramienta completa ok.
Fail-closed: si la fase normalize no corrió (falta normalizacion.json) o terminó con error según
run.json, ningún control determinista pasa (quedan no_evaluado). Un crudo sin su meta no cuenta
como herramienta ok. Un fail fuera del alcance del modo se informa igual (la evidencia no se
oculta), pero el motivo lo declara.
Interpretación declarada: con aplicabilidad desconocida (falta una respuesta de la entrevista)
un `pass` determinista se mantiene, pero el motivo lo advierte.
Controles con `aviso_legal` (DECISIONES.md #4): nunca quedan en pass (el auditor no afirma
cumplimiento): con un hallazgo, fail; si no, manual_pendiente hasta que el creador confirme, en cualquier
modo y aunque la aplicabilidad sea desconocida. Si perfil.json declara datos_personales = false (y no
declara salud ni menores = true), pasan a no_aplica con el motivo "el creador declaró que no usa datos
personales" y la fecha de la declaración (perfil.json → declaraciones.datos_personales.fecha si existe;
si no, la fecha de la corrida en que se leyó). No entran en el nivel: ver gates.py.
UX-SUS-68 (`exigido_sin_condicion`, DECISIONES.md #5): sin datos SUS con usuarios reales queda
manual_pendiente con un motivo explícito; N4 de UX no se otorga sin él.
F3 (veredictos.py): si existe veredictos.jsonl, sus decisiones validadas se aplican aquí: falsos positivos con razón
y archivo:línea, hallazgos de IA (fail/incierto) y pases de IA solo en controles llm/mixto (pases_ia). Una pregunta
de la entrevista sin respuesta (perfil.json → pendientes_entrevista) deja sus controles fuera de pass.
H-2 (DECISIONES.md #11): <proyecto>/.auditor-integral/fp-verificados.json (lo escribe una persona) descarta hallazgos
verificados como falsos positivos; el control sin otros hallazgos queda no_aplica con motivo «descartado por
verificación humana (quién, fecha)» y descarte_humano (no es pass). Reglas en veredictos.py.
Sin marcas de tiempo ni duraciones (criterio F1-3: mismos bytes en dos corridas).
"""
import argparse
import fnmatch
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import catalogo  # noqa: E402
import utiles  # noqa: E402

AGENTES_LLM = {"triage-fp", "fp-check", "redactor-dueno", "auditar-perfil"}
COMPONENTES_ENTREVISTA = {"entrevista"}
COMPONENTES_MANUALES = {"auditar-sus"}
MOTIVO_LLM = "juicio LLM no ejecutado en F1"
MOTIVO_LEGAL = ("aviso legal: verificación pendiente del creador (no bloquea el nivel; el auditor no afirma "
                "cumplimiento; DECISIONES.md #4)")
MOTIVO_SUS = ("sin datos SUS con usuarios reales: se exige SUS promedio >= 68 para N4, sin condición y también "
              "en herramientas internas (DECISIONES.md #5); N4 no se otorga hasta medirlo")
DECLARACION_SIN_DATOS = "el creador declaró que no usa datos personales"
EVIDENCIA_DEFECTO = "checks_pass"   # fail-closed si el control no declara evidencia_pass
MOTIVO_NO_DEMOSTRABLE = ("no demostrable en análisis estático: requiere juicio LLM / sonda dinámica / entrevista "
                         "(lo resolverían F3 revisores, F4 sondas o la entrevista)")
REGLA_INVENTARIO = "detectar_stack:inventario"
TEXTO_ESTADO_HERR = {"ausente": "herramienta ausente", "error": "la herramienta terminó con error",
                     "timeout": "timeout de la herramienta", "sin_red": "sin red",
                     "parcial": "ejecución parcial (no basta para declarar pass)",
                     "no_evaluado": "no evaluado por la herramienta (p. ej. sin red)",
                     "sin_normalizar": "la fase normalize no se ejecutó o terminó con error (fail-closed)",
                     "sin_meta": "crudo sin meta del adaptador (no se puede confirmar que corrió bien)",
                     None: "sin datos de la herramienta (no se ejecutó)"}


def es_agente_llm(nombre):
    return nombre.startswith("revisor-") or nombre in AGENTES_LLM


def efectivo(h, fecha_ref):
    """True si el hallazgo cuenta para fail."""
    est = h.get("estado_hallazgo", "abierto")
    if est == "falso_positivo":
        return False
    if est == "aceptado":
        ac = h.get("aceptacion") or {}
        if h.get("severidad") == "critica" and h.get("gate") == "N1":
            return True
        if not all(ac.get(k) for k in ("firma", "fecha", "vencimiento", "razon")):
            return True
        return str(ac["vencimiento"]) < str(fecha_ref)
    return True


def _motivo(texto):
    return (texto or "")[:300] or None


MAX_MOTIVO_HERR = 110


PREFIJO_MOTIVO_REAL = {"no_evaluado": "no evaluado", "parcial": "ejecución parcial"}


def _texto_herr(h, est, motivos):
    """«h: texto del estado». Si la herramienta quedó no_evaluado o parcial y declaró el motivo real (check:
    normalizacion.json → estado_checks; adaptador: `error` de su meta, p. ej. «sin red (AUDITOR_SIN_RED)…»), se cita
    ese motivo en vez del genérico «(p. ej. sin red)». Solo cambia el texto: el estado del control lo decide calcular()
    (nunca produce pass)."""
    real = (motivos or {}).get(utiles.canon_herramienta(h)) if est in PREFIJO_MOTIVO_REAL else None
    if real:
        real = " ".join(str(real).split())
        if len(real) > MAX_MOTIVO_HERR:
            real = real[:MAX_MOTIVO_HERR - 1].rstrip() + "…"
        return f"{h}: {PREFIJO_MOTIVO_REAL[est]}: {real}"
    return f"{h}: {TEXTO_ESTADO_HERR.get(est, 'estado desconocido')}"


def _faltantes(control):
    try:
        nombres = sorted(catalogo.nombres_en_condicion(control.get("condicion", "siempre")))
    except catalogo.ErrorCondicion:
        nombres = []
    return ", ".join(nombres) or "condición"


def _regla_mapeada(control, reglas):
    for regla in sorted(reglas):
        for patron in control.get("mapea_reglas", []):
            if fnmatch.fnmatchcase(regla, patron):
                return regla
    return None


def evidencia_pass(control):
    ev = control.get("evidencia_pass") or EVIDENCIA_DEFECTO
    if control.get("exige_checks_pass") and ev == "ausencia_suficiente":
        return "checks_pass"
    return ev


def _fuente_de_regla(regla):
    herr, _, resto = regla.partition(":")
    return resto.split(".", 1)[0] if herr == "check" else herr


def _condicional_incumplido(c, h, datos):
    """Motivo si un `alcance_condicional` de la herramienta h no se cumple; None si se cumple (o no hay)."""
    for cond in c.get("alcance_condicional", []) or []:
        hr, _, req = str(cond.get("requiere", "")).partition(".")
        hs, _, si = str(cond.get("si", "")).partition(".")
        if utiles.canon_herramienta(hr) != utiles.canon_herramienta(h) or not req or not si:
            continue
        valor_req = datos.get(req)
        if isinstance(valor_req, int) and valor_req > 0:
            continue
        valor_si = datos.get(si) if utiles.canon_herramienta(hs) == utiles.canon_herramienta(h) else None
        if isinstance(valor_si, int) and valor_si == 0:
            continue
        explicacion = cond.get("motivo") or f"{cond['si']} > 0 exige {cond['requiere']} > 0"
        txt_req = valor_req if isinstance(valor_req, int) else "sin registrar"
        if isinstance(valor_si, int):
            return f"{explicacion} ({cond['si']} = {valor_si} commits, pero {cond['requiere']} = {txt_req})"
        return f"{explicacion} ({cond['si']} sin registrar y {cond['requiere']} = {txt_req}; fail-closed)"
    return None


def _excluyente_incumplido(c, h, datos, exigir_registro=True):
    """Motivo si una clave de `alcance_excluyente` de la herramienta h es > 0 (p. ej. semgrep.fuentes_sin_reglas:
    código escaneado para el que el ruleset no tiene reglas); None si todas están registradas y valen 0.
    Ronda 3 (fail-closed): una clave NO registrada también bloquea (antes se toleraba por las metas anteriores a la
    ronda 2): si el adaptador dejara de emitirla, el pase vacío de f17/f20 no se reabre en silencio. Con
    exigir_registro=False (alcance requerido en 0: el resultado no sería pass) una clave ausente no cambia nada."""
    for ex in c.get("alcance_excluyente", []) or []:
        he, _, clave = str(ex.get("clave", "")).partition(".")
        if utiles.canon_herramienta(he) != utiles.canon_herramienta(h) or not clave:
            continue
        valor = datos.get(clave)
        if not isinstance(valor, int) or isinstance(valor, bool):
            if not exigir_registro:
                continue
            return (f"{ex['clave']} sin registrar en el alcance de {h}: no se puede descartar código o consultas que "
                    "la herramienta no cubre (fail-closed)")
        if valor > 0:
            return f"{ex.get('motivo') or 'alcance excluyente'} ({ex['clave']} = {valor})"
    return None


def _evaluar_alcance(c, ok, alcance):
    """(herramienta, None) si alguna herramienta ok analizó ≥ 1 objeto relevante; (None, "cero") si la que corrió
    registró alcance 0; (None, "sin_registro") si ninguna registró su alcance; (None, ("condicional", motivo)) si el
    alcance base está, pero falta un `alcance_condicional` (p. ej. repo git con commits sin historial escaneado)."""
    requeridos = {}
    for r in c.get("alcance_requerido", []):
        h, _, clave = r.partition(".")
        requeridos.setdefault(utiles.canon_herramienta(h), []).append(clave)
    resultado = (None, "sin_registro")
    for h in ok:
        claves = requeridos.get(utiles.canon_herramienta(h))
        datos = (alcance or {}).get(utiles.canon_herramienta(h))
        if not claves or not isinstance(datos, dict) or any(not isinstance(datos.get(k), int) for k in claves):
            continue
        excluye = _excluyente_incumplido(c, h, datos, exigir_registro=all(datos[k] > 0 for k in claves))
        if excluye is not None:  # ronda 2: hay objetos relevantes que la herramienta no cubre → nunca pass
            resultado = (None, ("condicional", excluye))
            continue
        if all(datos[k] > 0 for k in claves):
            falta = _condicional_incumplido(c, h, datos)
            if falta is None:
                return h, None
            resultado = (None, ("condicional", falta))
        elif resultado[1] == "sin_registro":
            resultado = (None, "cero")
    return resultado


def declaracion_sin_datos(perfil, corrida=None, perfil_json=None):
    """Declaración del creador de que NO usa datos personales, o None.

    Solo cuenta si viene de perfil.json (entrevista) con datos_personales = false y sin salud ni menores
    = true (sería contradictoria). Fecha: perfil.json → declaraciones.datos_personales.fecha si existe;
    si no, la fecha de la corrida (run.json) en que se registró.
    """
    if (perfil or {}).get("origen") != "perfil":
        return None
    b = perfil.get("banderas") or {}
    if b.get("datos_personales") is not False or b.get("salud") is True or b.get("menores") is True:
        return None
    fecha = None
    if isinstance(perfil_json, dict):
        d = ((perfil_json.get("declaraciones") or {}).get("datos_personales") or {})
        if isinstance(d, dict) and isinstance(d.get("fecha"), str) and d["fecha"][:10]:
            fecha = d["fecha"][:10]
    if fecha is None:
        fecha = utiles.fecha_referencia(corrida) if corrida is not None else None
    return {"fecha": fecha, "fuente": "perfil.json", "banderas": {"datos_personales": False}}


def _ajuste_legal(reg, c, declaracion):
    if reg["estado"] == "fail":
        return
    if declaracion:
        reg.update(estado="no_aplica", herramienta=None, motivo=_motivo(
            f"{DECLARACION_SIN_DATOS} ({declaracion.get('fuente', 'perfil.json')}, "
            f"registrada el {declaracion.get('fecha') or 'sin fecha'})"))
        return
    previo = reg.get("motivo") or ""
    extra = ""
    if reg["estado"] == "pass":
        extra = "; las herramientas no encontraron problemas, pero eso no acredita cumplimiento"
    elif "aplicabilidad sin confirmar" in previo or c.get("aplicabilidad") == "desconocida":
        extra = f"; no se sabe si hay datos personales (falta respuesta: {_faltantes(c)})"
    reg.update(estado="manual_pendiente", motivo=_motivo(MOTIVO_LEGAL + extra))


def calcular(indice, hallazgos, herr_estado, checks_pass, modo, fecha_ref, declaracion=None, alcance=None,
             motivos=None, pases_ia=None, motivos_sin_pase=None):
    """indice: {id: control con `aplicabilidad`}; herr_estado: {herramienta: ok|ausente|error|timeout|sin_red}.
    declaracion: resultado de declaracion_sin_datos() (o None).
    alcance: {herramienta canónica: {clave: nº de objetos analizados}} (meta.alcance; ver alcance_herramientas).
    motivos: {herramienta canónica: motivo declarado por el check} (normalizacion.json → estado_checks); se cita
    cuando un control queda no_aplica porque la herramienta no encontró nada que analizar.
    pases_ia: {control: {agente, motivo}} de veredictos.evaluar (F3): un control llm, o mixto cuya parte
    determinista ya corrió sin hallazgos, pasa a pass solo si está aquí (veredictos.py ya aplicó las reglas duras)."""
    pases_ia = pases_ia or {}
    motivos = {utiles.canon_herramienta(k): v for k, v in (motivos or {}).items() if v}
    # Ronda 6 (integración, DECISIONES.md #12): motivo con que un check en estado ok explica por qué NO emitió su pase
    # (p. ej. «37 archivos de datos no inspeccionables…»); se cita en el no_evaluado por falta de pase explícito.
    motivos_sin_pase = {utiles.canon_herramienta(k): v for k, v in (motivos_sin_pase or {}).items() if v}
    limite = utiles.num_nivel(utiles.LIMITE_MODO.get(modo, "N4"))
    por_control = {}
    aceptados = {}
    for h in hallazgos:
        if efectivo(h, fecha_ref):
            por_control.setdefault(h["control"], []).append(h["id"])
        elif h.get("estado_hallazgo") == "aceptado":
            aceptados.setdefault(h["control"], []).append(h["id"])
    resultado = []
    for cid, c in indice.items():
        metodo = c.get("metodo", "determinista")
        reg = {"control": cid, "estado": None, "motivo": None, "metodo": metodo, "duracion_s": None,
               "herramienta": None, "hallazgos": []}
        aplic = c.get("aplicabilidad", "aplica")
        if c.get("aviso_legal") and declaracion and not por_control.get(cid):
            _ajuste_legal(reg, c, declaracion)
            resultado.append(reg)
            continue
        if aplic == "no_aplica":
            reg.update(estado="no_aplica", motivo=_motivo(f"perfil: no se cumple «{c.get('condicion')}»"))
            resultado.append(reg)
            continue
        aviso = (f"; aplicabilidad sin confirmar (falta respuesta: {_faltantes(c)})" if aplic == "desconocida" else "")
        if por_control.get(cid):
            reg.update(estado="fail", hallazgos=sorted(set(por_control[cid])))
            if utiles.num_nivel(c["gate"]) > limite:
                reg["motivo"] = _motivo(f"hallazgo incidental fuera del alcance del modo {modo} ({c['gate']} > "
                                        f"{utiles.LIMITE_MODO.get(modo, 'N4')}): se informa, pero el modo no "
                                        "evalúa este nivel")
            resultado.append(reg)
            continue
        herrs = list(c.get("herramientas", []))
        parciales = set(c.get("herramientas_parciales", []))
        llm = [h for h in herrs if es_agente_llm(h)]
        entrevista = [h for h in herrs if h in COMPONENTES_ENTREVISTA]
        manuales = [h for h in herrs if h in COMPONENTES_MANUALES]
        det = [h for h in herrs if h not in llm and h not in entrevista and h not in manuales]
        if utiles.num_nivel(c["gate"]) > limite:
            reg.update(estado="no_evaluado", motivo=_motivo(
                f"fuera del alcance del modo {modo} ({c['gate']} > {utiles.LIMITE_MODO.get(modo, 'N4')})" + aviso))
        elif metodo == "manual":
            reg.update(estado="manual_pendiente", motivo=_motivo("requiere verificación manual" + aviso))
        elif metodo == "llm" and cid in pases_ia and pases_ia[cid].get("agente") in llm:
            reg.update(estado="pass", herramienta=pases_ia[cid]["agente"], motivo=_motivo(pases_ia[cid]["motivo"] + aviso))
        elif metodo == "llm":
            reg.update(estado="no_evaluado", motivo=_motivo(MOTIVO_LLM + (f" ({', '.join(llm)})" if llm else "") + aviso))
        elif aplic == "desconocida" and not det:
            reg.update(estado="no_evaluado", motivo=_motivo(f"falta respuesta en la entrevista: {_faltantes(c)}"))
        else:
            ev = evidencia_pass(c)
            regla_ok = _regla_mapeada(c, checks_pass) if ev != "no_demostrable_estatico" else None
            faltan_pases = []
            if regla_ok and c.get("pases_requeridos"):  # ronda 2: todas las subcondiciones (AND), no una (OR)
                faltan_pases = [p for p in c["pases_requeridos"]
                                if not any(fnmatch.fnmatchcase(r, p) for r in checks_pass)]
                if faltan_pases:
                    regla_ok = None
            ok = [h for h in det if h not in parciales and herr_estado.get(utiles.canon_herramienta(h)) == "ok"]
            sin_alcance = None
            if regla_ok:
                fuente_pass = _fuente_de_regla(regla_ok)
            elif ev != "ausencia_suficiente":
                fuente_pass = None  # que la herramienta corra ok no basta: hace falta el pase explícito
            elif ok:
                fuente_pass, sin_alcance = _evaluar_alcance(c, ok, alcance)
            else:
                fuente_pass = None
            if ev == "no_demostrable_estatico" and llm and ok:
                fuente_pass = ok[0]  # solo para el motivo de la rama LLM, que nunca declara pass
            nada_nd = [h for h in det if herr_estado.get(utiles.canon_herramienta(h)) == "no_aplica"]
            if ev == "no_demostrable_estatico" and not entrevista and det and not llm and nada_nd and not ok:
                # Ronda 9: «nada que analizar» (p. ej. sin repositorio git) sigue siendo no_aplica, no un pass.
                detalle = motivos.get(utiles.canon_herramienta(nada_nd[0]))
                reg.update(estado="no_aplica", herramienta=nada_nd[0], motivo=_motivo(
                    f"la herramienta no encontró nada que analizar ({nada_nd[0]}"
                    + (f": {detalle}" if detalle else "") + ")" + aviso))
            elif ev == "no_demostrable_estatico" and not entrevista and det and not llm and c.get("motivo_no_demostrable"):
                # Ronda 9 (DECISIONES.md #13): motivo propio del control + lo que el check explica de su alcance.
                motivo_check = motivos_sin_pase.get(utiles.canon_herramienta(ok[0])) if ok else None
                if motivo_check and len(motivo_check) > 140:
                    motivo_check = motivo_check[:139] + "…"
                if motivo_check:
                    detalle_nd = f"; {motivo_check}"
                elif ok:
                    detalle_nd = f" ({', '.join(ok)} corrió sin hallazgos)"
                else:
                    detalle_nd = " (" + "; ".join(_texto_herr(h, herr_estado.get(utiles.canon_herramienta(h)), motivos)
                                                  for h in det) + ")"
                reg.update(estado="no_evaluado", herramienta=ok[0] if ok else None, motivo=_motivo(
                    "no demostrable en análisis estático: " + c["motivo_no_demostrable"] + detalle_nd + aviso))
            elif ev == "no_demostrable_estatico" and not entrevista and det and not llm:
                estados_det = sorted({_texto_herr(h, herr_estado.get(utiles.canon_herramienta(h)), motivos)
                                      if herr_estado.get(utiles.canon_herramienta(h)) != "ok" else f"{h} corrió sin hallazgos"
                                      for h in det})
                reg.update(estado="no_evaluado", motivo=_motivo(
                    f"{MOTIVO_NO_DEMOSTRABLE}; {', '.join(estados_det)}, pero sus reglas no cubren el control completo"
                    + aviso))
            elif entrevista:
                reg.update(estado="no_evaluado", motivo=_motivo("requiere respuesta en la entrevista (perfil.json)" + aviso))
            elif not det:
                reg.update(estado="no_evaluado", motivo=_motivo("sin herramienta determinista asignada" + aviso))
            elif fuente_pass is None and faltan_pases:
                reg.update(estado="no_evaluado", motivo=_motivo(
                    f"faltan pases requeridos: {', '.join(faltan_pases)}; el control exige todas sus subcondiciones "
                    "(pases_requeridos) y una sola no basta para pass" + aviso))
            elif fuente_pass is None and sin_alcance == "cero":
                estado_sin = c.get("sin_alcance") if c.get("sin_alcance") in ("no_aplica", "no_evaluado") else "no_evaluado"
                reg.update(estado=estado_sin, herramienta=ok[0], motivo=_motivo(
                    f"{c.get('motivo_sin_alcance') or 'sin objetos que analizar'}: {ok[0]} analizó 0 de "
                    f"{', '.join(c.get('alcance_requerido', []))}; la ausencia de hallazgos no es evidencia" + aviso))
            elif fuente_pass is None and isinstance(sin_alcance, tuple):
                reg.update(estado="no_evaluado", herramienta=ok[0], motivo=_motivo(
                    f"{sin_alcance[1]}; la ausencia de hallazgos no basta" + aviso))
            elif fuente_pass is None and sin_alcance == "sin_registro":
                reg.update(estado="no_evaluado", motivo=_motivo(
                    f"{ok[0]} corrió sin hallazgos, pero no registró su alcance ({', '.join(c.get('alcance_requerido', [])) or 'sin alcance_requerido'}): "
                    "sin precondición de alcance no hay pass (fail-closed)" + aviso))
            elif fuente_pass is None and ev == "checks_pass" and ok:
                motivo_check = motivos_sin_pase.get(utiles.canon_herramienta(ok[0]))
                if motivo_check and len(motivo_check) > 170:  # deja sitio al aviso dentro de los 300 de _motivo
                    motivo_check = motivo_check[:169] + "…"
                reg.update(estado="no_evaluado", motivo=_motivo(
                    (f"{ok[0]} corrió sin hallazgos y sin el pase explícito que exige el control: {motivo_check}"
                     if motivo_check else
                     f"{ok[0]} corrió sin hallazgos, pero el control exige un pase explícito en checks_pass "
                     f"({', '.join(c.get('mapea_reglas', [])) or 'ninguna regla mapeada'}): sin él no hay pass")
                    + aviso))
            elif fuente_pass is None and any(
                    herr_estado.get(utiles.canon_herramienta(h)) == "no_aplica" for h in det):
                nada = [h for h in det if herr_estado.get(utiles.canon_herramienta(h)) == "no_aplica"]
                detalle = motivos.get(utiles.canon_herramienta(nada[0]))
                reg.update(estado="no_aplica", herramienta=nada[0], motivo=_motivo(
                    f"la herramienta no encontró nada que analizar ({nada[0]}"
                    + (f": {detalle}" if detalle else "") + ")" + aviso))
            elif fuente_pass is None:
                partes = []
                for h in det:
                    est_h = herr_estado.get(utiles.canon_herramienta(h))
                    if h in parciales and est_h == "ok":
                        partes.append(f"{h}: cobertura parcial del control (sin hallazgos, no basta para pass)")
                    else:
                        partes.append(_texto_herr(h, est_h, motivos))
                reg.update(estado="no_evaluado", motivo=_motivo("; ".join(partes) + aviso))
            elif llm and cid in pases_ia and pases_ia[cid].get("agente") in llm:
                reg.update(estado="pass", herramienta=pases_ia[cid]["agente"], motivo=_motivo(
                    f"{pases_ia[cid]['motivo']}; parte determinista sin hallazgos ({fuente_pass})" + aviso))
            elif llm:
                reg.update(estado="no_evaluado", herramienta=fuente_pass, motivo=_motivo(
                    f"parte determinista sin hallazgos ({fuente_pass}); {MOTIVO_LLM} ({', '.join(llm)})" + aviso))
            else:
                motivo = None
                if aceptados.get(cid):
                    motivo = f"riesgo aceptado con firma: {', '.join(sorted(aceptados[cid]))}"
                if aviso:
                    motivo = (motivo + aviso) if motivo else aviso[2:]
                reg.update(estado="pass", herramienta=fuente_pass, motivo=_motivo(motivo))
        if reg["estado"] == "pass":
            contradice = _pass_contradicho(c, por_control)
            if contradice:
                reg.update(estado="no_evaluado", motivo=_motivo(contradice + aviso))
        if c.get("aviso_legal"):
            _ajuste_legal(reg, c, None)
        elif c.get("exigido_sin_condicion") and reg["estado"] == "manual_pendiente":
            reg["motivo"] = _motivo(MOTIVO_SUS + aviso)
        resultado.append(reg)
    return resultado


def _pass_contradicho(c, por_control):
    """Ronda 3 (PV-R2-06): motivo si un control de `pass_contradicho_por` tiene hallazgos efectivos en la corrida (p. ej.
    una inyección SQL de semgrep asignada a DAT-SQL-CONCATENADO contradice el pass de SEG-SAST-INY); None si no."""
    for x in c.get("pass_contradicho_por", []) or []:
        otro = x.get("control") if isinstance(x, dict) else x
        if otro and por_control.get(otro):
            ids = ", ".join(sorted(set(por_control[otro]))[:5])
            motivo = (x.get("motivo") if isinstance(x, dict) else None) or f"{otro} tiene hallazgos en esta corrida"
            return f"{motivo} ({otro}: {ids}); no hay pass sin contradicción (fail-closed)"
    return None


def estado_herramientas(corrida):
    """{herramienta canónica: estado} a partir de crudo/*.meta.json, de los archivos crudos
    presentes (sin meta = ok si se leyeron) y de los errores de lectura de normalizacion.json."""
    corrida = Path(corrida)
    crudo = corrida / "crudo"
    estados = {k: v["estado"] for k, v in utiles.cargar_metas(crudo).items()}
    if crudo.is_dir():
        for p in sorted(crudo.iterdir()):
            n = p.name
            if not p.is_file() or n.endswith(".meta.json"):
                continue
            if n.startswith("check_") and n.endswith(".json"):
                nombre = n[len("check_"):-len(".json")]
            elif n.startswith("gitleaks"):
                nombre = "gitleaks"
            elif n.startswith("osv"):
                nombre = "osv-scanner"
            elif n.endswith(".sarif"):
                nombre = n[:-len(".sarif")].split("_")[0]
            else:
                continue
            estados.setdefault(utiles.canon_herramienta(nombre), "sin_meta")
    if (corrida / "perfil_tecnico.json").is_file():
        estados.setdefault("detectar_stack", "ok")
    resumen = utiles.leer_json(corrida / "normalizacion.json", {}) or {}
    for nombre, info in (resumen.get("estado_checks") or {}).items():
        est = (info or {}).get("estado")
        canon = utiles.canon_herramienta(nombre)
        if est and est != "ok":  # el check declaró que no pudo evaluar (p. ej. sin red)
            estados[canon] = est if est in utiles.ESTADOS_META else "error"
        elif est == "ok" and estados.get(canon) == "sin_meta":  # el propio JSON del check declara ok
            estados[canon] = "ok"
    for err in resumen.get("errores_lectura", []):
        archivo = err.split(":", 1)[0]
        if archivo.startswith("check_"):
            nombre = archivo[len("check_"):].split(".")[0]
        elif archivo.startswith("gitleaks"):
            nombre = "gitleaks"
        elif archivo.startswith("osv"):
            nombre = "osv-scanner"
        else:
            nombre = archivo.split(".")[0].split("_")[0]
        estados[utiles.canon_herramienta(nombre)] = "error"
    return estados


def alcance_herramientas(corrida):
    """{herramienta canónica: {clave: nº}} desde meta.alcance de crudo/*.meta.json (solo enteros ≥ 0)."""
    res = {}
    crudo = Path(corrida) / "crudo"
    if not crudo.is_dir():
        return res
    for ruta in sorted(crudo.glob("*.meta.json")):
        m = utiles.leer_json(ruta)
        if not isinstance(m, dict) or not isinstance(m.get("alcance"), dict):
            continue
        nombre = utiles.canon_herramienta(m.get("herramienta") or ruta.name[:-len(".meta.json")])
        datos = {k: v for k, v in m["alcance"].items() if isinstance(v, int) and not isinstance(v, bool) and v >= 0}
        previo = res.setdefault(nombre, {})
        for k, v in datos.items():  # varios metas de la misma herramienta: gana el menor alcance (conservador)
            previo[k] = min(previo[k], v) if k in previo else v
    return res


def motivos_checks(resumen):
    """{herramienta canónica: motivo} de los checks que declararon un estado distinto de ok (normalizacion.json)."""
    res = {}
    for nombre, info in ((resumen or {}).get("estado_checks") or {}).items():
        if isinstance(info, dict) and info.get("estado") != "ok" and info.get("motivo"):
            res[utiles.canon_herramienta(nombre)] = str(info["motivo"])
    return res


def motivos_checks_sin_pase(resumen):
    """{herramienta canónica: motivo} de los checks en estado ok que declararon un motivo (normalizacion.json): el
    check corrió, pero explica por qué no hay pase (ronda 6)."""
    res = {}
    for nombre, info in ((resumen or {}).get("estado_checks") or {}).items():
        if isinstance(info, dict) and info.get("estado") == "ok" and info.get("motivo"):
            res[utiles.canon_herramienta(nombre)] = str(info["motivo"])
    return res


def motivos_adaptadores(corrida):
    """{herramienta canónica: error} de los meta de adaptadores (crudo/*.meta.json) en estado no_evaluado o parcial
    (D1: osv-scanner sin red deja «sin red (AUDITOR_SIN_RED): …» en `error`). Solo texto para el motivo."""
    res = {}
    for nombre, meta in utiles.cargar_metas(Path(corrida) / "crudo").items():
        if meta.get("estado") in PREFIJO_MOTIVO_REAL and meta.get("error"):
            res[nombre] = str(meta["error"])
    return res


def inventario_no_vacio(tecnico):
    """INF-INVENTARIO «Stack y plataforma de despliegue detectados»: el inventario es evidencia solo si detectó ≥ 1
    lenguaje o framework (ronda 1) Y ≥ 1 plataforma de despliegue (ronda 3, PV-R2-08: un run.sh o una carpeta de tests
    sola no bastan)."""
    return (isinstance(tecnico, dict) and bool(tecnico.get("lenguajes") or tecnico.get("frameworks"))
            and bool(tecnico.get("plataformas_despliegue")))


def normalizacion_valida(corrida, run=None):
    """None si la fase normalize terminó bien; si no, el motivo (fail-closed: sin ella no hay pass)."""
    corrida = Path(corrida)
    run = utiles.leer_run(corrida) if run is None else run
    fase = (run.get("fases") or {}).get("normalize")
    if fase is not None and fase.get("estado") != "ok":
        return f"la fase normalize terminó en estado {fase.get('estado')!r}"
    if not (corrida / "normalizacion.json").is_file():
        return "la fase normalize no se ejecutó (falta normalizacion.json)"
    return None


def generar(corrida):
    corrida = Path(corrida)
    run = utiles.leer_run(corrida)
    perfil = utiles.cargar_perfil(corrida)
    indice = utiles.indice_controles(perfil)
    modo = utiles.modo_corrida(corrida)
    falta_norm = normalizacion_valida(corrida, run)
    if falta_norm:
        # Sin normalize válido no se sabe qué encontraron las herramientas: nada puede pasar.
        hallazgos, resumen = [], {}
        herr = {utiles.canon_herramienta(h): "sin_normalizar"
                for c in indice.values() for h in c.get("herramientas", [])}
        print(f"estado: {falta_norm}; ningún control determinista puede pasar", file=sys.stderr)
    else:
        hallazgos = utiles.leer_jsonl(corrida / "hallazgos.jsonl")
        resumen = utiles.leer_json(corrida / "normalizacion.json", {}) or {}
        herr = estado_herramientas(corrida)
    declaracion = declaracion_sin_datos(perfil, corrida, utiles.leer_json(corrida / "perfil.json"))
    pases = set(resumen.get("checks_pass", []))
    tecnico = utiles.leer_json(corrida / "perfil_tecnico.json")
    if not falta_norm and inventario_no_vacio(tecnico):
        # el inventario ES la salida de detectar_stack: pase explícito (INF-INVENTARIO), solo si no está vacío
        pases.add(REGLA_INVENTARIO)
    import veredictos  # F3: decisiones de la IA (veredictos.jsonl), validadas con reglas duras
    ver = None
    fp_humanos = None
    if not falta_norm:
        hay_fp_humano = veredictos.hay_registro_fp(corrida)   # fuente autorizada (--fp-verificados) o archivo del repo
        if (corrida / veredictos.ARCHIVO).is_file() or hay_fp_humano:
            # con veredictos (o falsos positivos verificados por una persona) se usan todas las instancias (sin el
            # tope de 5): un falso positivo de una instancia no puede ocultar las demás
            hallazgos = utiles.leer_jsonl(corrida / "hallazgos_todos.jsonl") or hallazgos
        # H-2 (DECISIONES.md #11): antes que la IA, para que sus veredictos no reabran ni «descarten» lo ya verificado
        hallazgos, fp_humanos = veredictos.aplicar_fp_humanos(corrida, hallazgos)
        ver = veredictos.evaluar(corrida, indice, hallazgos)
        if ver is not None:
            hallazgos = ver["hallazgos"] + ver["hallazgos_ia"]
    controles = calcular(indice, hallazgos, herr, pases, modo, utiles.fecha_referencia(corrida), declaracion,
                         alcance=alcance_herramientas(corrida) if not falta_norm else {},
                         motivos={**motivos_adaptadores(corrida), **motivos_checks(resumen)},
                         pases_ia=(ver or {}).get("pases"), motivos_sin_pase=motivos_checks_sin_pase(resumen))
    if ver is not None:
        veredictos.ajustar(controles, ver)
    veredictos.ajustar_pendientes(controles, utiles.leer_json(corrida / "perfil.json"))
    veredictos.ajustar_fp_humanos(controles, fp_humanos, indice)   # H-2: después de todo; nunca produce pass
    if falta_norm:
        (corrida / veredictos.FP_HUMANOS).unlink(missing_ok=True)
    veredictos.registrar(corrida, ver, controles)
    commit = run.get("commit7") or run.get("commit")
    datos = {"version_esquema": "1", "corrida": run.get("id"), "commit": commit if commit else None,
             "modo": modo, "generado": None, "controles": controles}
    utiles.escribir_json(corrida / "estado.json", datos)
    return datos


def main(argv=None):
    ap = argparse.ArgumentParser(description="Estado por control → estado.json")
    ap.add_argument("corrida_pos", nargs="?", metavar="DIR_CORRIDA")
    ap.add_argument("--corrida")
    a = ap.parse_args(argv)
    corrida = a.corrida or a.corrida_pos
    if not corrida or not Path(corrida).is_dir():
        print("estado.py: indique una carpeta de corrida existente", file=sys.stderr)
        return 2
    datos = generar(corrida)
    conteo = {}
    for c in datos["controles"]:
        conteo[c["estado"]] = conteo.get(c["estado"], 0) + 1
    print("estado: " + ", ".join(f"{k} {v}" for k, v in sorted(conteo.items())), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

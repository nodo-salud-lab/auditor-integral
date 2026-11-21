#!/usr/bin/env python3
"""Compuertas N0-N5 por dominio y global → gates.json (PLAN_MAESTRO §4.2; DECISIONES.md #4).

Uso:  gates.py DIR_CORRIDA   |   gates.py --corrida DIR_CORRIDA
      (regenera antes estado.json con estado.py, salvo --usar-estado)

Algoritmo (§4.2, exacto):
 1. ok(d, n): todo control aplicable del dominio d con gate ≤ n está en pass o no_aplica.
 2. Nivel demostrado ND(d) = máx {n : ok(d, n)}; no_evaluado y manual_pendiente cuentan como
    fallo; N0 si no se cumple N1.
 3. Nivel potencial NP(d): igual, pero no_evaluado no bloquea (desconocido); fail y
    manual_pendiente sí (§4.2.3 solo exime a no_evaluado).
 4. Nivel global = mín_d ND(d) sobre los dominios activos (≥ 1 control aplicable). "¿Está listo?"
    usa solo el demostrado.
 5. Bloqueo: un fail en un control con bloquea_global = true, o un crítico abierto en SEG o DAT,
    deja el global ≤ N1. Los controles legales no están en esta regla (DECISIONES.md #4).
    Secreto vivo (fail en un control de secreto) o datos reales expuestos (datos_reales_cargados
    = true y fail en un control de exposición) → N0. Sin verificación de revocación, todo secreto
    detectado se presume vivo (se declara en el informe). Excepción AUD-SEC: si TODOS los hallazgos
    del control de secreto tienen confianza "baja" (generic-api-key en un bundle minificado sin
    prefijo de proveedor; normalizar/gitleaks.py) y ningún triage los confirmó ("verdadero"), el
    control queda en fail pero sin bloqueo (ni secreto_vivo ni bloquea_global/crítico) hasta el triage.
    DECISIONES.md #10: un control no_evaluado por falso positivo de la IA sobre un grave (motivo de
    veredictos.ajustar, roadmap.es_motivo_fp_ia) genera los mismos bloqueos que en fail, con "pendiente_ia": true
    y "nota" (falta verificación humana); el tope se aplica igual. AUD-SEC no lo suprime: el triage ya ocurrió.
    R6 (gates-cli): global.bloqueos tiene UNA entrada por control: `tipo`/`tope` del motivo más estricto y
    `tipos`/`motivos` con todos (antes, p. ej., SEG-SECRETO-REPO salía dos veces: secreto_vivo N0 y bloquea_global N1).
 5b. DECISIONES.md #11 (H-2): un control descartado por verificación humana (estado.py → no_aplica con
    descarte_humano; <proyecto>/.auditor-integral/fp-verificados.json) cuenta como OK igual que no_aplica y no
    genera bloqueos; no es pass (score.py no lo suma). hallazgos_para_gates marca esos hallazgos falso_positivo.
    Solo se aplica si el operador autorizó el registro con --fp-verificados. Se listan en global.descartes_humanos
    y, con alguno, listo_datos_reales nunca es "SI" (a lo sumo "CONDICIONAL").
 6. Cobertura por nivel: evaluados (pass + fail) / aplicables; < 100 % → "Nn no verificado".
Controles con aviso_legal = true (DECISIONES.md #4): no bloquean ni cuentan para ningún nivel (ni del
dominio ni global): si contaran, su manual_pendiente permanente dejaría a OPS, y por el mínimo al global,
en N1. Se listan en global.avisos_legales y en dominios[d].avisos_legales para el aviso destacado del informe.
R6 (gates-cli): aplicabilidad por perfil_tecnico.tipo_proyecto (catalogo/aplicabilidad_tipo_proyecto.toml): los
controles solo web/servidor (cli_libreria) o de navegador (movil) en no_evaluado/manual_pendiente sin hallazgos pasan a
no_aplica con motivo; sin tipo o con «desconocido» no cambia nada (ajustar_tipo_proyecto).
Sin marcas de tiempo: misma entrada → mismos bytes.
"""
import argparse
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import catalogo  # noqa: E402
import estado as estado_mod  # noqa: E402
import roadmap  # noqa: E402
import utiles  # noqa: E402
import veredictos  # noqa: E402

NIVELES_GATE = ("N1", "N2", "N3", "N4", "N5")
CONTROLES_SECRETO = ("SEG-SECRETO-REPO", "SEG-SECRETO-BUNDLE", "SEG-ENV-PUBLICAS", "SEG-LLM-CLAVE")
DOMINIOS_BLOQUEO_CRITICO = ("SEG", "DAT")
REGLA_EXPOSICION = "SALUD-DATOS-REALES-EXPOSICION"
HITOS = {
    "N0": "Ninguno: no apto para uso",
    "N1": "Demo privada, sin datos reales",
    "N2": "Piloto cerrado con usuarios invitados y datos reales limitados",
    "N3": "Lanzamiento público",
    "N4": "Operación comercial con SLA",
    "N5": "Crecimiento y auditorías de terceros",
}
OK_DEMOSTRADO = {"pass", "no_aplica"}
# §4.2.3: en el potencial solo no_evaluado es "desconocido"; manual_pendiente sigue contando como fallo.
BLOQUEA_POTENCIAL = {"fail", "manual_pendiente"}
# DECISIONES.md #10: bloqueo de un control que la IA dejó en no_evaluado por un posible falso positivo grave.
NOTA_PENDIENTE_IA = ("sin confirmar: la IA (triage-fp) lo marcó como posible falso positivo; "
                     "falta verificación humana")


def controles_exposicion():
    """Controles de exposición de datos (los de la regla contextual de salud + datos reales)."""
    pr = catalogo.cargar_perfil_riesgo()
    for r in pr.get("regla_contextual", []):
        if r.get("id") == REGLA_EXPOSICION:
            return set(r.get("controles", []))
    return set()


def _nivel(estados_por_gate, ok_fn):
    nivel = "N0"
    for n in NIVELES_GATE:
        if all(ok_fn(e) for e in estados_por_gate.get(n, [])):
            nivel = n
        else:
            break
    return nivel


def _min_nivel(niveles):
    niveles = [n for n in niveles if n]
    return min(niveles, key=utiles.num_nivel) if niveles else "N0"


def _cobertura(aplicables, evaluados):
    return round(evaluados / aplicables, 3) if aplicables else 1.0


def _pendiente_triage(h):
    """AUD-SEC: hallazgo de confianza baja que ningún triage confirmó como verdadero ('incierto' cuenta como
    verdadero: F3, PLAN_MAESTRO §3.3)."""
    triage = h.get("triage") or {}
    return h.get("confianza") == "baja" and triage.get("veredicto") not in ("verdadero", "incierto")


def _secreto_sin_confirmar(cid, ids, por_id):
    if cid not in CONTROLES_SECRETO or not ids or not all(i in por_id for i in ids):
        return False
    return all(_pendiente_triage(por_id[i]) for i in ids)


def _clave_motivo(m):
    return (utiles.num_nivel(m["tope"]), m["tipo"])


def _bloqueo_unico(cid, motivos, hallazgos, extra):
    """R6 (gates-cli): un bloqueo por control. `tipo` y `tope` son los del motivo más estricto (el tope más bajo;
    a igualdad, orden alfabético del tipo, el mismo criterio de orden de antes), y `tipos`/`motivos` conservan todos
    los motivos (antes cada motivo era una entrada aparte y la CLI contaba 7 bloqueos para 5 controles)."""
    motivos = sorted(motivos, key=_clave_motivo)
    return {"control": cid, "tipo": motivos[0]["tipo"], "tope": motivos[0]["tope"],
            "tipos": [m["tipo"] for m in motivos], "motivos": motivos, "hallazgos": hallazgos, **extra}


def calcular(estados, indice, hallazgos, banderas, exposicion):
    sev_hallazgo = {h["id"]: h.get("severidad") for h in hallazgos}
    por_id = {h["id"]: h for h in hallazgos}
    por_dominio = {d: {} for d in utiles.ORDEN_DOMINIOS}
    detalle = {d: {n: [] for n in NIVELES_GATE} for d in utiles.ORDEN_DOMINIOS}
    bloqueos = []
    avisos = {}
    for e in estados:
        c = indice.get(e["control"])
        if c is None:
            continue
        d = c["dominio"]
        por_dominio.setdefault(d, {})
        detalle.setdefault(d, {n: [] for n in NIVELES_GATE})
        if c.get("aviso_legal"):
            if e["estado"] != "no_aplica":
                avisos.setdefault(d, []).append({"control": e["control"], "estado": e["estado"]})
            continue
        if e["estado"] != "no_aplica":
            por_dominio[d].setdefault(c["gate"], []).append(e["estado"])
            detalle[d][c["gate"]].append((e["control"], e["estado"]))
        cid = e["control"]
        # DECISIONES.md #10: no_evaluado por FP de la IA sobre un grave → mismos bloqueos que en fail, marcados
        # pendiente_ia (el estado no cambia). Cualquier otro no_evaluado (p. ej. herramienta faltante) no bloquea.
        pendiente_ia = e["estado"] == "no_evaluado" and roadmap.es_motivo_fp_ia(e.get("motivo"))
        if e["estado"] != "fail" and not pendiente_ia:
            continue
        ids = e.get("hallazgos") or []
        if pendiente_ia:
            ids = ids or [h["id"] for h in hallazgos if h.get("control") == cid
                          and h.get("severidad") in ("critica", "alta")
                          and (h.get("triage") or {}).get("veredicto") == "falso_positivo"]
        elif _secreto_sin_confirmar(cid, ids, por_id):
            continue  # AUD-SEC: fail sin bloqueo hasta el triage (con triage FP manda la rama pendiente_ia)
        if ids and any(i in sev_hallazgo for i in ids):
            critico = any(sev_hallazgo.get(i) == "critica" for i in ids)
        else:
            critico = c.get("severidad_base") == "critica"
        extra = {"pendiente_ia": True, "nota": NOTA_PENDIENTE_IA} if pendiente_ia else {}
        hs = sorted(set(ids))
        motivos = []
        if cid in CONTROLES_SECRETO:
            motivos.append({"tipo": "secreto_vivo", "tope": "N0"})
        if banderas.get("datos_reales_cargados") is True and cid in exposicion:
            motivos.append({"tipo": "datos_reales_expuestos", "tope": "N0"})
        if c.get("bloquea_global"):
            motivos.append({"tipo": "bloquea_global", "tope": "N1"})
        elif critico and d in DOMINIOS_BLOQUEO_CRITICO:
            motivos.append({"tipo": "critico_seg_dat", "tope": "N1"})
        if motivos:
            bloqueos.append(_bloqueo_unico(cid, motivos, hs, extra))

    dominios = {}
    for d in sorted(por_dominio, key=lambda x: utiles.ORDEN_DOMINIOS.index(x) if x in utiles.ORDEN_DOMINIOS else 99):
        gates_d = por_dominio[d]
        activo = any(gates_d.values())
        niveles = {}
        for n in NIVELES_GATE:
            items = detalle[d][n]
            cuenta = {k: sum(1 for _, s in items if s == k) for k in ("pass", "fail", "no_evaluado", "manual_pendiente")}
            evaluados = cuenta["pass"] + cuenta["fail"]
            niveles[n] = {"aplicables": len(items), **cuenta, "evaluados": evaluados,
                          "cobertura": _cobertura(len(items), evaluados),
                          "verificado": evaluados == len(items),
                          "fallidos": sorted(cid for cid, s in items if s == "fail"),
                          "pendientes": sorted(cid for cid, s in items if s in ("no_evaluado", "manual_pendiente"))}
        if activo:
            nd = _nivel(gates_d, lambda s: s in OK_DEMOSTRADO)
            np_ = _nivel(gates_d, lambda s: s not in BLOQUEA_POTENCIAL)
            leyenda = None
            if nd != "N5" and utiles.num_nivel(np_) > utiles.num_nivel(nd):
                sig = NIVELES_GATE[utiles.num_nivel(nd)]
                leyenda = f"{sig} no verificado (cobertura {round(niveles[sig]['cobertura'] * 100)} %)"
        else:
            nd = np_ = leyenda = None
        dominios[d] = {"activo": activo, "nivel_demostrado": nd, "nivel_potencial": np_, "leyenda": leyenda,
                       "niveles": niveles,
                       "avisos_legales": sorted(avisos.get(d, []), key=lambda a: a["control"])}

    activos = [d for d, v in dominios.items() if v["activo"]]
    nd_sin = _min_nivel([dominios[d]["nivel_demostrado"] for d in activos])
    np_sin = _min_nivel([dominios[d]["nivel_potencial"] for d in activos])
    tope = _min_nivel([b["tope"] for b in bloqueos]) if bloqueos else "N5"
    nd = _min_nivel([nd_sin, tope])
    np_ = _min_nivel([np_sin, tope])
    bloqueos = sorted(bloqueos, key=lambda b: (utiles.num_nivel(b["tope"]), b["tipo"], b["control"]))

    cobertura_por_nivel = {}
    for n in NIVELES_GATE:
        apl = sum(dominios[d]["niveles"][n]["aplicables"] for d in activos)
        ev = sum(dominios[d]["niveles"][n]["evaluados"] for d in activos)
        cobertura_por_nivel[n] = {"aplicables": apl, "evaluados": ev, "cobertura": _cobertura(apl, ev),
                                  "verificado": ev == apl}

    if utiles.num_nivel(nd) >= utiles.num_nivel("N2"):
        listo = "SI"
    elif not bloqueos and utiles.num_nivel(np_) >= utiles.num_nivel("N2"):
        listo = "CONDICIONAL"
    else:
        listo = "NO"
    # Descartes humanos (H-2, DECISIONES.md #11): siempre visibles en gates.json. Nada prueba criptográficamente que
    # los firmó una persona, así que con alguno aplicado «¿listo para datos reales?» nunca es SI (a lo sumo
    # CONDICIONAL: la decisión queda a la vista del dueño). Nunca sube nada.
    descartes = []
    for e in estados:
        dh = e.get("descarte_humano")
        if isinstance(dh, dict):
            descartes.append({"control": e["control"], "estado": e["estado"], "quien": dh.get("quien"),
                              "fecha": dh.get("fecha"), "hallazgos": list(dh.get("hallazgos") or [])})
        elif "descartado por verificación humana" in (e.get("motivo") or ""):
            # el control sigue en otro estado por otra causa, pero parte de sus hallazgos los descartó una persona
            descartes.append({"control": e["control"], "estado": e["estado"], "quien": None, "fecha": None,
                              "hallazgos": []})
    descartes.sort(key=lambda x: x["control"])
    if descartes and listo == "SI":
        listo = "CONDICIONAL"

    return {
        "version_esquema": "1",
        "global": {
            "nivel_demostrado": nd,
            "nivel_potencial": np_,
            "nivel_demostrado_sin_bloqueos": nd_sin,
            "nivel_potencial_sin_bloqueos": np_sin,
            "hito": HITOS[nd],
            "hito_potencial": HITOS[np_],
            "listo_datos_reales": listo,
            "descartes_humanos": descartes,
            "bloqueos": bloqueos,
            "cuello_de_botella": [d for d in activos if dominios[d]["nivel_demostrado"] == nd_sin],
            "dominios_activos": activos,
            "niveles_no_verificados": [n for n in NIVELES_GATE if not cobertura_por_nivel[n]["verificado"]],
            "presuncion_secreto_vivo": "sin verificación de revocación, todo secreto detectado se presume vivo",
            "avisos_legales": sorted((a for lista in avisos.values() for a in lista), key=lambda a: a["control"]),
        },
        "dominios": dominios,
        "cobertura_por_nivel": cobertura_por_nivel,
    }


RUTA_APLICABILIDAD_TIPO = utiles.RAIZ / "catalogo" / "aplicabilidad_tipo_proyecto.toml"
TIPOS_PROYECTO = ("web", "api", "spa", "movil", "cli_libreria", "desconocido")
ESTADOS_AJUSTABLES_TIPO = ("no_evaluado", "manual_pendiente")


# Ronda 6 (integración, DECISIONES.md #12): detectar_stack escribe detalle.tipo_proyecto = [valor] (el esquema de
# perfil_tecnico no admite claves nuevas en la raíz) con su propio vocabulario; aquí se traduce al de la tabla de
# aplicabilidad. servidor-web no se traduce a web/api: no hay regla para ellos y no cambiaría nada.
TRADUCCION_TIPO_STACK = {"movil": "movil", "spa": "spa", "cli-python": "cli_libreria", "libreria-python": "cli_libreria",
                         "servidor-web": "web", "desconocido": "desconocido"}


def tipo_proyecto(tecnico):
    """perfil_tecnico.tipo_proyecto (texto, o {"valor": …}) o, si falta, detalle.tipo_proyecto de detectar_stack (lista
    con un único valor, traducido con TRADUCCION_TIPO_STACK); None si falta, es ambiguo (≠ 1 valor), desconocido o no
    es un valor válido (fail-closed: sin tipo no cambia nada)."""
    if not isinstance(tecnico, dict):
        return None
    v = tecnico.get("tipo_proyecto")
    if isinstance(v, dict):
        v = v.get("valor", v.get("tipo"))
    if v is None and isinstance(tecnico.get("detalle"), dict):
        d = tecnico["detalle"].get("tipo_proyecto")
        if isinstance(d, str):
            d = [d]
        if isinstance(d, list) and len(set(d)) == 1 and isinstance(d[0], str):
            v = TRADUCCION_TIPO_STACK.get(d[0])
    if not isinstance(v, str) or v not in TIPOS_PROYECTO or v == "desconocido":
        return None
    return v


def reglas_tipo_proyecto(ruta=None):
    """{tipo: (motivo, {controles})} de catalogo/aplicabilidad_tipo_proyecto.toml ({} si falta: no cambia nada)."""
    datos = utiles.leer_toml(ruta or RUTA_APLICABILIDAD_TIPO) or {}
    res = {}
    for r in datos.get("regla", []) or []:
        if isinstance(r, dict) and isinstance(r.get("tipo"), str) and isinstance(r.get("motivo"), str):
            res[r["tipo"]] = (r["motivo"], set(r.get("controles") or []))
    return res


def ajustar_tipo_proyecto(estados, tipo, reglas=None):
    """R6 (gates-cli): controles exclusivamente web/servidor (cli_libreria) o de navegador (movil) → no_aplica con
    motivo. Solo toca no_evaluado/manual_pendiente sin hallazgos y que no sean un posible FP de la IA; nunca un fail
    ni un pass. Sin tipo (None) no cambia nada (fail-closed). Devuelve la lista de controles ajustados."""
    if tipo is None:
        return []
    reglas = reglas if reglas is not None else reglas_tipo_proyecto()
    if tipo not in reglas:
        return []
    motivo, controles = reglas[tipo]
    ajustados = []
    for e in estados:
        if (e.get("control") in controles and e.get("estado") in ESTADOS_AJUSTABLES_TIPO and not e.get("hallazgos")
                and not roadmap.es_motivo_fp_ia(e.get("motivo"))):
            e["estado"] = "no_aplica"
            e["motivo"] = motivo[:300]
            e["herramienta"] = None
            ajustados.append(e["control"])
    return ajustados


def generar(corrida, usar_estado=False):
    corrida = Path(corrida)
    if usar_estado and (corrida / "estado.json").is_file():
        datos_estado = utiles.leer_json(corrida / "estado.json")
    else:
        datos_estado = estado_mod.generar(corrida)
    # R6: aplicabilidad por perfil_tecnico.tipo_proyecto. Se reescribe estado.json para que informe, puntaje e IUA
    # vean el mismo estado que los niveles.
    if ajustar_tipo_proyecto(datos_estado["controles"],
                             tipo_proyecto(utiles.leer_json(corrida / "perfil_tecnico.json"))):
        utiles.escribir_json(corrida / "estado.json", datos_estado)
    perfil = utiles.cargar_perfil(corrida)
    indice = utiles.indice_controles(perfil)
    hallazgos = utiles.leer_jsonl(corrida / "hallazgos_todos.jsonl") or utiles.leer_jsonl(corrida / "hallazgos.jsonl")
    hallazgos = veredictos.hallazgos_para_gates(corrida, hallazgos)  # F3: triage de la IA + hallazgos_ia.jsonl
    g = calcular(datos_estado["controles"], indice, hallazgos, perfil["banderas"], controles_exposicion())
    g["modo"] = datos_estado.get("modo")
    g["commit"] = datos_estado.get("commit")
    utiles.escribir_json(corrida / "gates.json", g)
    return g


def main(argv=None):
    ap = argparse.ArgumentParser(description="Niveles N0-N5 por dominio y global → gates.json")
    ap.add_argument("corrida_pos", nargs="?", metavar="DIR_CORRIDA")
    ap.add_argument("--corrida")
    ap.add_argument("--usar-estado", action="store_true", help="no regenerar estado.json")
    a = ap.parse_args(argv)
    corrida = a.corrida or a.corrida_pos
    if not corrida or not Path(corrida).is_dir():
        print("gates.py: indique una carpeta de corrida existente", file=sys.stderr)
        return 2
    g = generar(corrida, a.usar_estado)
    # R6: un bloqueo por control (gates.json ya viene deduplicado); el conteo es de controles únicos
    n_bloq = len({b["control"] for b in g["global"]["bloqueos"]})
    print(f"gates: global demostrado {g['global']['nivel_demostrado']} · potencial {g['global']['nivel_potencial']}"
          f" · bloqueos {n_bloq} control(es)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

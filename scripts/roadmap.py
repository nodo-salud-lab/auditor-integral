#!/usr/bin/env python3
"""Hoja de ruta de crecimiento → roadmap.json (PLAN_MAESTRO §7). El orden lo decide este script.

Uso:  roadmap.py DIR_CORRIDA     (requiere estado.json y gates.json)

Selección: controles en fail / no_evaluado / manual_pendiente del SIGUIENTE nivel de cada dominio
(ND(d) + 1), más los críticos en fail de cualquier nivel. Lo demás queda fuera ("más adelante").
Orden: (a) bloqueos (bloquea_global), (b) dependencias técnicas (CI y entornos primero),
(c) severidad, (d) dominio cuello de botella del global, (e) esfuerzo S/M/L (ESTIMACIÓN del
catálogo), luego fail antes que no evaluado y el orden del catálogo.
Grupos: esta_semana (críticos en fail de esfuerzo XS/S) · siguiente_nivel · criticos_otros_niveles.
F3-C: si la IA (triage-fp, decisiones_ia.json → triage) marcó como falso positivo TODOS los hallazgos
crítico/alto de un control que no está en fail, el ítem lleva revision_ia y «qué hacer»/«verificación» pasan a
una verificación humana concreta (archivo:línea) con la remediación del catálogo como condicional. El estado,
el orden y los grupos no cambian (la IA nunca produce pass ni borra un hallazgo).
"""
import argparse
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import utiles  # noqa: E402

NIVELES_GATE = ("N1", "N2", "N3", "N4", "N5")
DEPENDENCIAS_PRIMERO = ("COD-CI-BASICO", "INF-ENTORNOS", "INF-ENTORNOS-SEPARADOS")
ESFUERZO = {"XS": 0, "S": 1, "M": 2, "L": 3, "XL": 4}
ESTADO_ORDEN = {"fail": 0, "no_evaluado": 1, "manual_pendiente": 2}
GRUPOS = (("esta_semana", "Esta semana"), ("siguiente_nivel", "Para llegar al siguiente nivel"),
          ("criticos_otros_niveles", "Críticos de otros niveles"))


def _siguiente(nivel):
    if nivel is None or nivel == "N5":
        return None
    return NIVELES_GATE[utiles.num_nivel(nivel)]  # N0 → N1, N1 → N2, ...


MOTIVO_FP_CRITICO = "falso positivo crítico según IA"   # lo escribe veredictos.ajustar (regla a)
MOTIVO_FP_ALTO = "falso positivo alto según IA"         # ídem para severidad alta (F3-C, 18-11-2026)
MOTIVOS_FP_IA = (MOTIVO_FP_CRITICO, MOTIVO_FP_ALTO)
VEREDICTOS_TRIAGE = ("verdadero", "falso_positivo", "incierto")
MAX_UBICACIONES = 5


def es_motivo_fp_ia(motivo):
    """True si el motivo es el de veredictos.ajustar: FP de la IA sobre un crítico/alto (requiere verificación humana).
    ajustar lo pone siempre al inicio; la frase en otra posición puede venir de texto del LLM (motivo_omision, valor
    rechazado por el schema) y no cuenta (verificación adversarial 19-11-2026: fabricaba un bloqueo pendiente_ia)."""
    return (motivo or "").startswith(MOTIVOS_FP_IA)


def triage_de_corrida(corrida):
    """{hallazgo_id: {veredicto, razon, modelo}} de decisiones_ia.json → triage (lo escribe veredictos.py).
    Solo entradas bien formadas; ilegible o ausente → {} (el informe queda como sin triage, nunca más favorable)."""
    dec = utiles.leer_json(Path(corrida) / "decisiones_ia.json")
    triage = dec.get("triage") if isinstance(dec, dict) else None
    if not isinstance(triage, dict):
        return {}
    return {hid: t for hid, t in triage.items()
            if isinstance(hid, str) and isinstance(t, dict) and t.get("veredicto") in VEREDICTOS_TRIAGE
            and isinstance(t.get("razon"), str)}


def _lugar(h):
    u = h.get("ubicacion") or {}
    if not u.get("archivo"):
        return None
    return str(u["archivo"]) + (f":{u['linea']}" if u.get("linea") is not None else "")


def lista_ubicaciones(lugares):
    """Ubicaciones como código en línea (texto del repo auditado: sin Markdown activo)."""
    lugares = [x for x in dict.fromkeys(lugares) if x]
    texto = ", ".join("`" + utiles.una_linea(x).replace("`", "'") + "`" for x in lugares[:MAX_UBICACIONES])
    return texto + (f" y {len(lugares) - MAX_UBICACIONES} más" if len(lugares) > MAX_UBICACIONES else "")


def graves_marcados_fp(cid, hallazgos, triage):
    """Hallazgos crítico/alto abiertos del control si TODOS tienen triage falso_positivo (si no, [])."""
    graves = [h for h in hallazgos if h.get("control") == cid and h.get("severidad") in ("critica", "alta")
              and h.get("estado_hallazgo", "abierto") == "abierto"]
    if graves and all((triage.get(h.get("id")) or {}).get("veredicto") == "falso_positivo" for h in graves):
        return graves
    return []


FP_HUMANO_REL = ".auditor-integral/fp-verificados.json"   # = veredictos.FP_HUMANO_REL (H-2, DECISIONES.md #11)


def _cierre_estado(estado):
    """Qué significa el juicio de la IA para el estado REAL del control (F3-C adv.: no prometer un no_evaluado que no
    es). H-2: la verificación humana solo cambia algo si la persona la registra en FP_HUMANO_REL."""
    if estado == "pass":   # defensa: desde F3-C un FP de crítico/alto ya no deja pass (veredictos.ajustar)
        return ("Atención: el control quedó en `pass` aunque la IA descartó hallazgos graves; no confíe en ese pass "
                "hasta que una persona lo verifique.")
    if estado in ("no_evaluado", "manual_pendiente"):
        return (f"El control queda `{estado}` (nunca pass por un juicio de la IA) y la verificación humana no lo "
                f"cambia por sí sola: solo cuenta si la persona la registra en `{FP_HUMANO_REL}` (sección 6c del "
                "informe); sin ese registro sale de ahí cuando una corrida nueva ya no encuentra el hallazgo.")
    return "El juicio de la IA no basta para dar el control por cumplido."


def sin_mecanismo_fp(control, severidad, estado=None):
    """Qué hacer si la persona confirma el falso positivo: lo registra ella en FP_HUMANO_REL (H-2); la IA no puede."""
    texto = ("el auditor no tiene un mecanismo para que la IA registre un falso positivo; la persona que lo "
             f"verificó lo registra en `{FP_HUMANO_REL}` del proyecto (control, huella H-… de la sección 6, quién, "
             "fecha AAAA-MM-DD y conclusión; formato en la sección 6c del informe) y vuelve a correr la auditoría: el "
             "control queda «descartado por verificación humana», que no es pass pero deja de bloquear el nivel")
    if severidad == "critica" and control.get("gate") == "N1":
        texto += " y los críticos de N1 nunca se aceptan como riesgo (estado.py)"
    else:
        texto += ("; el esquema de hallazgos admite `estado_hallazgo = aceptado` con firma, fecha, vencimiento y "
                  "razón, pero ningún script lo carga todavía")
    texto += "."
    if control["id"].startswith("SEG-SECRETO"):
        texto += (" No agregue el hallazgo a `.gitleaksignore`: el auditor lo toma como posible silenciamiento de "
                  "secretos y deja gitleaks en estado parcial, que no basta para declarar pass en ningún control que "
                  "dependa de gitleaks (adaptadores/gitleaks.sh).")
    return texto + " " + _cierre_estado(estado)


def remediacion_condicional(control, severidad, lugares, remediacion, estado=None):
    """Remediación cuando la IA marcó como falso positivo todos los hallazgos graves del control."""
    secreto = control["id"].startswith("SEG-SECRETO")
    que = "hay una credencial real" if secreto else "el problema es real"
    si_real = "Si es una credencial real" if secreto else "Si es real"
    return (f"Verificar a mano en {lista_ubicaciones(lugares)} si {que}. {si_real}: "
            f"{utiles.una_linea(remediacion or 'ver catálogo').strip()} Si no lo es: "
            f"{sin_mecanismo_fp(control, severidad, estado)}")


def _verificacion_fp(n, severidad, lugares, estado):
    return (f"Verificación humana: la IA (triage-fp) marcó {n} hallazgo(s) de severidad {severidad} como posible "
            f"falso positivo; revisar {lista_ubicaciones(lugares)} antes de actuar. {_cierre_estado(estado)}")


# H-9 / O4 (investigacion/18): cada «Verificar» da el comando real de los dos canales. Los skills de un plugin
# llevan el prefijo del plugin (docs/ACTIVAR.md §3, [NO VERIFICADO] en una sesión real). La CLI no lanza los
# jueces LLM ni la entrevista: para esos casos solo hay camino por Claude Code (o respuestas.json a mano).
PROYECTO_CLI = '"<carpeta del proyecto>"'


def comando(accion, modo="estandar"):
    """Par CLI / Claude Code para una acción: auditar, doctor, perfil, informe o juicio."""
    if accion == "doctor":
        return ("`bin/auditar doctor | python3 -I scripts/doctor_tabla.py` (CLI) o "
                "`/auditor-integral:auditar-doctor` (Claude Code)")
    if accion == "perfil":
        return ("`/auditor-integral:auditar-perfil` (Claude Code; por CLI: escribir `respuestas.json` y "
                f"`bin/auditar perfil {PROYECTO_CLI} --respuestas respuestas.json`)")
    if accion == "informe":
        return f"`bin/auditar report {PROYECTO_CLI}` (CLI) o `/auditor-integral:auditar-informe` (Claude Code)"
    if accion == "juicio":
        return (f"`/auditor-integral:auditar --modo {modo}` (Claude Code; la CLI no lanza los jueces LLM)")
    return f"`bin/auditar all {PROYECTO_CLI} --modo {modo}` (CLI) o `/auditor-integral:auditar --modo {modo}` (Claude Code)"


def _modo_superior(modo):
    return {"rapido": "estandar", "estandar": "profundo"}.get(modo, "profundo")


def _verificacion(control, est, modo):
    if est["estado"] == "manual_pendiente":
        return ("Verificación manual: registrar la evidencia y responder la entrevista "
                f"({comando('perfil', modo)}); luego {comando('informe', modo)}.")
    motivo = est.get("motivo") or ""
    if est["estado"] == "no_evaluado" and es_motivo_fp_ia(motivo):
        return ("Verificación humana: la IA marcó como posible falso positivo un hallazgo crítico o alto del control; "
                "revisarlo a mano (sección 6 del informe) antes de actuar.")
    if est["estado"] == "no_evaluado":
        if "entrevista" in motivo or "perfil:" in motivo:
            return f"Responder la entrevista ({motivo or 'ver motivo'}): {comando('perfil', modo)}."
        if "juicio LLM" in motivo or "no demostrable en análisis estático" in motivo:
            return f"Requiere juicio LLM o sonda ({motivo}): {comando('juicio', _modo_superior(modo) if modo == 'rapido' else modo)}."
        if "fuera del alcance del modo" in motivo:
            return f"Fuera del alcance del modo {modo}: corrida nueva con {comando('auditar', _modo_superior(modo))}."
        return (f"Habilitar lo que falta ({motivo or 'ver motivo'}; ver {comando('doctor', modo)}) y hacer una "
                f"corrida nueva: {comando('auditar', modo)}.")
    return f"Corrida nueva con {comando('auditar', modo)}: el control {control['id']} debe quedar en pass."


# R6 (gates-cli): remediación de secretos coherente con dónde está el secreto. «Rotar y limpiar el historial con git
# filter-repo» solo corresponde si el secreto está versionado o en el historial. Marcas OPCIONALES del hallazgo
# normalizado (las agrega el grupo «secretos»; sin ellas, o con cualquier duda, se usa el texto del catálogo):
#   secreto.jwt_rol (o jwt_rol)        "anon" → clave pública por diseño (AuditorJwtRol=anon en el crudo de gitleaks)
#   secreto.versionado (o versionado)  false → el archivo no está versionado (ignorado o sin git add)
#   no_versionado                      true → ídem (nombre alternativo)
# ubicacion.commit presente = el hallazgo viene del historial: siempre cuenta como versionado.
CONTROLES_REMEDIACION_SECRETO = ("SEG-SECRETO-REPO", "SEG-SECRETO-BUNDLE")
_RUTA_REMEDIACIONES = utiles.RAIZ / "plantillas" / "remediaciones.toml"


def _marca(h, clave):
    sec = h.get("secreto") if isinstance(h.get("secreto"), dict) else {}
    marcas = h.get("marcas") if isinstance(h.get("marcas"), dict) else {}
    for fuente in (sec, marcas, h):
        if clave in fuente:
            return fuente[clave]
    return None


# Ronda 6 (integración, DECISIONES.md #12): prefijos de regla con que normalizar/gitleaks.py y archivos_clave marcan
# los JWT anon y los secretos locales ignorados (hoy el catálogo los manda a SEG-SECRETO-LOCAL; si un hallazgo así
# llegara a SEG-SECRETO-REPO/BUNDLE, por ejemplo por un catálogo anterior, la remediación igual no pide rotar).
PREFIJO_REGLA_ANON = "jwt-anon-publico:"
PREFIJOS_REGLA_LOCAL = ("secreto-local-ignorado:", "archivos_clave.secreto_en_env_local")


def _reglas(h):
    return [str(f.get("regla") or "") for f in (h.get("fuente") or []) if isinstance(f, dict)]


def clase_secreto(h):
    """'publica' (JWT de rol anon), 'no_versionado' (archivo fuera de git) o 'versionado' (cualquier otro caso,
    incluido sin marcas: fail-closed). Las marcas pueden venir como campos (secreto.jwt_rol, versionado…) o como
    prefijo de la regla de TODAS las fuentes del hallazgo (ronda 6): si una fuente no lo trae, cuenta como versionado."""
    if (h.get("ubicacion") or {}).get("commit"):
        return "versionado"
    reglas = _reglas(h)
    if reglas and all(r.startswith(PREFIJO_REGLA_ANON) for r in reglas):
        return "publica"
    if reglas and all(r.startswith(PREFIJOS_REGLA_LOCAL) for r in reglas):
        return "no_versionado"
    rol = _marca(h, "jwt_rol")
    if isinstance(rol, str) and rol.strip().lower() == "anon":
        return "publica"
    if _marca(h, "versionado") is False or _marca(h, "no_versionado") is True:
        return "no_versionado"
    return "versionado"


def textos_remediacion_secreto():
    datos = utiles.leer_toml(_RUTA_REMEDIACIONES) or {}
    t = datos.get("remediacion_secreto") or {}
    return {k: v for k, v in t.items() if isinstance(v, str) and v.strip()}


def remediacion_secreto(control, hallazgos_control, base):
    """Texto de remediación para un control de secreto según sus hallazgos (todas las instancias). Solo cambia el
    texto del catálogo si TODAS las instancias son públicas o no versionadas; con una sola versionada (o sin marca)
    queda el texto de rotar + limpiar el historial."""
    if control not in CONTROLES_REMEDIACION_SECRETO or not hallazgos_control:
        return base
    clases = {clase_secreto(h) for h in hallazgos_control}
    if "versionado" in clases:
        return base
    textos = textos_remediacion_secreto()
    if clases == {"publica"}:
        return textos.get("clave_publica") or base
    if clases == {"no_versionado"}:
        return textos.get("no_versionado") or base
    return textos.get("no_versionado_y_publica") or textos.get("no_versionado") or base


def calcular(estados, indice, gates, hallazgos, modo="estandar", triage=None, todos=None):
    """todos: todas las instancias (hallazgos_todos.jsonl) para decidir la remediación de secretos; por defecto
    `hallazgos`."""
    triage = triage or {}
    sev_h = {h["id"]: h.get("severidad") for h in hallazgos}
    remed = {}
    for h in hallazgos:
        if h.get("remediacion") and h.get("control") not in remed:
            remed[h["control"]] = h["remediacion"]
    for cid in CONTROLES_REMEDIACION_SECRETO:
        if cid in remed:
            remed[cid] = remediacion_secreto(cid, [h for h in (todos or hallazgos) if h.get("control") == cid],
                                             remed[cid])
    orden_cat = {cid: i for i, cid in enumerate(indice)}
    cuello = set(gates.get("global", {}).get("cuello_de_botella", []))
    dominios = gates.get("dominios", {})
    bloqueos_ia = {}   # DECISIONES.md #10: bloqueos que dependen de un juicio de IA pendiente de verificación humana
    for b in gates.get("global", {}).get("bloqueos") or []:
        if b.get("pendiente_ia"):
            x = bloqueos_ia.setdefault(b["control"], {"tipos": [], "tope": b["tope"], "pendiente_ia": True,
                                                       "nota": b.get("nota")})
            for t in b.get("tipos") or [b["tipo"]]:   # R6: una entrada por control con todos sus tipos
                if t not in x["tipos"]:
                    x["tipos"].append(t)
            x["tope"] = min(x["tope"], b["tope"], key=utiles.num_nivel)
    items = []
    for e in estados:
        c = indice.get(e["control"])
        if c is None or e["estado"] not in ESTADO_ORDEN:
            continue
        sev = c.get("severidad_base", "media")
        for i in e.get("hallazgos") or []:
            if sev_h.get(i):
                sev = utiles.max_severidad(sev, sev_h[i])
        dom = dominios.get(c["dominio"], {})
        siguiente = _siguiente(dom.get("nivel_demostrado")) if dom.get("activo", True) else None
        es_siguiente = siguiente is not None and c["gate"] == siguiente
        es_critico = e["estado"] == "fail" and sev == "critica"
        # DECISIONES.md #10: un bloqueo pendiente de IA siempre entra (aunque su gate no sea el siguiente nivel).
        if not (es_siguiente or es_critico or c["id"] in bloqueos_ia):
            continue
        esfuerzo = c.get("esfuerzo") or "M"
        if es_critico and ESFUERZO.get(esfuerzo, 2) <= ESFUERZO["S"]:
            grupo = "esta_semana"
        elif es_siguiente:
            grupo = "siguiente_nivel"
        else:
            grupo = "criticos_otros_niveles"
        que_hacer = remed.get(c["id"]) or f"Cumplir «{c.get('titulo', c['id'])}»."
        verificacion = _verificacion(c, e, modo)
        revision = None
        marcados = graves_marcados_fp(c["id"], hallazgos, triage) if e["estado"] != "fail" else []
        if marcados:  # la IA marcó como FP todos sus graves: primero una persona verifica (sin pass ni borrado)
            lugares = [_lugar(h) for h in marcados]
            sev_fp = min((h["severidad"] for h in marcados), key=utiles.rango_severidad)
            que_hacer = remediacion_condicional(c, sev_fp, lugares, remed.get(c["id"]), e["estado"])
            verificacion = _verificacion_fp(len(marcados), sev_fp, lugares, e["estado"])
            revision = {"veredicto": "falso_positivo", "agente": "triage-fp",
                        "hallazgos": [h["id"] for h in marcados], "ubicaciones": [x for x in lugares if x]}
        item = {
            "control": c["id"], "titulo": c.get("titulo", c["id"]), "dominio": c["dominio"], "gate": c["gate"],
            "estado": e["estado"], "severidad": sev, "esfuerzo": esfuerzo, "bloquea_global": bool(c.get("bloquea_global")),
            "grupo": grupo, "motivo": e.get("motivo"), "hallazgos": len(e.get("hallazgos") or []),
            "que_hacer": que_hacer, "verificacion": verificacion, "referencia": c.get("fuente"),
            "_orden": (not c.get("bloquea_global"), c["id"] not in DEPENDENCIAS_PRIMERO, utiles.rango_severidad(sev),
                       c["dominio"] not in cuello, ESFUERZO.get(esfuerzo, 2), ESTADO_ORDEN[e["estado"]],
                       orden_cat.get(c["id"], 9999)),
        }
        if revision:
            item["revision_ia"] = revision
        if c["id"] in bloqueos_ia:
            item["bloqueo"] = bloqueos_ia[c["id"]]
        items.append(item)
    items.sort(key=lambda i: i["_orden"])
    for n, i in enumerate(items, 1):
        del i["_orden"]
        i["orden"] = n
    return items


def generar(corrida):
    corrida = Path(corrida)
    datos_estado = utiles.leer_json(corrida / "estado.json")
    gates = utiles.leer_json(corrida / "gates.json")
    if not datos_estado or not gates:
        raise FileNotFoundError("faltan estado.json o gates.json (ejecute gates.py antes)")
    indice = utiles.indice_controles(utiles.cargar_perfil(corrida))
    import veredictos   # diferido: H-2, hallazgos descartados por verificación humana (fp_humanos.json)
    hallazgos = veredictos.marcar_fp_humanos(corrida, utiles.leer_jsonl(corrida / "hallazgos.jsonl"))
    todos = veredictos.marcar_fp_humanos(corrida, utiles.leer_jsonl(corrida / "hallazgos_todos.jsonl")) or hallazgos
    items = calcular(datos_estado["controles"], indice, gates, hallazgos, datos_estado.get("modo") or "estandar",
                     triage=triage_de_corrida(corrida), todos=todos)
    datos = {"version_esquema": "1", "nivel_actual": gates["global"]["nivel_demostrado"], "items": items,
             "grupos": [{"id": g, "titulo": t} for g, t in GRUPOS]}
    utiles.escribir_json(corrida / "roadmap.json", datos)
    return datos


def main(argv=None):
    ap = argparse.ArgumentParser(description="Hoja de ruta → roadmap.json")
    ap.add_argument("corrida_pos", nargs="?", metavar="DIR_CORRIDA")
    ap.add_argument("--corrida")
    a = ap.parse_args(argv)
    corrida = a.corrida or a.corrida_pos
    if not corrida or not Path(corrida).is_dir():
        print("roadmap.py: indique una carpeta de corrida existente", file=sys.stderr)
        return 2
    try:
        generar(corrida)
    except FileNotFoundError as exc:
        print(f"roadmap.py: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

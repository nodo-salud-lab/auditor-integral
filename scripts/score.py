#!/usr/bin/env python3
"""Puntaje 0-100, cobertura y letra A-E por dominio → score.json (PLAN_MAESTRO §4.4; DECISIONES.md #1).
Informativo: NO decide el nivel (lo decide gates.py).

Uso:  score.py DIR_CORRIDA   |   score.py --corrida DIR_CORRIDA     (requiere estado.json)

  Puntaje(d)   = 100 × Σ w(c)·[pass] / Σ w(c), sobre controles evaluados (pass o fail) del dominio;
                 w = peso de la severidad (config/pesos.toml [severidad]: OpenSSF Scorecard 10/7,5/5/2,5; info 0).
  Cobertura(d) = evaluados / aplicables (no_aplica fuera). Con cobertura < umbral
                 (config/umbrales.toml cobertura_controles_puntaje) el puntaje sale en gris ("insuficiente").
  Letra(d)     = peor fail abierto del dominio, estilo SonarQube MQR: A sin fallos (o solo info), B baja,
                 C media, D alta, E crítica ([rating_dominio]). No compensatoria: un crítico da E aunque el
                 puntaje sea alto. Sin controles evaluados → sin letra.
  Global       = [puntaje_global].metodo:
                 "agrupado_scorecard" (G1, adoptado): 100 × Σ w(c)·m(c)·[pass] / Σ w(c)·m(c) sobre TODOS
                   los controles evaluados (GetAggregateScore de Scorecard; no evaluados excluidos);
                 "media_simple_dominios" (G2) y "media de dominios ponderada por controles aplicables" (G3).
                 m(c) = factor ([multiplicador_contextual], ×1,5 de CVSS v3.1 §7.4) si el control es de
                 SEG/DAT y salud o pagos = true; si no, 1. La letra global es la peor de los dominios.
"""
import argparse
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import utiles  # noqa: E402

RUTA_PESOS = utiles.RAIZ / "config" / "pesos.toml"
RUTA_UMBRALES = utiles.RAIZ / "config" / "umbrales.toml"


METODO_G1 = "agrupado_scorecard"
METODO_G2 = "media_simple_dominios"
METODO_G3 = "media de dominios ponderada por controles aplicables"
METODOS = (METODO_G1, METODO_G2, METODO_G3)
ORDEN_SEV = ("critica", "alta", "media", "baja")  # de peor a mejor; info no baja la letra (Sonar MQR)
LETRAS_DEFECTO = {"ninguno": "A", "baja": "B", "media": "C", "alta": "D", "critica": "E"}


def _peor(severidades):
    for s in ORDEN_SEV:
        if s in severidades:
            return s
    return "ninguno"


def calcular(estados, indice, pesos, umbral_pct, banderas, factor=1.5, dominios_factor=("SEG", "DAT"),
             banderas_factor=("salud", "pagos"), metodo=METODO_G1, letras=None):
    if metodo not in METODOS:
        raise ValueError(f"método de puntaje global desconocido: {metodo!r} (válidos: {', '.join(METODOS)})")
    letras = letras or LETRAS_DEFECTO
    aplica_factor = any(banderas.get(b) is True for b in banderas_factor)
    acumulado = {}
    g_num = g_den = 0.0
    g_pass = g_ev = 0
    for e in estados:
        c = indice.get(e["control"])
        if c is None or e["estado"] == "no_aplica":
            continue
        d = acumulado.setdefault(c["dominio"], {"aplicables": 0, "evaluados": 0, "w_total": 0.0, "w_pass": 0.0,
                                                "pass": 0, "fail": 0, "sev_fail": set()})
        d["aplicables"] += 1
        if e["estado"] in ("pass", "fail"):
            w = float(pesos.get(c.get("severidad_base"), 0))
            m = factor if aplica_factor and c["dominio"] in dominios_factor else 1.0
            d["evaluados"] += 1
            d["w_total"] += w
            d[e["estado"]] += 1
            g_den += w * m
            g_ev += 1
            if e["estado"] == "pass":
                d["w_pass"] += w
                g_num += w * m
                g_pass += 1
            else:
                d["sev_fail"].add(c.get("severidad_base"))
    umbral = umbral_pct / 100.0
    dominios = {}
    for dom in sorted(acumulado, key=lambda x: utiles.ORDEN_DOMINIOS.index(x) if x in utiles.ORDEN_DOMINIOS else 99):
        a = acumulado[dom]
        if a["evaluados"] and a["w_total"] > 0:
            puntaje = round(100.0 * a["w_pass"] / a["w_total"], 1)
        elif a["evaluados"]:
            puntaje = round(100.0 * a["pass"] / a["evaluados"], 1)
        else:
            puntaje = None
        cobertura = round(a["evaluados"] / a["aplicables"], 3) if a["aplicables"] else 0.0
        gris = puntaje is None or cobertura < umbral
        leyenda = (f"insuficiente (cobertura {round(cobertura * 100)} % < {umbral_pct:g} %)" if gris else None)
        peor = _peor(a["sev_fail"]) if a["evaluados"] else None
        dominios[dom] = {"puntaje": puntaje, "cobertura": cobertura, "aplicables": a["aplicables"],
                         "evaluados": a["evaluados"], "pass": a["pass"], "fail": a["fail"], "gris": gris,
                         "leyenda": leyenda, "peor_fail": peor, "letra": letras.get(peor) if peor else None}
    if metodo == METODO_G1:
        if g_den > 0:
            puntaje_global = round(100.0 * g_num / g_den, 1)
        else:
            puntaje_global = round(100.0 * g_pass / g_ev, 1) if g_ev else None
    else:
        num = den = 0.0
        for dom, v in dominios.items():
            if v["puntaje"] is None:
                continue
            w = v["aplicables"] if metodo == METODO_G3 else 1.0
            w *= factor if aplica_factor and dom in dominios_factor else 1.0
            num += w * v["puntaje"]
            den += w
        puntaje_global = round(num / den, 1) if den else None
    tot_apl = sum(v["aplicables"] for v in dominios.values())
    tot_ev = sum(v["evaluados"] for v in dominios.values())
    cobertura_global = round(tot_ev / tot_apl, 3) if tot_apl else 0.0
    peores = {v["peor_fail"] for v in dominios.values() if v["peor_fail"]}
    peor_global = _peor(peores) if peores else None
    return {
        "version_esquema": "1",
        "dominios": dominios,
        "global": {"puntaje": puntaje_global, "cobertura": cobertura_global,
                   "gris": puntaje_global is None or cobertura_global < umbral,
                   "factor_aplicado": aplica_factor, "factor": factor if aplica_factor else 1.0,
                   "metodo": metodo, "peor_fail": peor_global,
                   "letra": letras.get(peor_global) if peor_global else None},
        "umbral_cobertura": umbral,
        "pesos": dict(pesos),
        "nota": ("Informativo: el nivel N0-N5 lo decide gates.py, no este puntaje. Pesos de OpenSSF Scorecard y "
                 "letra estilo SonarQube; la correspondencia de severidades es nominal (sin validar en este "
                 "auditor: ESTIMACIÓN)."),
    }


def cargar_config():
    pesos_toml = utiles.leer_toml(RUTA_PESOS)
    sev_toml = pesos_toml.get("severidad", {})
    sev = {k: v for k, v in sev_toml.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}
    mult = pesos_toml.get("multiplicador_contextual", {})
    letras = {k: v for k, v in pesos_toml.get("rating_dominio", {}).items()
              if k in LETRAS_DEFECTO and isinstance(v, str)} or dict(LETRAS_DEFECTO)
    umbral = utiles.leer_toml(RUTA_UMBRALES).get("umbral", {}).get("cobertura_controles_puntaje", {}).get("valor", 70)
    return {"severidad": sev, "umbral": umbral, "multiplicador": mult, "letras": letras,
            "metodo": pesos_toml.get("puntaje_global", {}).get("metodo", METODO_G1),
            "origen": sev_toml.get("origen", "propuesta")}


def generar(corrida):
    corrida = Path(corrida)
    datos_estado = utiles.leer_json(corrida / "estado.json")
    if not datos_estado:
        raise FileNotFoundError("falta estado.json (ejecute gates.py o estado.py antes)")
    perfil = utiles.cargar_perfil(corrida)
    indice = utiles.indice_controles(perfil)
    cfg = cargar_config()
    mult = cfg["multiplicador"]
    s = calcular(datos_estado["controles"], indice, cfg["severidad"], cfg["umbral"], perfil["banderas"],
                 factor=float(mult.get("factor", 1.5)), dominios_factor=tuple(mult.get("dominios", ("SEG", "DAT"))),
                 banderas_factor=tuple(mult.get("banderas", ("salud", "pagos"))), metodo=cfg["metodo"],
                 letras=cfg["letras"])
    s["origen_pesos"] = cfg["origen"]
    utiles.escribir_json(corrida / "score.json", s)
    return s


def main(argv=None):
    ap = argparse.ArgumentParser(description="Puntaje 0-100 y cobertura por dominio → score.json")
    ap.add_argument("corrida_pos", nargs="?", metavar="DIR_CORRIDA")
    ap.add_argument("--corrida")
    a = ap.parse_args(argv)
    corrida = a.corrida or a.corrida_pos
    if not corrida or not Path(corrida).is_dir():
        print("score.py: indique una carpeta de corrida existente", file=sys.stderr)
        return 2
    try:
        s = generar(corrida)
    except (FileNotFoundError, ValueError) as exc:
        print(f"score.py: {exc}", file=sys.stderr)
        return 1
    print(f"score: global {s['global']['puntaje']} (letra {s['global']['letra']}) · cobertura {s['global']['cobertura']}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

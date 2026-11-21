#!/usr/bin/env python3
"""Perfil de riesgo: perfil_tecnico.json + respuestas.json del creador → perfil.json (PLAN_MAESTRO §3.6; F3).

Entrevistas: plantillas/entrevista_e0.md (preguntas 1-10) y plantillas/entrevista_e5.md (11-16). Rápido pregunta
solo 3, 7 y 9; estándar 1-10; profundo 1-16.

respuestas.json (lo llena el skill auditar-perfil con lo que dice el creador; nunca lo inventa el LLM):
  {"fecha": "AAAA-MM-DD", "modo": "estandar",
   "respuestas": {"1": "texto", ...},                      # texto libre por pregunta; ausente o null = sin respuesta
   "declaraciones": {"datos_personales": false, ...},      # banderas que el creador declaró explícitamente
   "rutas_sinteticas": ["pruebas/sinteticos"],             # AUD-SINT: carpetas o archivos de datos sintéticos
   "flujograma": {"archivo": "flujograma.mmd", "estado": "borrador" | "confirmado"}}

Reglas (fail-closed; «no se asume la respuesta»):
- Banderas de archivos (baas, llm, pagos…): las de perfil_tecnico.json. Si la entrevista declara true y los archivos
  false, queda true (más controles aplican); si declara false y los archivos dicen true, gana la evidencia de
  archivos y se registra en `discrepancias`. origen_banderas: archivos | entrevista | ambos | sin_dato.
- Banderas solo de entrevista (datos_personales, salud, menores, ue, datos_reales_cargados, usuarios_3m/12m): solo
  desde `declaraciones` con el tipo correcto (booleano; enteros ≥ 0 para usuarios). Un texto en `respuestas` sin
  declaración NO fija la bandera (queda null). Valores inválidos se ignoran y se anotan en `advertencias`.
- Una pregunta queda en `pendientes_entrevista` si no tiene texto de respuesta y no están declaradas todas sus
  banderas, o si alguna de sus banderas quedó sin declarar. Sus controles no pueden quedar en pass
  (veredictos.ajustar_pendientes, aplicado por estado.py) y las banderas null dejan sus controles en no_evaluado.
- `declaraciones` registra valor, fecha y pregunta de cada bandera declarada (estado.py usa
  declaraciones.datos_personales.fecha para el aviso legal, DECISIONES.md #4).
- `sinteticos`: rutas relativas declaradas por el creador (se descartan absolutas o con ..). Quedan registradas;
  la exclusión efectiva del crítico DAT-PII-REPO sigue configurándose en confidencial.toml [sinteticos].
- Las respuestas se enmascaran (PII y secretos) y se recortan a 2000 caracteres antes de escribirse.
- La salida valida contra schemas/perfil.schema.json; si no valida, no se escribe (código 1).

A3 (investigacion/18): sin respuestas.json (ni --respuestas) y con un perfil.json que ya trae datos de la entrevista,
no se sobrescribe: sale con código 1 y perfil.json queda intacto (antes se pisaba con un perfil vacío). Lo mismo si
respuestas.json existe pero no es JSON válido o no es un objeto (código 1, perfil.json intacto). Las claves de primer
nivel desconocidas (p. ej. «respuesta» en singular) se ignoran con una advertencia en perfil.json y por stderr.

Uso:  perfil.py --corrida DIR [--respuestas ARCHIVO]   (por defecto DIR/respuestas.json)
"""
import argparse
import json
import re
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import enmascarar  # noqa: E402
import utiles  # noqa: E402
import validar_schema  # noqa: E402

SCHEMA = utiles.RAIZ / "schemas" / "perfil.schema.json"
# Pregunta → banderas que fija y controles que dependen de su respuesta (mapeo: ESTIMACIÓN a revisar por el
# investigador; los ids se verifican contra el catálogo en tests/test_f3a_perfil.py).
PREGUNTAS = {
    1: {"tema": "qué hace y para quién", "banderas": [], "controles": ["OPS-PERFIL-RIESGO"]},
    2: {"tema": "3-5 flujos más importantes (flujograma)", "banderas": [], "controles": ["COD-FLUJOGRAMA", "COD-CRITERIOS"]},
    3: {"tema": "datos personales, de salud, de menores, usuarios en la UE",
        "banderas": ["datos_personales", "salud", "menores", "ue"],
        "controles": ["OPS-PRIVACIDAD", "OPS-DERECHOS-TITULAR", "OPS-TRANSFERENCIAS", "OPS-LLM-PII"]},
    4: {"tema": "pagos y proveedor", "banderas": ["pagos"], "controles": ["SEG-PAGOS-SERVIDOR"]},
    5: {"tema": "IA dentro de la app y quién paga el consumo", "banderas": ["llm"], "controles": ["ESC-LLM-TOPE"]},
    6: {"tema": "envío de emails", "banderas": ["emails"], "controles": ["INF-EMAIL-ASYNC"]},
    7: {"tema": "dónde está publicada y si hay staging", "banderas": [],
        "controles": ["INF-PLATAFORMA", "INF-ENTORNOS", "INF-ENTORNOS-SEPARADOS"]},
    8: {"tema": "usuarios esperados a 3 y 12 meses", "banderas": ["usuarios_3m", "usuarios_12m"],
        "controles": ["ESC-VOLUMEN-REALISTA"]},
    9: {"tema": "usuarios o datos reales cargados", "banderas": ["datos_reales_cargados"], "controles": ["OPS-PERFIL-RIESGO"]},
    10: {"tema": "cuentas (hosting, BD, dominio) a nombre del creador", "banderas": [], "controles": ["OPS-CUENTAS"]},
    11: {"tema": "backups/PITR y prueba de restauración", "banderas": [], "controles": ["DAT-BACKUP"]},
    12: {"tema": "RTO y RPO tolerables", "banderas": [], "controles": ["OPS-RPO-RTO"]},
    13: {"tema": "tope de gasto o alertas de presupuesto", "banderas": [], "controles": ["ESC-PRESUPUESTO", "OPS-PLAN-GRATIS"]},
    14: {"tema": "quién más es admin y si usa MFA", "banderas": [], "controles": ["OPS-CUENTAS-EFECTIVO"]},
    15: {"tema": "política de privacidad publicada", "banderas": [], "controles": ["OPS-PRIVACIDAD"]},
    16: {"tema": "qué haría hoy si se filtrara una clave", "banderas": [], "controles": ["OPS-SECRETOS-CICLO"]},
}
MODOS = {"rapido": [3, 7, 9], "estandar": list(range(1, 11)), "profundo": list(range(1, 17))}
BANDERAS_ENTEROS = ("usuarios_3m", "usuarios_12m")
BANDERAS_DECLARABLES_ARCHIVO = ("pagos", "llm", "emails")
RE_FECHA = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def preguntas_del_modo(modo):
    return list(MODOS.get(modo or "estandar", MODOS["estandar"]))


def _pregunta_de(bandera):
    for n, p in PREGUNTAS.items():
        if bandera in p["banderas"]:
            return n
    return None


def _valor_valido(bandera, v):
    if bandera in BANDERAS_ENTEROS:
        return isinstance(v, int) and not isinstance(v, bool) and v >= 0
    return isinstance(v, bool)


def _ruta_valida(r):
    if not isinstance(r, str) or not r.strip() or r.startswith(("/", "~")) or "\\" in r:
        return False
    partes = [p for p in r.strip().split("/") if p not in ("", ".")]
    return bool(partes) and ".." not in partes


CLAVES_RESPUESTAS = ("fecha", "modo", "respuestas", "declaraciones", "rutas_sinteticas", "flujograma")


def combinar(tecnico, respuestas, modo, fecha):
    tecnico = tecnico if isinstance(tecnico, dict) else {}
    respuestas = respuestas if isinstance(respuestas, dict) else {}
    advertencias, discrepancias = [], []
    for k in sorted(map(str, respuestas)):
        if k not in CLAVES_RESPUESTAS:
            advertencias.append(f"clave desconocida ignorada en respuestas.json: {k[:40]} (válidas: "
                                f"{', '.join(CLAVES_RESPUESTAS)})")

    textos = {}
    for k, v in (respuestas.get("respuestas") or {}).items() if isinstance(respuestas.get("respuestas"), dict) else []:
        n = int(k) if str(k).isdigit() else None
        if n not in PREGUNTAS:
            advertencias.append(f"respuesta a una pregunta inexistente ignorada: {str(k)[:20]}")
            continue
        if v is None:
            continue
        if not isinstance(v, str):
            advertencias.append(f"respuesta {n} ignorada: no es texto")
            continue
        if v.strip():
            textos[n] = enmascarar.recortar(enmascarar.enmascarar_texto(v.strip()), 2000)

    declaradas = {}
    decl_crudas = respuestas.get("declaraciones") if isinstance(respuestas.get("declaraciones"), dict) else {}
    for b, v in sorted(decl_crudas.items()):
        if b not in utiles.BANDERAS_ENTREVISTA + BANDERAS_DECLARABLES_ARCHIVO:
            advertencias.append(f"declaración ignorada: {str(b)[:40]} no es una bandera de entrevista")
            continue
        if v is None:
            continue
        if not _valor_valido(b, v):
            advertencias.append(f"declaración {b} ignorada: valor de tipo inválido (no se asume)")
            continue
        declaradas[b] = v

    banderas, origen = {}, {}
    for b in utiles.BANDERAS_ARCHIVOS:
        v_arch = tecnico.get(b) if b in tecnico else None
        if b in declaradas:
            v_dec = declaradas[b]
            if v_arch is True and v_dec is False:
                discrepancias.append(f"{b}: los archivos indican true y el creador declaró false; gana la evidencia "
                                     "de archivos (fail-closed)")
            valor = (v_arch or v_dec) if isinstance(v_arch, bool) else v_dec
            banderas[b], origen[b] = valor, ("ambos" if v_arch is not None else "entrevista")
        else:
            banderas[b] = v_arch
            origen[b] = "archivos" if v_arch is not None else "sin_dato"
    for b in utiles.BANDERAS_COMPLEMENTO_TECNICO:
        if isinstance(tecnico.get(b), bool):
            banderas[b] = tecnico[b]
            origen[b] = "archivos"
    for b in utiles.BANDERAS_ENTREVISTA:
        banderas[b] = declaradas.get(b)
        origen[b] = "entrevista" if b in declaradas else "sin_dato"

    declaraciones = {b: {"valor": v, "fecha": fecha, "fuente": "entrevista", "pregunta": _pregunta_de(b)}
                     for b, v in sorted(declaradas.items())}
    preguntadas = set(preguntas_del_modo(modo))
    pendientes = {}
    for n, p in PREGUNTAS.items():
        faltan = [b for b in p["banderas"] if b not in declaradas]
        if faltan or (not p["banderas"] and n not in textos):
            pendientes[str(n)] = {"controles": list(p["controles"]), "banderas": faltan, "preguntada": n in preguntadas}

    sint = respuestas.get("rutas_sinteticas") or []
    sint = sint if isinstance(sint, list) else []
    validas = sorted({r.strip().strip("/") for r in sint if _ruta_valida(r)})
    descartadas = sorted({str(r)[:300] for r in sint if not _ruta_valida(r)})

    flujo = respuestas.get("flujograma")
    if not (isinstance(flujo, dict) and isinstance(flujo.get("archivo"), str)
            and flujo.get("estado") in ("borrador", "confirmado")):
        flujo = None
    else:
        flujo = {"archivo": flujo["archivo"][:300], "estado": flujo["estado"]}

    perfil = {"version_esquema": "1", "banderas": banderas, "origen_banderas": origen,
              "entrevista": {"modo": modo, "respuestas": {str(n): textos.get(n) for n in sorted(preguntadas | set(textos))}},
              "flujograma": flujo, "fecha": fecha, "declaraciones": declaraciones,
              "sinteticos": {"rutas": validas, "descartadas": descartadas, "fecha": fecha,
                             "fuente": "creador (entrevista)"},
              "pendientes_entrevista": pendientes, "discrepancias": discrepancias, "advertencias": advertencias}
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    if validar_schema.validar(tecnico, validar_schema.subschema(schema, "perfil_tecnico")) == []:
        perfil["tecnico"] = tecnico
    return perfil


class PerfilConDatos(ValueError):
    """A3 (investigacion/18): no hay respuestas.json y perfil.json ya trae respuestas de la entrevista."""


def perfil_con_datos(perfil):
    """True si un perfil.json existente guarda algo que solo sale de la entrevista (respuestas, declaraciones,
    flujograma, rutas sintéticas o banderas de entrevista no nulas): regenerarlo sin respuestas.json lo borraría."""
    if not isinstance(perfil, dict):
        return False
    entrevista = perfil.get("entrevista") if isinstance(perfil.get("entrevista"), dict) else {}
    resp = entrevista.get("respuestas") if isinstance(entrevista.get("respuestas"), dict) else {}
    sint = perfil.get("sinteticos") if isinstance(perfil.get("sinteticos"), dict) else {}
    banderas = perfil.get("banderas") if isinstance(perfil.get("banderas"), dict) else {}
    return bool(any(isinstance(v, str) and v.strip() for v in resp.values())
                or perfil.get("declaraciones") or perfil.get("flujograma") or sint.get("rutas")
                or any(banderas.get(b) is not None for b in utiles.BANDERAS_ENTREVISTA))


def leer_respuestas(ruta):
    """respuestas.json como dict. A3 (revisión adversarial 2026-11-20): si existe pero no es JSON válido (p. ej. una
    coma final que dejó el LLM que lo escribe) o no es un objeto, lanza ValueError ANTES de escribir nada: antes se
    tomaba como {} y perfil.json se pisaba en silencio, con rc 0."""
    try:
        datos = json.loads(Path(ruta).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise ValueError(f"no se pudo leer {Path(ruta).name}: {e.__class__.__name__}; perfil.json queda sin cambios")
    except ValueError as e:
        raise ValueError(f"{Path(ruta).name}: JSON inválido ({e}); corríjalo y vuelva a ejecutar; perfil.json queda "
                         "sin cambios")
    if not isinstance(datos, dict):
        raise ValueError(f"{Path(ruta).name}: debe ser un objeto JSON {{…}} (formato en scripts/perfil.py), no "
                         f"{type(datos).__name__}; perfil.json queda sin cambios")
    return datos


def generar(corrida, ruta_respuestas=None):
    corrida = Path(corrida)
    explicito = ruta_respuestas is not None
    ruta_respuestas = Path(ruta_respuestas) if ruta_respuestas else corrida / "respuestas.json"
    if not explicito and not ruta_respuestas.is_file() and perfil_con_datos(utiles.leer_json(corrida / "perfil.json")):
        # A3: antes se regeneraba con {} y las respuestas escritas a mano en perfil.json se perdían en silencio.
        raise PerfilConDatos(
            "perfil.json ya tiene respuestas de la entrevista y no hay respuestas.json: no se sobrescribe con un "
            "perfil vacío (se perderían). Escriba las respuestas en respuestas.json (formato en scripts/perfil.py) "
            "o pase --respuestas ARCHIVO; perfil.json queda sin cambios")
    respuestas = leer_respuestas(ruta_respuestas) if ruta_respuestas.is_file() else {}
    tecnico = utiles.leer_json(corrida / "perfil_tecnico.json")
    modo = respuestas.get("modo") if respuestas.get("modo") in MODOS else utiles.modo_corrida(corrida)
    fecha = respuestas.get("fecha") if isinstance(respuestas.get("fecha"), str) and RE_FECHA.match(respuestas["fecha"]) \
        else utiles.fecha_referencia(corrida)
    perfil = combinar(tecnico, respuestas, modo, fecha)
    errores = validar_schema.validar(perfil, json.loads(SCHEMA.read_text(encoding="utf-8")))
    if errores:
        raise ValueError("perfil.json no valida contra perfil.schema.json: " + "; ".join(errores[:5]))
    utiles.escribir_json(corrida / "perfil.json", perfil)
    return perfil


def main(argv=None):
    ap = argparse.ArgumentParser(description="perfil_tecnico.json + respuestas.json → perfil.json")
    ap.add_argument("corrida_pos", nargs="?", metavar="DIR_CORRIDA")
    ap.add_argument("--corrida")
    ap.add_argument("--respuestas")
    a = ap.parse_args(argv)
    corrida = a.corrida or a.corrida_pos
    if not corrida or not Path(corrida).is_dir():
        print("perfil.py: indique una carpeta de corrida existente", file=sys.stderr)
        return 2
    if a.respuestas and not Path(a.respuestas).is_file():
        print(f"perfil.py: no existe {a.respuestas}", file=sys.stderr)
        return 2
    try:
        p = generar(corrida, a.respuestas)
    except ValueError as e:
        print(f"perfil.py: {e}", file=sys.stderr)
        return 1
    for adv in p.get("advertencias") or []:
        print(f"perfil.py: advertencia: {adv}", file=sys.stderr)
    print(f"perfil: {len(p['pendientes_entrevista'])} preguntas pendientes; declaraciones: "
          f"{', '.join(p['declaraciones']) or 'ninguna'}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

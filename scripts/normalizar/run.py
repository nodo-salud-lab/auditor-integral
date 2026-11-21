#!/usr/bin/env python3
"""Normaliza el crudo de una corrida → hallazgos.jsonl (PLAN_MAESTRO §3.1, paso "Normalizar").

Uso:  run.py DIR_CORRIDA      |   run.py --corrida DIR_CORRIDA

Lee <corrida>/crudo/:
  gitleaks*.json        → normalizar/gitleaks.py
  *.sarif               → normalizar/sarif.py (semgrep, zizmor, ...)
  osv*.json             → normalizar/osv.py
  check_*.json          → normalizar/checks.py
  *.meta.json           → versión y estado de cada herramienta
Escribe:
  hallazgos.jsonl        hallazgos fusionados, ≤ 5 por (control, archivo), validados contra el schema
  hallazgos_todos.jsonl  los mismos sin tope (para métricas de validación; no va al LLM)
  normalizacion.json     resumen: conteos por herramienta, reglas sin mapear, checks_pass, errores
  digest/                digest mínimo para el LLM (scripts/digest.py)
Todo ordenado de forma estable y sin marcas de tiempo (criterio F1-3).

Rutas confidenciales (config/confidencial.toml, DECISIONES.md #3): todo registro cuya ruta caiga ahí se
descarta antes de construir el hallazgo (defensa en profundidad si una herramienta o check las leyó);
normalizacion.json cuenta cuántos en `excluidos_confidenciales`, sin ruta ni contenido. Los registros en
.auditoria/ (salidas del propio auditor, p. ej. un SBOM de una corrida anterior) se descartan y se cuentan
en `excluidos_salidas_auditor`.
Si el crudo no trae check_datos_confidenciales.json y el proyecto existe, se ejecuta ese check aquí
(solo metadatos). Desde 2026-11-18 ese check está en TAREAS de ejecutar_scanners.sh; esta invocación
queda como respaldo (p. ej. `normalize` sin `scan`) y no se repite si el crudo ya lo trae.
Códigos de salida: 0 ok · 1 algún hallazgo no valida contra el schema · 2 uso incorrecto.
"""
import argparse
import json
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import utiles  # noqa: E402
import validar_schema  # noqa: E402
from normalizar import checks, comun, gitleaks, osv, sarif  # noqa: E402

sys.path.append(str(_SCRIPTS / "checks"))
import datos_confidenciales  # noqa: E402

MAX_LINEAS_CONTENIDO = 40
MAX_BYTES_CONTENIDO = 2_000_000


def _asegurar_check_confidencial(crudo, proyecto):
    if proyecto is None or (crudo / "check_datos_confidenciales.json").exists():
        return
    try:
        datos_confidenciales.main([str(proyecto), str(crudo)])
    except Exception as exc:  # el check nunca debe tumbar la normalización
        print(f"run.py: datos_confidenciales falló: {type(exc).__name__}", file=sys.stderr)


def _en_ruta_confidencial(archivo, proyecto, conf):
    """Se prueba la ruta tal como la informó la herramienta (relativa al proyecto) y la normalizada:
    normalizar_archivo puede acortar una ruta inexistente (datos-reales/.env → .env)."""
    if not archivo:
        return False
    bruta = comun.normalizar_archivo(archivo, None)
    candidatas = []
    if bruta and proyecto is not None and bruta.startswith("/"):
        base = str(proyecto).rstrip("/") + "/"
        if bruta.startswith(base):
            candidatas.append(bruta[len(base):])
    elif bruta:
        candidatas.append(bruta)
    rel = comun.normalizar_archivo(archivo, proyecto)
    if rel and not rel.startswith("/"):
        candidatas.append(rel)
    return any(datos_confidenciales.es_confidencial(c, conf) for c in candidatas)


def _en_salidas_auditor(archivo, proyecto):
    """True si el registro apunta a .auditoria/ (salidas del propio auditor: p. ej. el SBOM de una corrida
    anterior que osv-scanner encuentra al recorrer el proyecto). Re-auditoría de kine us, 2026-11-18."""
    if not archivo:
        return False
    for ruta in (comun.normalizar_archivo(archivo, proyecto), comun.normalizar_archivo(archivo, None)):
        if not ruta:
            continue
        if proyecto is not None and ruta.startswith(str(proyecto).rstrip("/") + "/"):
            ruta = ruta[len(str(proyecto).rstrip("/")) + 1:]
        if ruta == ".auditoria" or ruta.startswith(".auditoria/"):
            return True
    return False


def _huella_de_lineas(proyecto, reg, conf):
    """sha256 del texto normalizado de las líneas linea..linea_fin del archivo (sin guardar el texto).
    None si no se puede: sin proyecto, ruta confidencial o fuera del proyecto, hallazgo del historial git."""
    archivo, linea = reg.get("archivo"), reg.get("linea")
    if proyecto is None or not archivo or not isinstance(linea, int) or linea < 1 or reg.get("commit"):
        return None
    rel = comun.normalizar_archivo(archivo, proyecto)
    if not rel or rel.startswith("/") or datos_confidenciales.es_confidencial(rel, conf):
        return None
    fin = reg.get("linea_fin") if isinstance(reg.get("linea_fin"), int) else linea
    fin = max(linea, min(fin, linea + MAX_LINEAS_CONTENIDO - 1))
    ruta = (proyecto / rel)
    try:
        if ruta.is_symlink() or not ruta.is_file() or ruta.stat().st_size > MAX_BYTES_CONTENIDO:
            return None
        if proyecto.resolve() not in ruta.resolve().parents:
            return None
        with open(ruta, encoding="utf-8", errors="replace") as f:
            lineas = [l for n, l in enumerate(f, 1) if linea <= n <= fin]
    except OSError:
        return None
    return comun.huella_contenido("\n".join(lineas)) if lineas else None

SCHEMA = utiles.RAIZ / "schemas" / "hallazgo.schema.json"


def clasificar(ruta):
    nombre = ruta.name
    if nombre.endswith(".meta.json"):
        return None
    if nombre.endswith(".sarif") or nombre.endswith(".sarif.json"):
        return "sarif"
    if nombre.startswith("gitleaks") and nombre.endswith(".json"):
        return "gitleaks"
    if nombre.startswith("osv") and nombre.endswith(".json"):
        return "osv"
    if nombre.startswith("check_") and nombre.endswith(".json"):
        return "checks"
    return "ignorado"


def normalizar(corrida):
    corrida = Path(corrida)
    crudo = corrida / "crudo"
    run = utiles.leer_run(corrida)
    proyecto = Path(run["proyecto"]) if run.get("proyecto") else None
    if proyecto is not None and not proyecto.is_dir():
        proyecto = None
    perfil = utiles.cargar_perfil(corrida)
    indice = utiles.indice_controles(perfil)
    if crudo.is_dir():
        _asegurar_check_confidencial(crudo, proyecto)
    metas = utiles.cargar_metas(crudo)
    conf = datos_confidenciales.cargar()
    ctx = {"proyecto": proyecto, "metas": metas, "confidencial": conf}
    comun._CONTENIDO.clear()
    archivos = sorted(p for p in crudo.iterdir() if p.is_file()) if crudo.is_dir() else []

    secretos = []
    for p in archivos:
        if clasificar(p) == "gitleaks":
            secretos += gitleaks.secretos(p)

    registros, pasan, errores, ignorados, por_herr, estados_checks = [], set(), [], [], {}, {}
    for p in archivos:
        tipo = clasificar(p)
        if tipo is None:
            continue
        if tipo == "ignorado":
            ignorados.append(p.name)
            continue
        try:
            if tipo == "gitleaks":
                regs = gitleaks.leer(p, ctx)
            elif tipo == "sarif":
                regs = sarif.leer(p, ctx)
            elif tipo == "osv":
                regs = osv.leer(p, ctx)
            else:
                regs, ok = checks.leer(p, ctx)
                pasan.update(ok)
                est, motivo = checks.estado_de(p)
                estados_checks[checks.nombre_check(p)] = {"estado": est, "motivo": motivo}
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            errores.append(f"{p.name}: {type(exc).__name__}")
            continue
        for r in regs:
            clave = r.get("herramienta_fuente") or r["herramienta"]
            por_herr[clave] = por_herr.get(clave, 0) + 1
        registros += regs

    hallazgos, sin_mapear, excluidos, propias = [], set(), 0, 0
    for r in registros:
        if _en_salidas_auditor(r.get("archivo"), proyecto) or _en_salidas_auditor(r.get("archivo_original"), proyecto):
            propias += 1
            continue
        if (r.get("herramienta_fuente") != "datos_confidenciales"
                and (_en_ruta_confidencial(r.get("archivo"), proyecto, conf)
                     or _en_ruta_confidencial(r.get("archivo_original"), proyecto, conf))):
            excluidos += 1
            continue
        huella = _huella_de_lineas(proyecto, r, conf)
        if huella:
            r = dict(r, contenido_hash=huella)
        h = comun.construir(r, indice, secretos)
        if h is None:
            sin_mapear.add(f"{r['herramienta']}:{r.get('regla')}"[:200])
        else:
            hallazgos.append(h)

    orden = utiles.orden_catalogo()
    todos = comun.ordenar(comun.fusionar(hallazgos), orden)
    limitados = comun.ordenar(comun.limitar(todos), orden)

    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    invalidos = []
    for h in todos + limitados:
        errs = validar_schema.validar(h, schema)
        if errs:
            invalidos.append(f"{h.get('id')}: {errs[0]}")

    resumen = {
        "version_esquema": "1",
        "por_herramienta": dict(sorted(por_herr.items())),
        "registros": len(registros),
        "hallazgos": len(limitados),
        "hallazgos_todos": len(todos),
        "sin_mapear": sorted(sin_mapear),
        "checks_pass": sorted(pasan),
        "errores_lectura": sorted(errores),
        "ignorados": sorted(ignorados),
        "herramientas": {k: {"estado": v.get("estado"), "version": v.get("version")} for k, v in sorted(metas.items())},
        "estado_checks": dict(sorted(estados_checks.items())),
        "perfil_origen": perfil["origen"],
        "invalidos": sorted(invalidos),
        "excluidos_confidenciales": excluidos,
        "excluidos_salidas_auditor": propias,
    }
    return limitados, todos, resumen


def main(argv=None):
    ap = argparse.ArgumentParser(description="Normaliza crudo/ → hallazgos.jsonl")
    ap.add_argument("corrida_pos", nargs="?", metavar="DIR_CORRIDA")
    ap.add_argument("--corrida")
    a = ap.parse_args(argv)
    corrida = a.corrida or a.corrida_pos
    if not corrida or not Path(corrida).is_dir():
        print("run.py: indique una carpeta de corrida existente", file=sys.stderr)
        return 2
    corrida = Path(corrida)
    limitados, todos, resumen = normalizar(corrida)
    utiles.escribir_jsonl(corrida / "hallazgos.jsonl", limitados)
    utiles.escribir_jsonl(corrida / "hallazgos_todos.jsonl", todos)
    utiles.escribir_json(corrida / "normalizacion.json", resumen)
    try:
        import digest
        digest.generar(corrida)
    except ImportError:
        pass
    if resumen["invalidos"]:
        for linea in resumen["invalidos"]:
            print(f"run.py: hallazgo inválido: {linea}", file=sys.stderr)
        return 1
    print(f"normalizar: {resumen['hallazgos']} hallazgos ({resumen['hallazgos_todos']} sin tope); "
          f"{len(resumen['sin_mapear'])} reglas sin mapear; errores de lectura: {len(resumen['errores_lectura'])}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

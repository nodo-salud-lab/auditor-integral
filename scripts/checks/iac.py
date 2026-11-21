#!/usr/bin/env python3
"""iac — fallback de checkov (DECISIONES #6; investigacion/13 §4.8). Cobertura parcial.

Archivos: *.tf, *.tfvars, manifiestos Kubernetes (*.yaml|*.yml con apiVersion: y kind:),
docker-compose*.yml / compose*.yaml. Sin ninguno → no_aplica.
Reglas de patrón: semgrep con las reglas LOCALES de reglas/semgrep/iac/ (--metrics=off, sin registro
remoto, solo sobre los archivos IaC detectados). Reglas de contexto: Python.

Subregla               sev     motor    → control
  tf_ingreso_abierto    alta    semgrep  → INF-IAC
  tf_bucket_publico     alta    semgrep
  tf_sin_cifrado        media   semgrep
  tf_bd_publica         alta    semgrep
  tf_secreto_literal    alta    semgrep  → INF-IAC y SEG-SECRETO-REPO (valor enmascarado)
  k8s_privilegiado      alta    semgrep  (también privileged: true en compose)
  k8s_host              alta    semgrep
  k8s_sin_nonroot       media   python   (Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob sin runAsNonRoot: true)
  k8s_sin_limites       baja    python   (sin resources.limits)
  k8s_latest            media   python   (image sin tag o :latest; también en compose)
  compose_puerto_bd     media   python   (5432/3306/6379/27017 publicados sin 127.0.0.1)
Sin semgrep: solo corren las reglas de contexto y el estado es "parcial".
Uso: iac.py PROYECTO DIR_CRUDO
"""
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402

NOMBRE = "iac"
REEMPLAZA = "checkov"
HERRAMIENTAS_REALES = ("checkov",)
REGLAS = fb.RAIZ_AUDITOR / "reglas" / "semgrep" / "iac"
SEV_POR_REGLA = {"tf_ingreso_abierto": "alta", "tf_bucket_publico": "alta", "tf_sin_cifrado": "media",
                 "tf_bd_publica": "alta", "tf_secreto_literal": "alta", "k8s_privilegiado": "alta", "k8s_host": "alta"}
KINDS_POD = re.compile(r"^kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|Job|CronJob|ReplicaSet)\s*$", re.M)
PUERTOS_BD = ("5432", "3306", "6379", "27017")
TIMEOUT_SEMGREP = 120


def archivos_iac(proyecto):
    salida = []
    for p in fb.recorrer(proyecto, {".tf", ".tfvars", ".yaml", ".yml"}):
        n = p.name.lower()
        if p.suffix in (".tf", ".tfvars"):
            salida.append((p, "tf"))
            continue
        if re.match(r"^(docker-)?compose[\w.-]*\.ya?ml$", n):
            salida.append((p, "compose"))
            continue
        if "/.github/" in "/" + fb.rel(proyecto, p):
            continue
        texto = comun.leer(p) or ""
        if re.search(r"^apiVersion:\s*\S", texto, re.M) and re.search(r"^kind:\s*\S", texto, re.M):
            salida.append((p, "k8s"))
    return salida


def _bin_semgrep():
    return os.environ.get("AUDITOR_BIN_SEMGREP") or shutil.which("semgrep")


def _enmascarar_linea(linea):
    return re.sub(r'(=\s*")([^"]*)(")', lambda m: m.group(1) + comun.enmascarar(m.group(2)) + m.group(3), linea)


def correr_semgrep(proyecto, rutas):
    """Hallazgos de las reglas locales; (hallazgos, error|None)."""
    binario = _bin_semgrep()
    if not binario:
        return [], "semgrep ausente"
    cmd = [binario, "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet", "--no-git-ignore",
           "--timeout", "30", "--config", str(REGLAS), *[fb.rel(proyecto, p) for p in rutas]]
    try:
        r = subprocess.run(cmd, cwd=proyecto, capture_output=True, text=True, timeout=TIMEOUT_SEMGREP,
                           env=dict(os.environ, SEMGREP_ENABLE_VERSION_CHECK="0", SEMGREP_SEND_METRICS="off"))
    except (OSError, subprocess.TimeoutExpired) as e:
        return [], f"semgrep falló: {type(e).__name__}"
    if r.returncode > 1:
        return [], f"semgrep terminó con código {r.returncode}: {(r.stderr or '')[-200:]}"
    try:
        datos = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return [], "salida de semgrep ilegible"
    hallazgos = []
    vistos = set()
    for res in datos.get("results", []):
        sub = str(res.get("check_id", "")).rsplit(".", 1)[-1]
        if sub not in SEV_POR_REGLA:
            continue
        ruta = res.get("path", "")
        linea = (res.get("start") or {}).get("line")
        clave = (sub, ruta, linea)
        if clave in vistos:
            continue
        vistos.add(clave)
        texto = comun.leer(Path(proyecto) / ruta) or ""
        ev = fb.evidencia_linea(texto, linea)
        if sub == "tf_secreto_literal" or re.search(r"password|secret|token|key", ev, re.I):
            ev = _enmascarar_linea(ev)
        hallazgos.append(comun.hallazgo(NOMBRE, sub, ruta, linea, (res.get("extra") or {}).get("message", sub),
                                        ev, SEV_POR_REGLA[sub]))
    return hallazgos, None


def _bloques_contenedor(lineas):
    """[(n_inicio, [líneas])] de cada elemento de `containers:`/`initContainers:` (por indentación)."""
    bloques = []
    for i, linea in enumerate(lineas):
        m = re.match(r"^(\s*)(?:initC|c)ontainers:\s*$", linea)
        if not m:
            continue
        base, item, actual = len(m.group(1)), None, None
        for j in range(i + 1, len(lineas)):
            x = lineas[j]
            if not x.strip():
                continue
            ind = len(x) - len(x.lstrip())
            es_item = x.lstrip().startswith("- ")
            if item is None and es_item and ind >= base:
                item = ind
            if es_item and ind == item:
                actual = [j + 1, [x]]
                bloques.append(actual)
            elif ind > (item if item is not None else base) and actual is not None:
                actual[1].append(x)
            else:
                break
    return [(b[0], b[1]) for b in bloques]


def reglas_contexto(proyecto, archivos):
    hallazgos = []
    for p, tipo in archivos:
        texto = comun.leer(p)
        if texto is None:
            continue
        arch = fb.rel(proyecto, p)
        lineas = texto.splitlines()

        def h(sub, n, mensaje, sev):
            hallazgos.append(comun.hallazgo(NOMBRE, sub, arch, n, mensaje, fb.evidencia_linea(texto, n), sev))

        if tipo in ("k8s", "compose"):
            for n, l in enumerate(lineas, 1):
                m = re.match(r"^\s*-?\s*image:\s*[\"']?([^\s\"'#]+)", l)
                if m:
                    img = m.group(1)
                    ultimo = img.split("@", 1)[0].rsplit("/", 1)[-1]
                    if "@sha256:" not in img and "$" not in img and (":" not in ultimo or ultimo.endswith(":latest")):
                        h("k8s_latest", n, f"Imagen sin versión fija o con :latest ({img}).", "media")
        if tipo == "k8s":
            for doc_ini, doc in _documentos(lineas):
                if not KINDS_POD.search("\n".join(doc)):
                    continue
                doc_txt = "\n".join(doc)
                if not re.search(r"runAsNonRoot:\s*true", doc_txt):
                    kind = KINDS_POD.search(doc_txt)
                    n = doc_ini + doc_txt[:kind.start()].count("\n")
                    h("k8s_sin_nonroot", n, "Workload sin securityContext.runAsNonRoot: true.", "media")
                for n_rel, bloque in _bloques_contenedor(doc):
                    if not re.search(r"^\s*limits:\s*$", "\n".join(bloque), re.M):
                        h("k8s_sin_limites", doc_ini + n_rel - 1, "Contenedor sin resources.limits (CPU/memoria).", "baja")
        if tipo == "compose":
            for n, l in enumerate(lineas, 1):
                m = re.match(r"""^\s*-\s*["']?([\d.]+:)?(\d+)(?::(\d+))?(/\w+)?["']?\s*$""", l)
                if not m:
                    continue
                host_ip = m.group(1) or ""
                destino = m.group(3) or m.group(2)
                if destino in PUERTOS_BD and not host_ip.startswith("127.0.0.1"):
                    h("compose_puerto_bd", n, f"Puerto de base de datos {destino} publicado en todas las interfaces "
                      "(usar 127.0.0.1:… o no publicarlo).", "media")
    return hallazgos


def _documentos(lineas):
    docs, actual, ini = [], [], 1
    for n, l in enumerate(lineas, 1):
        if l.strip() == "---":
            if actual:
                docs.append((ini, actual))
            actual, ini = [], n + 1
            continue
        actual.append(l)
    if actual:
        docs.append((ini, actual))
    return docs


def analizar(proyecto, crudo=None, usar_semgrep=True):
    proyecto = Path(proyecto)
    archivos = archivos_iac(proyecto)
    if not archivos:
        return fb.resultado(REEMPLAZA, estado="no_aplica", motivo="no hay archivos de IaC (Terraform, Kubernetes, compose)")
    hallazgos = reglas_contexto(proyecto, archivos)
    estado, motivo = "ok", None
    if usar_semgrep:
        hs, error = correr_semgrep(proyecto, [p for p, _ in archivos])
        hallazgos.extend(hs)
        if error:
            estado, motivo = "parcial", f"{error}: solo se evaluaron las reglas de contexto"
    else:
        estado, motivo = "parcial", "reglas semgrep no ejecutadas: solo se evaluaron las reglas de contexto"
    hallazgos.sort(key=lambda h: (h["archivo"] or "", h["linea"] or 0, h["regla"]))
    pases = []
    # el pase exige IaC del proyecto: archivos de tests o fixtures se escanean (hallazgos) pero no demuestran nada
    propios = [p for p, _ in archivos if not comun.es_test_o_fixture(fb.rel(proyecto, p))]
    if not hallazgos and estado == "ok" and propios:
        pases.append(fb.pase(NOMBRE, "iac", f"{len(archivos)} archivos IaC sin misconfiguraciones de las reglas locales"))
    return fb.resultado(REEMPLAZA, hallazgos, pases, estado=estado, motivo=motivo)


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))

#!/usr/bin/env python3
"""dockerfile — fallback de hadolint (DECISIONES #6; investigacion/13 §4.6). Cobertura parcial.

Subregla (hallazgo)          sev     equivale a                     → control
  tag_latest                  media   DL3006 / DL3007               → INF-DOCKERFILE
  usuario_root                media   DL3002
  sudo                        media   DL3004
  add_vs_copy                 baja    DL3020
  add_url                     media   (ADD remoto sin checksum)
  cmd_shell_form              baja    DL3025
  apt_sin_pin / apk_sin_pin / pip_sin_pin   baja   DL3008 / DL3018 / DL3013
  secreto_en_env              alta    (secretos en la imagen)       → INF-DOCKERFILE, SEG-SECRETO-REPO
  curl_pipe_sh                media
  sin_multistage              baja    (intención "multi-stage" del control)
  copy_todo_sin_dockerignore  media   (riesgo de copiar .env)
Pases: ok_<subregla> por Dockerfile cuando la subregla se evaluó sin hallazgos.
No incluye ShellCheck sobre RUN (hadolint sí). Uso: dockerfile.py PROYECTO DIR_CRUDO
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402

NOMBRE = "dockerfile"
REEMPLAZA = "hadolint"
HERRAMIENTAS_REALES = ("hadolint",)

SUBREGLAS = ("tag_latest", "usuario_root", "sudo", "add_vs_copy", "add_url", "cmd_shell_form", "apt_sin_pin",
             "apk_sin_pin", "pip_sin_pin", "secreto_en_env", "curl_pipe_sh", "sin_multistage",
             "copy_todo_sin_dockerignore")
RE_INSTR = re.compile(r"^\s*([A-Za-z]+)\s+(.*)$", re.S)
RE_SECRETO = re.compile(r"^(\S*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY)\S*?)(\s*=\s*|\s+)(\S.*)$", re.I)
RE_ARCHIVO_COMPRIMIDO = re.compile(r"\.(tar|tar\.gz|tgz|tar\.xz|tar\.bz2|txz)$", re.I)
RE_CURL_SH = re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
RE_BUILD = re.compile(r"\bnpm\s+(ci|install|run\s+build)\b|\byarn\b|\bpnpm\b|\bpip3?\s+install\b|\bgo\s+build\b|"
                      r"\bcargo\s+build\b|\bmvn\b|\bgradle\b")


# `dockerfile.<ext>` con extensión de código o de texto conocido NO es un Dockerfile (p. ej. el propio dockerfile.py
# de este check: «from pathlib import Path» se leía como `FROM pathlib`). Dockerfile.dev, Dockerfile.prod,
# *.dockerfile y Containerfile siguen contando.
EXT_NO_DOCKERFILE = frozenset({".py", ".pyc", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".md",
                               ".json", ".yml", ".yaml", ".toml", ".txt", ".rb", ".go", ".rs", ".java", ".php",
                               ".html", ".css", ".ini", ".cfg", ".lock", ".log", ".bak", ".orig", ".swp"})


def es_dockerfile(p):
    nl = p.name.lower()
    if nl in ("dockerfile", "containerfile") or nl.endswith(".dockerfile"):
        return True
    return nl.startswith("dockerfile.") and Path(nl).suffix not in EXT_NO_DOCKERFILE


def instrucciones(texto):
    """[(linea_inicio, instruccion_mayus, argumentos)] uniendo continuaciones con '\\'."""
    salida = []
    actual, inicio = [], None
    for n, linea in enumerate(texto.splitlines(), 1):
        s = linea.rstrip()
        if not actual and (not s.strip() or s.strip().startswith("#")):
            continue
        if actual and s.strip().startswith("#"):
            continue
        if inicio is None:
            inicio = n
        if s.endswith("\\"):
            actual.append(s[:-1])
            continue
        actual.append(s)
        m = RE_INSTR.match(" ".join(x.strip() for x in actual))
        if m:
            salida.append((inicio, m.group(1).upper(), m.group(2).strip()))
        actual, inicio = [], None
    if actual:
        m = RE_INSTR.match(" ".join(x.strip() for x in actual))
        if m:
            salida.append((inicio, m.group(1).upper(), m.group(2).strip()))
    return salida


def _paquetes(args, comando):
    """Paquetes tras `apt-get install` / `apk add` / `pip install` (sin flags), por subcomando."""
    paquetes = []
    for trozo in re.split(r"&&|;|\|\|", args):
        m = re.search(comando, trozo)
        if not m:
            continue
        for w in trozo[m.end():].split():
            if w.startswith("-") or w in ("\\",):
                continue
            paquetes.append(w)
    return paquetes


def analizar_archivo(proyecto, ruta, hallazgos, pases):
    texto = comun.leer(ruta)
    if texto is None:
        return
    arch = fb.rel(proyecto, ruta)
    ins = instrucciones(texto)
    encontrados = set()

    def h(sub, linea, mensaje, evidencia, sev):
        encontrados.add(sub)
        hallazgos.append(comun.hallazgo(NOMBRE, sub, arch, linea, mensaje, evidencia, sev))

    etapas = set()
    froms = []
    usuario_final = None
    for linea, cmd, args in ins:
        if cmd == "FROM":
            usuario_final = None
            partes = [x for x in args.split() if not x.startswith("--")]
            imagen = partes[0] if partes else ""
            froms.append((linea, imagen))
            if len(partes) >= 3 and partes[1].upper() == "AS":
                etapas.add(partes[2].lower())
            if imagen.lower() == "scratch" or imagen.lower() in etapas or "$" in imagen:
                continue
            nombre_img = imagen.split("@", 1)[0]
            ultimo = nombre_img.rsplit("/", 1)[-1]
            if "@sha256:" in imagen:
                continue
            if ":" not in ultimo or ultimo.endswith(":latest"):
                h("tag_latest", linea, "FROM sin versión fija o con :latest (equivale a hadolint DL3006/DL3007).",
                  f"FROM {imagen}", "media")
        elif cmd == "USER":
            usuario_final = args.split(":")[0].strip()
        elif cmd == "RUN":
            if re.search(r"(^|[\s;&|])sudo\s", args):
                h("sudo", linea, "RUN usa sudo (DL3004).", f"RUN {args}"[:200], "media")
            if RE_CURL_SH.search(args):
                h("curl_pipe_sh", linea, "Descarga ejecutada directamente con sh (curl|sh): sin verificación de integridad.",
                  f"RUN {args}"[:200], "media")
            sin_pin = [p for p in _paquetes(args, r"\bapt(-get)?\s+install\b") if "=" not in p]
            if sin_pin:
                h("apt_sin_pin", linea, "apt-get install sin versión fija (DL3008): " + ", ".join(sin_pin[:5]),
                  f"RUN {args}"[:200], "baja")
            sin_pin = [p for p in _paquetes(args, r"\bapk\s+add\b") if "=" not in p]
            if sin_pin:
                h("apk_sin_pin", linea, "apk add sin versión fija (DL3018): " + ", ".join(sin_pin[:5]),
                  f"RUN {args}"[:200], "baja")
            pip = _paquetes(args, r"\bpip3?\s+install\b")
            if pip and not re.search(r"\s-r\s|--requirement|\s-e\s|\s\.(\s|$)", " " + args + " "):
                sin_pin = [p for p in pip if "==" not in p and not p.startswith((".", "/")) and "@" not in p]
                if sin_pin:
                    h("pip_sin_pin", linea, "pip install sin versión fija (DL3013): " + ", ".join(sin_pin[:5]),
                      f"RUN {args}"[:200], "baja")
        elif cmd == "ADD":
            fuentes = [x for x in args.split() if not x.startswith("--")][:-1]
            if any(re.match(r"https?://", f) for f in fuentes):
                h("add_url", linea, "ADD descarga una URL remota sin verificación de checksum; usar curl + verificación o COPY.",
                  f"ADD {args}"[:200], "media")
            elif fuentes and not all(RE_ARCHIVO_COMPRIMIDO.search(f) for f in fuentes):
                h("add_vs_copy", linea, "ADD para archivos locales: usar COPY (DL3020).", f"ADD {args}"[:200], "baja")
        elif cmd in ("CMD", "ENTRYPOINT"):
            if not args.startswith("["):
                h("cmd_shell_form", linea, f"{cmd} en forma shell: las señales no llegan al proceso (DL3025).",
                  f"{cmd} {args}"[:200], "baja")
        elif cmd in ("ENV", "ARG"):
            for asignacion in re.findall(r"(\S+=(?:\"[^\"]*\"|'[^']*'|\S+))", args) or [args]:
                m = RE_SECRETO.match(asignacion)
                if m and m.group(3).strip() and not comun.es_referencia_variable(m.group(3).strip().strip("'\"")):
                    h("secreto_en_env", linea, f"{cmd} con nombre de secreto y valor literal: queda en las capas de la imagen.",
                      f"{cmd} {m.group(1)}={comun.enmascarar(m.group(3).strip())}", "alta")
        elif cmd == "COPY":
            partes = [x for x in args.split() if not x.startswith("--")]
            if len(partes) >= 2 and "." in partes[:-1] and not any(x.startswith("--from") for x in args.split()):
                if not (ruta.parent / ".dockerignore").exists() and not (Path(proyecto) / ".dockerignore").exists():
                    h("copy_todo_sin_dockerignore", linea, "COPY . sin .dockerignore: puede copiar .env, .git u otros secretos.",
                      f"COPY {args}"[:200], "media")
    if froms:
        if usuario_final is None or usuario_final.lower() in ("root", "0"):
            h("usuario_root", froms[-1][0], "La etapa final corre como root (sin USER no-root) (DL3002).",
              f"FROM {froms[-1][1]}" + (f" … USER {usuario_final}" if usuario_final else ""), "media")
        if len(froms) == 1 and any(cmd == "RUN" and RE_BUILD.search(a) for _, cmd, a in ins):
            h("sin_multistage", froms[0][0], "Compila/instala dependencias en una sola etapa: la imagen final arrastra "
              "herramientas de build (usar multi-stage).", f"FROM {froms[0][1]}", "baja")
    if comun.es_test_o_fixture(arch):
        return  # un Dockerfile de test o fixture se analiza (hallazgos) pero no demuestra nada del proyecto (sin pase)
    for sub in SUBREGLAS:
        if sub not in encontrados:
            pases.append(fb.pase(NOMBRE, sub, f"{sub}: sin hallazgos en {arch}", arch))


def analizar(proyecto, crudo=None):
    proyecto = Path(proyecto)
    archivos = [p for p in fb.recorrer(proyecto) if es_dockerfile(p)]
    if not archivos:
        return fb.resultado(REEMPLAZA, estado="no_aplica", motivo="no hay Dockerfile/Containerfile")
    hallazgos, pases = [], []
    for p in archivos:
        analizar_archivo(proyecto, p, hallazgos, pases)
    return fb.resultado(REEMPLAZA, hallazgos, pases)


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))

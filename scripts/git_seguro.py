"""Invocación de git sobre un repositorio NO confiable (el proyecto auditado).

Un repositorio recibido como zip o tarball trae su propio .git/config, y git ejecuta comandos
definidos ahí: core.fsmonitor (en status), core.hooksPath, diff.external y diff.<driver>.textconv
(en log -p / diff), filtros clean/smudge (al comparar el working tree con el índice)...
Reglas de este módulo:
  - se fuerzan, con -c (precedencia sobre cualquier config del repo), core.fsmonitor=false,
    core.hooksPath=/dev/null, diff.external= y core.untrackedCache=false;
  - el auditor solo usa comandos que no comparan contenido del working tree (rev-parse, ls-files
    --error-unmatch, check-ignore, log): nunca `status` ni `diff` contra el working tree, que
    podrían ejecutar filtros clean definidos por el repo;
  - GIT_CONFIG_NOSYSTEM=1 y sin terminal (GIT_TERMINAL_PROMPT=0).
Para procesos hijos que llaman a git por su cuenta (gitleaks git), `entorno()` exporta las mismas
claves con GIT_CONFIG_COUNT/GIT_CONFIG_KEY_n/GIT_CONFIG_VALUE_n.
"""
import os
import subprocess

CONFIG_SEGURA = (
    ("core.fsmonitor", "false"),
    ("core.hooksPath", "/dev/null"),
    ("diff.external", ""),
    ("core.untrackedCache", "false"),
)


def argumentos():
    salida = []
    for clave, valor in CONFIG_SEGURA:
        salida += ["-c", f"{clave}={valor}"]
    return salida


def entorno(base=None):
    env = dict(os.environ if base is None else base)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_CONFIG_COUNT"] = str(len(CONFIG_SEGURA))
    for i, (clave, valor) in enumerate(CONFIG_SEGURA):
        env[f"GIT_CONFIG_KEY_{i}"] = clave
        env[f"GIT_CONFIG_VALUE_{i}"] = valor
    return env


def ejecutar(proyecto, *args, timeout=30):
    """(returncode, stdout) o (None, None) si git no se pudo ejecutar."""
    try:
        r = subprocess.run(["git", "--no-optional-locks", *argumentos(), "-C", str(proyecto), *args],
                           capture_output=True, text=True, timeout=timeout, env=entorno(), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    return r.returncode, r.stdout

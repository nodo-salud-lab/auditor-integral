#!/usr/bin/env python3
"""Hook PreToolUse del plugin: durante /auditar, bloquea Write/Edit/MultiEdit/NotebookEdit fuera de .auditoria/.

Activo cuando:
  - la variable de entorno AUDITAR_ACTIVO=1, o
  - existe el marcador <proyecto>/.auditoria/.auditar_activo (proyecto = CLAUDE_PROJECT_DIR o cwd del
    evento). El marcador existe porque un skill no puede fijar variables de entorno de la sesión:
    /auditar lo crea al empezar y lo borra al terminar.
Con el hook activo, una ruta es válida solo si, ya normalizada (sin '..'), contiene un componente
exactamente igual a ".auditoria", y lo sigue conteniendo después de resolver los enlaces simbólicos
(os.path.realpath): un '.auditoria' que es un enlace a otra carpeta no habilita escribir allá.
Ante una entrada ilegible o sin ruta se bloquea (fail-closed).

Salida (formato vigente de hooks de Claude Code): JSON en stdout con
  {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                          "permissionDecisionReason": "..."}}
y código 0. Si permite, no imprime nada. Solo biblioteca estándar.
"""
import json
import os
import posixpath
import sys

HERRAMIENTAS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
CARPETA = ".auditoria"
MARCADOR = ".auditar_activo"


def _activo(evento):
    if os.environ.get("AUDITAR_ACTIVO") == "1":
        return True
    bases = [os.environ.get("CLAUDE_PROJECT_DIR"), (evento or {}).get("cwd")]
    return any(b and os.path.isfile(os.path.join(b, CARPETA, MARCADOR)) for b in bases)


def _denegar(razon):
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                             "permissionDecisionReason": razon}}, ensure_ascii=False))
    return 0


def ruta_permitida(ruta, cwd):
    if not ruta:
        return False
    r = str(ruta).replace("\\", "/")
    if not r.startswith("/"):
        r = posixpath.join((cwd or os.getcwd()).replace("\\", "/"), r)
    partes = posixpath.normpath(r).split("/")
    if CARPETA not in partes:
        return False
    # Resuelve enlaces simbólicos: el primer '.auditoria' de la ruta debe ser una carpeta real.
    i = partes.index(CARPETA)
    base = "/".join(partes[:i + 1]) or "/"
    if os.path.islink(base):
        return False
    real = os.path.realpath(r)
    return CARPETA in real.replace("\\", "/").split("/")


def main():
    texto = sys.stdin.read()
    try:
        evento = json.loads(texto) if texto.strip() else None
    except ValueError:
        evento = None
    if not _activo(evento if isinstance(evento, dict) else None):
        return 0
    if not isinstance(evento, dict):
        return _denegar("auditor-integral: entrada del hook ilegible durante /auditar; se bloquea por seguridad.")
    if evento.get("tool_name") not in HERRAMIENTAS:
        return 0
    entrada = evento.get("tool_input") or {}
    ruta = entrada.get("file_path") or entrada.get("notebook_path")
    if ruta_permitida(ruta, evento.get("cwd")):
        return 0
    return _denegar(f"auditor-integral: durante /auditar solo se puede escribir dentro de {CARPETA}/ "
                    f"(intento: {ruta or 'sin ruta'}). La auditoría no modifica el proyecto.")


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""con_timeout — ejecuta un comando con límite de tiempo (macOS no trae `timeout`).

Uso: con_timeout.py SEGUNDOS COMANDO [ARGS...]
  Devuelve el código de salida del comando, 124 si se agotó el tiempo (como GNU timeout),
  127 si el comando no existe y 2 si el uso es incorrecto.
El comando corre en su propio grupo de procesos: al agotarse el tiempo se envía SIGTERM al grupo
completo (también a los hijos) y, 3 s después, SIGKILL.

Ronda 6 (grupo secretos): en macOS, os.killpg puede lanzar PermissionError (EPERM) cuando el grupo ya solo
tiene procesos zombis o un miembro cambió de credenciales. Antes esa excepción escapaba sin capturar, el
script terminaba con código 1 y un traceback, y ejecutar_scanners.sh registraba un «error» genérico en vez
del timeout. Ahora cualquier OSError al señalar el grupo se trata como «no se pudo señalar» (se sigue con la
siguiente señal) y el resultado de un tiempo agotado es SIEMPRE 124, con un motivo claro en stderr.
"""
import os
import signal
import subprocess
import sys


def _senal_grupo(pgid, sig):
    """Envía `sig` al grupo. "ok", "sin_grupo" (ya no existe) o un texto con el motivo si no se pudo (EPERM u
    otro OSError): nunca lanza, para que un timeout no se convierta en un error genérico."""
    try:
        os.killpg(pgid, sig)
        return "ok"
    except ProcessLookupError:
        return "sin_grupo"
    except PermissionError:
        return f"sin permiso para enviar la señal {int(sig)} al grupo {pgid} (EPERM; en macOS ocurre si solo quedan zombis)"
    except OSError as exc:
        return f"no se pudo enviar la señal {int(sig)} al grupo {pgid}: {type(exc).__name__}"


def main(argv):
    if len(argv) < 2:
        print("uso: con_timeout.py SEGUNDOS COMANDO [ARGS...]", file=sys.stderr)
        return 2
    try:
        limite = float(argv[0])
        if limite <= 0:
            raise ValueError
    except ValueError:
        print(f"con_timeout.py: segundos inválidos: {argv[0]!r}", file=sys.stderr)
        return 2
    try:
        proc = subprocess.Popen(argv[1:], start_new_session=True)
    except FileNotFoundError:
        print(f"con_timeout.py: no existe el comando: {argv[1]}", file=sys.stderr)
        return 127
    except PermissionError:
        print(f"con_timeout.py: sin permiso para ejecutar: {argv[1]}", file=sys.stderr)
        return 126

    def reenviar(signum, _frame):  # Ctrl-C / SIGTERM al padre → al grupo hijo
        _senal_grupo(proc.pid, signum)

    signal.signal(signal.SIGTERM, reenviar)
    signal.signal(signal.SIGINT, reenviar)
    try:
        return proc.wait(timeout=limite)
    except subprocess.TimeoutExpired:
        avisos = []
        for sig, espera in ((signal.SIGTERM, 3), (signal.SIGKILL, 3)):
            r = _senal_grupo(proc.pid, sig)
            if r == "sin_grupo":
                break
            if r != "ok":
                avisos.append(r)
            try:
                proc.wait(timeout=espera)
                break
            except subprocess.TimeoutExpired:
                continue
        # Los nietos del grupo pueden seguir vivos aunque el líder ya terminó.
        r = _senal_grupo(proc.pid, signal.SIGKILL)
        if r not in ("ok", "sin_grupo"):
            avisos.append(r)
        try:  # no dejar al líder como zombi si sigue sin recogerse
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            avisos.append("el proceso principal no terminó tras SIGKILL")
        nota = f" (aviso: {'; '.join(dict.fromkeys(avisos))})" if avisos else ""
        print(f"con_timeout.py: tiempo agotado ({limite:g} s): {' '.join(argv[1:])}{nota}", file=sys.stderr)
        return 124


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

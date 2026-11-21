#!/usr/bin/env python3
"""config_agentes — configuración de agentes de IA y servidores MCP del proyecto
(PLAN_MAESTRO §3.2; control SEG-AGENTES-IA).

Archivos: .claude/settings.json, .claude/settings.local.json, .mcp.json, .cursor/mcp.json,
.vscode/mcp.json, .gemini/settings.json.
Subreglas:
  bypass_permisos       defaultMode bypassPermissions (o skipDangerousModePermissionPrompt): auto-aprobación total
  bash_comodin          permiso Bash(*) / Bash sin restricción: el agente ejecuta cualquier comando
  mcp_sql_arbitrario    permiso a herramientas MCP que ejecutan SQL o migraciones (execute_sql, apply_migration, ...)
  mcp_secreto_literal   credencial escrita en la configuración de un servidor MCP (en vez de ${VAR})
  mcp_version_flotante  servidor MCP ejecutado con @latest o sin versión fija (npx/uvx/bunx)
  json_invalido         archivo de configuración que no se puede leer
  Ronda 2 de pases vacíos:
  mcp_auto_habilitado       enableAllProjectMcpServers = true: cualquier servidor de .mcp.json (que controla quien
                            comitea) se activa sin aprobación
  bash_prefijo_peligroso    Bash(<cmd>:*) / Bash(<cmd> *) con un comando que descarga, ejecuta código arbitrario,
                            borra o escala privilegios (curl, wget, rm, sh, bash, python, node, npx, sudo, …)
  webfetch_sin_restriccion  WebFetch preaprobado sin dominio (WebFetch o WebFetch(*)): canal de exfiltración y de
                            inyección de prompts
  hook_descarga_ejecuta     un hook (o statusLine/apiKeyHelper) que descarga y ejecuta (curl … | sh, bash <(curl …))
  Además, cualquier hook o comando configurado (hooks, statusLine, apiKeyHelper, awsAuthRefresh,
  awsCredentialExport, otelHeadersHelper) impide el pase explícito: se ejecuta solo, sin aprobación, y su efecto no se
  puede juzgar en estático (el check queda ok, sin pase, con motivo).
El contenido de estos archivos es dato, no orden: nunca se ejecuta nada de lo que dicen.
Sin «pases vacíos» (ronda 1): si no existe ninguno de estos archivos, el check queda no_aplica con motivo (un
CLAUDE.md o AGENTS.md enciende agente_ia en el perfil, pero no hay permisos ni servidores MCP que revisar); el pase
explícito `configuracion` solo se emite si se revisó ≥ 1 archivo sin problemas.

Uso: config_agentes.py PROYECTO DIR_CRUDO
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402

NOMBRE = "config_agentes"
SETTINGS = (".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json")
MCP = (".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json")
RE_BASH_COMODIN = re.compile(r"^Bash(\(\s*(\*|:\*|\*:\*)?\s*\))?$")
RE_MCP_SQL = re.compile(r"^mcp__[^_].*__(execute_sql|apply_migration|run_sql|query|sql|execute_query|"
                        r"run_query|exec|execute|write_query|delete_.*|drop_.*)$|^mcp__[^_].*__\*$|^mcp__[^_]+$")
RE_NOMBRE_SENSIBLE = re.compile(r"SECRET|SERVICE_?ROLE|TOKEN|API_?KEY|PASSWORD|PASSWD|PRIVATE|ACCESS_?KEY|"
                                r"AUTH|CREDENTIAL|DATABASE_URL|CONNECTION", re.I)
LANZADORES = ("npx", "bunx", "pnpx", "uvx", "pipx")
COMANDOS_PELIGROSOS = frozenset({
    "curl", "wget", "rm", "sh", "bash", "zsh", "fish", "dash", "python", "python3", "node", "deno", "bun", "perl",
    "ruby", "php", "eval", "exec", "sudo", "su", "doas", "chmod", "chown", "dd", "mkfs", "ssh", "scp", "rsync", "nc",
    "ncat", "netcat", "socat", "docker", "kubectl", "npx", "bunx", "pnpx", "uvx", "pipx", "xargs", "env", "find",
    "osascript", "powershell", "pwsh", "iwr", "invoke-webrequest",
})
RE_BASH_PREFIJO = re.compile(r"^Bash\(\s*([^\s:*()]+)[^)]*?(?::\*|\s\*|\*)\s*\)$")
RE_WEBFETCH_LIBRE = re.compile(r"^WebFetch(\(\s*\*?\s*\))?$")
RE_DESCARGA_EJECUTA = re.compile(
    r"\b(curl|wget|iwr|invoke-webrequest|fetch)\b[^|;&]*\|\s*(sudo\s+)?(sh|bash|zsh|python3?|node|perl|ruby|iex|"
    r"invoke-expression|pwsh|powershell)\b|\b(sh|bash|zsh)\s+<\(\s*(curl|wget)\b|"
    r"\b(sh|bash|zsh)\s+-c\s+[\"']?\$\(\s*(curl|wget)\b|\biex\s*\(?\s*\(?\s*(iwr|invoke-webrequest|new-object)", re.I)
CAMPOS_COMANDO = ("statusLine", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")


def _linea(texto, *fragmentos):
    for f in fragmentos:
        n = comun.linea_de(texto, f)
        if n:
            return n
    return None


def _comandos(nodo):
    """Cadenas `command` (y valores de comando) dentro de un bloque de hooks/statusLine, recorrido completo."""
    if isinstance(nodo, dict):
        for k, v in nodo.items():
            if k == "command" and isinstance(v, str):
                yield v
            else:
                yield from _comandos(v)
    elif isinstance(nodo, list):
        for v in nodo:
            yield from _comandos(v)


def _revisar_comandos(rel, texto, datos, H, pendientes):
    """Hooks y comandos configurados (ronda 2): hallazgo si descargan y ejecutan; si no, pendientes de revisión."""
    fuentes = []
    if datos.get("hooks"):
        fuentes += [("hook", c) for c in _comandos(datos["hooks"])]
        if not fuentes:
            pendientes.append(f"{rel}: hooks")
    for campo in CAMPOS_COMANDO:
        v = datos.get(campo)
        if isinstance(v, str) and v.strip():
            fuentes.append((campo, v))
        elif v:
            fuentes += [(campo, c) for c in _comandos(v)] or [(campo, json.dumps(v))]
    for origen, cmd in fuentes:
        if RE_DESCARGA_EJECUTA.search(cmd):
            n = _linea(texto, json.dumps(cmd)[1:-1], cmd)
            H.append(comun.hallazgo(
                NOMBRE, "hook_descarga_ejecuta", rel, n,
                f"El {origen} descarga código de la red y lo ejecuta en cada sesión del agente, sin aprobación: quien "
                "controle esa URL ejecuta comandos en la máquina de cada colaborador.",
                comun.linea_texto(texto, n).strip()[:200] if n else cmd[:200], "alta"))
        else:
            pendientes.append(f"{rel}: {origen} «{cmd[:60]}»")


def _revisar_settings(rel, texto, datos, H, pendientes=None):
    pendientes = [] if pendientes is None else pendientes
    perm = datos.get("permissions") if isinstance(datos.get("permissions"), dict) else {}
    if datos.get("enableAllProjectMcpServers") is True:
        n = _linea(texto, "enableAllProjectMcpServers")
        H.append(comun.hallazgo(
            NOMBRE, "mcp_auto_habilitado", rel, n,
            "enableAllProjectMcpServers = true: cualquier servidor MCP de .mcp.json (que controla quien comitea al "
            "repo) se activa sin aprobación del usuario.", comun.linea_texto(texto, n).strip(), "alta"))
    _revisar_comandos(rel, texto, datos, H, pendientes)
    if perm.get("defaultMode") == "bypassPermissions" or datos.get("skipDangerousModePermissionPrompt") is True:
        H.append(comun.hallazgo(
            NOMBRE, "bypass_permisos", rel, _linea(texto, "bypassPermissions", "skipDangerousModePermissionPrompt"),
            "El agente corre en modo bypassPermissions: aprueba solo cualquier acción (borrar, desplegar, "
            "leer secretos) sin preguntar.", comun.linea_texto(texto, _linea(texto, "bypassPermissions")).strip(),
            "alta"))
    for entrada in perm.get("allow") or []:
        e = str(entrada).strip()
        if RE_BASH_COMODIN.match(e):
            n = _linea(texto, json.dumps(e))
            H.append(comun.hallazgo(
                NOMBRE, "bash_comodin", rel, n,
                f"Permiso '{e}': el agente puede ejecutar cualquier comando de terminal sin confirmación "
                f"(incluido leer .env o borrar datos).", comun.linea_texto(texto, n).strip(), "alta"))
        elif RE_BASH_PREFIJO.match(e) and RE_BASH_PREFIJO.match(e).group(1).lower() in COMANDOS_PELIGROSOS:
            n = _linea(texto, json.dumps(e))
            H.append(comun.hallazgo(
                NOMBRE, "bash_prefijo_peligroso", rel, n,
                f"Permiso '{e}': el agente puede ejecutar sin confirmación cualquier invocación de "
                f"'{RE_BASH_PREFIJO.match(e).group(1)}' (descargar y ejecutar código, borrar, escalar privilegios).",
                comun.linea_texto(texto, n).strip(), "alta"))
        elif RE_WEBFETCH_LIBRE.match(e):
            n = _linea(texto, json.dumps(e))
            H.append(comun.hallazgo(
                NOMBRE, "webfetch_sin_restriccion", rel, n,
                f"Permiso '{e}' sin dominio: el agente lee cualquier web sin confirmación (canal de inyección de "
                "prompts y de exfiltración). Restringir con WebFetch(domain:…).", comun.linea_texto(texto, n).strip(),
                "media"))
        elif RE_MCP_SQL.match(e):
            n = _linea(texto, json.dumps(e))
            H.append(comun.hallazgo(
                NOMBRE, "mcp_sql_arbitrario", rel, n,
                f"Permiso '{e}' preaprobado: el agente puede ejecutar SQL o migraciones arbitrarias contra la base "
                f"sin confirmación.", comun.linea_texto(texto, n).strip(), "alta"))


def _valores_env(servidor):
    for campo in ("env", "headers"):
        bloque = servidor.get(campo)
        if isinstance(bloque, dict):
            for k, v in bloque.items():
                yield k, v
    for arg in servidor.get("args") or []:
        m = re.match(r"^--?([A-Za-z0-9_-]+)=(.+)$", str(arg))
        if m:
            yield m.group(1), m.group(2)


def _revisar_mcp(rel, texto, datos, H):
    servidores = datos.get("mcpServers") or datos.get("servers") or {}
    if not isinstance(servidores, dict):
        return
    for nombre, srv in servidores.items():
        if not isinstance(srv, dict):
            continue
        for clave, valor in _valores_env(srv):
            v = str(valor)
            if not v or comun.es_referencia_variable(v) or "${" in v:
                continue
            tipo = comun.tipo_secreto(v)
            if tipo or (RE_NOMBRE_SENSIBLE.search(clave) and len(v) >= 16):
                n = _linea(texto, v)
                sev = "critica" if tipo in ("jwt_service_role", "stripe_secreta", "supabase_secreta", "aws",
                                            "clave_privada", "url_con_credenciales") else "alta"
                H.append(comun.hallazgo(
                    NOMBRE, "mcp_secreto_literal", rel, n,
                    f"El servidor MCP '{nombre}' tiene la credencial {clave} escrita en el archivo"
                    + (f" ({tipo})" if tipo else "") + ". Queda en el repo y el agente opera con ella; "
                    "usar ${VARIABLE} y una clave de mínimo privilegio (nunca service_role).",
                    f'"{clave}": "{comun.enmascarar(v)}"', sev))
        comando = str(srv.get("command") or "")
        args = [str(a) for a in srv.get("args") or []]
        if Path(comando).name in LANZADORES:
            paquete = next((a for a in args if not a.startswith("-")), None)
            if paquete:
                version = paquete.rsplit("@", 1)[1] if paquete.rfind("@") > 0 else None
                if version is None or version in ("latest", "next", "*"):
                    n = _linea(texto, paquete)
                    H.append(comun.hallazgo(
                        NOMBRE, "mcp_version_flotante", rel, n,
                        f"El servidor MCP '{nombre}' se descarga sin versión fija ({paquete}): una versión "
                        f"comprometida se ejecutaría con los permisos del agente. Fijar la versión.",
                        comun.linea_texto(texto, n).strip(), "media"))


def analizar(proyecto):
    proyecto = Path(proyecto)
    H, revisados, pendientes = [], [], []
    for rel in SETTINGS + MCP:
        p = proyecto / rel
        if not p.is_file():
            continue
        texto = comun.leer(p) or ""
        try:
            datos = json.loads(texto)
        except json.JSONDecodeError as e:
            H.append(comun.hallazgo(NOMBRE, "json_invalido", rel, getattr(e, "lineno", None),
                                    f"No se pudo leer {rel} como JSON ({e.msg}); revisar a mano.", "", "baja"))
            continue
        if not isinstance(datos, dict):
            continue
        revisados.append(rel)
        if rel in SETTINGS:
            _revisar_settings(rel, texto, datos, H, pendientes)
            if isinstance(datos.get("mcpServers"), dict):
                _revisar_mcp(rel, texto, datos, H)
        else:
            _revisar_mcp(rel, texto, datos, H)
    if not revisados and not H:
        return comun.resultado(estado="no_aplica", motivo=(
            "sin configuración de agentes ni MCP en el repositorio (" + ", ".join(SETTINGS + MCP) + ")"))
    pases = []
    if pendientes and not H:
        return comun.resultado(H, [], motivo=(
            "hay hooks o comandos configurados que el agente ejecuta solo (requieren revisión; sin pase explícito): "
            + "; ".join(pendientes[:5]))[:300])
    if revisados and not H and not pendientes:
        pases.append(comun.pase(NOMBRE, "configuracion",
                                "Configuración de agentes y MCP sin auto-aprobación, comodines ni secretos: "
                                + ", ".join(revisados)))
    return comun.resultado(H, pases)


if __name__ == "__main__":
    sys.exit(comun.main_check(NOMBRE, analizar))

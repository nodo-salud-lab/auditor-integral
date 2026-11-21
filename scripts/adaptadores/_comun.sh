# _comun.sh — funciones compartidas por los adaptadores (se carga con `source`; no se ejecuta).
#
# Contrato de un adaptador:  <herramienta>.sh PROYECTO DIR_CRUDO
#   - ejecuta la herramienta y guarda la salida cruda en DIR_CRUDO/<herramienta>.(json|sarif)
#   - escribe DIR_CRUDO/<herramienta>.meta.json (ver meta.py) en todos los casos
#   - herramienta ausente → meta estado "ausente" y salida 0 (el control quedará no_evaluado)
#   - devuelve 0 salvo uso incorrecto (2): los fallos de la herramienta quedan en el meta,
#     no detienen la fase.
# El binario se puede sustituir con AUDITOR_BIN_<NOMBRE> (lo usan los tests).
# Nada aquí escribe fuera de DIR_CRUDO ni modifica el proyecto auditado.

ADAPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(cd "$ADAPT_DIR/../.." && pwd)"
PY="${AUDITOR_PYTHON:-python3}"
CON_TIMEOUT="$RAIZ/scripts/con_timeout.py"
TIMEOUT_VERSION_S="${AUDITOR_TIMEOUT_VERSION_S:-15}"

# Evita telemetría y consultas de versión nuevas.
export SEMGREP_ENABLE_VERSION_CHECK=0 SEMGREP_SEND_METRICS=off

# SEGURIDAD (correcciones post-verificación):
# 1. Los adaptadores hacen `cd` al proyecto auditado. Con `python -c` o `python -`, Python pone el cwd
#    en sys.path[0]: un json.py del repo se importaría en lugar de la biblioteca estándar. Por eso todo
#    Python en línea usa "${PYI[@]}" (modo aislado -I: sin cwd en sys.path, sin PYTHON* ni site del usuario).
#    Los scripts propios se ejecutan por ruta (sys.path[0] = su carpeta, no el cwd).
# 2. git (el nuestro y el que lanza gitleaks) no debe ejecutar nada del .git/config del repo auditado
#    (core.fsmonitor, core.hooksPath, diff.external): se fuerzan por entorno, igual que scripts/git_seguro.py.
PYI=("$PY" -I)
export GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_CONFIG_COUNT=4 \
  GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=false \
  GIT_CONFIG_KEY_1=core.hooksPath GIT_CONFIG_VALUE_1=/dev/null \
  GIT_CONFIG_KEY_2=diff.external GIT_CONFIG_VALUE_2= \
  GIT_CONFIG_KEY_3=core.untrackedCache GIT_CONFIG_VALUE_3=false

ahora() { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
transcurrido() { perl -e 'printf "%.3f", $ARGV[1] - $ARGV[0]' "$1" "$(ahora)"; }

# comando_texto ARGS... → representación copiable del comando (con comillas cuando hace falta)
comando_texto() {
  local salida="" a
  for a in "$@"; do
    case "$a" in
      *[!A-Za-z0-9_./:=@%+,-]*|'') salida+="'${a//\'/\'\\\'\'}' " ;;
      *) salida+="$a " ;;
    esac
  done
  printf '%s' "${salida% }"
}

# adaptador_iniciar NOMBRE VAR_BIN BIN_POR_DEFECTO "$@"
# Define PROYECTO, CRUDO, BIN, NOMBRE, META, LOGS, EJEC_JSONL, INICIO_ADAPT.
adaptador_iniciar() {
  NOMBRE="$1"; local var="$2" defecto="$3"; shift 3
  if [ $# -ne 2 ]; then
    echo "uso: $NOMBRE.sh PROYECTO DIR_CRUDO" >&2; exit 2
  fi
  [ -d "$1" ] || { echo "$NOMBRE.sh: no es una carpeta: $1" >&2; exit 2; }
  PROYECTO="$(cd "$1" && pwd)"
  mkdir -p "$2" || { echo "$NOMBRE.sh: no se pudo crear $2" >&2; exit 2; }
  CRUDO="$(cd "$2" && pwd)"
  META="$CRUDO/$NOMBRE.meta.json"
  LOGS="$CRUDO/.tmp_$NOMBRE"
  rm -rf "$LOGS"; mkdir -p "$LOGS"
  EJEC_JSONL="$LOGS/ejecuciones.jsonl"; : > "$EJEC_JSONL"
  INICIO_ADAPT="$(ahora)"
  local pedido="${!var:-$defecto}"
  BIN="$(command -v "$pedido" 2>/dev/null || true)"
  if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    escribir_meta ausente "" "" "" "$NOMBRE no está instalado (se buscó '$pedido'); el control queda no_evaluado"
    limpiar_tmp
    exit 0
  fi
}

limpiar_tmp() { rm -rf "$LOGS"; }

# version_de ARGS... → primera versión X.Y.Z que imprima el comando (vacío si no hay)
version_de() {
  "$PY" "$CON_TIMEOUT" "$TIMEOUT_VERSION_S" "$@" 2>&1 </dev/null \
    | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true
}

# ejecutar MODO SALIDA_RELATIVA -- COMANDO...
# Corre el comando (stderr a un log), mide la duración y agrega una línea a EJEC_JSONL.
# Deja ULTIMO_CODIGO, ULTIMO_LOG, ULTIMO_DUR y ULTIMO_CMD.
ejecutar() {
  local modo="$1" salida="$2"; shift 3
  ULTIMO_LOG="$LOGS/$modo.log"
  ULTIMO_CMD="$(comando_texto "$@")"
  local t0; t0="$(ahora)"
  "$@" >"$LOGS/$modo.stdout" 2>"$ULTIMO_LOG" </dev/null
  ULTIMO_CODIGO=$?
  ULTIMO_DUR="$(transcurrido "$t0")"
}

# registrar_ejecucion MODO SALIDA ESTADO [ERROR]
registrar_ejecucion() {
  "${PYI[@]}" - "$EJEC_JSONL" "$1" "$2" "$3" "$ULTIMO_CODIGO" "$ULTIMO_DUR" "$ULTIMO_CMD" "${4:-}" <<'PYEOF'
import json, sys
ruta, modo, salida, estado, codigo, dur, cmd, error = sys.argv[1:9]
with open(ruta, "a", encoding="utf-8") as f:
    f.write(json.dumps({"modo": modo, "salida": salida or None, "estado": estado, "exit_code": int(codigo),
                        "duracion_s": round(float(dur), 3), "comando": cmd, "error": error or None},
                       ensure_ascii=False) + "\n")
PYEOF
}

# cola_log ARCHIVO → últimas líneas útiles del log (para el campo error)
cola_log() { [ -f "$1" ] && grep -v '^[[:space:]]*$' "$1" | tail -n 8; }

# escribir_meta ESTADO EXIT_CODE COMANDO SALIDAS(coma) ERROR [EXTRA_JSON]
escribir_meta() {
  local args=(--salida "$META" --herramienta "$NOMBRE" --estado "$1"
              --duracion "$(transcurrido "${INICIO_ADAPT:-$(ahora)}")" --comando "${3:-}" --salidas "${4:-}")
  [ -n "${VERSION:-}" ] && args+=(--version "$VERSION")
  [ -n "${2:-}" ] && args+=(--exit-code "$2")
  [ -n "${5:-}" ] && args+=(--error "$5")
  [ -s "${EJEC_JSONL:-/nonexistent}" ] && args+=(--ejecuciones-jsonl "$EJEC_JSONL")
  [ -n "${6:-}" ] && args+=(--extra-json "$6")
  "$PY" "$ADAPT_DIR/meta.py" "${args[@]}"
}

# json_valido ARCHIVO → 0 si el archivo existe y es JSON
json_valido() { [ -s "$1" ] && "${PYI[@]}" -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" 2>/dev/null; }

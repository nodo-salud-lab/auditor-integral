#!/usr/bin/env bash
# doctor.sh — detecta las herramientas externas del auditor (PLAN_MAESTRO §8.1) y sus versiones.
# NUNCA instala nada: para las faltantes solo informa el comando sugerido como texto.
#
# Uso: doctor.sh [--salida ARCHIVO] [--timeout SEGUNDOS] [--tabla]
#   Sin --salida escribe el JSON a stdout.
#   Timeout por herramienta: --timeout, o variable AUDITOR_DOCTOR_TIMEOUT (por defecto 10 s).
#   --tabla: en vez del JSON imprime una tabla legible (scripts/doctor_tabla.py); con --salida el JSON va al archivo.
#
# Solo lectura y vite.config (Anexo C del brazo C, M-04): el auditor no ejecuta vite, vitest ni scripts
# del proyecto auditado. Un vite.config.(ts|js|mjs) que llama a git al cargarse (p. ej. `git status` o
# `git rev-parse` para inyectar la versión) puede escribir .git/index cuando lo carga cualquier runner
# de vite o vitest (refresca el índice). Si se corre a mano un runner del proyecto durante una auditoría,
# hágalo con GIT_OPTIONAL_LOCKS=0 y compare `git status` antes y después. El runner opcional de tipos
# (scripts/checks/tipos.py) solo invoca tsc --noEmit, que tipa vite.config pero no lo ejecuta.
set -u

SALIDA=""
TABLA=""
TIMEOUT_S="${AUDITOR_DOCTOR_TIMEOUT:-10}"

while [ $# -gt 0 ]; do
  case "$1" in
    --salida) SALIDA="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT_S="${2:-}"; shift 2 ;;
    --tabla) TABLA=1; shift ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "doctor.sh: argumento desconocido: $1" >&2; exit 2 ;;
  esac
done
case "$TIMEOUT_S" in ''|*[!0-9]*) echo "doctor.sh: --timeout debe ser un entero" >&2; exit 2 ;; esac

# Evita que semgrep consulte la red por versiones nuevas y que npx descargue paquetes.
export SEMGREP_ENABLE_VERSION_CHECK=0
export npm_config_offline=true
export npm_config_update_notifier=false

# nombre|comando de versión|instalación sugerida|¿probar vía npx si no está en PATH? (s/n)
CATALOGO='gitleaks|gitleaks version|brew install gitleaks|n
semgrep|semgrep --version|pipx install semgrep|n
osv-scanner|osv-scanner --version|brew install osv-scanner|n
zizmor|zizmor --version|pipx install zizmor|n
trivy|trivy --version|brew install trivy|n
jscpd|jscpd --version|npm install -g jscpd|s
knip|knip --version|npm install -g knip|s
squawk|squawk --version|npm install -g squawk-cli|n
k6|k6 version|brew install k6|n
hadolint|hadolint --version|brew install hadolint|n
actionlint|actionlint --version|brew install actionlint|n
checkov|checkov --version|pipx install checkov|n
lizard|lizard --version|pipx install lizard (NO usar brew install lizard: esa fórmula es un compresor distinto)|n
node|node --version|brew install node|n
npx|npx --version|brew install node|n
python3|python3 --version|brew install python|n
jq|jq --version|brew install jq|n
git|git --version|brew install git|n
playwright|playwright --version|npm install -D @playwright/test && npx playwright install chromium|s
lhci|lhci --version|npm install -g @lhci/cli|s
nuclei|nuclei -version|brew install nuclei|n
syft|syft version|brew install syft|n
zap.sh|zap.sh -version|brew install --cask zap (o Docker: ghcr.io/zaproxy/zaproxy:stable zap-baseline.py)|n
psql|psql --version|brew install libpq && brew link --force libpq (para correr splinter.sql con una conexión de solo lectura)|n'

TMPDIR_DOCTOR="$(mktemp -d "${TMPDIR:-/tmp}/doctor.XXXXXX")"
trap 'rm -rf "$TMPDIR_DOCTOR"' EXIT

json_texto() {
  # Escapa una cadena para JSON (o devuelve null si está vacía).
  local s="$1"
  if [ -z "$s" ]; then printf 'null'; return; fi
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\t'/ }"
  s="${s//$'\r'/ }"
  s="${s//$'\n'/ }"
  # elimina otros caracteres de control
  s="$(printf '%s' "$s" | LC_ALL=C tr -d '\000-\010\013\014\016-\037')"
  printf '"%s"' "$s"
}

# Ejecuta un comando con timeout, en su propio grupo de procesos (mata también a los hijos).
# Escribe la salida combinada en $2 y deja el código en la variable global CODIGO (124 = timeout).
ejecutar_con_timeout() {
  local limite="$1" salida="$2"; shift 2
  perl -e 'setpgrp(0,0); exec @ARGV or exit 127' -- "$@" >"$salida" 2>&1 </dev/null &
  local pid=$! pasos=$(( limite * 10 )) i=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$i" -ge "$pasos" ]; then
      kill -TERM -- "-$pid" 2>/dev/null
      sleep 0.3
      kill -KILL -- "-$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      CODIGO=124
      return
    fi
    sleep 0.1
    i=$(( i + 1 ))
  done
  wait "$pid"
  CODIGO=$?
}

extraer_version() {
  # Primera secuencia N.N(.N) de la salida.
  grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' "$1" 2>/dev/null | head -n 1
}

primera_linea() {
  grep -m 1 -v '^[[:space:]]*$' "$1" 2>/dev/null | cut -c1-200
}

PLATAFORMA="$(uname -s 2>/dev/null) $(uname -m 2>/dev/null)"
GENERADO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TIENE_NPX="$(command -v npx 2>/dev/null || true)"

CUERPO=""
SEP=""
while IFS='|' read -r NOMBRE CMD_VERSION INSTALAR PROBAR_NPX; do
  [ -z "$NOMBRE" ] && continue
  RUTA="$(command -v "$NOMBRE" 2>/dev/null || true)"
  VIA=""
  ESTADO="ausente"; VERSION=""; DETALLE=""
  read -r -a PARTES <<<"$CMD_VERSION"
  if [ -n "$RUTA" ]; then
    VIA="path"
    ARGS=("${PARTES[@]:1}")
    ejecutar_con_timeout "$TIMEOUT_S" "$TMPDIR_DOCTOR/out" "$RUTA" "${ARGS[@]}"
  elif [ "$PROBAR_NPX" = "s" ] && [ -n "$TIENE_NPX" ]; then
    # npx --no: usa solo un paquete ya instalado (local o global); nunca descarga.
    ejecutar_con_timeout "$TIMEOUT_S" "$TMPDIR_DOCTOR/out" "$TIENE_NPX" --no -- "${PARTES[@]}"
    if [ "$CODIGO" -eq 0 ]; then VIA="npx"; RUTA="$TIENE_NPX"; else CODIGO=-1; fi
  else
    CODIGO=-1
  fi

  if [ "$CODIGO" -eq 124 ]; then
    ESTADO="timeout"; DETALLE="sin respuesta en ${TIMEOUT_S} s"
  elif [ "$CODIGO" -eq -1 ]; then
    ESTADO="ausente"; RUTA=""; VIA=""
  else
    VERSION="$(extraer_version "$TMPDIR_DOCTOR/out")"
    if [ "$CODIGO" -eq 0 ] && [ -n "$VERSION" ]; then
      ESTADO="ok"
    else
      ESTADO="error"; DETALLE="código $CODIGO: $(primera_linea "$TMPDIR_DOCTOR/out")"
    fi
  fi

  if [ "$ESTADO" = "ok" ]; then DISPONIBLE=true; SUGERIDA=""; else DISPONIBLE=false; SUGERIDA="$INSTALAR"; fi

  CUERPO+="${SEP}    $(json_texto "$NOMBRE"): {\"disponible\": $DISPONIBLE, \"estado\": $(json_texto "$ESTADO"), \"version\": $(json_texto "$VERSION"), \"ruta\": $(json_texto "$RUTA"), \"via\": $(json_texto "$VIA"), \"comando_version\": $(json_texto "$CMD_VERSION"), \"detalle\": $(json_texto "$DETALLE"), \"instalacion_sugerida\": $(json_texto "$SUGERIDA")}"
  SEP=$',\n'
done <<<"$CATALOGO"

JSON="{
  \"version_esquema\": \"1\",
  \"generado\": $(json_texto "$GENERADO"),
  \"plataforma\": $(json_texto "$PLATAFORMA"),
  \"timeout_s\": $TIMEOUT_S,
  \"nota\": \"doctor.sh nunca instala; instalacion_sugerida es solo texto para el usuario.\",
  \"herramientas\": {
$CUERPO
  }
}"

if [ -n "$SALIDA" ]; then
  mkdir -p "$(dirname "$SALIDA")"
  printf '%s\n' "$JSON" >"$SALIDA"
elif [ -z "$TABLA" ]; then
  printf '%s\n' "$JSON"
fi
if [ -n "$TABLA" ]; then
  # Vista legible opcional; el JSON (salida por defecto) no cambia.
  printf '%s\n' "$JSON" | "${AUDITOR_PYTHON:-python3}" -I "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/doctor_tabla.py"
fi

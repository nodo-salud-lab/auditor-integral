#!/usr/bin/env bash
# ejecutar_scanners.sh — fase 2 (escaneo estático determinista, 0 tokens): despacha en paralelo los
# adaptadores (scripts/adaptadores/*.sh) y los chequeos propios (scripts/checks/*.py).
#
# Uso:
#   ejecutar_scanners.sh PROYECTO DIR_CORRIDA [MODO]
#   ejecutar_scanners.sh --proyecto P --corrida D [--modo M] [--timeout S] [--paralelo N]
# MODO: rapido | estandar | profundo (por defecto estandar). Corren en los tres modos los cuatro
# adaptadores, los cinco chequeos propios (con datos_confidenciales, solo metadatos) y los once fallbacks
# estáticos de la Decisión 6 (cobertura parcial; cada uno se omite solo si herramientas.json declara
# disponible la herramienta real), más el runner opcional de tipos (checks/tipos.py: tsc --noEmit con un tsc confiable
# externo, AUDITOR_BIN_TSC o PATH; el node_modules/.bin/tsc del proyecto solo con AUDITOR_CONFIAR_TSC_PROYECTO=1;
# Anexo C, M-01; ronda 4). Los chequeos se invocan con python -I (aislado).
#
# Salida en DIR_CORRIDA/crudo/:
#   <herramienta>.(json|sarif) + <herramienta>.meta.json     (adaptadores)
#   check_<nombre>.json + check_<nombre>.meta.json            (chequeos propios)
#   logs/<tarea>.log                                          (stderr de cada tarea)
#   resumen_scan.json                                         (estado y conteo por herramienta)
# y una tabla de conteos por stdout.
#
# Timeout por tarea: --timeout, o AUDITOR_TIMEOUT_S (por defecto 300 s). Una tarea que lo supera queda
# con meta estado "timeout" (exit_code 124) y su control saldrá no_evaluado.
# Paralelismo: --paralelo, o AUDITOR_PARALELO (por defecto 4), con xargs -P.
# Sin red (D1): AUDITOR_SIN_RED distinto de vacío/0 (el usuario no autorizó la red; lo exporta el skill /auditar o
# `auditar --sin-red`) se normaliza a AUDITOR_SIN_RED=1 y se hereda a cada tarea: osv-scanner solo --offline con base
# local (si no, no_evaluado), registro_deps no consulta npm/PyPI, semgrep no descarga el registro y zizmor queda
# --offline. Cada meta dice «sin red (AUDITOR_SIN_RED)». Ningún otro chequeo usa la red (grep de http/urllib/curl/npm).
# Código de salida: 0 si se despachó todo (aunque alguna herramienta falle o falte: queda en su meta);
# 2 uso incorrecto; 1 si no se pudo crear crudo/.
set -u

SELF="${BASH_SOURCE[0]}"
RAIZ="$(cd "$(dirname "$SELF")/.." && pwd)"
PY="${AUDITOR_PYTHON:-python3}"

# Tareas: nombre|tipo|script|archivo_meta (sin .meta.json)|herramienta
TAREAS='gitleaks|adaptador|adaptadores/gitleaks.sh|gitleaks|gitleaks
semgrep|adaptador|adaptadores/semgrep.sh|semgrep|semgrep
osv|adaptador|adaptadores/osv.sh|osv|osv
zizmor|adaptador|adaptadores/zizmor.sh|zizmor|zizmor
env_publicas|check|checks/env_publicas.py|check_env_publicas|check:env_publicas
registro_deps|check|checks/registro_deps.py|check_registro_deps|check:registro_deps
archivos_clave|check|checks/archivos_clave.py|check_archivos_clave|check:archivos_clave
config_agentes|check|checks/config_agentes.py|check_config_agentes|check:config_agentes
datos_confidenciales|check|checks/datos_confidenciales.py|check_datos_confidenciales|check:datos_confidenciales
duplicacion|check|checks/duplicacion.py|check_duplicacion|check:duplicacion
complejidad|check|checks/complejidad.py|check_complejidad|check:complejidad
deps_muertas|check|checks/deps_muertas.py|check_deps_muertas|check:deps_muertas
migraciones_sql|check|checks/migraciones_sql.py|check_migraciones_sql|check:migraciones_sql
dockerfile|check|checks/dockerfile.py|check_dockerfile|check:dockerfile
iac|check|checks/iac.py|check_iac|check:iac
sbom|check|checks/sbom.py|check_sbom|check:sbom
workflows|check|checks/workflows.py|check_workflows|check:workflows
rls_estatico|check|checks/rls_estatico.py|check_rls_estatico|check:rls_estatico
ux_estatico|check|checks/ux_estatico.py|check_ux_estatico|check:ux_estatico
presupuesto_build|check|checks/presupuesto_build.py|check_presupuesto_build|check:presupuesto_build
tipos|check|checks/tipos.py|check_tipos|check:tipos
rutas_inventario|check|checks/rutas_inventario.py|check_rutas_inventario|check:rutas_inventario'

# --- modo interno: una sola tarea (lo invoca xargs) ---------------------------------------------
if [ "${1:-}" = "--una-tarea" ]; then
  linea="$(printf '%s\n' "$TAREAS" | grep "^$2|")" || exit 0
  IFS='|' read -r nombre tipo script meta herramienta <<<"$linea"
  log="$AUDITOR_CRUDO/logs/$nombre.log"
  inicio=$(perl -MTime::HiRes=time -e 'printf "%.3f", time')
  if [ "$tipo" = adaptador ]; then
    "$PY" "$RAIZ/scripts/con_timeout.py" "$AUDITOR_TIMEOUT" bash "$RAIZ/scripts/$script" "$AUDITOR_PROYECTO" "$AUDITOR_CRUDO" >"$log" 2>&1
  else
    "$PY" "$RAIZ/scripts/con_timeout.py" "$AUDITOR_TIMEOUT" "$PY" -I "$RAIZ/scripts/$script" "$AUDITOR_PROYECTO" "$AUDITOR_CRUDO" >"$log" 2>&1
  fi
  codigo=$?
  dur=$(perl -e 'printf "%.3f", $ARGV[1] - $ARGV[0]' "$inicio" "$(perl -MTime::HiRes=time -e 'printf "%.3f", time')")
  if [ "$codigo" -eq 124 ]; then
    "$PY" "$RAIZ/scripts/adaptadores/meta.py" --salida "$AUDITOR_CRUDO/$meta.meta.json" --herramienta "$herramienta" \
      --estado timeout --exit-code 124 --duracion "$dur" --comando "$script" \
      --error "superó el límite de ${AUDITOR_TIMEOUT} s; el control queda no_evaluado"
  elif [ ! -f "$AUDITOR_CRUDO/$meta.meta.json" ]; then
    "$PY" "$RAIZ/scripts/adaptadores/meta.py" --salida "$AUDITOR_CRUDO/$meta.meta.json" --herramienta "$herramienta" \
      --estado error --exit-code "$codigo" --duracion "$dur" --comando "$script" --error-archivo "$log"
  fi
  echo "[$nombre] terminó con código $codigo en ${dur}s" >&2
  exit 0
fi

uso() { sed -n '2,24p' "$SELF" | sed 's/^# \{0,1\}//'; }
error_uso() { echo "ejecutar_scanners.sh: $*" >&2; exit 2; }

PROYECTO=""; CORRIDA=""; MODO=""; TIMEOUT="${AUDITOR_TIMEOUT_S:-300}"; PARALELO="${AUDITOR_PARALELO:-4}"
POS=()
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) uso; exit 0 ;;
    --proyecto) PROYECTO="${2:-}"; shift 2 ;;
    --corrida) CORRIDA="${2:-}"; shift 2 ;;
    --modo) MODO="${2:-}"; shift 2 ;;
    --timeout) TIMEOUT="${2:-}"; shift 2 ;;
    --paralelo) PARALELO="${2:-}"; shift 2 ;;
    -*) error_uso "opción desconocida: $1" ;;
    *) POS+=("$1"); shift ;;
  esac
done
[ "${#POS[@]}" -gt 3 ] && error_uso "demasiados argumentos"
[ -z "$PROYECTO" ] && [ "${#POS[@]}" -ge 1 ] && PROYECTO="${POS[0]}"
[ -z "$CORRIDA" ] && [ "${#POS[@]}" -ge 2 ] && CORRIDA="${POS[1]}"
[ -z "$MODO" ] && [ "${#POS[@]}" -ge 3 ] && MODO="${POS[2]}"
MODO="${MODO:-${AUDITOR_MODO:-estandar}}"
[ -n "$PROYECTO" ] && [ -n "$CORRIDA" ] || { uso >&2; exit 2; }
[ -d "$PROYECTO" ] || error_uso "no es una carpeta: $PROYECTO"
case "$MODO" in rapido|estandar|profundo) ;; *) error_uso "modo inválido: $MODO (rapido|estandar|profundo)" ;; esac
case "$TIMEOUT" in ''|*[!0-9]*|0) error_uso "--timeout debe ser un entero positivo" ;; esac
case "$PARALELO" in ''|*[!0-9]*|0) error_uso "--paralelo debe ser un entero positivo" ;; esac

PROYECTO="$(cd "$PROYECTO" && pwd)"
mkdir -p "$CORRIDA/crudo/logs" || { echo "ejecutar_scanners.sh: no se pudo crear $CORRIDA/crudo" >&2; exit 1; }
CRUDO="$(cd "$CORRIDA/crudo" && pwd)"

# Las metas de una corrida anterior en la misma carpeta no deben confundirse con las nuevas.
printf '%s\n' "$TAREAS" | while IFS='|' read -r _ _ _ meta _; do rm -f "$CRUDO/$meta.meta.json"; done

export AUDITOR_PROYECTO="$PROYECTO" AUDITOR_CRUDO="$CRUDO" AUDITOR_TIMEOUT="$TIMEOUT" AUDITOR_MODO="$MODO"
TXT_RED=""
case "${AUDITOR_SIN_RED:-}" in
  ""|0) ;;
  *) export AUDITOR_SIN_RED=1
     unset AUDITOR_ZIZMOR_EN_LINEA
     TXT_RED=" · sin red (AUDITOR_SIN_RED): ninguna herramienta consulta servicios externos" ;;
esac
echo "ejecutar_scanners: $PROYECTO · modo $MODO · timeout ${TIMEOUT}s · paralelo $PARALELO$TXT_RED" >&2
INICIO=$SECONDS
printf '%s\n' "$TAREAS" | cut -d'|' -f1 | xargs -P "$PARALELO" -n 1 bash "$SELF" --una-tarea

"$PY" "$RAIZ/scripts/resumen_crudo.py" "$CRUDO" --modo "$MODO" --duracion "$(( SECONDS - INICIO ))"
exit 0

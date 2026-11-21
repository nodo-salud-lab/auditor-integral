#!/usr/bin/env python3
"""env_publicas — variables con prefijo público (VITE_, NEXT_PUBLIC_, EXPO_PUBLIC_, ...) y nombre
o valor sensible (PLAN_MAESTRO §3.2; control SEG-ENV-PUBLICAS, N1).

Todo lo que lleva prefijo público se copia al bundle del navegador: un nombre como
VITE_OPENAI_API_KEY o VITE_SUPABASE_SERVICE_ROLE_KEY significa que el secreto queda expuesto.

Subreglas:
  nombre_sensible    .env*: variable pública con nombre sensible (crítica con valor; alta si está vacía)
  valor_secreto      .env*: variable pública de nombre inocuo cuyo valor tiene forma de secreto
                     (sk_live_, sk-..., JWT con role service_role, ...)
  referencia_codigo  código: se lee una variable pública sensible que no está declarada en ningún .env*
                     (suele definirse en el panel del hosting; igual termina en el bundle)
Los valores nunca se copian a la evidencia.
Sin «pases vacíos» (ronda 1): el pase explícito solo se emite si se analizó ≥ 1 archivo .env* o ≥ 1 archivo de código
que lee variables de entorno (import.meta.env, process.env, $env/…). Sin nada de eso → estado no_aplica con motivo
(no hay variables públicas que revisar).

Uso: env_publicas.py PROYECTO DIR_CRUDO   → DIR_CRUDO/check_env_publicas.json (+ .meta.json)
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402

NOMBRE = "env_publicas"
PREFIJOS = ("VITE_", "NEXT_PUBLIC_", "EXPO_PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_", "GATSBY_",
            "PUBLIC_", "VUE_APP_", "NG_APP_", "SVELTE_PUBLIC_")
RE_PREFIJO = "(?:" + "|".join(PREFIJOS) + ")"

# Fragmentos de nombre que indican secreto (sobre el nombre sin el prefijo).
SENSIBLE = re.compile(
    r"SECRET|SERVICE_?ROLE|PRIVATE|PASSWORD|PASSWD|(^|_)PWD($|_)|TOKEN|API_?KEY|ACCESS_?KEY|AUTH_?KEY|"
    r"CREDENTIAL|DATABASE_URL|(^|_)DB_(URL|PASS)|CONNECTION_STRING|SIGNING|WEBHOOK|ENCRYPTION|"
    r"SESSION_KEY|ADMIN_KEY|MASTER_KEY|SECRET_KEY|(^|_)SK($|_)")
# Públicas por diseño: ganan sobre SENSIBLE salvo que el valor tenga forma de secreto.
PUBLICA_POR_DISENO = re.compile(
    r"ANON_?KEY|PUBLISHABLE|PUBLIC_?KEY|SITE_?KEY|MEASUREMENT_ID|FIREBASE\w*API_?KEY|MAPS\w*KEY|"
    r"POSTHOG_KEY|DSN$|CLIENT_ID$|APP_ID$|PROJECT_ID$|PROJECT_REF$|(?<!DATABASE)(?<!DB)_URL$")

RE_ENV_LINEA = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
RE_REF_CODIGO = re.compile(
    r"(?:import\.meta\.env|process\.env)(?:\.(" + RE_PREFIJO + r"[A-Z0-9_]+)|\[\s*['\"](" + RE_PREFIJO +
    r"[A-Z0-9_]+)['\"]\s*\])|\$env/static/public[^\n]*?\b(PUBLIC_[A-Z0-9_]+)")
EXT_CODIGO = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro"}
RE_LEE_ENV = re.compile(r"import\.meta\.env|process\.env|\$env/(static|dynamic)/")
MARCADORES_VACIO = {"", '""', "''", "changeme", "change_me", "xxx", "<tu-clave>", "your-key-here", "tu_clave"}


def _es_publica(nombre):
    return nombre.startswith(PREFIJOS)


def _sin_prefijo(nombre):
    for p in sorted(PREFIJOS, key=len, reverse=True):
        if nombre.startswith(p):
            return nombre[len(p):]
    return nombre


def nombre_sensible(nombre):
    base = _sin_prefijo(nombre)
    return bool(SENSIBLE.search(base)) and not PUBLICA_POR_DISENO.search(base)


def _archivos_env(proyecto):
    for p in comun.recorrer(proyecto):
        n = p.name
        if n == ".env" or n.startswith(".env.") or n.endswith(".env"):
            yield p


def _limpiar_valor(v):
    v = v.strip()
    if v and v[0] in "'\"":
        cierre = v.find(v[0], 1)
        return v[1:cierre] if cierre > 0 else v[1:]
    return re.split(r"\s+#", v, maxsplit=1)[0].strip()


def analizar(proyecto):
    proyecto = Path(proyecto)
    hallazgos = []
    declaradas = set()
    n_env = n_codigo_env = 0

    for archivo in _archivos_env(proyecto):
        texto = comun.leer(archivo)
        if texto is None:
            continue
        n_env += 1
        ejemplo = archivo.name.endswith((".example", ".sample", ".template", ".dist"))
        for n, linea in enumerate(texto.splitlines(), 1):
            if linea.lstrip().startswith("#"):
                continue
            m = RE_ENV_LINEA.match(linea)
            if not m:
                continue
            var, valor = m.group(1), _limpiar_valor(m.group(2))
            if not _es_publica(var):
                continue
            declaradas.add(var)
            tiene_valor = valor.lower() not in MARCADORES_VACIO and not comun.es_referencia_variable(valor)
            tipo = comun.tipo_secreto(valor) if tiene_valor else None
            evid = f"{var}=" + (f"<valor oculto, {len(valor)} caracteres>" if tiene_valor else "<vacío>")
            rel = comun.rel(proyecto, archivo)
            if nombre_sensible(var):
                sev = "critica" if (tiene_valor and not ejemplo) else "alta"
                hallazgos.append(comun.hallazgo(
                    NOMBRE, "nombre_sensible", rel, n,
                    f"{var} tiene prefijo público: su valor se copia al bundle del navegador y cualquiera "
                    f"puede leerlo. Moverla al servidor sin prefijo público y rotarla si ya se publicó.",
                    evid, sev))
            elif tipo:
                hallazgos.append(comun.hallazgo(
                    NOMBRE, "valor_secreto", rel, n,
                    f"{var} es pública (va al bundle) pero su valor tiene forma de credencial privada "
                    f"({tipo}). Reemplazarla por la clave pública correspondiente y rotar la expuesta.",
                    evid, "critica"))

    for archivo in comun.recorrer(proyecto, extensiones=EXT_CODIGO):
        texto = comun.leer(archivo)
        if texto is None:
            continue
        if RE_LEE_ENV.search(texto):
            n_codigo_env += 1
        vistas = set()
        for m in RE_REF_CODIGO.finditer(texto):
            var = next(g for g in m.groups() if g)
            if var in declaradas or var in vistas or not nombre_sensible(var):
                continue
            vistas.add(var)
            n = texto.count("\n", 0, m.start()) + 1
            hallazgos.append(comun.hallazgo(
                NOMBRE, "referencia_codigo", comun.rel(proyecto, archivo), n,
                f"El código del cliente lee {var}: con prefijo público el valor termina en el bundle "
                f"aunque se configure en el panel del hosting.",
                comun.linea_texto(texto, n).strip(), "alta"))

    if not hallazgos and not n_env and not n_codigo_env:
        return comun.resultado(estado="no_aplica", motivo=(
            "sin archivos .env* ni código que lea variables de entorno: no hay variables públicas que revisar"))
    pases = [] if hallazgos else [comun.pase(
        NOMBRE, "nombre_sensible", f"Ninguna variable pública con nombre o valor sensible ({n_env} archivo(s) .env*, "
        f"{n_codigo_env} archivo(s) de código que leen variables de entorno).")]
    return comun.resultado(hallazgos, pases)


if __name__ == "__main__":
    sys.exit(comun.main_check(NOMBRE, analizar))

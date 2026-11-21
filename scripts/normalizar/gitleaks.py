"""Lector del reporte JSON de gitleaks (lista de {RuleID, File, StartLine, Secret, Match, Commit, ...}).

El Secret nunca sale de aquí sin enmascarar: secretos() lo entrega a enmascarar.py para que
construir() lo oculte en snippet y evidencia. Los hallazgos bajo dist/, build/, .next/ u out/
se mapean a SEG-SECRETO-BUNDLE (catalogo.control_por_regla con archivo).

AUD-SEC (Anexo C del brazo C): un generic-api-key dentro de un bundle (dist/, build/, .next/, out/) o
de un *.min.* cuyo secreto no lleva un prefijo de proveedor reconocido (sk_live_, ghp_, AKIA, xox…, JWT
con role service_role, etc.) suele ser texto minificado de una biblioteca. Se informa igual, pero con
confianza "baja": gates.py no lo trata como secreto vivo ni bloquea hasta que un triage lo confirme.

O3 (privacidad): el crudo ya no trae el Secret en claro (gitleaks --redact=100 + gitleaks_redactar.py). Los
secretos conocidos llegan como Huella (AuditorHuella) y el prefijo de proveedor como AuditorProveedor (bool).
Si el Secret está redactado y no hay AuditorProveedor, no se baja la confianza (fail-closed: no se presume texto
minificado sin poder verlo). Si está redactado y no hay AuditorHuella, no se usa la línea del working tree como
snippet/evidencia (tendría el secreto en claro y nada lo enmascararía): se usa el Match redactado.

Ronda 6 (grupo secretos; verificación real 2026-11-20: el nivel global salía N0 por estos falsos positivos):
  - AuditorJwtRol = "anon" (JWT cuyo payload dice role anon: clave anon de Supabase, pública por diseño, va en el
    cliente) → regla "jwt-anon-publico:<regla>", confianza "baja" y un mensaje que dice que NO hay que rotarla.
  - AuditorGit = "ignorado" (archivo ignorado por git y sin ningún commit que lo toque) → regla
    "secreto-local-ignorado:<regla>", confianza "baja" y un mensaje «secreto local no versionado (ignorado por
    git)» que recomienda no versionarlo, sin pedir rotación ni git filter-repo.
  En ambos casos el hallazgo sigue visible. Con confianza baja, gates.py no lo trata como secreto vivo ni bloquea
  mientras ningún triage lo confirme (AUD-SEC); si se une a otro hallazgo de confianza mayor, manda la mayor.
  Las reglas con prefijo permiten que el catálogo las mapee a un control de severidad baja/info (pedido abierto:
  hoy caen en gitleaks:* → SEG-SECRETO-REPO, crítico). service_role, "otro", "ilegible", "no_versionado",
  "ignorado_con_historial", "desconocido" y "sin_git" no cambian nada (fail-closed).
"""
import base64
import json
import re
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from normalizar import comun  # noqa: E402

sys.path.append(str(_SCRIPTS / "checks"))
import datos_confidenciales as _dc  # noqa: E402
import catalogo as _catalogo  # noqa: E402
import enmascarar  # noqa: E402

HERRAMIENTA = "gitleaks"
REGLAS_GENERICAS = {"generic-api-key"}
# Prefijos de proveedor reconocidos (formatos publicados por cada proveedor). Un secreto con uno de
# ellos mantiene su confianza aunque gitleaks lo haya visto solo con la regla genérica.
PREFIJOS_PROVEEDOR = re.compile(
    r"^(?:sk_live_|sk_test_|rk_live_|rk_test_|pk_live_|whsec_"          # Stripe
    r"|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_|glpat-"                     # GitHub, GitLab
    r"|AKIA|ASIA|AGPA|AIDA|AROA|AIza|ya29\."                          # AWS, Google
    r"|xox[abposre]-|xapp-"                                            # Slack
    r"|sk-ant-|sk-proj-|sk-[A-Za-z0-9]{20,}"                           # Anthropic, OpenAI
    r"|SG\.|hf_|npm_|pypi-|shpat_|shpss_|dop_v1_|sbp_|sb_secret_|sq0atp-|sq0csp-|EAAC)")
PREFIJO_ANON = "jwt-anon-publico:"
PREFIJO_LOCAL = "secreto-local-ignorado:"
MSG_ANON = ("clave pública por diseño: JWT con role anon (clave anon de Supabase), pensada para ir en el cliente; "
            "no requiere rotación. Verifique que RLS proteja todas las tablas expuestas, porque esta clave da acceso "
            "como rol anon")
MSG_LOCAL = ("secreto local no versionado (ignorado por git): el archivo está en .gitignore y ningún commit lo "
             "contiene; no hace falta rotarlo ni limpiar el historial. Recomendación: mantenerlo fuera del "
             "repositorio (no usar git add -f) y no copiarlo a builds ni a respaldos compartidos")
# Etiquetas cortas que encabezan la evidencia (el campo mensaje no llega al hallazgo; la evidencia sí, recortada a 300).
ETIQUETA_ANON = "clave pública por diseño (JWT role anon): no requiere rotación"
ETIQUETA_LOCAL = ("secreto local no versionado (ignorado por git): no hace falta rotar ni git filter-repo; "
                  "no lo versione")
_MSG_TRIAGE = ("confianza baja: regla genérica en un bundle minificado y sin prefijo de proveedor "
               "reconocido; no se presume secreto vivo hasta el triage")


def _cargar(ruta):
    with open(ruta, encoding="utf-8") as f:
        datos = json.load(f)
    if datos is None:
        return []
    if not isinstance(datos, list):
        raise ValueError("se esperaba una lista JSON (formato de gitleaks)")
    return [d for d in datos if isinstance(d, dict)]


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def rol_jwt(valor):
    """Rol del payload de un JWT, sin verificar la firma: "anon", "service_role", "otro", "ilegible", o None si el
    valor no tiene forma de JWT (tres segmentos y cabecera eyJ…). Ronda 6: lo usa gitleaks_redactar.py, que es
    donde todavía se tiene el valor; no imprime ni guarda el payload."""
    v = str(valor or "").strip().strip("'\"`")
    partes = v.split(".")
    if len(partes) != 3 or not partes[0].startswith("eyJ"):
        return None
    cuerpo = partes[1]
    if not cuerpo or any(c not in _B64URL for c in cuerpo):
        return "ilegible"
    duplicadas = []

    def _sin_duplicados(pares):
        claves = [k for k, _ in pares]
        if len(claves) != len(set(claves)):
            duplicadas.append(True)
        return dict(pares)

    try:
        datos = json.loads(base64.urlsafe_b64decode(cuerpo + "=" * (-len(cuerpo) % 4)).decode("utf-8"),
                           object_pairs_hook=_sin_duplicados)
    except (ValueError, UnicodeDecodeError):
        return "ilegible"
    if not isinstance(datos, dict) or duplicadas:
        # Claves repetidas (p. ej. dos "role"): cada servidor resuelve distinto; fail-closed (DECISIONES #12).
        return "ilegible"
    rol = datos.get("role")
    if rol == "service_role":
        return rol
    if rol == "anon":
        # Solo es "clave pública por diseño" si tiene forma de clave anon de Supabase (iss supabase* o ref) y no
        # trae claims de privilegio en ningún nivel; cualquier otro JWT con role=anon queda como "otro".
        iss = str(datos.get("iss") or "").lower()
        if not (iss.startswith("supabase") or "ref" in datos):
            return "otro"
        if _privilegio(datos):
            return "otro"
        return "anon"
    return "otro"


_CLAIMS_PRIVILEGIO = frozenset({"admin", "is_admin", "scope", "scopes", "permissions", "roles", "groups"})


def _privilegio(obj, raiz=True):
    """True si el payload trae algún claim de privilegio o el texto service_role en cualquier campo anidado."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in _CLAIMS_PRIVILEGIO:
                return True
            if not (raiz and k == "role") and _privilegio(v, False):
                return True
        return False
    if isinstance(obj, list):
        return any(_privilegio(v, False) for v in obj)
    return isinstance(obj, str) and "service_role" in obj.lower()


def _jwt_service_role(secreto):
    return rol_jwt(secreto) == "service_role"


def con_prefijo_de_proveedor(secreto):
    secreto = str(secreto or "").strip().strip("'\"`")
    return bool(PREFIJOS_PROVEEDOR.match(secreto)) or _jwt_service_role(secreto)


def en_bundle_minificado(archivo):
    if not archivo:
        return False
    nombre = str(archivo).replace("\\", "/").rsplit("/", 1)[-1]
    return _catalogo._es_bundle(archivo) or ".min." in nombre


def confianza(regla, archivo, secreto, proveedor=None):
    """AUD-SEC: "baja" para generic-api-key en bundle minificado sin prefijo de proveedor.

    `proveedor` (AuditorProveedor del crudo) manda cuando el secreto está redactado; si no se sabe, no se baja."""
    if regla not in REGLAS_GENERICAS:
        return "alta"
    if not en_bundle_minificado(archivo):
        return "media"
    if enmascarar.secreto_redactado(secreto):
        tiene_prefijo = proveedor if isinstance(proveedor, bool) else True
    else:
        tiene_prefijo = con_prefijo_de_proveedor(secreto)
    return "media" if tiene_prefijo else "baja"


def secretos(ruta):
    """Secretos conocidos del reporte: valores en claro (reportes antiguos) o Huella (AuditorHuella)."""
    try:
        return enmascarar.secretos_de_hallazgos(_cargar(ruta))
    except (OSError, ValueError):
        return []


def linea_de_contexto(proyecto, archivo, linea, col_ini=None, col_fin=None, margen=60):
    """Texto de la línea en el working tree (ventana alrededor de la coincidencia si es larga).

    Sirve para que el mismo secreto repetido en dos líneas distintas (p. ej. VITE_STRIPE_SECRET_KEY
    y STRIPE_SECRET_KEY) dé dos fingerprints distintos. None si no se puede leer.
    """
    if not proyecto or not archivo or archivo.startswith("/") or not isinstance(linea, int) or linea < 1:
        return None
    ruta = Path(proyecto) / archivo
    try:
        if not ruta.is_file() or ruta.stat().st_size > 50_000_000:
            return None
        with open(ruta, encoding="utf-8", errors="replace") as f:
            for n, texto in enumerate(f, 1):
                if n == linea:
                    texto = texto.rstrip("\n")
                    if len(texto) > 400 and isinstance(col_ini, int):
                        ini = max(0, col_ini - 1 - margen)
                        fin = (col_fin if isinstance(col_fin, int) else col_ini) + margen
                        texto = texto[ini:fin]
                    return texto.strip()[:600]
    except OSError:
        return None
    return None


# Carpetas que suelen publicarse tal cual aunque estén en .gitignore (deploy por CLI, Capacitor/Ionic, estáticos).
_CARPETAS_PUBLICABLES = frozenset({"www", "public", "static", "dist", "build", "out", ".next", ".output",
                                   ".vercel", ".netlify", "_site"})


def _quizas_publicado(archivo):
    partes = str(archivo or "").replace("\\", "/").split("/")[:-1]
    return any(p in _CARPETAS_PUBLICABLES for p in partes)


def _sin_prefijo_confirmado(d):
    """Fail-closed: solo se rebaja un secreto ignorado si consta que NO tiene prefijo de proveedor (sk_live_, AKIA,
    ghp_, service_role…). Si no se sabe (valor redactado y sin AuditorProveedor), no se rebaja."""
    p = d.get("AuditorProveedor")
    if isinstance(p, bool):
        return not p
    sec = d.get("Secret")
    if sec and not enmascarar.secreto_redactado(sec):
        return not con_prefijo_de_proveedor(sec)
    return False


def leer(ruta, ctx):
    proyecto = ctx.get("proyecto")
    meta = ctx.get("metas", {}).get(HERRAMIENTA) or {}
    version = meta.get("version")
    # gitleaks-git.json trae rutas relativas a la raíz del repo; prefijo_git = carpeta del proyecto en él.
    prefijo = str(meta.get("prefijo_git") or "").strip("/")
    registros = []
    for d in _cargar(ruta):
        regla = str(d.get("RuleID") or "desconocida")
        match = d.get("Match") or d.get("Secret") or ""
        archivo_crudo = d.get("File")
        if prefijo and isinstance(archivo_crudo, str) and archivo_crudo.startswith(prefijo + "/"):
            archivo_crudo = archivo_crudo[len(prefijo) + 1:]
        archivo = comun.normalizar_archivo(archivo_crudo, proyecto)
        linea = d.get("StartLine") if isinstance(d.get("StartLine"), int) else None
        conf = ctx.get("confidencial")
        confidencial = conf is not None and any(
            x and not str(x).startswith("/") and _dc.es_confidencial(str(x), conf) for x in (archivo, archivo_crudo))
        # En una ruta confidencial (DECISIONES.md #3) no se lee la línea de contexto del archivo.
        # Fail-closed (O3): si el Secret está redactado y no hay huella (gitleaks_redactar.py no pudo recuperar el
        # valor), nada podría enmascarar el secreto en la línea del working tree: se usa solo el Match redactado.
        sin_huella = (enmascarar.secreto_redactado(d.get("Secret"))
                      and enmascarar.Huella.desde(d.get("AuditorHuella")) is None)
        contexto = None if (d.get("Commit") or confidencial or sin_huella) else linea_de_contexto(
            proyecto, archivo, linea, d.get("StartColumn"), d.get("EndColumn"))
        conf_reg = confianza(regla, archivo or archivo_crudo, d.get("Secret") or "", d.get("AuditorProveedor"))
        mensaje = d.get("Description") or ""
        rol = d.get("AuditorJwtRol")
        if rol is None and not enmascarar.secreto_redactado(d.get("Secret")):
            rol = rol_jwt(d.get("Secret"))  # reportes antiguos con el valor en claro
        etiqueta = ""
        if rol == "anon":
            etiqueta = ETIQUETA_ANON + " · "
            regla, conf_reg = PREFIJO_ANON + regla, "baja"
            mensaje = f"{mensaje} ({MSG_ANON})" if mensaje else MSG_ANON
        elif (d.get("AuditorGit") == "ignorado" and not d.get("Commit") and not _quizas_publicado(archivo or archivo_crudo)
              and _sin_prefijo_confirmado(d)):
            etiqueta = ETIQUETA_LOCAL + " · "
            regla, conf_reg = PREFIJO_LOCAL + regla, "baja"
            mensaje = f"{mensaje} ({MSG_LOCAL})" if mensaje else MSG_LOCAL
        elif conf_reg == "baja":
            mensaje = f"{mensaje} ({_MSG_TRIAGE})" if mensaje else _MSG_TRIAGE
        registros.append({
            "herramienta": HERRAMIENTA,
            "version": version,
            "regla": regla,
            "archivo": archivo,
            "archivo_original": archivo_crudo,
            "linea": linea,
            "snippet": contexto or match,
            "mensaje": mensaje,
            "evidencia": f"{etiqueta}{regla}: {contexto or match}",
            "severidad_herramienta": None,
            "confianza": conf_reg,
            "referencias": ["CWE-798"],
            "commit": d.get("Commit") or None,
        })
    return registros

#!/usr/bin/env python3
"""Enmascarado de secretos y PII en cualquier texto (PLAN_MAESTRO §3.2 y §3.5).

Regla: ningún texto destinado al LLM (hallazgos.jsonl, digest/, informe.md, hoja-de-ruta.md,
merged.sarif) contiene un secreto completo. El secreto se reemplaza por
    prefijo (4 a 8 caracteres) + "****" + últimos 4
y los valores de PII (email, rut, teléfono, dirección...) por "****".

Detección, en este orden:
  1. bloques de clave privada (PEM);
  2. secretos explícitos (p. ej. el campo Secret de gitleaks), del más largo al más corto;
  3. contraseña dentro de una URL (esquema://usuario:CLAVE@host);
  4. patrones conocidos (Stripe, AWS, GitHub, OpenAI, Anthropic, SendGrid, Slack, Google,
     GitLab, npm, Twilio, JWT, Supabase sb_secret_);
  5. asignaciones "nombre_sensible = valor" (secret, token, password, api_key, clave...);
  6. PII por nombre de columna o clave (email, rut, telefono, direccion...), y emails y RUT sueltos.

Es idempotente: enmascarar dos veces da lo mismo que una.

Uso CLI: enmascarar.py [--secretos-de gitleaks.json] < entrada > salida
Solo biblioteca estándar.
"""
import argparse
import hashlib
import json
import re
import secrets as _secrets
import sys

MASCARA = "****"

PREFIJOS_CONOCIDOS = (
    "sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_", "whsec_",
    "github_pat_", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-proj-", "sk-ant-",
    "xoxb-", "xoxp-", "xoxa-", "xoxo-", "xoxs-", "xoxr-", "glpat-", "npm_", "AKIA", "ASIA",
    "AIza", "SG.", "eyJ", "sb_secret_",
)

# Cuerpo: base64, espacios y saltos escapados (\\n en JSON). Sin END, se detiene donde termina el
# base64 (nunca consume el resto del documento). El lookahead evita re-enmascarar.
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?!\*\*\*\*)(?:[A-Za-z0-9+/=\s]|\\[nr])*"
                  r"(?:-----END [A-Z0-9 ]*PRIVATE KEY-----)?")
_URL_CLAVE = re.compile(r"(?P<pre>\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^:/\s@]+:)(?P<val>[^@\s/*]+)(?P<post>@)")

_PATRONES = [re.compile(p) for p in (
    r"eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}",
    r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}",
    r"\bwhsec_[A-Za-z0-9]{16,}",
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    r"\bgh[pousr]_[A-Za-z0-9]{30,}",
    r"\bgithub_pat_[A-Za-z0-9_]{30,}",
    r"\bsk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_\-]{20,}",
    r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}",
    r"\bxox[abposr]-[A-Za-z0-9\-]{10,}",
    r"\bAIza[0-9A-Za-z_\-]{30,}",
    r"\bglpat-[A-Za-z0-9_\-]{20,}",
    r"\bnpm_[A-Za-z0-9]{36}",
    r"\bSK[0-9a-f]{32}\b",
    r"\bsb_secret_[A-Za-z0-9_\-]{10,}",
)]

_NOMBRES_SENSIBLES = (r"[A-Za-z0-9_\-]*(?:secret|token|passw(?:or)?d|passwd|pwd|api_?key|apikey|clave|"
                      r"contrase(?:n|ñ)a|private_?key|access_?key|credential|auth_?key|signing_?key|"
                      r"client_?secret|webhook_?secret)[A-Za-z0-9_\-]*")
_ASIGNACION = re.compile(
    r"(?P<pre>(?i:\b" + _NOMBRES_SENSIBLES + r")[\"']?\s*(?:=|:)\s*[\"'`]?)"
    r"(?P<val>[A-Za-z0-9_\-/+.~][A-Za-z0-9_\-/+.~=]{7,})(?![*A-Za-z0-9_\-/+.~=])")
_IDENTIFICADOR = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[\w$]+)+$")
_NO_VALORES = {"undefined", "null", "true", "false", "none", "required", "optional", "string", "number"}

_NOMBRES_PII = (r"e_?mail|correo(?:_electronico)?|rut|run_paciente|dni|pasaporte|tel[eé]fono|telefono_?\w*|"
                r"celular|movil|phone|direcci[oó]n|domicilio|address|fecha_?nacimiento|nacimiento|"
                r"diagn[oó]stico|prevision|ficha_?clinica")
_PII_KV = re.compile(
    r"(?P<pre>[\"']?\b(?i:" + _NOMBRES_PII + r")\b[\"']?\s*(?:=|:)\s*)"
    r"(?:\"(?P<v1>[^\"\n]*)\"|'(?P<v2>[^'\n]*)'|(?P<v3>[^\s,;)}\]\"'*][^\s,;)}\]\"']*))")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}")
_RUT = re.compile(r"\b\d{1,2}\.?\d{3}\.?\d{3}-[\dkK]\b")


def enmascarar_valor(secreto):
    """Prefijo (4-8) + **** + últimos 4. Secretos cortos se ocultan casi enteros."""
    s = str(secreto)
    n = len(s)
    if n <= 8:
        return MASCARA
    if n < 16:
        return s[:2] + MASCARA
    prefijo = 4
    for p in PREFIJOS_CONOCIDOS:
        if s.startswith(p):
            prefijo = max(4, min(len(p), 8))
            break
    prefijo = min(prefijo, n - 12) if n - 12 >= 4 else 4  # siempre quedan >= 8 ocultos
    return s[:prefijo] + MASCARA + s[-4:]


# --- Huellas de secretos (O3): el crudo de gitleaks ya no guarda el valor en claro -------------------------
# Para seguir enmascarando «secretos conocidos» en otros textos (digest, informe, veredictos) sin guardar el valor,
# gitleaks_redactar.py deja en cada hallazgo una huella no reversible:
#   {"v": 1, "longitud": n, "mascara": enmascarar_valor(s), "sal": hex, "scrypt": hex}
# La máscara solo expone lo que el informe ya muestra (prefijo + últimos 4). Para buscar el secreto en un texto se
# prueban únicamente las ventanas de igual longitud que empiezan con el prefijo y terminan con el sufijo de la
# máscara, y se confirman con scrypt (lento a propósito: dificulta la fuerza bruta de secretos cortos).
# Secretos de <= 8 caracteres no tienen huella: su máscara no deja prefijo y la búsqueda sería por fuerza bruta.
_SCRYPT = {"n": 2 ** 12, "r": 8, "p": 1, "dklen": 32}


def _scrypt(valor, sal):
    return hashlib.scrypt(valor.encode("utf-8"), salt=sal, **_SCRYPT).hex()


def huella_secreto(secreto):
    """Huella no reversible de `secreto` (dict JSON) o None si es demasiado corto para buscarlo."""
    s = str(secreto or "")
    if len(s) <= 8:
        return None
    sal = _secrets.token_bytes(16)
    return {"v": 1, "longitud": len(s), "mascara": enmascarar_valor(s), "sal": sal.hex(), "scrypt": _scrypt(s, sal)}


class Huella:
    """Secreto conocido solo por su huella; enmascarar_texto() lo acepta junto a los valores en claro."""
    __slots__ = ("longitud", "mascara", "prefijo", "sufijo", "sal", "hash", "_cache")

    @classmethod
    def desde(cls, d):
        try:
            if not isinstance(d, dict) or d.get("v") != 1:
                return None
            n, mascara = int(d["longitud"]), str(d["mascara"])
            pre, _, suf = mascara.partition(MASCARA)
            sal, h = bytes.fromhex(d["sal"]), str(d["scrypt"])
            if n <= 8 or not pre or MASCARA not in mascara or len(pre) + len(suf) >= n or len(h) != 64:
                return None
        except (KeyError, TypeError, ValueError):
            return None
        o = cls()
        o.longitud, o.mascara, o.prefijo, o.sufijo, o.sal, o.hash, o._cache = n, mascara, pre, suf, sal, h, {}
        return o

    def _es(self, candidato):
        if candidato not in self._cache:
            self._cache[candidato] = _scrypt(candidato, self.sal) == self.hash
        return self._cache[candidato]

    def reemplazar(self, texto):
        if self.prefijo not in texto:
            return texto
        partes, i, ultimo = [], texto.find(self.prefijo), 0
        while i != -1:
            cand = texto[i:i + self.longitud]
            if len(cand) == self.longitud and cand.endswith(self.sufijo) and MASCARA not in cand and self._es(cand):
                partes.append(texto[ultimo:i])
                partes.append(self.mascara)
                ultimo = i + self.longitud
                i = texto.find(self.prefijo, ultimo)
            else:
                i = texto.find(self.prefijo, i + 1)
        partes.append(texto[ultimo:])
        return "".join(partes)


def _sub_asignacion(m):
    val = m.group("val")
    if _IDENTIFICADOR.match(val) or val.lower() in _NO_VALORES or val.startswith(("process.", "import.", "os.")):
        return m.group(0)
    if not re.search(r"\d", val) and len(val) < 20:
        return m.group(0)  # palabras comunes (p. ej. "password: requerido")
    return m.group("pre") + enmascarar_valor(val)


def _sub_pii(m):
    pre = m.group("pre")
    if m.group("v1") is not None:
        v, q = m.group("v1"), '"'
    elif m.group("v2") is not None:
        v, q = m.group("v2"), "'"
    else:
        v, q = m.group("v3"), ""
    if not v or v == MASCARA or _IDENTIFICADOR.match(v) or v.lower() in _NO_VALORES:
        return m.group(0)
    return f"{pre}{q}{MASCARA}{q}"


def enmascarar_texto(texto, secretos=()):
    """Enmascara secretos y PII en `texto`. `secretos`: valores exactos conocidos (p. ej. de gitleaks)."""
    if texto is None:
        return None
    t = str(texto)
    if not t:
        return t
    t = _PEM.sub("-----BEGIN PRIVATE KEY-----" + MASCARA, t)
    huellas = [x for x in secretos if isinstance(x, Huella)]
    claros = {str(x) for x in secretos if x and not isinstance(x, Huella) and len(str(x)) >= 6}
    # del más largo al más corto, mezclando valores en claro y huellas
    for s in sorted(list(claros) + huellas, key=lambda x: x.longitud if isinstance(x, Huella) else len(x), reverse=True):
        if isinstance(s, Huella):
            t = s.reemplazar(t)
            continue
        if "PRIVATE KEY" in s:
            continue  # ya tratado por _PEM
        t = t.replace(s, enmascarar_valor(s))
    t = _URL_CLAVE.sub(lambda m: m.group("pre") + enmascarar_valor(m.group("val")) + m.group("post")
                       if m.group("val") != MASCARA and MASCARA not in m.group("val") else m.group(0), t)
    for patron in _PATRONES:
        t = patron.sub(lambda m: enmascarar_valor(m.group(0)), t)
    t = _ASIGNACION.sub(_sub_asignacion, t)
    t = _PII_KV.sub(_sub_pii, t)
    t = _EMAIL.sub(MASCARA + "@" + MASCARA, t)
    t = _RUT.sub("**.***.***-*", t)
    return t


def enmascarar_obj(obj, secretos=()):
    """Enmascara recursivamente todos los textos de una estructura JSON (sin romper el escapado)."""
    if isinstance(obj, str):
        return enmascarar_texto(obj, secretos)
    if isinstance(obj, list):
        return [enmascarar_obj(x, secretos) for x in obj]
    if isinstance(obj, dict):
        return {k: enmascarar_obj(v, secretos) for k, v in obj.items()}
    return obj


def recortar(texto, maximo=300):
    """Recorta a `maximo` caracteres con '…' final (después de enmascarar)."""
    if texto is None:
        return None
    t = str(texto)
    return t if len(t) <= maximo else t[:maximo - 1] + "…"


def secreto_redactado(valor):
    """True si el campo Secret ya no trae el valor en claro (redactado por gitleaks o enmascarado)."""
    v = str(valor or "")
    return not v or "REDACTED" in v or MASCARA in v


def secretos_de_hallazgos(datos):
    """Secretos conocidos de una lista de hallazgos de gitleaks: el valor si viene en claro (reportes antiguos o
    un binario que ignoró --redact) o, si está redactado, su Huella (AuditorHuella) cuando se pudo recuperar."""
    salida = []
    for d in datos if isinstance(datos, list) else []:
        if not isinstance(d, dict):
            continue
        sec = d.get("Secret")
        if sec and not secreto_redactado(sec):
            salida.append(sec)
            continue
        h = Huella.desde(d.get("AuditorHuella"))
        if h is not None:
            salida.append(h)
    return salida


def secretos_de_gitleaks(ruta):
    """Secretos conocidos de un reporte JSON de gitleaks (vacía si no se puede leer); ver secretos_de_hallazgos."""
    try:
        with open(ruta, encoding="utf-8") as f:
            datos = json.load(f)
    except (OSError, ValueError):
        return []
    return secretos_de_hallazgos(datos)


def secretos_de_corrida(corrida):
    """Secretos conocidos de una corrida: Secret de todo crudo/gitleaks*.json."""
    from pathlib import Path
    crudo = Path(corrida) / "crudo"
    secretos = []
    if crudo.is_dir():
        for ruta in sorted(crudo.glob("gitleaks*.json")):
            if not ruta.name.endswith(".meta.json"):
                secretos += secretos_de_gitleaks(ruta)
    return secretos


def main(argv=None):
    ap = argparse.ArgumentParser(description="Enmascara secretos y PII de la entrada estándar.")
    ap.add_argument("--secretos-de", action="append", default=[], help="reporte JSON de gitleaks")
    a = ap.parse_args(argv)
    secretos = []
    for r in a.secretos_de:
        secretos += secretos_de_gitleaks(r)
    sys.stdout.write(enmascarar_texto(sys.stdin.read(), secretos))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""gitleaks_redactar.py — post-proceso del reporte JSON de gitleaks antes de dejarlo en crudo/ (O3, privacidad).

gitleaks.sh corre gitleaks con --redact=100 (Secret = "REDACTED" y el valor sustituido por "REDACTED" en Match).
Como defensa adicional (un binario que ignore --redact, una versión que no redacte algún campo), este script
reescribe cada hallazgo de modo que ningún campo conserve el secreto en claro:

  Secret            → enmascarar_valor(secreto) (prefijo + **** + últimos 4, lo mismo que muestra el informe),
                      o "REDACTED" si no se pudo recuperar el valor
  Match, Line       → enmascarar_texto(..., [secreto])
  AuditorHuella     → huella no reversible (enmascarar.huella_secreto: máscara + longitud + scrypt con sal) para que
                      digest/informe/veredictos sigan enmascarando ese secreto en otros textos
  AuditorProveedor  → bool: el secreto tiene prefijo de proveedor reconocido (normalizar/gitleaks.py, AUD-SEC)

Recuperación del valor cuando gitleaks ya lo redactó: se lee el archivo como BYTES (working tree, o
`git show COMMIT:File` para hallazgos del historial) en StartLine..EndLine y se toma la ventana de la coincidencia por
columnas. Medido en gitleaks 8.30.1: las columnas cuentan BYTES UTF-8 (no caracteres), 1-based inclusivas, y en líneas
> 1 vienen corridas en +1 porque cuentan el salto de línea. La ventana se toma exactamente en esas columnas, sin
tolerancia: un desplazamiento haría aceptar otro valor cuando el Match no tiene contexto fijo (p. ej. Match =
"REDACTED"). El valor solo se acepta si la ventana es UTF-8 válido y coincide exactamente con el Match redactado (las
partes fuera de "REDACTED" son idénticas y todas las apariciones del secreto son iguales). Cuando el Match no tiene
contexto fijo con letras o dígitos (p. ej. "REDACTED", 'REDACTED"', "REDACTED "), la coincidencia sola no prueba nada,
así que además se exige que el valor quede en límites de palabra ASCII (como el \\b de las reglas de gitleaks): si el
carácter de un extremo es [A-Za-z0-9_], el de afuera no puede serlo. Una ventana corrida cae dentro de un token y se
rechaza. Si no, el hallazgo queda con
"REDACTED" y sin huella ni bandera (normalizar no baja la confianza ni usa la línea del archivo: fail-closed).

Ronda 6 (grupo secretos), dos marcas más, calculadas aquí porque es el único punto donde aún se tiene el valor:
  AuditorJwtRol   solo si el valor tiene forma de JWT (o la regla es "jwt" y no se pudo recuperar): "anon",
                  "service_role", "otro" (otro rol o sin role) o "ilegible" (payload que no es base64url/JSON, o
                  valor no recuperado y sin rol común en el archivo). Se decodifica el payload sin verificar la
                  firma y sin imprimir nada. Si el valor no se pudo recuperar (regla jwt), se usa el rol común de
                  todos los JWT candidatos del archivo (rol_jwt_por_archivo), solo si es único. Una clave
                  anon de Supabase es pública por diseño (va en el cliente); normalizar/gitleaks.py la informa con
                  confianza baja y sin pedir rotación. service_role, otro e ilegible siguen como siempre (fail-closed).
  AuditorGit      (solo con --estado-git, hallazgos sin Commit) estado del archivo en git, con git_seguro:
                  "versionado" (git ls-files), "no_versionado" (sin seguimiento y NO ignorado: se subiría con
                  git add .), "ignorado" (ignorado por git y sin ningún commit que lo toque: git log --all),
                  "ignorado_con_historial" (ignorado hoy, pero estuvo en algún commit), "sin_git" (el proyecto no está
                  en un repo) o "desconocido" (git falló: cuenta como repo). Solo "ignorado" baja de prioridad.

Al final se verifica que ningún valor recuperado siga en Secret/Match/Line; si queda alguno, o si la entrada no es una lista
de objetos, sale con código 1 SIN reescribir y gitleaks.sh borra el crudo (fail-closed).

Uso: gitleaks_redactar.py REPORTE --base DIR [--git-raiz DIR] [--estado-git]
  --base        carpeta a la que son relativas las rutas File de los modos dir/bundle (el proyecto)
  --git-raiz    raíz del repositorio para los hallazgos con Commit (modo git)
  --estado-git  marca AuditorGit en los hallazgos sin Commit (modo dir)
Solo biblioteca estándar. git se invoca con el entorno endurecido que exporta _comun.sh.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SCRIPTS))

import enmascarar  # noqa: E402
import git_seguro  # noqa: E402
from normalizar import gitleaks as n_gitleaks  # noqa: E402

TOKEN = "REDACTED"
MAX_BYTES = 50_000_000


def _bytes_archivo(base, archivo):
    if not archivo or not isinstance(archivo, str) or archivo.startswith("/") or ".." in Path(archivo).parts:
        return None
    ruta = Path(base) / archivo
    try:
        if not ruta.is_file() or ruta.stat().st_size > MAX_BYTES:
            return None
        return ruta.read_bytes()
    except OSError:
        return None


def _bytes_commit(raiz, commit, archivo, cache):
    if not raiz or not commit or not archivo or not all(c in "0123456789abcdef" for c in commit.lower()):
        return None
    clave = (commit, archivo)
    if clave not in cache:
        try:
            r = subprocess.run(["git", "-C", raiz, "--no-optional-locks", "show", "--no-textconv",
                                f"{commit}:{archivo}"], capture_output=True, timeout=60, env=os.environ)
            cache[clave] = r.stdout[:MAX_BYTES] if r.returncode == 0 else None
        except (OSError, subprocess.SubprocessError):
            cache[clave] = None
    return cache[clave]


def _offset(lineas, num_linea, columna):
    """Offset 0-based en BYTES del contenido unido por b'\\n' de la columna gitleaks (1-based, en bytes; +1 en líneas > 1)."""
    if not isinstance(num_linea, int) or not isinstance(columna, int) or num_linea < 1 or num_linea > len(lineas):
        return None
    base = sum(len(x) + 1 for x in lineas[:num_linea - 1])
    return base + columna - 1 - (1 if num_linea > 1 else 0)


def _secreto_de_ventana(ventana, partes):
    """Si `ventana` = partes[0] + S + partes[1] + S + ... + partes[k], devuelve S; si no, None."""
    k = len(partes) - 1
    fijo = sum(len(p) for p in partes)
    if k < 1 or (len(ventana) - fijo) <= 0 or (len(ventana) - fijo) % k:
        return None
    n = (len(ventana) - fijo) // k
    s = ventana[len(partes[0]):len(partes[0]) + n]
    return s if s and TOKEN not in s and s.join(partes) == ventana else None


_PALABRA = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


def _en_limites_de_palabra(datos, ini, fin):
    """True si datos[ini:fin] no está pegado a otro carácter de palabra ASCII en ninguno de sus extremos."""
    if fin <= ini:
        return False
    if datos[ini] in _PALABRA and ini > 0 and datos[ini - 1] in _PALABRA:
        return False
    if datos[fin - 1] in _PALABRA and fin < len(datos) and datos[fin] in _PALABRA:
        return False
    return True


def recuperar(d, base, git_raiz, cache):
    """Valor en claro del secreto de un hallazgo redactado, o None si no se puede asegurar."""
    match = d.get("Match")
    if not isinstance(match, str) or TOKEN not in match:
        return None
    if d.get("Commit"):
        datos = _bytes_commit(git_raiz, str(d["Commit"]), d.get("File"), cache)
    else:
        datos = _bytes_archivo(base, d.get("File"))
    if datos is None:
        return None
    s = _recuperar_por_columnas(d, datos, match)
    return s if s is not None else _recuperar_por_contexto(datos, match.split(TOKEN))


MAX_VALOR_CONTEXTO = 1024


def _recuperar_por_contexto(datos, partes):
    """Ronda 6: respaldo cuando las columnas no sirven (gitleaks lee archivos grandes por bloques y, en un .map de
    varios MB en una sola línea, las columnas son del bloque, no del archivo). Solo con contexto fuerte a ambos lados
    (Match = A + REDACTED + B, A con letras o dígitos ASCII y B no vacío) y solo si TODAS las apariciones de A…B en el
    archivo encierran el mismo valor: como el Match salió de ese archivo, el secreto es una de ellas, así que un valor
    único es el secreto. Varias candidatas distintas, ninguna, o un valor con espacios o saltos → None (fail-closed)."""
    if len(partes) != 2 or not partes[0] or not partes[1] or not any(c.isascii() and c.isalnum() for c in partes[0]):
        return None
    a, b = partes[0].encode("utf-8"), partes[1].encode("utf-8")
    valores, i = set(), datos.find(a)
    while i >= 0:
        ini = i + len(a)
        fin = datos.find(b, ini, ini + MAX_VALOR_CONTEXTO + len(b))
        if fin < 0:
            return None  # una aparición sin cierre cercano: no se puede descartar que sea el secreto
        try:
            v = datos[ini:fin].decode("utf-8")
        except UnicodeDecodeError:
            return None
        if not v or TOKEN in v or any(c.isspace() for c in v):
            return None
        valores.add(v)
        if len(valores) > 1:
            return None
        i = datos.find(a, i + 1)
    return valores.pop() if len(valores) == 1 else None


def _recuperar_por_columnas(d, datos, match):
    lineas = datos.split(b"\n")
    ini = _offset(lineas, d.get("StartLine"), d.get("StartColumn"))
    ultima = d.get("EndLine") if isinstance(d.get("EndLine"), int) and d.get("EndLine") >= 1 else d.get("StartLine")
    fin = _offset(lineas, ultima, d.get("EndColumn"))
    if ini is None or fin is None:
        return None
    a, b = ini, fin + 1
    if a < 0 or b > len(datos) or b <= a:
        return None
    try:
        ventana = datos[a:b].decode("utf-8")  # estricto: una ventana que corta un carácter multibyte no sirve
    except UnicodeDecodeError:
        return None
    partes = match.split(TOKEN)
    s = _secreto_de_ventana(ventana, partes)
    if s is None:
        return None
    if not any(c.isascii() and c.isalnum() for c in "".join(partes)):
        # contexto débil: exigir límites de palabra en la primera aparición del valor dentro de la ventana
        i = a + len(partes[0].encode("utf-8"))
        if not _en_limites_de_palabra(datos, i, i + len(s.encode("utf-8"))):
            return None
    return s


# Ronda 6: el rol se decodifica con la misma función que usa normalizar (un solo criterio).
rol_jwt = n_gitleaks.rol_jwt

# Candidatos a JWT en un archivo: TODO lo que la regla "jwt" de gitleaks podría capturar (cabecera ey + 17 o más,
# punto, payload ey + 17 o más con las mismas clases de caracteres que la regla o más amplias). La búsqueda es
# solapada (lookahead) para que ningún inicio posible quede tapado por un candidato anterior.
_RE_CANDIDATO_JWT = re.compile(rb"(?=(ey[A-Za-z0-9_\-]{17,})\.(ey[A-Za-z0-9_\-/\\]{17,})\.)")


def rol_jwt_por_archivo(datos):
    """Rol común de TODOS los JWT candidatos del contenido, o None si no hay candidatos o no todos dicen lo mismo.

    Sirve cuando gitleaks redactó el valor y las columnas no permiten recuperarlo (p. ej. un .map de varios MB en una
    sola línea: gitleaks lee por bloques y las columnas no son las del archivo). Si todos los candidatos son anon, el
    hallazgo de la regla jwt es necesariamente anon; si hay uno solo distinto o ilegible, no se presume nada."""
    roles = set()
    for m in _RE_CANDIDATO_JWT.finditer(datos):
        try:
            cand = (m.group(1) + b"." + m.group(2) + b".x").decode("ascii")
        except UnicodeDecodeError:
            return None
        roles.add(rol_jwt(cand) or "ilegible")
        if len(roles) > 1:
            return None
    return roles.pop() if len(roles) == 1 else None


class EstadoGit:
    """Estado en git de los archivos del working tree (relativos a `base`). Solo comandos que no comparan
    contenido (rev-parse, ls-files, check-ignore, log) con la configuración segura de git_seguro."""

    def __init__(self, base):
        self.base = str(base)
        self.cache = {}
        rc, out = git_seguro.ejecutar(self.base, "rev-parse", "--is-inside-work-tree")
        if rc is None:
            self.repo = None          # git no se pudo ejecutar: todo "desconocido" (cuenta como repo)
        else:
            self.repo = rc == 0 and (out or "").strip() == "true"

    def de(self, archivo):
        if self.repo is False:
            return "sin_git"
        if (self.repo is None or not isinstance(archivo, str) or not archivo or archivo.startswith("/")
                or ".." in Path(archivo).parts):
            return "desconocido"
        rel = archivo[2:] if archivo.startswith("./") else archivo
        if rel not in self.cache:
            self.cache[rel] = self._calcular(rel)
        return self.cache[rel]

    def _calcular(self, rel):
        rc, _ = git_seguro.ejecutar(self.base, "ls-files", "--error-unmatch", "--", f":(literal){rel}")
        if rc == 0:
            return "versionado"
        if rc != 1:
            return "desconocido"
        rc, _ = git_seguro.ejecutar(self.base, "check-ignore", "-q", "--", rel)
        if rc == 1:
            return "no_versionado"
        if rc != 0:
            return "desconocido"
        rc, out = git_seguro.ejecutar(self.base, "log", "--all", "--format=%H", "-n", "1", "--", f":(literal){rel}",
                                      timeout=60)
        if rc != 0 or out is None:
            return "desconocido"
        return "ignorado_con_historial" if out.strip() else "ignorado"


def procesar(datos, base, git_raiz, estado_git=False):
    if not isinstance(datos, list) or not all(isinstance(d, dict) for d in datos):
        raise ValueError("se esperaba una lista de objetos (formato de gitleaks)")
    cache = {}
    git = EstadoGit(base) if estado_git else None
    for d in datos:
        for campo in ("AuditorHuella", "AuditorProveedor", "AuditorJwtRol", "AuditorGit"):
            d.pop(campo, None)  # solo este script los escribe
        sec = d.get("Secret")
        valor = sec if isinstance(sec, str) and sec and not enmascarar.secreto_redactado(sec) else None
        if valor is None:
            valor = recuperar(d, base, git_raiz, cache)
        rol = rol_jwt(valor) if valor else None
        if rol is None and not valor and str(d.get("RuleID") or "").lower() == "jwt":
            # La regla es de JWT pero el valor no se pudo recuperar: solo se acepta un rol si TODOS los JWT
            # candidatos del archivo tienen ese rol; si no, "ilegible" (no se presume anon).
            contenido = (_bytes_commit(git_raiz, str(d["Commit"]), d.get("File"), cache) if d.get("Commit")
                         else _bytes_archivo(base, d.get("File")))
            rol = (rol_jwt_por_archivo(contenido) if contenido is not None else None) or "ilegible"
        if rol is not None:
            d["AuditorJwtRol"] = rol
        if git is not None and not d.get("Commit"):
            d["AuditorGit"] = git.de(d.get("File"))
        conocidos = [valor] if valor else []
        if valor:
            d["Secret"] = enmascarar.enmascarar_valor(valor)
            d["AuditorProveedor"] = n_gitleaks.con_prefijo_de_proveedor(valor)
            h = enmascarar.huella_secreto(valor)
            if h is not None:
                d["AuditorHuella"] = h
        elif "Secret" in d:
            d["Secret"] = TOKEN
        for campo in ("Match", "Line"):
            if isinstance(d.get(campo), str):
                if valor and TOKEN in d[campo]:
                    # misma evidencia (y fingerprint) que sin --redact: el valor enmascarado en vez de "REDACTED"
                    d[campo] = valor.join(d[campo].split(TOKEN))
                d[campo] = enmascarar.enmascarar_texto(d[campo], conocidos)
                if valor:
                    d[campo] = d[campo].replace(valor, enmascarar.enmascarar_valor(valor))
        if valor and any(valor in str(d.get(c) or "") for c in ("Secret", "Match", "Line")):
            raise ValueError("quedó un secreto sin enmascarar en el reporte")
    return json.dumps(datos, ensure_ascii=False, indent=1)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Enmascara Secret/Match/Line de un reporte JSON de gitleaks.")
    ap.add_argument("reporte")
    ap.add_argument("--base", required=True)
    ap.add_argument("--git-raiz")
    ap.add_argument("--estado-git", action="store_true")
    a = ap.parse_args(argv)
    ruta = Path(a.reporte)
    try:
        with open(ruta, encoding="utf-8") as f:
            datos = json.load(f)
        if datos is None:
            datos = []
        texto = procesar(datos, a.base, a.git_raiz, estado_git=a.estado_git)
    except (OSError, ValueError) as exc:
        print(f"gitleaks_redactar: no se pudo enmascarar {ruta.name}: {exc}", file=sys.stderr)
        return 1
    tmp = ruta.with_name(ruta.name + ".redactando")
    tmp.write_text(texto, encoding="utf-8")
    os.replace(tmp, ruta)
    return 0


if __name__ == "__main__":
    sys.exit(main())

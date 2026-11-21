#!/usr/bin/env python3
"""Materializa la app sembrada (brazo A) y su crudo de ejemplo desde plantillas inertes.

Por qué existe
--------------
La app sembrada trae, a propósito, secretos con forma real (canarios FALSOS), un `.env`, un
`.claude/settings.json` y un `.mcp.json` peligrosos y workflows de CI vulnerables. Versionados tal
cual, la protección de push de GitHub bloquearía el push, Dependabot/CodeQL abrirían alertas sobre
defectos plantados y quien clonara el repo tendría configuración de agente activa en disco. Por eso
en git solo viajan PLANTILLAS:

  validacion/plantilla-app-sembrada/           → validacion/app-sembrada/            (ignorada)
  tests/fixtures/crudo/plantilla-app_sembrada/ → tests/fixtures/crudo/app_sembrada/ (ignorada)

Reglas de la plantilla (inversas exactas al materializar):
  - cada componente de ruta que empieza con «.» se guarda con el prefijo «PUNTO»
    (`.env` → `PUNTO.env`, `.claude/` → `PUNTO.claude/`, `.github/` → `PUNTO.github/`);
  - cada archivo lleva el sufijo «.plantilla» (`package.json` → `package.json.plantilla`), para que
    ninguna herramienta (GitHub Actions, Dependabot, CodeQL, Claude Code, npm) lo reconozca;
  - cada canario se reemplaza por el marcador @@CANARIO:Cnn@@; su valor se arma aquí en tiempo de
    ejecución desde `_TABLA` (bytes invertidos y en hexadecimal: en git no tiene forma de secreto).
La materialización es byte a byte idéntica a la app original: misma verdad de terreno (archivo:línea)
y mismos números de detección (ver validacion/README.md).

Uso
---
  python3 -I validacion/sembrado.py                    materializa ambas en sus rutas por defecto
  python3 -I validacion/sembrado.py --verificar        exit 1 si lo materializado difiere de la plantilla
  python3 -I validacion/sembrado.py --destino DIR      solo la app sembrada, en DIR (vacío o inexistente)
  python3 -I validacion/sembrado.py --destino DIR --git   ídem + `git init` sin commits: reproduce las
                                                       condiciones de las corridas de referencia (métricas)
  python3 -I validacion/sembrado.py --listar           ids de canarios, tipo y largo (nunca valores)
  python3 -I validacion/sembrado.py --plantillar       (mantenimiento) app materializada → plantilla

Los tests llaman a `asegurar()` al importarse (tests/apoyo_corrida.py, tests/test_verdad_terreno.py).
Solo biblioteca estándar.
"""
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent

CONJUNTOS = {
    "app": (RAIZ / "validacion" / "plantilla-app-sembrada", RAIZ / "validacion" / "app-sembrada"),
    "crudo": (RAIZ / "tests" / "fixtures" / "crudo" / "plantilla-app_sembrada",
              RAIZ / "tests" / "fixtures" / "crudo" / "app_sembrada"),
}
# Dentro de un destino por defecto, lo que no viene de la plantilla y se conserva al sincronizar
# (salidas de `bin/auditar` sobre la app).
CONSERVAR = (".auditoria",)

PREFIJO_PUNTO = "PUNTO"
SUFIJO = ".plantilla"
MARCADOR = re.compile(rb"@@CANARIO:(C\d{2})@@")

# Formas de secreto que NO pueden quedar en una plantilla (control de --plantillar y de los tests).
# Son prefijos de proveedor + largo: el patrón no tiene, él mismo, forma de secreto.
FORMAS = {
    "aws": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "github": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})",
    "stripe": r"\b[srp]k_(?:live|test)_[0-9A-Za-z]{16,}",
    "openai/anthropic": r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}",
    "slack": r"\bxox[abposr]-[0-9A-Za-z-]{10,}",
    "google": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "sendgrid": r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}",
    "jwt": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "llave privada": r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{20,}",
    "supabase": r"\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{16,}",
}
# Nombres que una herramienta cargaría si aparecieran tal cual en el árbol versionado.
NOMBRES_ACTIVOS = {".env", ".mcp.json", ".claude", ".github", ".gitlab-ci.yml", ".cursor", ".vscode"}

# Canarios FALSOS de la app sembrada (no son credenciales de nadie).
# (id, descripción sin valor, valor = bytes invertidos en hexadecimal)
_TABLA = (
    ("C01", "JWT de Supabase (role service_role) (219 car.)",
     "73754f706e395734626d365f304c386b4e34667a52476f725870766a4a504335697353614854454773376d2e51667741"
     "6a4d3163444e7955444d796f6a497768585a6977434d7749544f35676a4e7a63544d36494364686c6d497349535a7339"
     "6d6366563259705a6e636c4e6e493649535a73396d63697769497146486131784762764e335935564864696847656b64"
     "476132526e493649695a6c4a6e497349535a7a466d59684258647a4a694f694d3363704a79652e394a435658706b4936"
     "49436335526e497349694e31497a55494a694f69634762684a7965"),
    ("C02", "API key de SendGrid (69 car.)",
     "44314773623274536469347a3454335038673343365579753033384a6e65786354434c354d2d37525a744f2e5f737649"
     "5544495f4e38656459504c535573415164562e4753"),
    ("C03", "API key de OpenAI (51 car.)",
     "6f515055505a3348496c6e366f62344d7a34546a4a466b626c4233544870454172354b706d4344426b456c6d516c7855"
     "2d6b73"),
    ("C04", "clave secreta live de Stripe (42 car.)",
     "71585a4c567638445537673733777a49444c6a793167794436686e7756465a396a4e5f6576696c5f6b73"),
    ("C05", "clave secreta live de Stripe (42 car.)",
     "4e7277596e504145534a6149415031593574594b734757594d434f474d7162695a6f5f6576696c5f6b73"),
    ("C06", "clave secreta live de Stripe (42 car.)",
     "64704e38616e414a7575415a76693865357158373458557778785a78704a3673486f5f6576696c5f6b73"),
    ("C07", "clave publicable de Stripe (42 car.)",
     "454f41594774423365574158476a676442364258524d526b42787471426577334e6c5f6576696c5f6b70"),
    ("C08", "clave secreta de acceso AWS (genérica) (40 car.)",
     "596f38707a457344795276794f6b7068477272523369763531522f686e335252494b657748724836"),
    ("C09", "token clásico de GitHub (40 car.)",
     "41374f6352374d4e6a38616e64424a316436617353336c7453654450424d77487347334a5f706867"),
    ("C10", "clave publicable (anon) de Supabase (37 car.)",
     "6752494e324154536357424a623167614f6d6e36666f5f656c62616873696c6275705f6273"),
    ("C11", "ID de clave de acceso AWS (20 car.)",
     "4d4e414c53324f4c413550374753374441494b41"),
    ("C12", "API key de Context7 (.mcp.json) (19 car.)",
     "7d59454b5f4950415f37545845544e4f437b24"),
)


def _valor(hex_invertido):
    return bytes.fromhex(hex_invertido)[::-1]


def canarios():
    """{id: bytes} — valores armados en tiempo de ejecución."""
    return {i: _valor(h) for i, _, h in _TABLA}


def formas_en(texto):
    """Lista de nombres de FORMAS presentes en `texto` (str)."""
    return [n for n, r in FORMAS.items() if re.search(r, texto)]


# ------------------------------------------------------------------------------------------- rutas
def a_destino(rel):
    """Ruta relativa de plantilla → ruta relativa materializada."""
    partes = list(Path(rel).parts)
    if not partes[-1].endswith(SUFIJO):
        raise ValueError(f"archivo de plantilla sin sufijo {SUFIJO}: {rel}")
    partes[-1] = partes[-1][: -len(SUFIJO)]
    partes = ["." + p[len(PREFIJO_PUNTO) + 1:] if p.startswith(PREFIJO_PUNTO + ".") else p for p in partes]
    return Path(*partes)


def a_plantilla(rel):
    """Ruta relativa materializada → ruta relativa de plantilla."""
    partes = [PREFIJO_PUNTO + p if p.startswith(".") else p for p in Path(rel).parts]
    partes[-1] += SUFIJO
    return Path(*partes)


def _archivos(base):
    return sorted(p for p in Path(base).rglob("*") if p.is_file() and not p.is_symlink())


# ---------------------------------------------------------------------------------- materializar
def contenido(plantilla_archivo, tabla=None):
    tabla = canarios() if tabla is None else tabla
    datos = Path(plantilla_archivo).read_bytes()

    def sub(m):
        cid = m.group(1).decode()
        if cid not in tabla:
            raise KeyError(f"{plantilla_archivo}: marcador de canario desconocido {cid}")
        return tabla[cid]

    return MARCADOR.sub(sub, datos)


def esperado(plantilla):
    """{ruta relativa materializada: bytes} para una carpeta de plantilla."""
    tabla = canarios()
    plantilla = Path(plantilla)
    return {a_destino(p.relative_to(plantilla)): contenido(p, tabla) for p in _archivos(plantilla)}


def _conservado(rel):
    return Path(rel).parts[0] in CONSERVAR


def diferencias(plantilla, destino):
    """Lista de rutas relativas que faltan, sobran o difieren (vacía = idéntico)."""
    destino = Path(destino)
    esp = esperado(plantilla)
    difs = []
    for rel, datos in esp.items():
        p = destino / rel
        if not p.is_file() or p.read_bytes() != datos:
            difs.append(str(rel))
    if destino.is_dir():
        for p in _archivos(destino):
            rel = p.relative_to(destino)
            if rel not in esp and not _conservado(rel):
                difs.append(f"{rel} (sobra)")
    return sorted(difs)


def materializar(plantilla, destino, sincronizar=False):
    """Escribe la plantilla en `destino`. Devuelve cuántos archivos escribió.

    sincronizar=False (destino elegido por el usuario): `destino` debe no existir o estar vacío.
    sincronizar=True (destinos por defecto, ignorados por git): reescribe solo lo que difiere y
    borra lo que sobra, salvo CONSERVAR.
    """
    destino = Path(destino)
    if not sincronizar and destino.exists() and any(destino.iterdir()):
        raise FileExistsError(f"el destino no está vacío: {destino}")
    esp = esperado(plantilla)
    escritos = 0
    for rel, datos in esp.items():
        p = destino / rel
        if p.is_file() and not p.is_symlink() and p.read_bytes() == datos:
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.is_symlink() or p.exists():
            p.unlink()
        tmp = p.with_name(p.name + ".tmp-sembrado")
        tmp.write_bytes(datos)
        tmp.chmod(0o644)
        tmp.replace(p)
        escritos += 1
    if sincronizar:
        for p in _archivos(destino):
            rel = p.relative_to(destino)
            if rel not in esp and not _conservado(rel):
                p.unlink()
        for d in sorted((d for d in destino.rglob("*") if d.is_dir()), key=lambda d: -len(d.parts)):
            rel = d.relative_to(destino)
            if not _conservado(rel) and not any(d.iterdir()):
                d.rmdir()
    return escritos


def asegurar():
    """Materializa (o resincroniza) los conjuntos en sus rutas por defecto. Idempotente."""
    for plantilla, destino in CONJUNTOS.values():
        materializar(plantilla, destino, sincronizar=True)


# ------------------------------------------------------------------------------------ plantillar
def plantillar(origen, plantilla):
    """(mantenimiento) Convierte una app materializada/editada en plantilla.

    Reemplaza cada canario conocido por su marcador y renombra rutas. Falla (sin escribir nada) si
    queda alguna forma de secreto: un canario nuevo debe agregarse antes a _TABLA.
    """
    origen, plantilla = Path(origen), Path(plantilla)
    tabla = sorted(canarios().items(), key=lambda kv: -len(kv[1]))
    salida, problemas = {}, []
    for p in _archivos(origen):
        rel = p.relative_to(origen)
        if _conservado(rel):
            continue
        datos = p.read_bytes()
        for cid, valor in tabla:
            datos = datos.replace(valor, b"@@CANARIO:" + cid.encode() + b"@@")
        formas = formas_en(datos.decode("utf-8", errors="ignore"))
        if formas:
            problemas.append(f"{rel}: {', '.join(formas)}")
        salida[a_plantilla(rel)] = datos
    if problemas:
        raise ValueError("quedan formas de secreto sin canario en _TABLA:\n  " + "\n  ".join(problemas))
    if plantilla.exists():
        shutil.rmtree(plantilla)
    for rel, datos in salida.items():
        (plantilla / rel).parent.mkdir(parents=True, exist_ok=True)
        (plantilla / rel).write_bytes(datos)
    return len(salida)


# ------------------------------------------------------------------------------------------- CLI
def main(argv=None):
    ap = argparse.ArgumentParser(description="Materializa la app sembrada y su crudo desde plantillas.")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--verificar", action="store_true", help="compara sin escribir; exit 1 si difiere")
    g.add_argument("--destino", help="materializa solo la app en esta carpeta (vacía o inexistente)")
    ap.add_argument("--git", action="store_true",
                    help="con --destino: `git init` sin commits en el destino (condiciones de las corridas de "
                         "referencia; ver validacion/README.md)")
    g.add_argument("--listar", action="store_true", help="ids, tipo y largo de los canarios (sin valores)")
    g.add_argument("--plantillar", action="store_true",
                   help="regenera las plantillas desde las carpetas materializadas por defecto")
    a = ap.parse_args(argv)
    if a.listar:
        for cid, desc, h in _TABLA:
            print(f"{cid}  {len(h) // 2:>4} bytes  {desc}")
        return 0
    if a.git and not a.destino:
        ap.error("--git requiere --destino")
    if a.destino:
        n = materializar(CONJUNTOS["app"][0], a.destino)
        if a.git:
            subprocess.run(["git", "-C", str(a.destino), "init", "-q"], check=True, stdin=subprocess.DEVNULL)
        print(f"app sembrada: {n} archivos en {a.destino}{' (git init, sin commits)' if a.git else ''}")
        return 0
    if a.plantillar:
        for nombre, (plantilla, destino) in CONJUNTOS.items():
            print(f"{nombre}: {plantillar(destino, plantilla)} archivos → {plantilla}")
        return 0
    if a.verificar:
        rc = 0
        for nombre, (plantilla, destino) in CONJUNTOS.items():
            if not Path(destino).exists():
                # clon limpio: no es una diferencia, es que falta materializar (rc 1 igual: no está verificado)
                print(f"{nombre}: no materializada; corra: python3 -I validacion/sembrado.py")
                rc = 1
                continue
            difs = diferencias(plantilla, destino)
            print(f"{nombre}: {'idéntico' if not difs else str(len(difs)) + ' diferencias'}")
            for d in difs:
                print(f"  {d}")
            rc |= bool(difs)
        return rc
    for nombre, (plantilla, destino) in CONJUNTOS.items():
        n = materializar(plantilla, destino, sincronizar=True)
        print(f"{nombre}: {n} archivos escritos en {destino}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

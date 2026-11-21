#!/usr/bin/env python3
"""deps_muertas — fallback de knip/depcheck (DECISIONES #6; investigacion/13 §4.3). Cobertura parcial.

Compara las dependencias declaradas en cada package.json (raíz y subproyectos; nunca node_modules)
con los paquetes importados por el código de su carpeta (import/require/import()/export from y
@import de CSS), los binarios citados en `scripts` y los nombres citados en archivos de configuración.

Subregla           sev    → control
  dep_sin_uso       baja   → COD-CICLOS-MUERTO (en dependencies y nunca usada)
  devdep_sin_uso    info   → COD-CICLOS-MUERTO (en devDependencies y nunca usada)
  dep_no_declarada  media  → COD-CICLOS-MUERTO y SEG-DEPS-EXISTEN (importada y no declarada:
                             dependencia fantasma / posible slopsquatting)
Pase ok_deps (sin hallazgos). No detecta exports/archivos sin uso ni ciclos (knip sí); conoce
~10 convenciones de plugins (knip ~100). Uso: deps_muertas.py PROYECTO DIR_CRUDO
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402

NOMBRE = "deps_muertas"
REEMPLAZA = "knip"
HERRAMIENTAS_REALES = ("knip", "depcheck")
EXT_CODIGO = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
EXT_CSS = {".css", ".scss", ".sass", ".less"}
SECCIONES = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
NUCLEO_NODE = frozenset("""
assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns domain
events fs fs/promises http http2 https inspector module net os path path/posix path/win32 perf_hooks process
punycode querystring readline repl stream stream/promises string_decoder sys test timers timers/promises tls
trace_events tty url util util/types v8 vm wasi worker_threads zlib
""".split())
# binario → paquete (cuando el nombre difiere)
BINARIOS = {"tsc": "typescript", "tsx": "tsx", "vue-tsc": "vue-tsc", "next": "next", "nuxt": "nuxt",
            "playwright": "@playwright/test", "eslint": "eslint", "prettier": "prettier", "jest": "jest",
            "vitest": "vitest", "vite": "vite", "tailwindcss": "tailwindcss", "postcss": "postcss",
            "nodemon": "nodemon", "ts-node": "ts-node", "concurrently": "concurrently", "rimraf": "rimraf",
            "husky": "husky", "lint-staged": "lint-staged", "astro": "astro", "svelte-kit": "@sveltejs/kit",
            "prisma": "prisma", "drizzle-kit": "drizzle-kit", "supabase": "supabase", "biome": "@biomejs/biome",
            "cross-env": "cross-env", "wrangler": "wrangler", "storybook": "storybook", "cypress": "cypress",
            "electron": "electron", "electron-builder": "electron-builder", "react-scripts": "react-scripts",
            "knip": "knip", "jscpd": "jscpd", "stylelint": "stylelint", "lhci": "@lhci/cli"}
RE_IMPORT = re.compile(r"""(?:\bimport\s[^'"`;]*?\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bexport\s[^'"`;]*?\bfrom\s*|"""
                       r"""\bimport\s+|\brequire\.resolve\s*\(\s*)['"]([^'"\n]+)['"]""")
RE_CSS_IMPORT = re.compile(r"""@(?:import|use|forward|plugin)\s+(?:url\()?['"]([^'"]+)['"]""")
RE_CONFIG = re.compile(r"^(vite|vitest|next|nuxt|astro|svelte|eslint|tailwind|postcss|babel|jest|playwright|prettier|"
                       r"stylelint|tsup|rollup|webpack|commitlint|lint-staged|cypress|drizzle|knip)\.config\.|"
                       r"^\.(eslintrc|prettierrc|babelrc|stylelintrc|postcssrc|lintstagedrc)|^tsconfig.*\.json$|"
                       r"^(components|vercel|netlify)\.json$|^\.?commitlintrc", re.I)
PREFIJOS_PLUGIN = ("eslint-plugin-", "eslint-config-", "@typescript-eslint/", "prettier-plugin-", "babel-plugin-",
                   "babel-preset-", "@babel/", "postcss-", "stylelint-config-", "@vitejs/", "vite-plugin-",
                   "@tailwindcss/", "tailwindcss-", "@commitlint/", "@eslint/")


def paquete_de(espec):
    """Nombre del paquete de un especificador, o None si es relativo, alias, núcleo o URL."""
    e = espec.strip()
    if not e or e.startswith((".", "/", "~", "#", "$", "virtual:", "http:", "https:", "data:", "\\")):
        return None
    if e.startswith("node:") or e.startswith("bun:"):
        return None
    if e.startswith("@/") or re.match(r"^@[A-Za-z]*/", e) and e.split("/", 1)[0] in ("@", "@src", "@app", "@lib", "@components"):
        return None
    e = e.split("?", 1)[0]
    partes = e.split("/")
    nombre = "/".join(partes[:2]) if e.startswith("@") else partes[0]
    if not e.startswith("@") and (e in NUCLEO_NODE or nombre in NUCLEO_NODE):
        return None
    if not re.fullmatch(r"(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*", nombre, re.I):
        return None
    return nombre


def _alias_tsconfig(carpeta):
    alias = set()
    for nombre in ("tsconfig.json", "jsconfig.json", "tsconfig.app.json"):
        p = carpeta / nombre
        texto = comun.leer(p) if p.is_file() else None
        if not texto:
            continue
        for m in re.finditer(r'"([^"*]+)/?\*?"\s*:\s*\[', texto):
            clave = m.group(1).rstrip("/*")
            if clave and clave not in ("compilerOptions", "paths"):
                alias.add(clave)
    return alias


def _linea_clave(texto, nombre):
    n = comun.linea_de(texto, re.compile(r'"' + re.escape(nombre) + r'"\s*:'))
    return n


def analizar(proyecto, crudo=None):
    proyecto = Path(proyecto)
    pkgs = [p for p in fb.recorrer(proyecto, nombres={"package.json"})]
    if not pkgs:
        return fb.resultado(REEMPLAZA, estado="no_evaluado", motivo="no hay package.json: el fallback solo analiza "
                            "dependencias JS/TS (código muerto en otros lenguajes requiere knip/vulture)")
    carpetas = sorted((p.parent for p in pkgs), key=lambda c: len(c.parts), reverse=True)
    declarados_por = {}
    textos_pkg = {}
    nombres_propios = set()
    for p in pkgs:
        texto = comun.leer(p) or ""
        try:
            datos = json.loads(texto)
        except json.JSONDecodeError:
            continue
        if not isinstance(datos, dict):
            continue
        textos_pkg[p.parent] = (texto, datos)
        if isinstance(datos.get("name"), str):
            nombres_propios.add(datos["name"])
        declarados_por[p.parent] = {s: dict(datos.get(s) or {}) for s in SECCIONES}

    def dueno(ruta):
        for c in carpetas:
            if c in ruta.parents:
                return c
        return None

    usados = {c: set() for c in textos_pkg}
    imports = {c: [] for c in textos_pkg}  # (paquete, archivo, linea)
    textos_config = {c: "" for c in textos_pkg}
    alias = {c: _alias_tsconfig(c) for c in textos_pkg}
    for f in fb.recorrer(proyecto):
        c = dueno(f)
        if c not in textos_pkg:
            continue
        suf = f.suffix.lower()
        es_config = bool(RE_CONFIG.match(f.name))
        if suf not in EXT_CODIGO and suf not in EXT_CSS and not es_config and f.name != "index.html":
            continue
        texto = comun.leer(f)
        if texto is None:
            continue
        if es_config:
            textos_config[c] += "\n" + texto
        patrones = [RE_CSS_IMPORT] if suf in EXT_CSS else [RE_IMPORT, RE_CSS_IMPORT]
        if f.name == "index.html":
            patrones = [re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""")]
        for pat in patrones:
            for m in pat.finditer(texto):
                espec = m.group(1)
                if any(espec == a or espec.startswith(a + "/") for a in alias[c]):
                    continue
                paq = paquete_de(espec)
                if paq:
                    usados[c].add(paq)
                    imports[c].append((paq, fb.rel(proyecto, f), texto.count("\n", 0, m.start()) + 1))
    raiz = proyecto if proyecto in textos_pkg else None
    hallazgos = []
    for c, (texto_pkg, datos) in sorted(textos_pkg.items()):
        scripts = " ".join(str(v) for v in (datos.get("scripts") or {}).values())
        for tok in re.findall(r"(?:^|&&|\|\||;|\s)(?:npx\s+|pnpm\s+(?:exec\s+|dlx\s+)?|yarn\s+|bunx\s+)?([a-z@][\w@/.-]*)", scripts):
            usados[c].add(BINARIOS.get(tok, tok))
        decl = declarados_por[c]
        todos = set().union(*[set(v) for v in decl.values()])
        if raiz and c != raiz:
            todos |= set().union(*[set(v) for v in declarados_por[raiz].values()])
        config = textos_config[c] + "\n" + texto_pkg
        hay_ts = any((c / n).is_file() for n in ("tsconfig.json", "tsconfig.app.json"))
        archivo_pkg = fb.rel(proyecto, c / "package.json")
        for seccion, sub, sev in (("dependencies", "dep_sin_uso", "baja"), ("devDependencies", "devdep_sin_uso", "info")):
            for dep in sorted(decl[seccion]):
                if dep in usados[c]:
                    continue
                if dep.startswith("@types/"):
                    base = dep[len("@types/"):]
                    base = "@" + base.replace("__", "/") if "__" in base else base
                    if base in usados[c] or base in todos or (hay_ts and base in ("node", "react", "react-dom")):
                        continue
                if dep.startswith(PREFIJOS_PLUGIN) or dep in BINARIOS.values():
                    corto = re.sub(r"^(@[^/]+/)?(eslint-plugin-|eslint-config-|prettier-plugin-|babel-plugin-|"
                                   r"babel-preset-|postcss-|vite-plugin-|stylelint-config-|tailwindcss-)", "", dep)
                    if dep in config.replace(f'"{dep}"', "", 1) or (corto and re.search(
                            r"[\"'/@]" + re.escape(corto) + r"\b", textos_config[c])):
                        continue
                if dep in ("typescript",) and hay_ts:
                    continue
                if re.search(r"['\"`]" + re.escape(dep) + r"(?:/[^'\"`]*)?['\"`]", textos_config[c]):
                    continue  # citada en una config (p. ej. environment: 'jsdom', optimizeDeps.exclude)
                if any(re.match(r"^\.?" + re.escape(dep) + r"(rc|\.config)\b", x.name) for x in c.iterdir()):
                    continue  # herramienta con su propio archivo de configuración (.prettierrc, eslint.config.js)
                hallazgos.append(comun.hallazgo(NOMBRE, sub, archivo_pkg, _linea_clave(texto_pkg, dep),
                                                f"«{dep}» está en {seccion} pero no se importa ni se usa en scripts/configs.",
                                                dep, sev))
        vistos = set()
        for paq, archivo, linea in imports[c]:
            if paq in todos or paq in nombres_propios or paq in vistos:
                continue
            vistos.add(paq)
            hallazgos.append(comun.hallazgo(NOMBRE, "dep_no_declarada", archivo, linea,
                                            f"Se importa «{paq}» pero no está declarado en {archivo_pkg}: dependencia "
                                            "fantasma (funciona por hoisting o no existe).", paq, "media"))
    pases = [] if hallazgos else [fb.pase(NOMBRE, "deps", f"{len(textos_pkg)} package.json: dependencias declaradas "
                                          "y usadas coinciden")]
    return fb.resultado(REEMPLAZA, hallazgos, pases)


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))

#!/usr/bin/env python3
"""ux_estatico — fallback estático de Playwright/axe (DECISIONES #6; investigacion/13 §4.10). Cobertura parcial.

Sin navegador no hay medición de comportamiento: solo heurísticas sobre el código fuente
(HTML, JSX/TSX, Vue, Svelte y CSS). Los controles dinámicos (flujo, reflow, teclado, foco) NUNCA
pueden quedar en pass por este fallback: sus pases son informativos (ver fallbacks_integracion.md).

Subregla            sev    → control
  html_sin_lang      media  → UX-LANG
  sin_viewport       alta   → UX-REFLOW (falta <meta viewport> o bloquea el zoom)
  img_sin_alt        alta   → UX-AXE-CRIT
  input_sin_label    alta   → UX-FORMULARIOS (input/select/textarea sin label, aria-label(ledby) ni title)
  click_en_div       media  → UX-TECLADO (onClick en elemento no interactivo sin role o sin manejador de teclado)
  tabindex_positivo  media  → UX-TECLADO
  outline_none       media  → UX-TECLADO, UX-FOCO-OCULTO (outline:none / outline-none sin foco alternativo)
Los elementos con atributos propagados ({...props}) no se juzgan (no se puede saber qué reciben).
Ronda 6 (stack), UX-FORMULARIOS:
- En JSX/TSX/Vue/Svelte/Astro solo cuentan las etiquetas nativas en minúscula (<input>, <select>); <Select label=…/> es
  un componente, no un campo.
- id dinámico: id={expr} con htmlFor={expr} (misma expresión) en el archivo cuenta como etiqueta asociada.
- Campo dentro de un componente reutilizable (función/const con nombre en mayúscula usada como <Nombre …> en el
  proyecto): la etiqueta puede estar en el componente que lo USA. Si TODOS los usos encontrados van dentro de un
  <label>…</label>, no hay hallazgo (queda en `no_juzgados` del resultado, con motivo, y sin pase de input_label); si
  solo algunos usos van dentro de <label>, el hallazgo baja de alta a media (no es un fallo seguro); si ningún uso lo
  envuelve (o no se encuentra ninguno), sigue en alta.
Uso: ux_estatico.py PROYECTO DIR_CRUDO
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402

NOMBRE = "ux_estatico"
REEMPLAZA = "playwright"
HERRAMIENTAS_REALES = ("playwright", "playwright_ux")
EXT_MARCADO = {".html", ".htm", ".jsx", ".tsx", ".vue", ".svelte", ".astro"}
EXT_CSS = {".css", ".scss", ".sass", ".less"}
NO_INTERACTIVOS = ("div", "span", "li", "td", "tr", "p", "section", "article", "img", "i", "label", "ul", "header",
                   "footer", "main", "nav", "figure")
RE_SPREAD = re.compile(r"\{\s*\.\.\.")
RE_FOCO_ALTERNATIVO = re.compile(r":focus-visible|:focus[^{]*\{[^}]*(box-shadow|border|outline\s*:\s*(?!none|0\b)[^;}]+|"
                                 r"text-decoration|background)", re.S)


def etiquetas(texto, nombres):
    """[(indice, nombre, texto_de_la_etiqueta)] de etiquetas de apertura, respetando comillas y {…} de JSX."""
    patron = re.compile(r"<(" + "|".join(nombres) + r")(?=[\s/>])", re.I)
    salida = []
    for m in patron.finditer(texto):
        i, prof, q = m.end(), 0, None
        while i < len(texto):
            c = texto[i]
            if q:
                if c == q:
                    q = None
            elif c in "\"'`":
                q = c
            elif c == "{":
                prof += 1
            elif c == "}":
                prof -= 1
            elif c == ">" and prof <= 0:
                break
            i += 1
        salida.append((m.start(), m.group(1).lower(), texto[m.start():i + 1]))
    return salida


def attr(tag, nombre):
    return re.search(r"(?<![\w-])" + nombre + r"\s*=", tag, re.I) is not None


def valor_attr(tag, nombre):
    m = re.search(r"(?<![\w-])" + nombre + r"""\s*=\s*(?:\{\s*)?["'`]([^"'`]*)["'`]""", tag, re.I)
    return m.group(1) if m else None


EXT_COMPONENTES = {".jsx", ".tsx", ".vue", ".svelte", ".astro"}
RE_DEF_COMPONENTE = re.compile(r"(?:\bfunction\s+([A-Z]\w*)\s*\(|\b(?:const|let|var)\s+([A-Z]\w*)\s*(?::[^=]{0,200})?=\s*"
                               r"(?:React\.)?(?:memo\s*\(|forwardRef\s*\(|\(|async\s*\(|function\b|\w+\s*=>))")
RE_ID_DINAMICO = re.compile(r"(?<![\w-])id\s*=\s*\{\s*([^{}]+?)\s*\}")
RE_FOR_DINAMICO = re.compile(r"(?<![\w-])htmlFor\s*=\s*\{\s*([^{}]+?)\s*\}")


def _componente_que_contiene(texto, idx):
    """Nombre del componente (función o const con nombre en mayúscula) definido más cerca antes de idx, o None."""
    nombre = None
    for m in RE_DEF_COMPONENTE.finditer(texto, 0, idx):
        nombre = m.group(1) or m.group(2)
    return nombre


def _dentro_de_label(texto, idx):
    abre, cierra = texto.rfind("<label", 0, idx), texto.rfind("</label", 0, idx)
    return abre > cierra


def _usos_componente(fuentes, nombre):
    """[(archivo, dentro_de_label)] de cada <Nombre …> en los archivos de componentes del proyecto."""
    patron = re.compile(r"<" + re.escape(nombre) + r"(?=[\s/>])")
    usos = []
    for arch, texto in fuentes.items():
        for m in patron.finditer(texto):
            usos.append((arch, _dentro_de_label(texto, m.start())))
    return usos


def analizar(proyecto, crudo=None):
    proyecto = Path(proyecto)
    hallazgos, evaluadas, no_juzgados = [], set(), []
    fuentes = {}
    for p in fb.recorrer(proyecto, EXT_COMPONENTES):
        t = comun.leer(p)
        if t is not None:
            fuentes[fb.rel(proyecto, p)] = t

    def h(sub, arch, texto, idx, mensaje, ev, sev):
        hallazgos.append(comun.hallazgo(NOMBRE, sub, arch, fb.linea_en(texto, idx), mensaje,
                                        fb.RE_ESPACIOS.sub(" ", ev)[:200], sev))

    for p in fb.recorrer(proyecto, EXT_MARCADO | EXT_CSS):
        texto = comun.leer(p)
        if texto is None:
            continue
        arch = fb.rel(proyecto, p)
        suf = p.suffix.lower()
        if suf in EXT_CSS:
            alternativo = RE_FOCO_ALTERNATIVO.search(texto)
            for m in re.finditer(r"\boutline\s*:\s*(none|0)\b", texto, re.I):
                evaluadas.add("outline")
                if not alternativo:
                    h("outline_none", arch, texto, m.start(), "outline:none sin estilo de foco alternativo "
                      "(:focus-visible) en el mismo archivo: el foco de teclado queda invisible.", m.group(0), "media")
            continue
        es_html = suf in (".html", ".htm")
        # <html lang> y <meta viewport>
        for idx, _, tag in etiquetas(texto, ["html"]):
            evaluadas.add("html_lang")
            if not attr(tag, "lang"):
                h("html_sin_lang", arch, texto, idx, "<html> sin atributo lang (WCAG 3.1.1).", tag, "media")
        if es_html and re.search(r"<(html|head)\b", texto, re.I):
            evaluadas.add("viewport")
            meta = [t for _, _, t in etiquetas(texto, ["meta"]) if re.search(r"name\s*=\s*[\"']viewport", t, re.I)]
            ancla = re.search(r"<head\b", texto, re.I) or re.search(r"<html\b", texto, re.I)
            if not meta:
                h("sin_viewport", arch, texto, ancla.start(), "Falta <meta name=\"viewport\">: la página no se adapta a "
                  "pantallas móviles.", ancla.group(0), "alta")
            elif re.search(r"user-scalable\s*=\s*(no|0)|maximum-scale\s*=\s*1(\.0*)?\b", meta[0], re.I):
                h("sin_viewport", arch, texto, texto.find(meta[0]), "El viewport bloquea el zoom (user-scalable=no o "
                  "maximum-scale=1; WCAG 1.4.4).", meta[0], "alta")
        # imágenes
        for idx, _, tag in etiquetas(texto, ["img"]):
            evaluadas.add("img_alt")
            if not attr(tag, "alt") and not RE_SPREAD.search(tag):
                h("img_sin_alt", arch, texto, idx, "<img> sin atributo alt (usar alt=\"\" si es decorativa).", tag, "alta")
        # campos de formulario
        ids_label = set(re.findall(r"""(?:htmlFor|\bfor)\s*=\s*(?:\{\s*)?["'`]([^"'`]+)["'`]""", texto))
        ids_label_din = {fb.RE_ESPACIOS.sub("", x) for x in RE_FOR_DINAMICO.findall(texto)}
        campos = etiquetas(texto, ["input", "select", "textarea"])
        if suf in EXT_COMPONENTES:  # en JSX <Select …> es un componente: solo cuentan las etiquetas nativas
            campos = [c for c in campos if texto[c[0] + 1:c[0] + 1 + len(c[1])] == c[1]]
        for idx, nombre, tag in campos:
            tipo = (valor_attr(tag, "type") or "").lower()
            if tipo in ("hidden", "submit", "button", "reset", "image"):
                continue
            evaluadas.add("input_label")
            if RE_SPREAD.search(tag) or any(attr(tag, a) for a in ("aria-label", "aria-labelledby", "title")):
                continue
            ident = valor_attr(tag, "id")
            if ident and ident in ids_label:
                continue
            din = RE_ID_DINAMICO.search(tag)
            if din and fb.RE_ESPACIOS.sub("", din.group(1)) in ids_label_din:
                continue
            if _dentro_de_label(texto, idx):
                continue
            componente = _componente_que_contiene(texto, idx) if suf in EXT_COMPONENTES else None
            if componente:
                usos = _usos_componente(fuentes, componente)
                if usos and all(dentro for _, dentro in usos):
                    no_juzgados.append({"archivo": arch, "linea": fb.linea_en(texto, idx), "componente": componente,
                                        "motivo": f"<{nombre}> dentro del componente reutilizable {componente}: sus "
                                        f"{len(usos)} uso(s) van dentro de un <label> en el componente que lo usa "
                                        "(etiqueta implícita; verificar en navegador)"})
                    continue
                if any(dentro for _, dentro in usos):
                    h("input_sin_label", arch, texto, idx, f"<{nombre}> sin etiqueta asociada dentro del componente "
                      f"reutilizable {componente}: {sum(1 for _, d in usos if d)} de {len(usos)} uso(s) lo envuelven en "
                      "un <label> y los demás no; no es un fallo seguro (WCAG 1.3.1/4.1.2).", tag, "media")
                    continue
            h("input_sin_label", arch, texto, idx, f"<{nombre}> sin etiqueta asociada (label, aria-label o "
              "aria-labelledby; WCAG 1.3.1/4.1.2).", tag, "alta")
        # onClick en elementos no interactivos
        if not es_html:
            for idx, nombre, tag in etiquetas(texto, list(NO_INTERACTIVOS)):
                if not re.search(r"(?<![\w-])on[Cc]lick\s*=", tag):
                    continue
                evaluadas.add("click_teclado")
                if RE_SPREAD.search(tag):
                    continue
                faltan = []
                if not attr(tag, "role"):
                    faltan.append("role")
                if not re.search(r"(?<![\w-])onKey(Down|Up|Press)\s*=", tag):
                    faltan.append("manejador de teclado (onKeyDown)")
                if faltan:
                    h("click_en_div", arch, texto, idx, f"onClick en <{nombre}> sin {' ni '.join(faltan)}: no se puede "
                      "activar con teclado (usar <button>).", tag, "media")
        for m in re.finditer(r"""(?<![\w-])tab[Ii]ndex\s*=\s*(?:\{\s*)?["']?([1-9]\d*)""", texto):
            h("tabindex_positivo", arch, texto, m.start(), "tabindex positivo: altera el orden natural del foco.",
              m.group(0), "media")
        # outline-none (Tailwind) y outline: 'none' en estilos en línea
        for m in re.finditer(r"""\b(?:class|className)\s*=\s*(\{[^{}]*\}|"[^"]*"|'[^']*')""", texto):
            if re.search(r"(?<![\w:-])outline-none\b", m.group(1)):
                evaluadas.add("outline")
                if not re.search(r"\bfocus(-visible|-within)?:", m.group(1)):
                    h("outline_none", arch, texto, m.start(), "Clase outline-none sin variante focus:/focus-visible: "
                      "el foco de teclado queda invisible.", m.group(0), "media")
        if re.search(r"""\boutline\s*:\s*["'](none|0)["']""", texto) and not re.search(r"focus-visible|:focus|onFocus", texto):
            m = re.search(r"""\boutline\s*:\s*["'](none|0)["']""", texto)
            evaluadas.add("outline")
            h("outline_none", arch, texto, m.start(), "Estilo en línea outline: none sin foco alternativo.", m.group(0), "media")
    hallazgos.sort(key=lambda x: (x["archivo"] or "", x["linea"] or 0, x["regla"]))
    con_hallazgo = {x["regla"].split(".", 1)[1] for x in hallazgos}
    equivalencia = {"html_lang": "html_sin_lang", "viewport": "sin_viewport", "img_alt": "img_sin_alt",
                    "input_label": "input_sin_label", "click_teclado": "click_en_div", "outline": "outline_none"}
    if no_juzgados:
        con_hallazgo.add("input_sin_label")  # sin pase de input_label: hubo campos que no se pudieron juzgar
    pases = [fb.pase(NOMBRE, k, f"{k}: sin hallazgos en el código fuente (verificación estática, no en navegador)")
             for k in sorted(evaluadas) if equivalencia[k] not in con_hallazgo]
    res = fb.resultado(REEMPLAZA, hallazgos, pases)
    if no_juzgados:
        res["no_juzgados"] = no_juzgados
    return res


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))

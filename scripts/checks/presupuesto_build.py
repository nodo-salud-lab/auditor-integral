#!/usr/bin/env python3
"""presupuesto_build — fallback estático de Lighthouse CI (DECISIONES #6; investigacion/13 §4.11). Cobertura parcial.

Mide la carpeta de build YA EXISTENTE (dist/, build/, out/). Si no existe, el control queda
no_evaluado: construir ejecutaría código del proyecto y el auditor no lo hace. Excepción declarada a
la exclusión de dist/ de los demás fallbacks; node_modules y las carpetas confidenciales (Decisión 3)
se siguen excluyendo. Solo se leen tamaños y nombres (y el contenido JS para medir gzip).

Subregla         sev                               → control
  chunk_grande    baja (media si > 2× umbral)       → UX-LIGHTHOUSE (parcial)
                  JS > umbral.bundle_chunk_max_kb (500 kB sin comprimir, kB = 1000 bytes:
                  build.chunkSizeWarningLimit por defecto de Vite)
  imagen_grande   baja (> 200 kB; ESTIMACIÓN)       → UX-LIGHTHOUSE (parcial)
  sin_cache_hash  info                              → INF-CACHE-CDN (parcial): asset en assets/ sin hash
                                                      en el nombre (no se puede cachear como inmutable)
  wasm_grande     info (no mapeada; Anexo C, AUD-WASM) .wasm/.onnx > umbral.binario_wasm_max_kb: peso de
                                                      runtimes WebAssembly y modelos que el presupuesto JS no ve
Pase ok_presupuesto (informativo): tamaños medidos. LCP solo se mide en navegador: UX-LCP-LAB nunca pasa
por este fallback. Uso: presupuesto_build.py PROYECTO DIR_CRUDO
"""
import gzip
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import comun  # noqa: E402
import fallback as fb  # noqa: E402

NOMBRE = "presupuesto_build"
REEMPLAZA = "lhci"
HERRAMIENTAS_REALES = ("lhci", "lighthouse")
CARPETAS_BUILD = ("dist", "build", "out")
EXT_JS = {".js", ".mjs", ".cjs"}
EXT_IMG = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".bmp"}
EXT_ASSET = EXT_JS | EXT_IMG | {".css", ".woff", ".woff2", ".ttf", ".otf"}
IMAGEN_MAX_KB = 200
EXT_BINARIO = {".wasm", ".onnx"}
def tiene_hash(nombre):
    """Hash de contenido al final del nombre (Vite/Rollup: base64url de 8 caracteres, con - y _)."""
    for m in re.finditer(r"(?=[.-]([A-Za-z0-9_-]{8,})\.[A-Za-z0-9]+$)", nombre):
        seg = m.group(1)
        for k in range(len(seg) - 7):
            trozo = seg[k:k + 8]
            if any(ch.isdigit() for ch in trozo) or (any(ch.isupper() for ch in trozo) and any(ch.islower() for ch in trozo)):
                return True
    return False
MAX_SIN_HASH = 10


def analizar(proyecto, crudo=None):
    proyecto = Path(proyecto)
    builds = [c for c in CARPETAS_BUILD if (proyecto / c).is_dir() and not (proyecto / c).is_symlink()]
    if not builds:
        return fb.resultado(REEMPLAZA, estado="no_evaluado", motivo="no hay carpeta de build (dist/, build/, out/); "
                            "el auditor no construye el proyecto")
    limite_kb = fb.umbral("bundle_chunk_max_kb", 500)
    limite_bin_kb = fb.umbral("binario_wasm_max_kb", 5000)
    hallazgos, sin_hash = [], []
    total_js = total_js_gz = n_js = 0
    for c in builds:
        for p in fb.recorrer(proyecto, permitir=CARPETAS_BUILD, desde=c):
            suf = p.suffix.lower()
            if suf in EXT_BINARIO:
                try:
                    kb_bin = p.stat().st_size / 1000
                except OSError:
                    continue
                if kb_bin > limite_bin_kb:
                    hallazgos.append(comun.hallazgo(NOMBRE, "wasm_grande", fb.rel(proyecto, p), None,
                                                    f"Binario {suf} de {kb_bin:.0f} kB > {limite_bin_kb} kB: no lo mide el "
                                                    "presupuesto de chunks JS; cargarlo bajo demanda y cachearlo "
                                                    "(informativo).", f"{p.name}: {kb_bin:.0f} kB", "info"))
                continue
            if suf not in EXT_ASSET:
                continue
            arch = fb.rel(proyecto, p)
            try:
                tam = p.stat().st_size
            except OSError:
                continue
            kb = tam / 1000
            if suf in EXT_JS:
                n_js += 1
                total_js += tam
                if tam <= 20_000_000:
                    try:
                        total_js_gz += len(gzip.compress(p.read_bytes(), compresslevel=6))
                    except OSError:
                        pass
                if kb > limite_kb:
                    hallazgos.append(comun.hallazgo(NOMBRE, "chunk_grande", arch, None,
                                                    f"Chunk JS de {kb:.0f} kB > {limite_kb} kB (límite de aviso de Vite): "
                                                    "dividir con import() dinámico o manualChunks.",
                                                    f"{p.name}: {kb:.0f} kB", "media" if kb > 2 * limite_kb else "baja"))
            elif suf in EXT_IMG and kb > IMAGEN_MAX_KB:
                hallazgos.append(comun.hallazgo(NOMBRE, "imagen_grande", arch, None,
                                                f"Imagen de {kb:.0f} kB > {IMAGEN_MAX_KB} kB: comprimir o servir WebP/AVIF.",
                                                f"{p.name}: {kb:.0f} kB", "baja"))
            if "assets" in p.relative_to(proyecto / c).parts and not tiene_hash(p.name):
                sin_hash.append(arch)
    for arch in sin_hash[:MAX_SIN_HASH]:
        hallazgos.append(comun.hallazgo(NOMBRE, "sin_cache_hash", arch, None, "Asset sin hash de contenido en el nombre: "
                                        "no puede cachearse como inmutable.", Path(arch).name, "info"))
    if len(sin_hash) > MAX_SIN_HASH:
        hallazgos.append(comun.hallazgo(NOMBRE, "sin_cache_hash", None, None, f"… y {len(sin_hash) - MAX_SIN_HASH} "
                                        "assets más sin hash.", f"{len(sin_hash)} assets", "info"))
    pases = []
    if not any(h["regla"].endswith((".chunk_grande", ".imagen_grande")) for h in hallazgos):
        pases.append(fb.pase(NOMBRE, "presupuesto", f"{n_js} archivos JS: {total_js / 1000:.0f} kB "
                             f"({total_js_gz / 1000:.0f} kB gzip); ningún chunk > {limite_kb} kB"))
    return fb.resultado(REEMPLAZA, hallazgos, pases)


if __name__ == "__main__":
    sys.exit(fb.main(NOMBRE, REEMPLAZA, HERRAMIENTAS_REALES, analizar))

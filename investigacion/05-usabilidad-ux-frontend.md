# 05 · Usabilidad, UX, accesibilidad, diseño y navegador/frontend

**Proyecto:** auditor-integral · **Fecha:** 2026-11-17 · **Sello:** SÍNTESIS (evidencia integrada) + GUÍA (procedimiento) · Los puntos marcados **ESTIMACIÓN** son inferencias de diseño, no datos medidos.

Regla de este informe: toda cifra lleva URL. Lo que no se pudo verificar contra la fuente primaria se marca **NO VERIFICADO**.

---

## 1. Resumen ejecutivo

1. **La mitad de la auditoría UX se puede automatizar en forma barata en tokens.** Playwright abre la app, axe-core revisa accesibilidad, Lighthouse/LHCI mide rendimiento y buenas prácticas, y todo sale en JSON. El LLM solo lee los resúmenes (conteo por regla e impacto), no el código ni el DOM completo.
2. **Lo automatizable no alcanza.** Deque reporta que sus pruebas automáticas detectan ~57 % (57,38 % según el informe completo, **decimal NO VERIFICADO**; el blog cita 57 %) del *volumen* de problemas de accesibilidad en su muestra de auditorías (13.000+ páginas, ~300.000 issues), y el resto requiere pruebas manuales o guiadas ([Deque 2021](https://www.deque.com/blog/automated-testing-study-identifies-57-percent-of-digital-accessibility-issues)). Es un dato del fabricante, medido sobre volumen y no sobre criterios WCAG. La usabilidad percibida (SUS, UMUX-Lite) necesita **usuarios reales**; la IA no puede responder un SUS en nombre de usuarios.
3. **El estado base de la web es malo, y la IA aprende de esa web.** WebAIM Million 2026: el 95,9 % de las home pages tiene fallas WCAG detectables, promedio 56,1 errores por página, y bajo contraste en el 83,9 % (cifras vía fuentes secundarias que citan a WebAIM: [Agiledrop](https://www.agiledrop.com/blog/web-accessibility-just-got-worse-a-year-into-eaa-enforcement), [Priority Pixels](https://prioritypixels.co.uk/insights/web-accessibility-is-getting-worse-according-to-the-2026-webaim-million-report/); **la página primaria de WebAIM no se abrió en esta sesión**).
4. **Las UIs generadas por LLM repiten esas barreras, pero responden a un buen prompt.** En W4A 2025 (Gurita y Vatavu; 80 UIs, GPT-4-turbo y Claude 3.5 Haiku), la tasa de violaciones según expertos bajó de 58 % a 19 % cuando el prompt incluía requisitos WCAG explícitos. Skip links pasaron de 0 % a 100 % y el acceso por teclado de 48 % a 94 % de los elementos interactivos (Tabla 4 del paper). Las herramientas automáticas, en cambio, **no** mostraron esa mejora (con prompt WCAG 17,32 % vs sin prompt 15,93 %; es decir, la herramienta reportó incluso algo más de violaciones con prompt WCAG): miden cosas distintas que los expertos ([reseña del paper](https://a11y-paradise.onrender.com/reviews/69ae41f68b9c91225e628c18)). Implicancia de diseño: el auditor necesita **las dos capas**, herramienta y juicio.
5. **Umbrales duros para el gate de producción:** LCP ≤ 2,5 s, INP ≤ 200 ms y CLS ≤ 0,1, medidos en el percentil 75 de visitas reales ([web.dev](https://web.dev/articles/defining-core-web-vitals-thresholds)), más WCAG 2.2 AA sin violaciones "critical/serious" de axe.

---

## 2. Marco normativo y de medición

### 2.1 Heurísticas de Nielsen (evaluación heurística)
Son 10 heurísticas: visibilidad del estado del sistema; correspondencia con el mundo real; control y libertad del usuario; consistencia y estándares; prevención de errores; reconocer antes que recordar; flexibilidad y eficiencia; diseño estético y minimalista; ayudar a reconocer, diagnosticar y recuperarse de errores; ayuda y documentación. Fuente: [NN/g](https://www.nngroup.com/articles/ten-usability-heuristics/) (URL no reabierta en esta sesión; la lista es canónica).

**Uso en el auditor:** el LLM evalúa capturas de Playwright de cada pantalla del flujo crítico contra las 10 heurísticas y asigna una severidad de 0 a 4. Es **juicio LLM**, con riesgo de falsos positivos. Debe etiquetarse como "evaluación heurística asistida" y no como test con usuarios.

### 2.2 SUS (System Usability Scale)
- Son 10 ítems Likert de 1 a 5 con ítems alternados positivo/negativo. Puntaje: (ítems impares − 1) + (5 − ítems pares), y la suma × 2,5 da un valor de 0 a 100.
- **Interpretación (Sauro/Lewis, MeasuringU):** promedio 68, que corresponde al percentil 50. Un 70 cae aproximadamente en el percentil 56 y un 52 en el percentil 15. Corte de "aceptable" ≈ >70 y "no aceptable" <50 ([MeasuringU](https://measuringu.com/?p=170)). La escala de notas A–F se construye sobre una curva de percentiles (los cortes exactos por letra quedan **NO VERIFICADOS**: las fuentes secundarias difieren entre sí).
- **Escala de adjetivos (Bangor, Kortum y Miller 2009, JUS 4(3):114-123):** media SUS "Excelente" 85,5, "Bueno" 71,4, "OK" 50,9 ([PDF JUS](https://uxpajournal.org/wp-content/uploads/sites/7/pdf/JUS_Bangor_May2009.pdf); valores tomados de una fuente secundaria de UXPA, **tabla original NO VERIFICADA: la URL del PDF devuelve 404 al 2026-11-17**). Los propios autores advierten que "OK" no significa "aceptable".
- **Muestra:** el SUS es un estimador. Con n pequeño, reportar media con IC95 %. **ESTIMACIÓN:** con n < 12 el intervalo será ancho; el auditor debe mostrarlo y no dar un número suelto.

### 2.3 UMUX-Lite
- Son 2 ítems de 7 puntos ("las capacidades cumplen mis requisitos" / "es fácil de usar"). Lewis, Utesch y Maher, CHI 2013.
- La regresión original hacia SUS (0,65 × ((a+b−2) × 100/12) + 22,9) **está superada**: Lah, Lewis y Šumak (2020) la encontraron sesgada en productos con SUS alto, y la guía actual recomienda interpolación lineal simple ([resumen y referencias](https://www.koji.so/docs/umux-lite-guide), [Borsci et al. 2015](https://informahealthcare.com/doi/abs/10.1080/10447318.2015.1064654)). El auditor debe usar la interpolación y no la regresión.
- **Uso:** encuesta in-app de bajo costo para producción (N4–N5). SUS queda para pruebas formales (N3).

### 2.4 WCAG 2.2 AA
- WCAG 2.2 es Recomendación W3C, con la versión vigente fechada el 12-12-2024 ([W3C TR](https://www.w3.org/TR/WCAG22/)). Se eliminó el criterio 4.1.1 Parsing.
- Criterios nuevos de nivel A/AA que el auditor debe chequear explícitamente porque axe cubre poco o nada de ellos: **2.4.11 Foco no oculto (AA)**, **2.5.7 Movimientos de arrastre (AA)**, **2.5.8 Tamaño de objetivo mínimo (AA)**, **3.2.6 Ayuda consistente (A)**, **3.3.7 Entrada redundante (A)** y **3.3.8 Autenticación accesible mínima (AA)** ([W3C TR](https://www.w3.org/TR/WCAG22/)).
- **ESTIMACIÓN:** 2.5.8 se puede medir de forma determinista con Playwright (bounding boxes de elementos interactivos < 24×24 CSS px). 2.4.11 se puede aproximar tabulando por la página y comprobando si el elemento enfocado queda tapado por headers sticky. 3.3.7 y 3.3.8 requieren recorrer el flujo y aplicar juicio.

### 2.5 Core Web Vitals
| Métrica | Bueno | Mejorable | Pobre |
|---|---|---|---|
| LCP | ≤ 2.500 ms | 2.500–4.000 ms | > 4.000 ms |
| INP | ≤ 200 ms | 200–500 ms | > 500 ms |
| CLS | ≤ 0,1 | 0,1–0,25 | > 0,25 |

Se evalúan en el percentil 75 de visitas, segmentado móvil/escritorio ([web.dev thresholds](https://web.dev/articles/defining-core-web-vitals-thresholds), [web.dev INP](https://web.dev/articles/inp)). INP reemplazó a FID como Core Web Vital estable en 2024 ([web.dev vitals](https://web.dev/articles/vitals)).

**Trampa clave:** INP es una métrica de **campo**. Lighthouse en laboratorio no mide INP real (usa TBT como proxy). Por eso el auditor debe distinguir:
- **Lab (determinista, pre-producción):** Lighthouse/LHCI → LCP, CLS, TBT.
- **Campo (N4+):** librería `web-vitals` en el cliente → LCP, INP y CLS reales enviados a analytics. Si el proyecto no tiene RUM, se reporta "INP: SIN DATOS DE CAMPO" y no se infiere.

---

## 3. Qué puede auditar la IA sola vs. qué necesita personas

| Aspecto | Automático determinista | LLM con evidencia (capturas/JSON) | Requiere usuarios reales / experto |
|---|---|---|---|
| Contraste, alt, labels, roles ARIA, idioma | axe-core, pa11y, Lighthouse a11y | — | Calidad del alt (¿describe bien?) |
| Navegación por teclado y foco | Playwright (Tab loop, `:focus-visible`, trampa de foco) | Revisar capturas del foco | Usuarios de lector de pantalla |
| Tamaño de objetivo 2.5.8 | Playwright bounding boxes | — | — |
| Rendimiento lab (LCP/CLS/TBT) | Lighthouse CI | Priorizar oportunidades | — |
| INP/CWV de campo | `web-vitals` + RUM | Resumen de tendencias | Tráfico real |
| Responsive / overflow | Playwright en viewports 360/768/1280 + detección de scroll horizontal | Revisar capturas | — |
| Compatibilidad de navegadores | Browserslist + eslint-plugin-compat; Playwright en chromium/firefox/webkit | — | Safari iOS real (WebKit ≠ Safari exacto) |
| Estados vacío/error/carga | Playwright con red interceptada (`route` → 500, lento, vacío) | Juzgar si el mensaje es útil | — |
| Formularios | axe (labels), Playwright (envío vacío, errores inline, `autocomplete`) | Claridad de mensajes de error | — |
| i18n | Linter de strings hardcodeados, extracción de claves faltantes, `lang` | — | Calidad de traducción |
| Consistencia de diseño | stylelint (valores mágicos, colores fuera de tokens) | Comparar capturas entre pantallas | — |
| Heurísticas de Nielsen | — | Sí (con severidad 0-4) | Validar con test de usuarios |
| Usabilidad percibida (SUS/UMUX-Lite) | Cálculo del puntaje | Interpretación | **Sí, obligatorio** |
| Comprensión del flujo / modelo mental | — | Hipótesis | **Sí** (test moderado, 5+ usuarios por perfil; regla de Nielsen: [NN/g](https://www.nngroup.com/articles/why-you-only-need-to-test-with-5-users/), URL no reabierta en esta sesión) |

**Principio de tokens:** el LLM nunca recibe el JSON crudo de Lighthouse (que pesa varios MB; **ESTIMACIÓN** basada en el formato LHR). Un script `jq` o Node extrae: score por categoría, las 3 métricas, top-10 auditorías fallidas con `id`, `title` y `displayValue`. De axe se extrae `{rule, impact, count, 1 selector ejemplo}`. Objetivo **ESTIMACIÓN**: < 2–3k tokens por página auditada.

---

## 4. Fallas típicas de UIs generadas por IA ("vibe coding")

Ordenadas por severidad. Las que tienen fuente se citan; el resto es **ESTIMACIÓN** basada en patrones observados y en la literatura citada.

1. **Divs clicables en lugar de `<button>`/`<a>`**, sin rol, sin tabindex y sin manejo de teclado. Inaccesibles por teclado. Detección: axe (parcial), Playwright con Tab loop y una regla eslint-plugin-jsx-a11y (`click-events-have-key-events`, `no-static-element-interactions`). Gurita y Vatavu encontraron acceso por teclado correcto en solo el 48 % de los elementos interactivos sin prompt WCAG (Tabla 4) ([reseña](https://a11y-paradise.onrender.com/reviews/69ae41f68b9c91225e628c18)).
2. **Falta de semántica estructural:** sin landmarks (11 %), jerarquía de headings rota (33 %), sin skip links (0 %) en UIs generadas sin instrucciones de accesibilidad (misma fuente).
3. **Bajo contraste**, sobre todo en temas oscuros, texto gris sobre gris y placeholders. Es la falla #1 de la web (83,9 %, WebAIM 2026 vía secundaria). El 84 % de sitios generados con ChatGPT tuvo violaciones de contraste, redimensionado o semántica (Aljedaani et al. 2024, citado en la reseña; **no verificado contra el original**).
4. **Solo "happy path":** sin estado de carga, sin estado vacío, errores de red tragados (`catch {}`) o pantalla en blanco. **ESTIMACIÓN**: es la falla de UX más común en prototipos de IA, porque los prompts describen el caso feliz. Detección: Playwright con `page.route` que fuerza 500, timeout y respuesta vacía, más captura.
5. **Formularios sin `<label>`, sin `autocomplete`, validación solo del lado cliente, errores no anunciados** (sin `aria-live`/`aria-describedby`). Detección: axe `label`, Playwright y grep de `autocomplete`.
6. **ARIA mal usado** (roles inventados, `aria-label` en elementos no interactivos, `aria-hidden` sobre contenido focusable). Los LLM tienen dificultades con ARIA ([Gurita y Vatavu, W4A 2025, PDF](https://mintviz.usv.ro/publications/2025.W4A.3.pdf)).
7. **Layout shift (CLS) por imágenes sin `width`/`height`**, fuentes web sin `font-display` y banners inyectados. Detección: Lighthouse `layout-shifts` y `unsized-images`.
8. **LCP lento por imágenes hero sin optimizar**, bundles enormes (librerías de íconos completas) y render 100 % cliente. Detección: Lighthouse, `source-map-explorer`/bundle analyzer.
9. **Responsive roto:** anchos fijos en px, scroll horizontal en 360 px y objetivos táctiles < 24 px (WCAG 2.5.8). Detección: Playwright a 360/390 px con `document.documentElement.scrollWidth > clientWidth`.
10. **Inconsistencia visual:** colores y espaciados hardcodeados que varían entre pantallas (cada prompt genera su propio estilo) y ausencia de tokens. Detección: stylelint (`color-no-hex` / `declaration-property-value-allowed-list`), conteo de valores únicos de color y tamaño de fuente.
11. **Falta `lang` en `<html>` y textos hardcodeados** sin i18n. El idioma de página es una falla persistente incluso con prompt WCAG (reseña citada). Detección: axe `html-has-lang` y linter de literales en JSX.
12. **Dependencia de APIs solo-Chromium** (p. ej. CSS o JS nuevos sin fallback) y pruebas solo en Chrome. Detección: eslint-plugin-compat + Browserslist y Playwright en WebKit/Firefox.
13. **Mensajes de error técnicos expuestos al usuario** (stack traces, "undefined", JSON). Viola la heurística 9 de Nielsen y además filtra información (cruza con seguridad). Detección: Playwright que fuerza errores y busca patrones (`Error:`, `undefined`, `at Object.`) en el texto visible.
14. **Modales sin trampa de foco ni cierre con Esc**, y foco que no vuelve al disparador. Detección: script Playwright.

**Dato de referencia de benchmark:** Microsoft publica `a11y-llm-eval` (MIT; Playwright + axe-core + aserciones propias, métrica pass@k) para medir qué tan accesible es el HTML que generan los LLM ([repo](https://github.com/microsoft/a11y-llm-eval)). Las tasas de aprobación por modelo que circulan en blogs (p. ej. "31 %" o "0 %") **NO VERIFICADAS**: no se confirmaron en el repo.

---

## 5. Herramientas y repositorios (verificados con `gh api`, 2026-11-17)

| Herramienta | Repo | ★ | Licencia | Último push | Salida | Uso en el auditor | Costo tokens |
|---|---|---|---|---|---|---|---|
| Playwright | [microsoft/playwright](https://github.com/microsoft/playwright) | 100.442 | Apache-2.0 | 2026-11-18 | JSON/HTML report, PNG | Motor: navegar flujos, capturas, viewports, interceptar red, 3 motores | bajo |
| axe-core | [dequelabs/axe-core](https://github.com/dequelabs/axe-core) | 7.848 | MPL-2.0 | 2026-11-17 | JSON (violations/impact) | Regla WCAG automática principal | bajo |
| @axe-core/playwright (axe-core-npm) | [dequelabs/axe-core-npm](https://github.com/dequelabs/axe-core-npm) | 737 | MPL-2.0 | 2026-11-16 | JSON | Integración axe dentro de los flujos E2E | bajo |
| Lighthouse | [GoogleChrome/lighthouse](https://github.com/GoogleChrome/lighthouse) | 31.147 | Apache-2.0 | 2026-11-18 | JSON (LHR), HTML | Perf/a11y/best-practices/SEO de laboratorio | medio (resumir con jq) |
| Lighthouse CI | [GoogleChrome/lighthouse-ci](https://github.com/GoogleChrome/lighthouse-ci) | 7.154 | Apache-2.0 | 2026-11-17 | JSON + asserts (exit code) | Gate en CI: `preset: lighthouse:recommended` + `minScore` por categoría ([docs](https://googlechrome.github.io/lighthouse-ci/docs/configuration.html)) | bajo |
| lighthouse-ci-action | [treosh/lighthouse-ci-action](https://github.com/treosh/lighthouse-ci-action) | 1.294 | MIT | 2026-03-12 | JSON | Atajo GitHub Actions | bajo |
| Unlighthouse | [harlan-zw/unlighthouse](https://github.com/harlan-zw/unlighthouse) | 4.957 | MIT | 2026-11-17 | JSON/CSV | Lighthouse en **todo el sitio** (crawl) | medio |
| pa11y | [pa11y/pa11y](https://github.com/pa11y/pa11y) | 4.602 | LGPL-3.0 | 2026-11-16 | JSON/CSV | Segunda opinión (runners axe + HTML_CodeSniffer) | bajo |
| pa11y-ci | [pa11y/pa11y-ci](https://github.com/pa11y/pa11y-ci) | 648 | LGPL-3.0 | 2026-11-16 | JSON | Lista de URLs/sitemap en CI | bajo |
| IBM Equal Access | [IBMa/equal-access](https://github.com/IBMa/equal-access) | 788 | Apache-2.0 | 2026-11-13 | JSON | Motor alternativo de reglas (complementa axe) | bajo |
| Siteimprove Alfa | [Siteimprove/alfa](https://github.com/Siteimprove/alfa) | 135 | MIT | 2026-11-12 | JSON/EARL | Reglas ACT; opcional | bajo |
| web-vitals | [GoogleChrome/web-vitals](https://github.com/GoogleChrome/web-vitals) | 8.692 | Apache-2.0 | 2026-11-12 | callbacks JS | RUM: INP/LCP/CLS de campo (N4+) | bajo |
| sitespeed.io | [sitespeedio/sitespeed.io](https://github.com/sitespeedio/sitespeed.io) | 5.053 | MIT | 2026-11-17 | JSON, HAR, video | Perf avanzada/sintética continua (N5) | medio |
| eslint-plugin-jsx-a11y | [jsx-eslint/eslint-plugin-jsx-a11y](https://github.com/jsx-eslint/eslint-plugin-jsx-a11y) | 3.632 | MIT | 2026-01-06 | JSON/SARIF (eslint) | A11y estática en JSX/React, sin navegador | bajo |
| eslint-plugin-compat | [amilajack/eslint-plugin-compat](https://github.com/amilajack/eslint-plugin-compat) | 3.188 | MIT | 2026-07-23 | JSON/SARIF | APIs no soportadas según Browserslist | bajo |
| Browserslist | [browserslist/browserslist](https://github.com/browserslist/browserslist) | 13.588 | MIT | 2026-11-16 | texto | Define el objetivo de navegadores | bajo |
| stylelint | [stylelint/stylelint](https://github.com/stylelint/stylelint) | 11.553 | MIT | 2026-11-18 | JSON | Consistencia CSS / uso de tokens | bajo |
| Style Dictionary | [style-dictionary/style-dictionary](https://github.com/style-dictionary/style-dictionary) | 4.885 | Apache-2.0 | 2026-11-03 | JSON/CSS | Recomendación de remediación: tokens | — |
| i18next-cli | [i18next/i18next-cli](https://github.com/i18next/i18next-cli) | 251 | MIT | 2026-11-17 | JSON | Claves faltantes/no usadas (i18next-parser está **archivado**) | bajo |
| Lingui | [lingui/js-lingui](https://github.com/lingui/js-lingui) | 5.936 | MIT | 2026-11-17 | catálogos | Alternativa i18n con extracción | bajo |
| jest-axe | [NickColley/jest-axe](https://github.com/NickColley/jest-axe) | 1.114 | MIT | 2026-11-02 | test result | A11y en tests unitarios de componentes | bajo |
| Accessibility Insights Web | [microsoft/accessibility-insights-web](https://github.com/microsoft/accessibility-insights-web) | 965 | MIT | 2026-11-03 | UI/JSON | Guía de prueba **manual** asistida (FastPass/Assessment) | n/a |
| Playwright MCP | [microsoft/playwright-mcp](https://github.com/microsoft/playwright-mcp) | 39.811 | Apache-2.0 | 2026-11-17 | árbol a11y/snapshots | Exploración interactiva por el agente; **costo alto en tokens**, usar solo para exploración | alto |
| Playwright CLI | [microsoft/playwright-cli](https://github.com/microsoft/playwright-cli) | 15.273 | Apache-2.0 | 2026-11-17 | texto/PNG | Alternativa más barata al MCP para capturas y codegen | bajo |
| Chrome DevTools MCP | [ChromeDevTools/chrome-devtools-mcp](https://github.com/ChromeDevTools/chrome-devtools-mcp) | 58.051 | Apache-2.0 | 2026-11-17 | traces/JSON | Trazas de rendimiento e INP en laboratorio vía agente | alto |
| a11y-llm-eval | [microsoft/a11y-llm-eval](https://github.com/microsoft/a11y-llm-eval) | 62 | MIT | 2026-05-07 | JSON | Referencia de diseño: Playwright + axe + aserciones R/BP | bajo |
| Web Interface Guidelines | [vercel-labs/web-interface-guidelines](https://github.com/vercel-labs/web-interface-guidelines) | 1.207 | MIT | 2026-10-05 | Markdown | Checklist de interfaz para el juicio LLM | bajo |
| agent-skills (Vercel) | [vercel-labs/agent-skills](https://github.com/vercel-labs/agent-skills) | 34.389 | sin SPDX | 2026-11-12 | Markdown | Ejemplos de skills de revisión web; revisar licencia antes de reutilizar | bajo |

Descartados: `GoogleChrome/web-vitals-extension` (archivado), `i18next/i18next-parser` (archivado), `abhinaba-ghosh/axe-playwright` (sin push desde 2025-09; se prefiere el oficial `@axe-core/playwright`).

---

## 6. Diseño propuesto del módulo `ux-frontend` del auditor

### 6.1 Pipeline (determinista primero, LLM al final)
```
0. Descubrir: framework (package.json), rutas (router/sitemap), flujos críticos (declarados en auditor.yml o inferidos por LLM desde rutas → CONFIRMAR con el usuario)
1. Estático (sin navegador): eslint jsx-a11y + compat, stylelint, i18n-cli, grep de patrones (onClick en div, img sin alt, catch vacío)
2. Levantar app (preview/build de producción, NO dev server para medir rendimiento)
3. Playwright por ruta × viewport {360, 768, 1280} × motor {chromium, webkit, firefox}:
   - axe (wcag2a, wcag2aa, wcag21aa, wcag22aa) → JSON
   - captura PNG de la pantalla completa
   - chequeos custom: scroll horizontal, targets <24px, Tab loop/foco visible, lang, consola con errores
   - estados forzados: red 500 / lenta 3G / respuesta vacía → captura
4. Lighthouse CI (3 corridas, mediana) en rutas clave, perfil móvil
5. Normalizar → findings.json (esquema común del auditor; SARIF opcional)
6. LLM: (a) resume findings por severidad; (b) evalúa capturas con heurísticas de Nielsen y estados vacío/error/carga; (c) prioriza la hoja de ruta
7. Usuarios (fuera de la IA): plantilla SUS/UMUX-Lite + guion de test de 5 tareas → el auditor calcula e interpreta
```

### 6.2 Reglas de severidad (para el gate)
- **Crítica:** violación axe `critical`; flujo crítico no completable por teclado; pantalla en blanco ante error de API; LCP > 4 s móvil.
- **Alta:** axe `serious`; CLS > 0,25; scroll horizontal en 360 px; formulario sin labels; sin estado de error.
- **Media:** axe `moderate`; CWV en "mejorable"; inconsistencia de tokens; sin estado vacío.
- **Baja:** axe `minor`; heurísticas cosméticas.

### 6.3 Escala de madurez UX/frontend (N1–N5)
| Nivel | Señales observables (todas verificables) |
|---|---|
| **N1 Prototipo** | El flujo feliz funciona en Chrome escritorio. Sin requisitos. |
| **N2 MVP** | 0 violaciones axe críticas en flujos clave; `lang`, labels y alt presentes; no hay scroll horizontal a 360 px; estados de carga y error presentes en las llamadas de red; LCP lab < 4 s. |
| **N3 Beta** | 0 axe critical/serious; navegación completa por teclado con foco visible; WCAG 2.2 AA nuevos (2.5.8, 2.4.11) revisados; LHCI en CI con umbrales (a11y ≥ 0,9, perf ≥ 0,8 móvil, **ESTIMACIÓN de umbral razonable**); pruebas en WebKit y Firefox; test con ≥5 usuarios y SUS medido. |
| **N4 Producción** | CWV de campo "buenos" en p75 (LCP ≤ 2,5 s, INP ≤ 200 ms, CLS ≤ 0,1) vía `web-vitals`; SUS ≥ 68 (promedio) con IC reportado; design tokens únicos; i18n sin strings hardcodeados (si aplica multi-idioma); auditoría manual de accesibilidad (lector de pantalla). |
| **N5 Escala** | Regresión visual y de a11y en cada PR; UMUX-Lite continuo in-app; presupuestos de rendimiento por ruta; monitoreo sintético (sitespeed.io); declaración de accesibilidad publicada; SUS ≥ ~80 (rango "excelente" según Bangor, **valor a confirmar en tabla original**). |

### 6.4 Hoja de ruta tipo ("qué hacer para crecer")
- N1→N2: convertir divs clicables en botones; agregar `lang`, labels y alt; envolver todo fetch con estados carga/error/vacío; corregir anchos fijos.
- N2→N3: activar LHCI + axe en CI; añadir la Tab-loop test; probar en WebKit; extraer tokens de color y espaciado; primer test con 5 usuarios + SUS.
- N3→N4: instrumentar `web-vitals` (RUM); optimizar LCP (imagen hero, SSR/streaming, división de bundles); revisión manual con lector de pantalla (NVDA/VoiceOver).
- N4→N5: regresión visual, presupuestos por ruta, encuesta UMUX-Lite continua.

---

## 7. Riesgos y límites del enfoque
- **axe sin violaciones ≠ accesible.** Cubre ~57 % del volumen de issues según el propio fabricante ([Deque](https://www.deque.com/blog/automated-testing-study-identifies-57-percent-of-digital-accessibility-issues)); hasta 80,39 % con pruebas guiadas (**NO VERIFICADO**: la página enlazada no contiene esa cifra).
- **Lighthouse en laboratorio es variable.** Se usan varias corridas y la mediana, y el rendimiento se mide sobre el build de producción.
- **WebKit de Playwright no es Safari iOS exacto.** Para N4+ se recomienda revisión en dispositivo real.
- **El juicio LLM sobre capturas puede alucinar problemas.** Cada hallazgo LLM debe apuntar a una captura y un selector, y se marca como "requiere verificación humana".
- **SUS/UMUX-Lite nunca se simulan con IA.** Si no hay datos de usuarios, el reporte dice "SIN DATOS DE USUARIOS" y el nivel máximo alcanzable es N3 parcial.
- **Privacidad:** las capturas de una app real pueden contener datos personales (relevante bajo Ley 19.628 en Chile). Hay que usar datos semilla o de prueba y no enviar capturas con datos reales a servicios externos.

---

## 8. Fuentes
- web.dev: [Core Web Vitals](https://web.dev/articles/vitals) · [Umbrales](https://web.dev/articles/defining-core-web-vitals-thresholds) · [INP](https://web.dev/articles/inp)
- W3C: [WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- Deque: [Estudio 57 %](https://www.deque.com/blog/automated-testing-study-identifies-57-percent-of-digital-accessibility-issues)
- WebAIM Million 2026 (vía secundarias): [Agiledrop](https://www.agiledrop.com/blog/web-accessibility-just-got-worse-a-year-into-eaa-enforcement) · [Priority Pixels](https://prioritypixels.co.uk/insights/web-accessibility-is-getting-worse-according-to-the-2026-webaim-million-report/)
- SUS: [MeasuringU](https://measuringu.com/?p=170) · [Bangor et al. 2009, JUS](https://uxpajournal.org/wp-content/uploads/sites/7/pdf/JUS_Bangor_May2009.pdf)
- UMUX-Lite: [Guía con referencias](https://www.koji.so/docs/umux-lite-guide) · [Borsci et al. 2015](https://informahealthcare.com/doi/abs/10.1080/10447318.2015.1064654)
- IA y accesibilidad: [Gurita y Vatavu, W4A 2025 (PDF)](https://mintviz.usv.ro/publications/2025.W4A.3.pdf) · [Reseña](https://a11y-paradise.onrender.com/reviews/69ae41f68b9c91225e628c18) · [microsoft/a11y-llm-eval](https://github.com/microsoft/a11y-llm-eval)
- Nielsen: [10 heurísticas](https://www.nngroup.com/articles/ten-usability-heuristics/) · [5 usuarios](https://www.nngroup.com/articles/why-you-only-need-to-test-with-5-users/)
- Lighthouse CI: [Configuración](https://googlechrome.github.io/lighthouse-ci/docs/configuration.html)


---

## Verificación

Verificación escéptica realizada el 2026-11-17 (gh api + WebFetch + extracción de texto del PDF W4A 2025).

### Repositorios (gh api repos/OWNER/REPO)
| Repo | Existe | Archivado | Estrellas | Licencia | Último push | Resultado |
|---|---|---|---|---|---|---|
| microsoft/playwright | sí | no | 100442 | Apache-2.0 | 2026-11-18 | OK |
| dequelabs/axe-core | sí | no | 7848 | MPL-2.0 | 2026-11-17 | OK |
| dequelabs/axe-core-npm | sí | no | 737 | MPL-2.0 | 2026-11-16 | OK |
| GoogleChrome/lighthouse | sí | no | 31147 | Apache-2.0 | 2026-11-18 | OK |
| GoogleChrome/lighthouse-ci | sí | no | 7154 | Apache-2.0 | 2026-11-17 | OK |
| harlan-zw/unlighthouse | sí | no | 4957 | MIT | 2026-11-17 | OK |
| pa11y/pa11y / pa11y-ci | sí | no | 4602 / 648 | LGPL-3.0 | 2026-11-16 | OK |
| IBMa/equal-access | sí | no | 788 | Apache-2.0 | 2026-11-13 | OK |
| GoogleChrome/web-vitals | sí | no | 8692 | Apache-2.0 | 2026-11-12 | OK |
| sitespeedio/sitespeed.io | sí | no | 5053 | MIT | 2026-11-17 | OK |
| jsx-eslint/eslint-plugin-jsx-a11y | sí | no | 3632 | MIT | 2026-01-06 | OK (actividad baja: ~10 meses sin push) |
| amilajack/eslint-plugin-compat | sí | no | 3188 | MIT | 2026-07-23 | OK (fecha de push añadida) |
| browserslist/browserslist | sí | no | 13588 | MIT | 2026-11-16 | OK |
| stylelint/stylelint | sí | no | 11553 | MIT | 2026-11-18 | OK |
| style-dictionary/style-dictionary | sí | no | 4885 | Apache-2.0 | 2026-11-03 | OK |
| i18next/i18next-cli | sí | no | 251 | MIT | 2026-11-17 | OK |
| i18next/i18next-parser | sí | **sí** | 552 | MIT | 2025-10-01 | Correctamente descartado |
| microsoft/accessibility-insights-web | sí | no | 965 | MIT | 2026-11-03 | OK |
| microsoft/playwright-mcp | sí | no | 39811 | Apache-2.0 | 2026-11-17 | OK |
| microsoft/playwright-cli | sí | no | 15273 | Apache-2.0 | 2026-11-17 | OK |
| ChromeDevTools/chrome-devtools-mcp | sí | no | 58052 | Apache-2.0 | 2026-11-17 | OK (58051→58052, diferencia trivial) |
| microsoft/a11y-llm-eval | sí | no | 62 | MIT | 2026-05-07 | OK (proyecto pequeño, solo referencia) |
| vercel-labs/web-interface-guidelines | sí | no | 1207 | MIT | 2026-10-05 | OK |
| NickColley/jest-axe | sí | no | 1114 | MIT | 2026-11-02 | OK |

Ningún repositorio inventado. Ninguno de los recomendados está archivado.

### Cifras y estudios
| Afirmación | Fuente | Resultado |
|---|---|---|
| W4A 2025: violaciones (expertos) 58 % → 19 % con prompt WCAG | PDF, sección 4.2.1 | CONFIRMADO |
| W4A 2025: landmarks 11 %, headings 33 %, skip links 0 % sin prompt (94/89/100 % con prompt) | PDF, Tabla 3 | CONFIRMADO |
| W4A 2025: acceso por teclado 48 % → 94 % | PDF, Tabla 4 | CONFIRMADO con matiz: es el % de **elementos interactivos**, no de UIs. Corregido en el texto y en el JSON |
| W4A 2025: herramientas automáticas 17,32 % vs 15,93 % | PDF, sección 4.1 | CONFIRMADO; aclarado que 17,32 % corresponde al prompt WCAG (más alto) |
| W4A 2025: idioma de página persiste como falla con prompt WCAG | PDF, sección 4.1 | CONFIRMADO ("persistent issues with language specification") |
| Deque: automatización cubre 57 % del volumen | Blog Deque | CONFIRMADO 57 %; decimal 57,38 % no aparece en la página enlazada (NO VERIFICADO) |
| Deque: 80,39 % con pruebas guiadas | Blog Deque | **NO VERIFICADO** (no aparece en la página enlazada) |
| CWV p75: LCP 2,5/4 s, INP 200/500 ms, CLS 0,1/0,25 | web.dev | CONFIRMADO |
| WebAIM Million 2026: bajo contraste en 83,9 % de home pages, falla #1 | Agiledrop (secundaria) | CONFIRMADO en la fuente secundaria (sube desde 79,1 %); fuente primaria WebAIM no consultada |
| Bangor 2009: Excelente 85,5 / Bueno 71,4 / OK 50,9 | PDF JUS | **NO VERIFICADO**: la URL devuelve 404; mantener como valor a confirmar |
| W4A 2025: "80 UIs" | PDF | NO VERIFICADO en esta pasada (modelos GPT-4-turbo y Claude 3.5 Haiku sí confirmados) |

### Correcciones aplicadas
1. Precisión del 48 % (elementos interactivos, no UIs).
2. Dirección de la diferencia 17,32 % vs 15,93 %.
3. 57,38 % y 80,39 % de Deque marcados NO VERIFICADO; se mantiene ~57 %.
4. URL de Bangor 2009 caída (404): valores SUS por adjetivo marcados NO VERIFICADO.
5. Fecha de push de eslint-plugin-compat (2026-07-23) añadida; nota de baja actividad de eslint-plugin-jsx-a11y.

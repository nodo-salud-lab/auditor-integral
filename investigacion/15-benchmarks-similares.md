# 15 · Benchmarks publicados de herramientas similares

Fecha de consulta: 2026-11-18. Fuentes revisadas con WebSearch/WebFetch y `gh api`. Este documento **no** cambia código ni configuración; sirve para situar las métricas del auditor (REAUDITORIA.md §R3.7) y el presupuesto de tokens (PLAN_MAESTRO §9) frente a cifras publicadas.

**Convenciones de este documento**

- **Independencia:** `INDEPENDIENTE` = estudio académico o tercero sin producto en competencia. `PROVEEDOR` = afirmación de quien vende la herramienta. `PROVEEDOR-RIVAL` = medición publicada por un competidor (conflicto de interés en sentido contrario). `MIXTO` = benchmark de un tercero, pero la cifra la conozco solo por lo que cita un proveedor.
- **NO VERIFICADO:** la cifra circula, pero no pude leerla en la fuente primaria o la fuente no publica método. No se usa para calibrar nada.
- Las fechas son las de publicación de la fuente (o la versión de arXiv leída).
- Sellos según CLAUDE.md: **SÍNTESIS** para las tablas, **ESTIMACIÓN** para las comparaciones con el auditor.

---

## 1. Advertencia de comparabilidad (leer antes de las tablas)

Las cifras **no son directamente comparables** entre filas, y tampoco con el auditor:

1. **Unidad de análisis distinta.** OWASP Benchmark y CASTLE puntúan por *caso de prueba* (TP/FP/TN/FN con verdad de terreno cerrada). Los estudios de revisión de PR (Greptile, Martian) puntúan por *bug sembrado o comentario*. Semgrep sobre Claude Code puntúa por *hallazgo reportado* (solo VPP, sin recall). El auditor puntúa por *defecto sembrado* (sensibilidad) y por *hallazgo* (VPP), con controles limpios para FP.
2. **Lenguaje y clase de defecto.** CASTLE es C; OWASP Benchmark es Java; SecVulEval y PrimeVul son C/C++; Semgrep–Claude Code es Python web. El auditor apunta a apps web JS/TS con Supabase y abarca controles no solo de seguridad.
3. **"Precisión" con definiciones distintas.** Semgrep Assistant reporta *acuerdo humano*; Anthropic Code Review reporta *% de hallazgos marcados incorrectos por el ingeniero* (desacuerdo opt-in, subestima los FP); Graphite reporta *tasa de comentarios ruidosos*. Ninguna es VPP contra verdad de terreno.
4. **Sesgo de espectro del auditor.** La app sembrada (brazo A) la construyó el mismo equipo que escribió las reglas; la sensibilidad de 0,85 es optimista frente a código real no sembrado. Un benchmark externo (p. ej., OWASP Benchmark o CASTLE) correría con reglas no ajustadas a él.

---

## 2. Tabla comparable

**SÍNTESIS.** Sens. = sensibilidad/recall/TPR. Prec. = precisión/VPP salvo que se indique otra cosa. "—" = no publicado.

### 2.1 SAST clásico y herramientas deterministas

| Herramienta | Tipo | Benchmark | Sens./recall | Precisión / FP | Costo | Fuente (fecha) | Independencia |
|---|---|---|---|---|---|---|---|
| CodeQL | SAST | CASTLE (250 casos C, 150 vulnerables, 25 CWE) | 29 % (45/150) | Prec. 48 %; 49 FP; CASTLE Score 634 | — | [arXiv 2503.09433v2](https://arxiv.org/html/2503.09433v2) (mar-2025) | INDEPENDIENTE |
| Semgrep Code | SAST | CASTLE | 23 % (36/150) | Prec. 34 %; 70 FP; score 541 | — | ídem | INDEPENDIENTE |
| SonarQube | SAST | CASTLE | 29 % (43/150) | Prec. 24 %; 135 FP; score 511 | — | ídem | INDEPENDIENTE |
| Snyk Code | SAST | CASTLE | 17 % (26/150) | Prec. 38 %; 42 FP; score 552 | — | ídem | INDEPENDIENTE |
| GitLab SAST | SAST | CASTLE | 23 % | Prec. 13 %; 240 FP; score 374 | — | ídem | INDEPENDIENTE |
| ESBMC | Verificación formal | CASTLE | 35 % | Prec. 62 %; 32 FP; score 661 (mejor no-LLM) | — | ídem | INDEPENDIENTE |
| ESBMC + CodeQL | Combinación | CASTLE | — | score 814 | — | ídem | INDEPENDIENTE |
| Mejor SAST por lenguaje (Horusec Java, CodeQL C, DevSkim Python) | SAST | Repo-level, 270 CVE reales en 134 proyectos | 37,5 % / 44,4 % / 30,0 % (≥1 vuln. detectada por CVE) | "Marked function ratio" 1,7 % / 5,2 % / 4,5 % (proxy de FP) | — | [arXiv 2407.16235v1](https://arxiv.org/html/2407.16235v1) (jul-2024) | INDEPENDIENTE |
| SAST combinados | Combinación | ídem | 50,0 % / 55,6 % / 50,0 % | marked 4,3 % / 7,2 % / 7,7 % | — | ídem | INDEPENDIENTE |
| CodeQL | SAST | CWE-Bench-Java (120 vulns reales) | 27/120 = 22,5 % | Tasa de falso descubrimiento ≈ 90 % (IRIS es 5,21 pp menor que CodeQL) | — | [ICLR 2025, IRIS](https://proceedings.iclr.cc/paper/2025/hash/582d4e27fa24168f3af1f4582655034b-Abstract-Conference.html); [arXiv 2405.17238](https://www.arxiv.org/pdf/2405.17238) | INDEPENDIENTE |
| SonarQube Developer 7.9.1 | SAST | OWASP Benchmark Java v1.2, solo 1.200 casos de inyección | TPR 85 % | FPR 1 % (Sonar lo llama "False-Detection Rate"); score 84 | — | [SonarSource](https://community.sonarsource.com/t/tech-story-takeaways-from-building-a-sast-product-and-why-owasp-benchmark-is-not-enough/15126) (2019); [blog Sonar](https://www.sonarsource.com/blog/enhancing-sast-detection-leveraging-benchmarks-for-measuring-progress/) (26-sep-2023) | PROVEEDOR (subconjunto elegido por el proveedor; descartó 372 casos) |
| Semgrep | SAST | OWASP Benchmark | TPR 87,06 % | FPR 42,09 % | — | Xygeni (vía búsqueda; versión de Semgrep no identificada) | PROVEEDOR-RIVAL · **NO VERIFICADO** |
| CodeQL | SAST | OWASP Benchmark | — | — | — | No encontré cifra publicada | **NO VERIFICADO** |
| Fluid Attacks SAST | SAST | OWASP Benchmark v1.2 | TPR 100 % | FPR 0 %; score 100 | — | [docs Fluid Attacks](https://docs.fluidattacks.com/find-fix/use-cli/overview/scanner-results-owasp-benchmark) (act. 27-oct-2026) | PROVEEDOR |

Notas OWASP Benchmark (fuente primaria: [repo OWASP/www-project-benchmark, `tab_scoring.md` y `tab_java_test_cases.md`](https://github.com/OWASP/www-project-benchmark), leído con `gh api` el 2026-11-18):
- v1.2 para Java tiene **2.740 casos** (11 categorías, verdaderos y falsos positivos en todas). La puntuación es el **índice de Youden** (TPR − FPR), escalado a 0-100, y puede ser negativa.
- **OWASP no publica hoy una tabla oficial de puntuaciones por herramienta.** Ofrece generadores de scorecard (BenchmarkUtils) y pide que los resultados sean reproducibles. Toda cifra de OWASP Benchmark que circula es autoinformada por un proveedor o un rival.
- El propio OWASP advierte que los casos son "considerablemente más simples" que las aplicaciones reales.

### 2.2 LLM como detector (académico)

| Herramienta | Tipo | Benchmark | Sens./recall | Precisión / FP | Costo | Fuente (fecha) | Independencia |
|---|---|---|---|---|---|---|---|
| GPT-o3 mini | LLM | CASTLE | 78 % (126/150) | Prec. 63 %; 73 FP; score 977 (mejor global) | — | [arXiv 2503.09433v2](https://arxiv.org/html/2503.09433v2) | INDEPENDIENTE |
| o1 | LLM | CASTLE | 78 % | Prec. 59 %; 90 FP | — | ídem | INDEPENDIENTE |
| DeepSeek R1 | LLM | CASTLE | 90 % | Prec. 47 %; 166 FP | — | ídem | INDEPENDIENTE |
| GPT-4o | LLM | CASTLE | 76 % | Prec. 54 %; 116 FP | — | ídem | INDEPENDIENTE |
| LLaMA 3.1 8B | LLM | CASTLE | 51 % | Prec. 20 %; 337 FP | — | ídem | INDEPENDIENTE |
| Claude 3.7 Sonnet | LLM multiagente | SecVulEval (5.867 CVE, 25.440 funciones C/C++) | Función 75,6 %; sentencia 53,2 % | Prec. función 41,9 %; sentencia 15,4 %; F1 sentencia 23,8 % (mejor) | No publicado | [arXiv 2505.19828v1](https://arxiv.org/html/2505.19828v1) (26-may-2025) | INDEPENDIENTE |
| GPT-4.1 | LLM multiagente | SecVulEval | Función 73,1 %; sentencia 49,2 % | Prec. función 40,7 %; sentencia 14,5 %; F1 sentencia 22,4 % | No publicado | ídem | INDEPENDIENTE |
| StarCoder2-7B | Code LM | PrimeVul vs BigVul | — | F1 68,26 % en BigVul → 3,09 % en PrimeVul (18,05 % tras ajuste fino) | — | [arXiv 2403.18624](https://arxiv.org/abs/2403.18624) (mar-2024; ICSE 2025) | INDEPENDIENTE |
| GPT-3.5 / GPT-4 | LLM | PrimeVul | — | "Sin mejora" sustancial según los autores; cifras por modelo no extraídas | — | ídem | INDEPENDIENTE · cifras por modelo **NO VERIFICADO** |
| 8 LLM (incl. GPT-4, PaLM2) | LLM | SecLLMHolmes, 228 escenarios C/Python | — | FPR alto en todos; respuestas no deterministas; con renombrar variables/funciones o añadir librerías, respuestas incorrectas en 26 % (PaLM2) y 17 % (GPT-4) | — | [arXiv 2312.12575](https://arxiv.org/abs/2312.12575) (IEEE S&P 2024) | INDEPENDIENTE |
| Mejor LLM ajustado por lenguaje | LLM fine-tuned | Repo-level 2407.16235 | 100 % (Java, C) / 90 % (Python) | marked 21,8 % / 25,6-36,2 % / 50,5 %; rango global 3,5-77,4 % | — | [arXiv 2407.16235v1](https://arxiv.org/html/2407.16235v1) | INDEPENDIENTE |
| IRIS + GPT-4 (LLM + CodeQL) | Híbrido | CWE-Bench-Java | 55/120 = 45,8 % (v1 decía 69) | FDR medio 84,82 % | — | [ICLR 2025](https://proceedings.iclr.cc/paper/2025/hash/582d4e27fa24168f3af1f4582655034b-Abstract-Conference.html) | INDEPENDIENTE |
| LLM de reparación (Gemini Flash) | Reparación | Vul4J (64 vulns Java, 319 parches) | — | 24,8 % de parches totalmente correctos; 0 % en validación de entradas | — | [arXiv 2603.10072](https://arxiv.org/html/2603.10072v1) (mar-2026) | INDEPENDIENTE (preprint; versión de Gemini ambigua entre v1 y v2) |
| GPT-4o | Reparación | Vul4J | — | 26 vulns (62 %) reparadas al menos una vez en 3 corridas | — | Antal et al. 2025 (vía búsqueda) | INDEPENDIENTE · **NO VERIFICADO** en fuente primaria |

Nota: Vul4J se usa sobre todo para **reparación**, no para detección. No encontré resultados de detección con LLM sobre Vul4J.

### 2.3 Agentes de codificación y revisores con IA (productos)

| Herramienta | Tipo | Benchmark | Sens./recall | Precisión / FP | Costo | Fuente (fecha) | Independencia |
|---|---|---|---|---|---|---|---|
| Claude Code (v1.0.32, Sonnet 4) | Agente LLM, prompt de seguridad | 11 apps web Python reales; 6 clases de vulnerabilidad | — (sin verdad de terreno de FN) | VPP 14 % (46 TP / 330 reportados); IDOR 22 %; SQLi 5 % | **USD 114** en total (11 apps × 6 clases, sin las corridas repetidas) | [Semgrep blog](https://semgrep.dev/blog/2025/finding-vulnerabilities-in-modern-web-apps-using-claude-code-and-openai-codex) (2-sep-2025) | PROVEEDOR-RIVAL (Semgrep vende detección) |
| OpenAI Codex (v0.2.0, o4-mini) | Agente LLM | ídem | — | VPP 18 % (21/115) | No registrado | ídem | PROVEEDOR-RIVAL |
| No determinismo (Claude Code) | — | Misma app, mismo prompt, 3 corridas | 3, 6 y 11 hallazgos distintos | — | — | ídem | PROVEEDOR-RIVAL |
| Semgrep Assistant / Multimodal | Triage LLM sobre SAST | >2.000 hallazgos triados por su equipo | Acuerdo en TP 96 % | **Acuerdo en FP 41 %** (25 % en la v1); "FP confidence rate" 96 % = acierta cuando marca FP, no cuántos FP atrapa | — | [Semgrep blog](https://semgrep.dev/blog/2025/building-an-appsec-ai-that-security-researchers-agree-with-96-of-the-time/) (22-ene-2025); [docs métricas](https://docs.semgrep.dev/semgrep-assistant/metrics) (21-ago-2025) | PROVEEDOR |
| Semgrep Assistant (uso) | ídem | 6,5 M hallazgos, 3.500 clientes | — | Reducción media de hallazgos 60 %; acuerdo de usuarios 96 % | — | [docs métricas](https://docs.semgrep.dev/semgrep-assistant/metrics) (21-ago-2025) | PROVEEDOR |
| Semgrep "98 % fewer false positives" | Marketing | — | — | — | — | [try.semgrep.dev](https://try.semgrep.dev/snyk-vs-semgrep/) | PROVEEDOR · **NO VERIFICADO** (sin método) |
| Anthropic Code Review | Multiagente + paso de verificación | Uso interno de Anthropic | PR con comentarios sustantivos: 16 % → 54 %; PR >1.000 líneas: 84 % con hallazgos (7,5 de media); <50 líneas: 31 % (0,5) | <1 % de hallazgos "marcados incorrectos" (desacuerdo explícito; subestima FP) | **USD 15-25 por revisión** en promedio; ≈20 min | [claude.com/blog/code-review](https://claude.com/blog/code-review) (9-mar-2026); [docs de costos](https://code.claude.com/docs/en/code-review-costs) | PROVEEDOR |
| claude-code-security-review (GitHub Action) | LLM + filtro de FP con un segundo cliente Claude | — | — | Promete "menos FP", sin cifras. Excluye por defecto DoS y rate limiting. "No endurecido contra prompt injection" | No publicado (modelo por defecto `claude-opus-4-1-20250805`; timeout 20 min) | [README](https://github.com/anthropics/claude-code-security-review) (leído 2026-11-18) | PROVEEDOR · métricas **NO VERIFICADO** (no existen) |
| Greptile | Revisor de PR | 50 bugs reales en 5 repos (jul-2025) | 82 % | No publicado ("no afecta el score") | — | [greptile.com/benchmarks](https://greptile.com/benchmarks) | PROVEEDOR (benchmark propio; además el detalle por caso no cuadra con algunos totales) |
| Cursor Bugbot / Copilot / CodeRabbit / Graphite | Revisores de PR | ídem Greptile | 58 % / 54 % / 44 % / 6 % | No publicado | — | ídem | PROVEEDOR-RIVAL (medidos por Greptile) |
| Greptile | Revisor de PR | Martian Code Review Bench (snapshot citado) | 50,6 % | Prec. 76,2 %; F1 60,8 % | — | [Greptile](https://www.greptile.com/content-library/greptile-martian-code-review-benchmark) | MIXTO · leaderboard primario **NO VERIFICADO** (la página de Martian no mostró datos al leerla) |
| CodeRabbit | Revisor de PR | Martian (ene-feb 2026) | — | Prec. 49,2 %; F1 51,2 % | — | [CodeRabbit (JA)](https://www.coderabbit.ai/ja/blog/coderabbit-tops-martian-code-review-benchmark-ja) (mar-2026) | MIXTO · **NO VERIFICADO** en Martian |
| CodeRabbit + Opus 5 | Revisor de PR | Benchmark interno de CodeRabbit | 61,1 % vs 55,2 % base | Precisión "accionable" 35,2 % vs 39,3 % base | — | [IT Brief](https://itbrief.co.uk/story/coderabbit-says-opus-5-5-beats-baseline-on-bug-review) (2026) | PROVEEDOR · fuente secundaria |
| Graphite Diamond | Revisor de PR | Producción | — | "<3 % de comentarios ruidosos"; 52 % de comentarios aceptados | — | [Graphite guía](https://graphite.com/guides/effectiveness-and-limitations-of-ai-code-review) | PROVEEDOR · **NO VERIFICADO** |
| GitHub Copilot Autofix | Reparación sobre alertas CodeQL | Beta pública may-jul 2024 | Al lanzarse, ">90 % de los tipos de alerta" y ">2/3 corregidas con poca o ninguna edición" | Mediana 28 min hasta el commit del fix vs 1,5 h manual | Incluido en GHAS | [GitHub blog](https://github.blog/news-insights/product-news/secure-code-more-than-three-times-faster-with-copilot-autofix/) (ago-2024); [docs uso responsable](https://docs.github.com/en/enterprise-cloud@latest/code-security/responsible-use/responsible-use-autofix-code-scanning) | PROVEEDOR · cifras de cobertura **NO VERIFICADO** en la documentación vigente |
| Snyk Agent Fix (ex DeepCode AI Fix) | Reparación | — | — | ">80 % de precisión" en los fixes | — | [Snyk blog](https://snyk.io/blog/building-ai-trust-with-snyk-code-and-snyk-agent-fix) | PROVEEDOR · **NO VERIFICADO** (sin método) |
| DeepCode AI Fix (paper) | Reparación | Defectos de análisis estático en JS | — | >80 % de defectos eliminados; coincidencia exacta con el fix humano en 10-50 % | — | [arXiv 2402.13291](https://www.arxiv.org/pdf/2402.13291) (feb-2024) | PROVEEDOR (autores de Snyk), con método publicado |

---

## 3. Costos en tokens o dinero publicados para revisiones agentic

| Qué | Cifra | Unidad | Fuente | Independencia |
|---|---|---|---|---|
| Anthropic Code Review | USD 15-25, ≈20 min | por revisión de PR (promedio); escala con el tamaño del PR, el nivel y los candidatos a verificar | [claude.com/blog/code-review](https://claude.com/blog/code-review) (9-mar-2026) | PROVEEDOR |
| Claude Code con prompts de seguridad | USD 114 | 11 apps × 6 clases (≈66 corridas, ≈USD 1,7 por corrida app-clase; cálculo propio) | [Semgrep](https://semgrep.dev/blog/2025/finding-vulnerabilities-in-modern-web-apps-using-claude-code-and-openai-codex) (2-sep-2025) | PROVEEDOR-RIVAL |
| Escaneo de un código completo con LLM | "decenas a cientos de dólares" | por escaneo | ídem | PROVEEDOR-RIVAL · estimación de los autores |
| Tokens por revisión (cualquier producto) | — | — | Ninguna fuente revisada publica tokens por revisión | **NO VERIFICADO** |
| SecVulEval / CASTLE / PrimeVul | — | — | No informan tokens ni costo | — |

**Conclusión de la §3:** no existe una cifra publicada y verificable de *tokens* por auditoría de seguridad agentic. Solo hay costos en dólares autoinformados (Anthropic) o medidos por un rival (Semgrep). El meta-presupuesto del auditor (≤ 60 k tokens en modo estándar, PLAN_MAESTRO §9) sigue siendo **ESTIMACIÓN** sin comparador externo directo; la conversión a dólares depende del modelo y del precio vigente, que no verifiqué aquí.

---

## 4. Dónde queda auditor-integral (ESTIMACIÓN)

Métricas del auditor en la app sembrada (REAUDITORIA.md §R3.7, corrida de cierre, IC95 % de Wilson):

| Métrica | Auditor (brazo A, autoevaluación) | Referencia publicada más cercana |
|---|---|---|
| Sensibilidad global | 57/67 = **0,85** (0,75-0,92) | LLM frontera en CASTLE: 0,76-0,90. SAST en CASTLE: 0,09-0,35. SAST en CVE reales a nivel de repo: ≤ 0,44 |
| Sensibilidad SEG·N1 (secretos, configuración) | 23/23 = **1,00** (0,86-1,00) | Sin benchmark publicado comparable para secretos/configuración en apps vibe-coded |
| VPP | 57/82 = **0,70** (0,59-0,78) | CASTLE: o3-mini 0,63, GPT-4o 0,54, CodeQL 0,48, Semgrep 0,34. Claude Code "solo prompt" en apps reales: 0,14. Greptile en Martian (MIXTO): 0,76 |
| FP en controles limpios | **0/56** (0,00-0,06) | OWASP Benchmark mide FPR por caso; no hay cifra oficial publicada. SecLLMHolmes: FPR alto en todos los LLM |
| Determinismo | Mismos fingerprints entre corridas (criterio F1-3) | Claude Code: 3/6/11 hallazgos con el mismo prompt (Semgrep); SecLLMHolmes: todos los modelos cambian de respuesta |
| Costo | ≤ 60 k tokens en modo estándar (meta, no medida) | Anthropic Code Review USD 15-25/PR; Claude Code USD ≈1,7 por app-clase (cálculo propio sobre Semgrep) |

**Lectura (ESTIMACIÓN, no conclusión):**

1. Las cifras del auditor caen **dentro o por encima** de lo publicado para LLM y muy por encima de SAST puro. Pero son una **autoevaluación sobre defectos sembrados por el mismo equipo**. Eso es justamente lo que PrimeVul muestra que infla el rendimiento (F1 68 % → 3 % al pasar a datos realistas). No se puede afirmar superioridad.
2. La ventaja estructural defendible es el **determinismo** y el **0/56 en controles limpios** (fail-closed + scripts), frente a la variabilidad documentada de los LLM. Es coherente con el hallazgo de 2407.16235: combinar herramientas sube la detección y combinar LLM baja los FP.
3. Ninguna cifra de proveedor de esta tabla sirve para calibrar `pesos.toml` ni `umbrales.toml` (DECISIONES #1 y #2): las definiciones de "precisión" no son VPP contra verdad de terreno.

## 5. Brechas y acciones sugeridas (GUÍA; la decisión es del investigador)

- **Validación externa barata (opción A):** correr los adaptadores SAST del auditor sobre **OWASP Benchmark Java v1.2** (2.740 casos) y generar el scorecard con BenchmarkUtils. Da un Youden comparable con cualquier tercero. Limitación: Java, fuera del stack objetivo, y solo mide la capa SAST.
- **Validación externa (opción B):** CASTLE (C, 250 casos) da comparación directa contra LLM y SAST con el mismo protocolo. Limitación: C, no web.
- **Comparador LLM puro (ya exigido en §9 para F6):** replicar el diseño de Semgrep (Claude Code con prompt por clase sobre kine us u otra app real) y medir VPP, costo en USD y tokens en 3 corridas. Es la única forma de verificar la afirmación de ahorro.
- **Datos que faltan:** el leaderboard primario de Martian, los scores oficiales de CodeQL/Semgrep en OWASP Benchmark y los tokens por revisión de cualquier producto. Todo eso queda **NO VERIFICADO**.

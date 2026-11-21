# 04 — Infraestructura, saturación, carga y escalabilidad

Fecha: 2026-11-17 · Dominio del auditor-integral: `infra-escalabilidad`
Sellos: **SÍNTESIS** (evidencia integrada con fuente), **ESTIMACIÓN** (heurística con supuestos explícitos), **GUÍA** (procedimiento), **NO VERIFICADO** (no se pudo confirmar con fuente primaria).

---

## 0. Resumen ejecutivo

1. En proyectos hechos con vibe coding, los fallos de infraestructura rara vez vienen de la plataforma elegida. Casi siempre salen de cuatro omisiones: **(a)** no hay límite de consumo (rate limiting ni tope de gasto), **(b)** las conexiones a la BD desde serverless no pasan por un pooler, **(c)** no hay observabilidad (no se sabe cuándo ni por qué falla) y **(d)** nunca se midió cuánta carga aguanta.
2. Casi todo se puede auditar **de forma determinista** con CLI que devuelven JSON/SARIF: `trivy config`, `checkov`, `hadolint`, `actionlint`/`zizmor`, `kubeconform`/`kube-linter` y `infracost`, además de `k6` con `--summary-export` para medir capacidad. El LLM solo hace falta para cuatro cosas: clasificar la arquitectura, elegir la plataforma según el contexto, interpretar los resultados de carga y redactar la hoja de ruta.
3. Escala de capacidad: no se adivina, **se mide**. La secuencia es prueba *breakpoint* con k6 (tasa de llegada abierta), luego la ley de Little para pasar de RPS a usuarios concurrentes, y por último un margen de seguridad.
4. Marcos de referencia: Google SRE (4 señales doradas, PRR), USE/RED, AWS Well-Architected (6 pilares), 12-Factor y OWASP API4:2023 (consumo de recursos sin restricción).

---

## 1. Marcos de referencia (SÍNTESIS)

| Marco | Qué aporta al auditor | Fuente |
|---|---|---|
| **Google SRE — 4 señales doradas** | Latencia, tráfico, errores y saturación. Indica medir también la latencia de los errores y usar percentiles e histogramas en vez de promedios, porque un promedio de 100 ms puede esconder un 1 % de peticiones de 5 s. El p99 en ventanas cortas sirve como alerta temprana de saturación. | https://sre.google/sre-book/monitoring-distributed-systems/ |
| **Google SRE — Production Readiness Review (PRR)** | Ejes que revisa: arquitectura y dependencias; instrumentación, métricas y monitoreo; respuesta a emergencias; planificación de capacidad; gestión de cambios; rendimiento (disponibilidad, latencia, eficiencia). Es la base del "checklist listo para producción". | https://sre.google/sre-book/evolving-sre-engagement-model/ |
| **Método USE (Brendan Gregg)** | Para cada *recurso* (CPU, memoria, disco, red, pool de conexiones) se revisa utilización, saturación y errores. Sirve para infraestructura. | https://www.brendangregg.com/usemethod.html |
| **Método RED (Tom Wilkie)** | Para cada *servicio* o endpoint se mide tasa (rate), errores y duración, con duración en p95/p99. Sirve para APIs. | https://grafana.com/files/grafanacon_eu_2018/Tom_Wilkie_GrafanaCon_EU_2018.pdf · https://grafana.com/blog/what-is-observability-best-practices-key-metrics-methodologies-and-more/ |
| **AWS Well-Architected** | 6 pilares: excelencia operativa, seguridad, fiabilidad, eficiencia de rendimiento, optimización de costos y sostenibilidad. Sirve de taxonomía para el informe final. | https://aws.amazon.com/architecture/well-architected/ |
| **12-Factor App** | 12 factores: código base, dependencias, configuración, servicios de respaldo, build/release/run, procesos, port binding, concurrencia, desechabilidad, paridad dev/prod, logs y procesos de admin. Los factores 3 (config en entorno), 6 (procesos sin estado), 9 (arranque y parada rápidos) y 11 (logs a stdout) se pueden chequear de forma estática. | https://12factor.net/ |
| **OWASP API Security Top 10 2023 — API4: Unrestricted Resource Consumption** | Ampara la exigencia de rate limiting, límites de tamaño o paginación y timeouts. Une seguridad con costo (*denial of wallet*). | https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/ |
| **SLO/SLI (Google SRE Workbook)** | Un SLI es una métrica de comportamiento (por ejemplo, la proporción de peticiones con status < 500 y latencia < X). Un SLO es la meta sobre ese SLI. El presupuesto de error es 1 − SLO. | https://sre.google/workbook/implementing-slos/ |
| **k6 — tipos de prueba** | Smoke, carga promedio, estrés, soak (resistencia), spike (picos) y breakpoint (punto de ruptura). | https://grafana.com/docs/k6/latest/testing-guides/test-types/ |

---

## 2. Fallos más probables en proyectos de vibe coding (infra y carga)

Contexto con fuente: Veracode (2025) evaluó más de 100 LLM en 80 tareas y encontró vulnerabilidades alineadas con OWASP Top 10 en el **45 %** de los casos, sin mejora en el tiempo (https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/). El estudio lo hizo un proveedor de herramientas de seguridad, así que hay que tratarlo como resultado del propio vendedor. Los casos de facturas enormes (por ejemplo, USD 98k/día en Firebase o USD 128k por una clave filtrada) circulan en foros y blogs y quedan como **NO VERIFICADO** en cuanto a cifras. El patrón sí está documentado en InfoQ (https://www.infoq.com/news/2025/08/denial-of-wallet-attack-cloud).

| # | Fallo | Por qué aparece con IA o vibe coding | Detección | Severidad |
|---|---|---|---|---|
| F1 | **Sin rate limiting ni tope de gasto** en endpoints públicos, sobre todo en los que llaman a APIs de LLM o de pago. Resultado: *denial of wallet* o caída. | El LLM genera el "camino feliz". El rate limiting es un requisito no funcional que nadie pide en el prompt. | Determinista parcial: grep/semgrep busca middleware de rate limit (`@upstash/ratelimit`, `express-rate-limit`, `slowapi`, reglas WAF en `vercel.json`/Cloudflare). Manual: comprobar que existen alertas de presupuesto en el proveedor. | crítica |
| F2 | **Conexiones a BD sin pooler desde serverless.** Cada invocación abre una conexión, se agotan `max_connections` y aparece el error "too many connections". | El tutorial típico usa la cadena de conexión directa. El LLM copia `new Pool()` dentro del handler. | Determinista: regex sobre `DATABASE_URL` o `.env.example` (puerto 5432 directo vs 6543 o `-pooler`). AST/grep: cliente creado dentro del handler. Para Prisma en transaction mode hace falta `pgbouncer=true`. Supabase recomienda el pooler en transaction mode (puerto 6543) para serverless, cliente a nivel de módulo, pool de 1 y prepared statements desactivados (https://supabase.com/docs/guides/database/connecting-to-postgres). Neon recomienda pools pequeños de 1 a 2 conexiones por contenedor más PgBouncer (https://neon.com/docs/connect/connection-pooling). | crítica |
| F3 | **Trabajo largo dentro de la petición HTTP** (IA, PDFs, emails masivos, scraping). Termina en timeouts 504. | El LLM lo pone todo en el route handler y no sugiere colas. | Determinista parcial: `maxDuration` en la configuración y llamadas a SDK de LLM o puppeteer dentro de las rutas. Vercel tiene un máximo de 300 s en Hobby y 800 s en Pro (1800 s en beta) y devuelve 504 `FUNCTION_INVOCATION_TIMEOUT` (https://vercel.com/docs/functions/limitations). Juicio LLM: ¿necesita cola o workflow? | alta |
| F4 | **Payloads grandes por la función** (subidas de archivos a través del backend). Resultado: 413. | El patrón ingenuo es "subir al servidor y de ahí a S3". | Determinista: grep de `multer`, `formData` en rutas serverless. Vercel limita el request/response a 4,5 MB (misma fuente). Recomendación: URLs prefirmadas. | media |
| F5 | **Sin observabilidad**: no hay Sentry ni OTel, no hay logs estructurados, health check ni alertas. Los fallos son silenciosos. | El vibe coder prueba "en su navegador". El LLM no instala instrumentación si no se le pide. | Determinista: dependencias (`@sentry/*`, `@opentelemetry/*`), existencia de un endpoint `/health`, logger estructurado (pino, winston, structlog). | alta |
| F6 | **Nunca se probó la carga**, así que se desconoce la capacidad (N+1, falta de índices, consultas sin `LIMIT`). | La IA escribe ORM con N+1 y listados sin paginar. | Determinista: k6 breakpoint más `EXPLAIN` (dominio BD). Estático: búsqueda de `findMany()` sin `take`/`limit`. | alta |
| F7 | **Estado en memoria o disco local en serverless o en varias réplicas** (sesiones, caché, uploads en `/tmp`). | Viola el factor 6 de 12-Factor. Funciona en local y falla al escalar. | Estático (semgrep): `fs.writeFile` fuera de `/tmp`, `Map` global usado como caché de sesión, `express-session` con MemoryStore. | alta |
| F8 | **Dockerfile inseguro o pesado**: `latest`, root, sin multi-stage, secretos en ARG/ENV. | Las plantillas generadas por LLM suelen omitir `USER` y fijar versiones. | Determinista: `hadolint -f json` y `trivy config` / `trivy image`. `dive` (eficiencia de capas) y `dockle`. | media |
| F9 | **IaC o configuración insegura** (buckets públicos, SG 0.0.0.0/0, BD expuesta, K8s sin límites de recursos). | La IA copia ejemplos permisivos para que "funcione". | Determinista: `checkov -o sarif`, `trivy config --format sarif`, `kube-linter`, `kubeconform`. | alta |
| F10 | **CI/CD inseguro o inexistente**: deploy manual, sin tests, workflows con `pull_request_target` e inyección. | No se configura pipeline, o se copia un YAML inseguro. | Determinista: `actionlint -format '{{json .}}'`, `zizmor --format sarif`. | media-alta |
| F11 | **Sin caché ni CDN**: SSR dinámico en todo, sin `Cache-Control`, imágenes sin optimizar. | El framework por defecto lo marca todo como dinámico si se leen cookies o headers. | Determinista: `curl -I` sobre rutas (cabeceras `cache-control`, `x-vercel-cache`, `cf-cache-status`) y Lighthouse CI (dominio frontend). | media |
| F12 | **Región de cómputo lejos de la BD** (función en `iad1`, BD en `sa-east-1`). Cada consulta paga el RTT intercontinental. | Se aceptan los valores por defecto. Vercel usa `iad1` por defecto (https://vercel.com/docs/functions/limitations). | Determinista: comparar la región en `vercel.json`/`fly.toml` con la región del host de la BD. | media |
| F13 | **Sin timeouts, reintentos con backoff ni circuit breaker** hacia APIs externas. Resultado: cascadas y tormentas de reintentos. | `fetch` sin `AbortSignal.timeout`. Bucles de retry sin jitter. | Semgrep: `fetch(` sin `signal`, `axios` sin `timeout`. | media |
| F14 | **Secretos en el repo o en el bundle del cliente** (por ejemplo `NEXT_PUBLIC_*_KEY` de servicios de pago). | Patrón muy documentado en apps vibe-coded. | Determinista: `gitleaks`/`trufflehog` (dominio seguridad) y grep de `NEXT_PUBLIC_`/`VITE_` con nombres `SECRET|SERVICE_ROLE`. | crítica |
| F15 | **Sin backups ni plan de recuperación** (RPO/RTO no definidos). Sin migraciones versionadas. | No es visible en el código. | Mixto: existencia de una carpeta `migrations/`. Pregunta al usuario: ¿PITR activado? | alta |
| F16 | **Costos sin modelar**: no se sabe cuánto cuesta un usuario más ni qué pasa si la app se hace viral. | No hay planificación de capacidad (eje del PRR). | `infracost` (si hay Terraform) y ESTIMACIÓN con tarifas del proveedor (LLM y usuario). | media |

---

## 3. Árbol de decisión de infraestructura (GUÍA + ESTIMACIÓN)

> Los umbrales de usuarios son **ESTIMACIÓN** heurística: dependen del costo por petición, que solo se conoce midiendo (sección 5). El árbol prioriza **datos sensibles y tipo de carga** antes que el volumen.

```
INICIO
│
├─ P1. ¿Maneja datos sensibles regulados (salud, Ley 19.628/20.584 en Chile, HIPAA, pagos)?
│    ├─ SÍ → se exige: región de datos conocida, cifrado en reposo, backups+PITR, logs de auditoría,
│    │       acuerdo de tratamiento de datos (DPA) con el proveedor; descartar tiers gratuitos sin SLA.
│    │       Continuar el árbol solo con proveedores que cumplan (verificar contra el texto legal; no asumir).
│    └─ NO → continuar
│
├─ P2. ¿La app es contenido mayormente estático (landing, docs, blog, SPA que consume APIs de terceros)?
│    └─ SÍ → ESTÁTICO + CDN (Vercel/Netlify/Cloudflare Pages/GitHub Pages). Escala casi sin límite;
│            el riesgo pasa a las APIs que consume. FIN.
│
├─ P3. ¿Backend con peticiones cortas (< ~10 s), tráfico irregular o bajo, sin conexiones persistentes?
│    └─ SÍ → SERVERLESS (Vercel/Netlify Functions, Cloudflare Workers, AWS Lambda)
│            Condiciones obligatorias: pooler de BD (F2), rate limit (F1), trabajos largos a cola (F3),
│            sin estado local (F7), payload < 4,5 MB en Vercel (F4).
│
├─ P4. ¿Necesita procesos de larga duración, WebSockets intensivos, workers, cron frecuentes,
│      binarios pesados o costo predecible con tráfico sostenido?
│    └─ SÍ → CONTENEDOR GESTIONADO (Railway, Fly.io, Render, Google Cloud Run)
│            Condiciones: Dockerfile limpio (hadolint), health checks, ≥2 réplicas si SLO > 99%,
│            autoscaling configurado, BD en la misma región.
│
├─ P5. ¿Presupuesto mínimo fijo, equipo con capacidad de operar Linux (parches, firewall, backups)?
│    └─ SÍ → VPS (Hetzner, DigitalOcean, Lightsail) + Docker Compose/Coolify/Kamal
│            Riesgo: punto único de fallo y toda la seguridad del SO bajo tu responsabilidad.
│            Para vibe coders sin experiencia en ops: NO recomendado como primera opción.
│
└─ P6. ¿Múltiples servicios, equipo de plataforma dedicado, requisitos multi-región/multi-tenant,
       >decenas de servicios, o cumplimiento que exige control fino de red?
     └─ SÍ → KUBERNETES gestionado (EKS/GKE/AKS). Si la respuesta a "¿quién opera el clúster?"
             es "nadie", la respuesta es NO a Kubernetes.
```

### Tabla de orientación por escala (ESTIMACIÓN; validar con la prueba breakpoint)

| Escala aproximada | Concurrencia pico típica | Infra mínima razonable | Requisitos que el auditor exige |
|---|---|---|---|
| Prototipo / demo | < 10 | Serverless o contenedor en tier gratuito | Ninguno bloqueante salvo F1 y F14 |
| MVP con usuarios reales | 10–100 | Serverless + BD gestionada con pooler, o 1 contenedor | F1, F2, F5, F14, F15, smoke test de carga |
| Beta / crecimiento | 100–1.000 | Serverless o ≥2 réplicas de contenedor + CDN + Redis | Todo lo anterior + SLO definidos, prueba de carga promedio y estrés, colas |
| Producción madura | 1.000–10.000 | Contenedores con autoscaling o serverless optimizado, réplicas de lectura | PRR completo, soak y spike, runbooks, alertas por SLO, IaC |
| Escala | > 10.000 | Multi-región, posible K8s, sharding o particionado | Capacity planning trimestral, chaos testing, FinOps |

> Para pasar de "usuarios registrados" a "concurrencia" hace falta conocer la proporción de activos y su tasa de peticiones. No hay un factor universal fiable. Cualquier proporción del tipo "1 de cada 10 está online" queda como **NO VERIFICADO** y hay que medirla con analítica.

### Límites de serverless que el auditor debe chequear (fuentes primarias)

| Límite | Valor | Fuente |
|---|---|---|
| Vercel: duración máx. (Node/Bun/Python, Fluid compute) | Hobby 300 s; Pro/Ent 800 s (1800 s beta) | https://vercel.com/docs/functions/limitations |
| Vercel: memoria | Hobby 2 GB/1 vCPU; Pro/Ent hasta 4 GB/2 vCPU | ídem |
| Vercel: request/response body | 4,5 MB (413 `FUNCTION_PAYLOAD_TOO_LARGE`) | ídem |
| Vercel: bundle | 250 MB sin comprimir (500 MB Python; 5 GB beta) | ídem |
| Vercel: descriptores de archivo | 1.024 compartidos entre ejecuciones concurrentes | ídem |
| Vercel Edge runtime | Debe empezar a responder en 25 s; streaming hasta 300 s | ídem |
| Supabase pooler transaction mode | Puerto 6543; sin prepared statements, LISTEN/NOTIFY ni estado de sesión | https://supabase.com/docs/guides/database/connecting-to-postgres |
| Neon PgBouncer | Hasta 10.000 conexiones cliente (no 10.000 consultas simultáneas); pool backend ≈ 90 % de `max_connections`; espera hasta `query_wait_timeout` | https://neon.com/docs/connect/connection-pooling |
| AWS Lambda (timeout, payload, concurrencia por cuenta) | Consultar cuotas vigentes | https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html (valores no extraídos en esta investigación: **NO VERIFICADO** aquí) |
| Cold starts | Depende del runtime, el tamaño del bundle y el proveedor. No hay una cifra universal. | **NO VERIFICADO**: hay que medirlo con k6 (primera petición tras inactividad) |

---

## 4. Patrones de escalabilidad que el auditor busca

| Patrón | Cuándo exigirlo | Evidencia estática buscada |
|---|---|---|
| **Rate limiting** (por IP, usuario o API key) | Siempre en endpoints públicos, de autenticación y de LLM | `@upstash/ratelimit` (repo upstash/ratelimit-js, 2.053★, MIT), `express-rate-limit`, `slowapi`, reglas WAF |
| **Colas / jobs en segundo plano** | Trabajo > p95 objetivo, emails, IA, webhooks | BullMQ, Inngest, Trigger.dev, QStash, SQS, Celery, Vercel Workflows |
| **Caché** (CDN → app → Redis → BD) | Lecturas repetidas, catálogos, resultados de IA | `Cache-Control`, `revalidate`, `unstable_cache`, cliente Redis |
| **CDN** | Siempre para assets estáticos | Configuración de la plataforma, cabeceras |
| **Pool de conexiones** | Siempre en serverless; dimensionado en contenedores | Cadena de conexión, opciones del cliente |
| **Idempotencia y reintentos con backoff+jitter** | Pagos, webhooks, integraciones | Claves de idempotencia, librerías tipo `p-retry` |
| **Timeouts explícitos** | Toda llamada saliente | `AbortSignal.timeout`, `timeout:` |
| **Paginación** | Todo listado | `LIMIT`/`take`/cursor |
| **Health / readiness** | Contenedores y K8s | `/health`, `HEALTHCHECK`, `livenessProbe` |
| **Degradación elegante** | Dependencias externas críticas | Feature flags, fallbacks |

---

## 5. Escala de capacidad: cómo estimar cuántos usuarios aguanta (GUÍA)

**Fundamento:** ley de Little, L = λ · W (concurrencia media = tasa de llegada × tiempo medio en el sistema). Ejemplo de cálculo: 5.000 req/s con 200 ms de latencia media equivalen a unas 1.000 peticiones en vuelo. Advertencias de la fuente: hay que usar la latencia **media** (no p99) en la fórmula, tratar por separado las clases de petición muy distintas y aplicar el margen después de medir, no modificando la ecuación (https://oneuptime.com/blog/post/2026-09-08-littles-law-rps-latency-concurrency/view; fuente secundaria. Sobre pruebas de carga: https://learn.microsoft.com/vi-vn/archive/blogs/chwitt/littles-law-and-how-it-impacts-load-testers).

**Procedimiento del skill `capacidad`:**

1. **Definir SLO** (con el usuario, sin autoseleccionar): por ejemplo p95 < 500 ms y errores < 1 %.
2. **Perfil de tráfico**: los 3 a 5 recorridos críticos (login, listado, acción principal, llamada a IA) con su peso relativo.
3. **Smoke** (1–5 VU, 1 min): valida el script.
4. **Breakpoint** con *executor* de tasa de llegada abierta (`ramping-arrival-rate` en k6). Un test cerrado con VU fijos reduce su propia tasa cuando el sistema se ralentiza y oculta la sobrecarga (fuente anterior).
5. **RPS sostenible máximo (λmax)** = el mayor escalón que cumple el SLO.
6. **Capacidad en usuarios concurrentes** ≈ λmax / (peticiones por segundo por usuario activo). La tasa por usuario se obtiene de la analítica o se estima declarando el supuesto (ESTIMACIÓN).
7. **Margen**: reservar margen explícito (por ejemplo, operar al 50–70 % de λmax). El porcentaje es una decisión de diseño y debe declararse.
8. **Identificar el cuello de botella** con USE sobre los recursos (CPU, memoria, pool de BD, conexiones, límites del proveedor) mientras corre la prueba.
9. **Soak** (horas) para fugas de memoria y conexiones. **Spike** para autoscaling y cold starts.

**Resultado:** un número con intervalo y supuestos explícitos, por ejemplo: "λmax ≈ X RPS con p95 < 500 ms; con Y req/s por usuario activo eso son ~Z usuarios concurrentes; cuello de botella: pool de BD".

> Regla ética y operativa: **nunca correr una prueba de carga contra producción ni contra servicios de terceros sin autorización explícita**. Hacerlo contra la API de un LLM o de pagos genera costos y puede violar sus términos. El skill exige un entorno staging y confirmación del usuario.

---

## 6. Herramientas (repos verificados con `gh api`, 2026-11-17)

| Herramienta | Repo | ★ | Licencia | Último push | Propósito | Salida | Costo en tokens |
|---|---|---|---|---|---|---|---|
| **k6** | https://github.com/grafana/k6 | 32.342 | AGPL-3.0 | 2026-11-17 | Pruebas de carga scriptables en JS con thresholds (exit code ≠ 0 si fallan) | `--summary-export` JSON, `--out json` | bajo (solo el resumen) |
| **Locust** | https://github.com/locustio/locust | 28.294 | MIT | 2026-11-16 | Carga en Python, headless | `--csv`, `--json` | bajo |
| **Artillery** | https://github.com/artilleryio/artillery | 9.121 | MPL-2.0 | 2026-10-20 | Carga declarativa YAML, incluye Playwright | `--output` JSON | bajo |
| **autocannon** | https://github.com/mcollina/autocannon | 8.543 | MIT | 2026-11-16 | Benchmark HTTP rápido (Node) | `--json` | muy bajo |
| **vegeta** | https://github.com/tsenart/vegeta | 25.252 | MIT | 2026-11-16 | Carga a tasa constante (modelo abierto) | `report -type=json` | muy bajo |
| **hey** | https://github.com/rakyll/hey | 20.797 | Apache-2.0 | 2026-01-10 | Benchmark HTTP mínimo | texto/CSV | muy bajo |
| **Trivy** | https://github.com/aquasecurity/trivy | 39.486 | Apache-2.0 | 2026-11-17 | `trivy config` (IaC: Terraform, Dockerfile, K8s, Helm), `trivy fs`/`image` (CVE, secretos) | JSON, SARIF | bajo |
| **tfsec** | https://github.com/aquasecurity/tfsec | 7.062 | MIT | 2026-03-25 | Terraform. **El README recomienda migrar a Trivy** → usar `trivy config` | JSON, SARIF | — (no usar) |
| **Checkov** | https://github.com/bridgecrewio/checkov | 9.163 | Apache-2.0 | 2026-11-17 | IaC multi-framework (Terraform, CFN, K8s, Dockerfile, GH Actions, Serverless) | JSON, SARIF, JUnit | bajo-medio (filtrar a FAILED) |
| **Hadolint** | https://github.com/hadolint/hadolint | 12.540 | GPL-3.0 | 2026-10-19 | Lint de Dockerfile (+ShellCheck) | `-f json`, `-f sarif` | muy bajo |
| **dockle** | https://github.com/goodwithtech/dockle | 3.298 | Apache-2.0 | 2026-11-16 | Buenas prácticas de imagen (CIS) | `-f json`, SARIF | muy bajo |
| **dive** | https://github.com/wagoodman/dive | 54.733 | MIT | 2026-11-17 | Eficiencia de capas de imagen (modo CI) | `--json` | bajo |
| **actionlint** | https://github.com/rhysd/actionlint | 4.419 | MIT | 2026-07-16 | Lint de GitHub Actions | `-format '{{json .}}'` | muy bajo |
| **zizmor** | https://github.com/zizmorcore/zizmor | 7.077 | MIT | 2026-11-18 | Seguridad de GitHub Actions (inyección, permisos) | JSON, SARIF | muy bajo |
| **kube-linter** | https://github.com/stackrox/kube-linter | 3.531 | Apache-2.0 | 2026-11-17 | Lint de manifiestos K8s/Helm (limits, probes, root) | JSON, SARIF | bajo |
| **kubeconform** | https://github.com/yannh/kubeconform | 3.259 | Apache-2.0 | 2026-06-13 | Validación de esquema K8s | JSON, JUnit | muy bajo |
| **kube-score** | https://github.com/zegl/kube-score | 3.105 | MIT | 2026-05-20 | Análisis de manifiestos K8s | JSON, SARIF | bajo |
| **Kubescape** | https://github.com/kubescape/kubescape | 11.960 | Apache-2.0 | 2026-11-17 | Postura de seguridad K8s (NSA, MITRE) | JSON, SARIF | medio |
| **conftest (OPA)** | https://github.com/open-policy-agent/conftest | 3.298 | (NOASSERTION en API; Apache-2.0 según repo, NO VERIFICADO) | 2026-11-16 | Políticas propias en Rego sobre YAML/JSON/HCL (reglas del auditor) | JSON, SARIF | muy bajo |
| **Infracost** | https://github.com/infracost/infracost | 12.621 | Apache-2.0 | 2026-11-16 | Estimación de costo desde Terraform | JSON | bajo |
| **Terrascan** | https://github.com/tenable/terrascan | 5.213 | Apache-2.0 | 2025-11-20 | **ARCHIVADO**: no usar | — | — |
| **OpenTelemetry Collector** | https://github.com/open-telemetry/opentelemetry-collector | 7.776 | Apache-2.0 | 2026-11-17 | Estándar de telemetría (recomendación, no chequeo) | OTLP | n/a |
| **OpenTelemetry JS** | https://github.com/open-telemetry/opentelemetry-js | 3.531 | Apache-2.0 | 2026-11-17 | SDK de instrumentación Node | OTLP | n/a |
| **Sentry JS SDK** | https://github.com/getsentry/sentry-javascript | 8.778 | (NOASSERTION; licencia propia, ver repo) | 2026-11-18 | Errores y performance en frontend y backend | — | n/a |
| **Prometheus** | https://github.com/prometheus/prometheus | 67.679 | Apache-2.0 | 2026-11-17 | Métricas USE/RED (para fases N4–N5) | API JSON | n/a |
| **Lighthouse CI** | https://github.com/GoogleChrome/lighthouse-ci | 7.154 | Apache-2.0 | 2026-11-17 | Rendimiento web y caché (cruce con dominio frontend) | JSON | bajo |
| **upstash/ratelimit-js** | https://github.com/upstash/ratelimit-js | 2.053 | MIT | 2026-11-17 | Rate limiting serverless (recomendación de remediación) | — | n/a |

**Nota sobre tokens:** todos los chequeos deterministas deben ejecutarse con salida JSON o SARIF y pasar por un **normalizador** (script `jq` o Python) que reduzca el resultado a `{tool, rule_id, severity, file, line, message}`, deduplique y entregue al LLM solo el top-N por severidad más los conteos. El LLM no lee el código completo ni el informe crudo.

---

## 7. Catálogo de chequeos del skill `infra-escalabilidad`

| ID | Chequeo | Método | Herramienta | Nivel exigido |
|---|---|---|---|---|
| INF-01 | Inventario de stack y plataforma de despliegue (vercel.json, netlify.toml, fly.toml, railway.json, Dockerfile, docker-compose, *.tf, k8s/, Procfile) | determinista | `find`/glob + script | N1 |
| INF-02 | Clasificar la arquitectura y elegir plataforma con el árbol de decisión (sección 3) | llm | Claude + respuestas del usuario (datos sensibles, presupuesto, carga) | N1 |
| INF-03 | Secretos fuera del repo; `.env` en `.gitignore`; `.env.example` sin valores reales | determinista | gitleaks/trufflehog + grep | N1 |
| INF-04 | Rate limiting presente en endpoints públicos, de auth y de LLM | mixto | semgrep/grep → LLM confirma cobertura | N2 |
| INF-05 | Pooler de BD en serverless (puerto 6543 o `-pooler`, `pgbouncer=true`, cliente a nivel de módulo) | determinista | regex sobre config + semgrep | N2 |
| INF-06 | Tareas largas fuera del request (cola o workflow); `maxDuration` coherente | mixto | grep SDKs LLM/puppeteer en rutas → LLM | N2 |
| INF-07 | Timeouts explícitos en llamadas salientes | determinista | semgrep (regla propia) | N2 |
| INF-08 | Error tracking instalado (Sentry o equivalente) | determinista | lectura de `package.json`/`requirements` | N2 |
| INF-09 | Endpoint de health check | determinista | grep de rutas + `curl` | N2 |
| INF-10 | Backups/PITR y migraciones versionadas | mixto | carpeta `migrations/` + pregunta al usuario | N2 |
| INF-11 | Alertas de presupuesto o tope de gasto en el proveedor | manual | checklist al usuario | N2 |
| INF-12 | Prueba de carga smoke + carga promedio con thresholds del SLO | determinista | k6 `--summary-export` | N2 (smoke) / N3 |
| INF-13 | Lint de Dockerfile (USER no-root, tag fijo, multi-stage, sin secretos) | determinista | hadolint `-f sarif`, trivy config | N2 si hay Dockerfile |
| INF-14 | CI con build+tests+lint antes del deploy; workflows seguros | determinista | actionlint, zizmor | N3 |
| INF-15 | Sin estado local en procesos (sesiones o archivos en memoria o disco) | mixto | semgrep → LLM | N3 |
| INF-16 | SLO/SLI definidos y documentados | manual + llm | plantilla SLO | N3 |
| INF-17 | Logs estructurados a stdout con correlación (request-id/trace-id) | determinista | dependencias + grep | N3 |
| INF-18 | Caché y CDN: cabeceras `Cache-Control` en assets y rutas cacheables | determinista | `curl -I` script + Lighthouse CI | N3 |
| INF-19 | Región del cómputo = región de la BD | determinista | config de plataforma vs host de la BD | N3 |
| INF-20 | Prueba breakpoint → λmax, concurrencia estimada, cuello de botella (USE) | mixto | k6 ramping-arrival-rate + LLM interpreta | N3 |
| INF-21 | IaC sin misconfiguraciones críticas | determinista | `trivy config --format sarif`, `checkov -o sarif` | N4 (N3 si hay IaC) |
| INF-22 | Manifiestos K8s: requests/limits, probes, no-root, esquema válido | determinista | kube-linter, kubeconform | N4 si hay K8s |
| INF-23 | Observabilidad distribuida (OpenTelemetry traces y métricas RED) | determinista | dependencias `@opentelemetry/*` | N4 |
| INF-24 | Alertas basadas en SLO y presupuesto de error; runbooks | manual | checklist PRR | N4 |
| INF-25 | Soak (fugas) y spike (autoscaling y cold start) | determinista | k6 | N4 |
| INF-26 | Redundancia: ≥2 réplicas o multi-AZ; despliegue sin downtime y rollback | mixto | config de plataforma + pregunta | N4 |
| INF-27 | Infra como código reproducible (no "click-ops") | determinista | existencia de *.tf / Pulumi / config de plataforma en repo | N4 |
| INF-28 | Modelo de costos por usuario y escenario viral | mixto | infracost + ESTIMACIÓN LLM con tarifas del proveedor | N4 |
| INF-29 | Capacity planning periódico, chaos/DR drills, multi-región | manual | checklist PRR | N5 |
| INF-30 | Conformidad 12-Factor (factores 3, 6, 9, 11) | mixto | semgrep + LLM | N3 |

---

## 8. Escala de madurez para este dominio (señales observables)

| Nivel | Nombre | Señales observables |
|---|---|---|
| **N1 Prototipo** | Funciona en mi máquina o en un deploy de un clic | Deploy en plataforma gestionada; sin secretos en el repo; sin pruebas de carga ni monitoreo |
| **N2 MVP** | Usuarios reales y fallos acotados | Rate limit en endpoints críticos; pooler de BD; Sentry; `/health`; backups activos; alerta de presupuesto; smoke test de carga aprobado |
| **N3 Beta** | Crece sin sustos | SLO definidos; k6 de carga promedio y breakpoint con λmax conocido; colas para trabajo largo; CDN y caché; CI con tests; logs estructurados; Dockerfile limpio |
| **N4 Producción** | Operable y recuperable | PRR aprobado; IaC sin críticos; OTel con métricas RED; alertas por SLO; runbooks; ≥2 réplicas; rollback probado; soak y spike aprobados; modelo de costos |
| **N5 Escala** | Escala con previsión | Capacity planning recurrente; autoscaling validado; multi-región o DR probado; FinOps; chaos testing; presupuestos de error que gobiernan los releases |

**Regla de puerta (gate):** un proyecto no sube de nivel si falla cualquier chequeo exigido en su nivel. Los críticos (INF-03, INF-04, INF-05) bloquean desde N2.

---

## 9. Integración en el auditor-integral (propuesta de diseño)

- **Skill `auditar-infra`** (SKILL.md breve) que orquesta: (1) script `inventario.sh` → JSON del stack; (2) cuestionario de 5 preguntas al usuario (datos sensibles, presupuesto mensual, usuarios esperados, SLO deseado, ¿hay staging?); (3) ejecución de las CLI disponibles con `--format sarif/json`; (4) `normalizar.py` → `hallazgos.json`; (5) el LLM aplica el árbol de decisión y redacta el informe con nivel N1–N5 y hoja de ruta.
- **Skill `capacidad`** separado y opt-in. Genera un script k6 a partir de las rutas detectadas, **pide confirmación** del entorno objetivo (nunca producción ni terceros), corre smoke y luego breakpoint, y aplica la ley de Little.
- **Reglas propias** en `semgrep` y `conftest` para F1, F2, F7 y F13, que no cubren las herramientas genéricas.
- Las CLI ausentes se reportan como "no evaluado" y nunca como "aprobado".

---

## 10. Fuentes

- Google SRE Book, Monitoring Distributed Systems: https://sre.google/sre-book/monitoring-distributed-systems/
- Google SRE Book, Evolving SRE Engagement Model (PRR): https://sre.google/sre-book/evolving-sre-engagement-model/
- Google SRE Workbook, Implementing SLOs: https://sre.google/workbook/implementing-slos/
- Brendan Gregg, USE Method: https://www.brendangregg.com/usemethod.html
- Tom Wilkie, RED Method (GrafanaCon EU 2018): https://grafana.com/files/grafanacon_eu_2018/Tom_Wilkie_GrafanaCon_EU_2018.pdf
- AWS Well-Architected: https://aws.amazon.com/architecture/well-architected/
- The Twelve-Factor App: https://12factor.net/
- OWASP API4:2023: https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
- Vercel Functions Limits (actualizado 2026-08-24): https://vercel.com/docs/functions/limitations
- Supabase, Connecting to Postgres: https://supabase.com/docs/guides/database/connecting-to-postgres
- Neon, Connection pooling: https://neon.com/docs/connect/connection-pooling
- k6, Test types: https://grafana.com/docs/k6/latest/testing-guides/test-types/
- Ley de Little aplicada a capacidad: https://oneuptime.com/blog/post/2026-09-08-littles-law-rps-latency-concurrency/view ; https://learn.microsoft.com/vi-vn/archive/blogs/chwitt/littles-law-and-how-it-impacts-load-testers
- Veracode 2025 GenAI Code Security Report (nota de prensa): https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/
- InfoQ, Denial of Wallet (2025-08): https://www.infoq.com/news/2025/08/denial-of-wallet-attack-cloud
- tfsec → Trivy (README del repo): https://github.com/aquasecurity/tfsec

---

## Verificación

Revisión escéptica hecha el 2026-11-17 con `gh api repos/OWNER/REPO` (estrellas, último push, licencia SPDX, archivado) y WebFetch sobre las fuentes primarias.

### Repositorios (23 comprobados; todos existen)

| Repo | Estrellas (API) | Último push | Licencia (API) | Archivado | Resultado |
|---|---|---|---|---|---|
| grafana/k6 | 32.342 | 2026-11-17 | AGPL-3.0 | no | OK |
| locustio/locust | 28.294 | 2026-11-16 | MIT | no | OK |
| artilleryio/artillery | 9.121 | 2026-10-20 | MPL-2.0 | no | OK |
| mcollina/autocannon | 8.543 | 2026-11-16 | MIT | no | OK |
| tsenart/vegeta | 25.252 | 2026-11-16 | MIT | no | OK |
| aquasecurity/trivy | 39.486 | 2026-11-17 | Apache-2.0 | no | OK |
| bridgecrewio/checkov | 9.163 | 2026-11-17 | Apache-2.0 | no | OK |
| hadolint/hadolint | 12.540 | 2026-10-19 | GPL-3.0 | no | OK |
| goodwithtech/dockle | 3.298 | 2026-11-16 | Apache-2.0 | no | OK |
| wagoodman/dive | 54.733 | 2026-11-17 | MIT | no | OK |
| rhysd/actionlint | 4.419 | 2026-07-16 | MIT | no | OK (sin push en 4 meses; activo pero más lento) |
| zizmorcore/zizmor | 7.077 | 2026-11-18 | MIT | no | OK |
| stackrox/kube-linter | 3.531 | 2026-11-17 | Apache-2.0 | no | OK |
| yannh/kubeconform | 3.259 | 2026-06-13 | Apache-2.0 | no | OK (último push hace 5 meses) |
| kubescape/kubescape | 11.960 | 2026-11-17 | Apache-2.0 | no | OK |
| open-policy-agent/conftest | 3.298 | 2026-11-16 | NOASSERTION | no | OK; licencia NO VERIFICADO vía API |
| infracost/infracost | 12.621 | 2026-11-16 | Apache-2.0 | no | OK |
| GoogleChrome/lighthouse-ci | 7.154 | 2026-11-17 | Apache-2.0 | no | OK |
| open-telemetry/opentelemetry-collector | 7.776 | 2026-11-17 | Apache-2.0 | no | OK |
| getsentry/sentry-javascript | 8.778 | 2026-11-18 | NOASSERTION | no | OK; licencia NO VERIFICADO vía API |
| upstash/ratelimit-js | 2.053 | 2026-11-17 | MIT | no | OK |
| aquasecurity/tfsec | 7.062 | 2026-03-25 | MIT | **no** | Corrección: no está archivado; el README pide migrar a Trivy ("Tfsec is now part of Trivy") |
| tenable/terrascan | **5.213** | 2025-11-20 | Apache-2.0 | **sí** | Confirmado archivado; se añade el dato de estrellas que faltaba |

### Cifras y afirmaciones clave

| Afirmación del informe | Fuente | Resultado |
|---|---|---|
| Vercel: duración 300 s por defecto, 800 s máx. Pro/Ent | vercel.com/docs/functions/limitations (actualizado 2026-08-24) | **Confirmado**, con matiz: además existe un máximo extendido de 1.800 s en beta (Pro/Ent). Hobby: 300 s máx. |
| Vercel: payload 4,5 MB (413 FUNCTION_PAYLOAD_TOO_LARGE) | misma | **Confirmado** (la respuesta en streaming no tiene ese límite) |
| Vercel: 1.024 descriptores de archivo; región por defecto iad1 | misma | **Confirmado** (1.024 compartidos entre ejecuciones concurrentes, incluido el runtime) |
| Veracode 2025: código inseguro en el 45 % de las tareas | nota de prensa Veracode | **Confirmado** el 45 %. El detalle "más de 100 LLM en 80 tareas" no se reconfirmó en esta pasada: tratar como dato del proveedor |
| Supabase: transaction pooler en puerto 6543 para serverless | supabase.com/docs/guides/database/connecting-to-postgres | **Confirmado** |
| Detección F2/INF-05 "5432 = directo" | misma | **Error de diseño corregido**: el *session pooler* de Supabase también usa 5432 (host `*.pooler.supabase.com`). La regla debe mirar el **host** (`db.<ref>.supabase.co` = directo; `pooler.supabase.com` o `-pooler` de Neon = pooler) y el puerto 6543, no solo el puerto |
| InfoQ 2025-08, denial of wallet | infoq.com/news/2025/08/denial-of-wallet-attack-cloud | **Confirmado** el artículo (USD 120.000 en 72 h por autoescalado sin tope tras un DDoS), pero la cifra viene de comentarios en LinkedIn/Reddit: **NO VERIFICADO** como incidente. Las cifras USD 98k/día (Firebase) y USD 128k siguen **NO VERIFICADO** |
| Ley de Little (blog archivado de Microsoft, URL vi-vn) | no reconsultada | La ley es estándar (L = λW); la URL concreta queda **NO VERIFICADO** en esta pasada |

### Correcciones aplicadas al resumen
1. Terrascan: 5.213 estrellas, archivado (confirmado).
2. tfsec: no archivado; "en migración a Trivy" (confirmado en README).
3. INF-05 / F2: la detección pasa a basarse en host + puerto 6543, no en "5432 = directo".
4. Vercel: se añade el máximo extendido 1.800 s (beta).
5. Licencias NOASSERTION (conftest, sentry-javascript) quedan como NO VERIFICADO.
6. No se encontraron repos inventados.

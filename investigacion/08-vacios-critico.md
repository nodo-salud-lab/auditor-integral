# 08 — Crítica de completitud: vacíos para auditar un proyecto vibe-coded de la idea a producción

Fecha: 2026-11-17 · Rol: crítico de completitud (nivel staff engineer) · Sello general: **SÍNTESIS** (evidencia integrada) + **GUÍA** (checks propuestos). Las cifras van con URL; lo no verificable se marca **NO VERIFICADO**.

## 0. Diagnóstico en una línea

Los 7 dominios cubren bien **seguridad técnica, BD, infra, UX, ciclo de ingeniería y ecosistema de herramientas**. Lo que falta no es más SAST: faltan las **capas de negocio y de operación que fallan después del deploy**, a saber: legal/privacidad (en especial Chile y datos de salud), pagos, email/notificaciones, móvil/PWA, **economía de la IA dentro de la app**, dependencia de SaaS (lock-in y salida), recuperación ante desastres como *proceso* (no solo backup), ciclo de vida de secretos, **logs de auditoría** (distintos de logs de depuración), licencias y, sobre todo, **mantenibilidad por alguien que no programa** (traspaso, bus factor y operación diaria).

Además hay **vacíos transversales del propio auditor**: no hay un modelo de puntuación (cómo se pasa de 200 checks a un nivel N1–N5), ni un “perfil de riesgo” que active dominios condicionales (¿maneja salud?, ¿cobra?, ¿envía emails?, ¿tiene app móvil?, ¿usa LLM?), ni una deduplicación de IDs (VC-, SEC-, DB-, INF-, ECO- repiten el mismo control con 3–4 IDs).

---

## 1. Vacíos transversales del diseño del auditor (prioridad máxima)

| # | Vacío | Por qué importa | Propuesta |
|---|---|---|---|
| T1 | **Duplicación de checks entre dominios** (secretos aparece como VC-04/05, SEC-01/02, DB-05, INF-03, ECO-02/06; RLS en VC-01/02, SEC-09, DB-01/02, ECO-05; rate limiting en VC-21, SEC-17, INF-04) | Cada duplicado cuesta tokens y ensucia el informe; el usuario no programador ve “3 fallas” donde hay 1 | Catálogo canónico único con ID estable (p. ej. `AUD-SECRETS-01`) y alias a los IDs de origen. Una herramienta → un hallazgo normalizado (SARIF) → un check |
| T2 | **Sin perfil de riesgo / triage inicial** | Un blog estático no necesita PCI ni Ley 21.719; una app de kinesiología con fichas sí | Paso 0 obligatorio: cuestionario de 10 preguntas + detección determinista (ECO-01) que genera `perfil.json` con flags: `datos_salud`, `pagos`, `emails`, `movil`, `llm`, `multi_tenant`, `usuarios_ue`, `menores` |
| T3 | **Sin modelo de puntuación/madurez explícito** | El usuario pidió “escala de usabilidad y qué hacer para crecer” | Regla de “gates”: un nivel N se alcanza solo si **todos** los checks bloqueantes ≤N pasan; la nota numérica es secundaria. Un crítico abierto en seguridad/legal tapa el nivel en N1 sin importar el resto |
| T4 | **Sin “definición de producción” por tipo de app** | “Listo para producción” no es lo mismo para un MVP interno de 5 usuarios que para un SaaS con pagos | Matriz de perfiles (interno / público sin datos / público con datos personales / datos sensibles o pagos) × nivel exigido |
| T5 | **Sin verificación de que el auditor mismo no rompe nada** | Varios checks son activos (DAST, k6, sqlmap, prueba negativa con anon key) | Regla dura: checks activos solo contra local/staging declarado por el usuario; nunca contra producción sin confirmación explícita (coherente con CLAUDE.md) |
| T6 | **Sin re-auditoría y deriva en el tiempo** | ECO-19 cubre diff, pero no hay “auditoría programada” (dependencias que se vuelven vulnerables sin tocar código) | Modo `--watch` mensual: solo deterministas baratos (osv-scanner, gitleaks, scorecard, expiración de certificados/dominio) |

---

## 2. Vacíos por arista

### 2.1 Privacidad y legal (Chile, GDPR, datos de salud) — **CRÍTICO**

**Hallazgo clave (verificado):** la Ley 21.719 se publicó el 13-12-2024, reforma íntegramente la Ley 19.628, crea la Agencia de Protección de Datos Personales y su vigencia legal es el **1-12-2026** (dentro de 2 semanas respecto de hoy). Hay un proyecto de postergación aprobado por el Senado el 28-10-2026 que la llevaría a 2027, aún en trámite en la Cámara ([BCN, ficha Ley 21.719](https://www.bcn.cl/balance-legislativo/detalle/ficha_LEY_21719_2024-12-13); [Garrigues](https://www.garrigues.com/es_ES/noticia/chile-ejecutivo-refuerza-futura-agencia-proteccion-datos-concede-ano-adicional-adaptacion); [Diario Constitucional](https://www.diarioconstitucional.cl/2026/06/12/la-ley-21-719-entra-en-vigor-el-1-de-diciembre-y-expone-vacios-en-regulacion-de-pequenas-empresas/)). **Verificar el estado del proyecto en BCN antes de cada auditoría** (dato volátil).

- Multas: leves hasta 5.000 UTM, graves hasta 10.000 UTM, gravísimas hasta 20.000 UTM; las fuentes secundarias **discrepan** en qué conductas son gravísimas y en la regla de reincidencia (triple vs. 2 %/4 % de ingresos). Fuente primaria a consultar: arts. 34 bis–35 en [BCN LeyChile idNorma=1209272](https://www.bcn.cl/leychile/navegar?idNorma=1209272). Cifras de multas tomadas de resúmenes secundarios ([GeoVictoria](https://www.geovictoria.com/es-cl/blog/nueva-ley-proteccion-de-datos-chile/), [Simplo](https://simplo.cl/proteccion-datos-personales-ley-21719-empresa/)): **verificar contra el texto legal**.
- Datos de salud = sensibles; regla general consentimiento expreso salvo excepciones taxativas ([Prey, guía sector salud](https://preyproject.com/es/resources/guia-de-cumplimiento-de-la-ley-de-proteccion-de-datos-para-el-sector-salud)). Además aplica la Ley 20.584 (ficha clínica) cuando hay atención de salud.
- **Doble notificación**: un incidente puede gatillar la Ley 21.663 (Marco de Ciberseguridad, vigente desde 1-1-2025; alerta temprana a ANCI en 3 h para obligados) y la Ley 21.719 ([Prey, doble notificación](https://preyproject.com/es/blog/doble-notificacion-incidente-ley-21663-ley-21719); [Cariola](https://cariola.cl/wp-content/uploads/2024/12/Alerta-Legal_27.12.2024.pdf)). Los plazos posteriores (24/72 h, 15 días) **discrepan entre fuentes**: verificar en DS 295/2024 e instrucciones ANCI. La 21.663 aplica a servicios esenciales/OIV; un MVP vibe-coded normalmente **no** es OIV, pero el auditor debe preguntarlo.
- GDPR si hay usuarios en la UE: art. 9 (categorías especiales, incluye salud), art. 30 (registro de actividades), art. 35 (EIPD/DPIA) — texto en [EUR-Lex 2016/679](https://eur-lex.europa.eu/eli/reg/2016/679/oj).

**Qué no cubren los 7 dominios:** VC-24 y SEC-36 mencionan la Ley 19.628 (que queda reemplazada), pero no hay checks de: inventario de datos, base de licitud por finalidad, consentimiento granular y revocable, derechos ARCO+portabilidad implementados en la app (exportar/borrar mi cuenta), política de privacidad coherente con lo que el código realmente recolecta (analytics, SDKs de terceros), transferencias internacionales (Supabase/Vercel/OpenAI alojan fuera de Chile), retención y borrado, y plan de respuesta a brechas.

**Lo que sí es automatizable:** inventario de PII por análisis de esquema + código (Bearer CLI ya lo hace por flujo de datos; Presidio para detectar PII en logs/fixtures/seed), lista de SDKs de terceros que envían datos (análisis del bundle + `package.json`), existencia de endpoints/acciones de exportar y eliminar cuenta, existencia de política de privacidad y su fecha. La adecuación jurídica **siempre** requiere revisión humana (no afirmar cumplimiento).

### 2.2 Pagos — **ALTA** (condicional `pagos`)

Fallas típicas de vibe coding (por patrón conocido; frecuencia en apps IA **NO VERIFICADO**): precio calculado en el cliente, éxito de pago decidido por la redirección del frontend (`/success`) en vez del webhook, webhook sin verificar firma, sin idempotencia (doble acreditación ante reintentos), claves secretas en el frontend, sin manejo de reembolsos/disputas/suscripciones vencidas.

Evidencia: la verificación de firma de Stripe exige el **cuerpo crudo**; un `express.json()` previo la rompe ([Stripe docs](https://docs.stripe.com/webhooks/signature)). Stripe reintenta entregas hasta 3 días en modo live ([Hookdeck](https://hookdeck.com/webhooks/platforms/guide-to-stripe-webhooks-features-and-best-practices), secundaria), por lo que el handler debe ser idempotente por `event.id`. OWASP tiene [Webhook Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html). PCI DSS: usar checkout alojado (Stripe Checkout / Mercado Pago / Webpay vía Transbank) reduce el alcance; **nunca** tocar el PAN en servidor propio.

Herramientas: `stripe-cli` (2.239★, Apache-2.0, activo) para `stripe trigger`/`listen` en local; `stripe-mock`; `hookdeck-cli`. Semgrep con reglas propias: `constructEvent` ausente en rutas `/webhook`, `amount` tomado de `req.body`.

### 2.3 Emails y notificaciones — **MEDIA/ALTA** (condicional `emails`)

Requisitos de Google/Yahoo para remitentes masivos (>5.000/día): SPF + DKIM + DMARC con alineación, unsubscribe de un clic RFC 8058 y spam < 0,3 % ([resumen Red Sift](https://redsift.com/guides/bulk-email-sender-requirements); fuente primaria: guía de remitentes de Gmail). Aunque una app pequeña no sea “masiva”, sin SPF/DKIM los emails transaccionales (reset de contraseña, OTP) caen a spam → el flujo de login “falla” para el usuario.

Fallas vibe-coded: envío síncrono dentro del request, sin cola ni reintento, plantillas con HTML del usuario sin escapar (inyección en emails), endpoint de “enviar invitación” sin rate limit (abuso como relay de spam), enumeración de usuarios en “olvidé mi contraseña”, tokens de reset sin expiración/un solo uso, falta de Mailpit/entorno de prueba (se envían correos reales en dev).

Herramientas: `checkdmarc` (327★, Apache-2.0) determinista sobre DNS; `mailpit` (10.965★, MIT; reemplaza a MailHog, sin push desde 02-2024) para pruebas locales.

### 2.4 Móvil / PWA — **MEDIA** (condicional `movil`)

- Lighthouse 12 **eliminó la categoría PWA** (mayo 2024) ([PageSpeed release notes](https://developers.google.cn/speed/docs/insights/release_notes); [Chrome: criterios de instalabilidad](https://developer.chrome.com/blog/update-install-criteria)). Cualquier skill que pida “score PWA de Lighthouse” está obsoleta. Usar validación de `manifest`/service worker propia o PWABuilder.
- Apps nativas/híbridas (Expo, Capacitor, Flutter generadas por IA): estándar OWASP MASVS (2.483★) y MobSF (22.256★, GPL-3.0) para análisis estático del APK/IPA (secretos embebidos, `allowBackup`, cleartext traffic, certificate pinning). No cubierto en ningún dominio.
- Fallas típicas: claves de API en el binario (se extraen trivialmente), deep links sin validar, almacenamiento de tokens en AsyncStorage sin cifrar, service worker que cachea respuestas autenticadas (fuga entre usuarios en dispositivo compartido), sin estrategia de actualización forzada.

### 2.5 IA dentro de la app (costos, prompt injection) — **CRÍTICA** (condicional `llm`)

Los dominios cubren prompt injection (SEC-30..34, VC-25), pero **no la economía**: OWASP LLM10:2025 *Unbounded Consumption* incluye *denial of wallet* ([OWASP GenAI](https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/)). Faltan:

- Tope de gasto **en el proveedor** (no solo rate limit en la app), cuota por usuario/plan, `max_tokens` explícito, límite de longitud de entrada, presupuesto por conversación.
- Modelo de costo unitario: tokens promedio × precio × llamadas/usuario/día → costo por usuario activo vs. precio cobrado (la app puede “escalar a la quiebra”).
- Observabilidad de LLM: trazas con tokens y costo por request (Langfuse 37.564★, Helicone 6.287★ Apache-2.0, LiteLLM 63.445★ como proxy con budgets).
- Evaluaciones de regresión del prompt (promptfoo 27.394★ MIT; garak 10.068★ Apache-2.0) en CI: el comportamiento cambia cuando el proveedor actualiza el modelo.
- Envío de PII/datos de salud al proveedor LLM = transferencia internacional y tratamiento por encargado (enlaza con 2.1); verificar política de retención/entrenamiento del proveedor y anonimizar (Presidio).
- Plan de degradación si el proveedor cae o depreca el modelo (fallback, mensajes al usuario).

### 2.6 Dependencias de terceros / SaaS lock-in — **MEDIA**

No hay check de **salida**. Evidencia (secundaria, sesgada por proveedores): el dato de Supabase es Postgres estándar y portable con `pg_dump`, pero el acoplamiento real está en Auth, Storage, RLS y SDK cliente; Firestore exige scripts de migración por colección ([Sacra](https://sacra.com/chat/h/a2b14572-77f5-4bc5-aa80-a6361a4956d3/); [moklabs](https://moklabs-research.pages.dev/reports/technology/2026-03-19-supabase-exit-strategy)) — **ESTIMACIÓN**, no hay fuente primaria neutral.

Checks propuestos: inventario de SaaS críticos (BaaS, auth, pagos, email, LLM, hosting) con plan, costo y titular de la cuenta; quién es **dueño** de cada cuenta (frecuente en vibe coding: la cuenta está a nombre del freelancer o del “amigo que ayudó”); dominio DNS a nombre del cliente y con renovación automática; export periódico probado; abstracción mínima (un módulo `lib/llm.ts`, `lib/email.ts`) en vez de SDK disperso; revisar límites del plan gratuito (pausa por inactividad, cuotas) que tumban la app en silencio.

### 2.7 Recuperación ante desastres — **ALTA**

Los dominios piden backups/PITR (VC-13, DB-23/24, INF-10), pero DR es más que backup. AWS Well-Architected REL13-BP02 da órdenes de magnitud: *backup & restore* RPO en horas y RTO ≤ 24 h; *pilot light* RPO minutos, RTO decenas de minutos ([AWS Well-Architected](https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_disaster_recovery.html)). Faltan:

- RPO/RTO **declarados por el dueño** del negocio (no inventados por el auditor).
- Backups fuera del proveedor principal (si se borra/suspende la cuenta de Supabase, el PITR se va con ella). restic (37.282★, BSD-2) o `pg_dump` a almacenamiento externo cifrado.
- Backup de lo que no es BD: buckets/Storage, variables de entorno, configuración de auth (proveedores OAuth, URLs de redirección), DNS, webhooks registrados.
- Runbook de restauración ejecutable por un no programador y un simulacro con tiempo medido.
- Escenario “el agente IA borró producción” (ya documentado en dominio 01): ¿se puede volver en < RTO?

### 2.8 Gestión de secretos y entornos — **ALTA**

Cubierto “sin secretos en repo/bundle”, pero no el **ciclo de vida**: inventario de secretos, dueño, fecha de última rotación, procedimiento de rotación tras fuga (gitleaks encuentra, pero ¿quién rota y cómo?), separación de claves por entorno (VC-12 parcial), secretos compartidos por WhatsApp/correo, claves personales del desarrollador en producción, preview deployments con claves de producción. Herramientas: SOPS (23.744★, MPL-2.0), dotenvx (5.883★, BSD-3), Infisical (30.569★). Check determinista: comparar nombres de variables entre `.env.example`, entorno de preview y producción (vía CLI de Vercel/Netlify/Railway en solo lectura).

### 2.9 Logging y auditoría — **ALTA** (crítica si `datos_salud`)

Los dominios tratan logs **técnicos** (estructurados, sin PII). Falta el **log de auditoría** de negocio: quién vio/modificó/exportó qué registro y cuándo, con integridad (append-only). OWASP Top 10:2025 A09 *Security Logging & Alerting Failures* recomienda audit trails con controles de integridad como tablas append-only ([OWASP A09:2025](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/)); el [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) separa logs de auditoría de los de seguridad y exige registrar éxitos y fallos de autenticación. Para fichas clínicas, la trazabilidad de accesos es además expectativa de la normativa sanitaria (verificar requisito exacto en la reglamentación de la Ley 20.584 — **NO VERIFICADO** aquí). Herramienta: pgaudit (1.727★) o triggers a tabla `audit_log` con RLS solo-insert; retención definida.

### 2.10 Licencias de software — **MEDIA**

Ningún dominio verifica licencias. Riesgos: dependencia GPL/AGPL en SaaS cerrado (AGPL obliga a ofrecer código a usuarios de red), assets/fuentes/iconos sin licencia, y **código generado que reproduce código copyleft**: un estudio sobre ChatGPT halló que el contexto del código puede inducir salidas coincidentes con código copyleft ([arXiv 2502.05023](https://arxiv.org/abs/2502.05023)); una auditoría de 53 LLM de código y 514 M de archivos encontró 38 M duplicados exactos de código con copyleft fuerte en los datos de entrenamiento ([arXiv 2403.15230](https://arxiv.org/abs/2403.15230)). Cuánto de eso llega a apps reales: **NO VERIFICADO**.

Herramientas deterministas y baratas: licencias de dependencias desde el SBOM (syft 9.918★ / cdxgen 1.121★ ya están en el stack) + política allow/deny; ScanCode Toolkit (2.675★) para detección de texto de licencia y coincidencias en el código propio; ORT (2.122★, Apache-2.0) si se quiere pipeline completo; REUSE (FSFE) para declarar licencias por archivo. LicenseFinder (sin push desde 07-2024): evitar.

### 2.11 Mantenibilidad para quien no programa — **CRÍTICA para el público objetivo**

Es el vacío más importante para el caso de uso real. Los checks de ingeniería (complejidad, duplicación, mutación) miden calidad para un programador, no la capacidad del dueño para operar la app. Faltan:

- **Bus factor / dependencia del asistente**: ¿puede alguien (humano o una nueva sesión de IA) entender el sistema sin la conversación original? Proxy determinista: existe `README` con arranque en ≤ 5 comandos, `CLAUDE.md`/`AGENTS.md` con arquitectura y reglas, flujograma, `.env.example`; ING-01 lo cubre parcialmente.
- **Runbook de operación diaria en lenguaje no técnico**: cómo desplegar, cómo volver atrás, qué hacer si “la página no carga”, a quién llamar, dónde ver errores (Sentry), cómo ver cuánto se está gastando.
- **Panel de salud para el dueño**: uptime, errores, gasto LLM, gasto infra, vencimiento de dominio/certificados, últimas copias de seguridad.
- **Reglas para el agente IA del proyecto** (guardarraíles en `CLAUDE.md`/hooks): no tocar producción, no desactivar RLS, no comitear `.env`, correr tests antes de terminar. Enlaza con ECO-20.
- **Tamaño cognitivo**: archivos > 500 líneas, componentes “dios”, lógica de negocio repartida (el usuario y la IA pierden contexto). Determinista con `lizard`/`scc`.

### 2.12 Documentación de traspaso — **ALTA**

Checklist de traspaso (entre freelancer → dueño, o entre sesiones de IA): inventario de cuentas y titulares, accesos con MFA y al menos 2 administradores, mapa de servicios (C4 nivel 1), decisiones (ADR; repo de joelparkerhenderson 17.485★ como plantilla), deuda conocida, riesgos aceptados firmados por el dueño, contactos de proveedores, procedimiento de baja de accesos del desarrollador saliente. Ningún dominio lo trata como entregable.

### 2.13 Otros vacíos menores detectados

- **Analítica y consentimiento de cookies**: SDKs de analítica/marketing cargados antes del consentimiento (enlaza con 2.1). Check determinista: scripts de terceros cargados en la primera petición (Playwright, `requests` antes de interacción).
- **Feature flags y despliegue gradual**: sin forma de apagar una función rota sin redeploy (Unleash AGPL / PostHog). Relevante en N4.
- **Zona horaria, moneda e i18n de datos** (fechas de citas en UTC vs. hora de Chile, cambios de horario de verano): fuente de bugs funcionales típica; UX-14 solo cubre textos.
- **Accesibilidad legal**: en Chile, la Ley 21.015/Ley 20.422 no imponen WCAG a privados en general (**NO VERIFICADO**; revisar si el cliente es órgano público, donde aplica la norma técnica de desarrollo de sitios web del Estado).
- **Pruebas de abuso de lógica de negocio**: cupones reutilizables, carreras (doble reserva de la misma hora), límites de plan gratuito evadibles desde el cliente. Requiere juicio LLM guiado por el flujograma.
- **Soporte y canal de reporte**: forma de que usuarios reporten fallos y de que investigadores reporten vulnerabilidades (`security.txt`, RFC 9116).

---

## 3. Checks nuevos propuestos (catálogo 08)

Formato: ID · descripción · método · nivel en que se exige.

| ID | Check | Método | Nivel |
|---|---|---|---|
| GAP-00 | Perfil de riesgo generado (flags salud/pagos/emails/móvil/LLM/UE/menores) | mixto | N1 |
| GAP-01 | Catálogo canónico deduplicado; cada hallazgo mapeado a un único ID | determinista | N1 (del auditor) |
| GAP-02 | Inventario de datos personales y sensibles (tablas/campos/flujos) | mixto (Bearer + esquema + LLM) | N2 |
| GAP-03 | Base de licitud y consentimiento por finalidad; consentimiento expreso para datos de salud | manual (jurídico) | N3 |
| GAP-04 | Derechos del titular implementados: exportar y eliminar cuenta (incluye storage y proveedores) | mixto | N3 |
| GAP-05 | Política de privacidad existe y coincide con SDKs/recolección real | mixto | N2 |
| GAP-06 | Transferencias internacionales identificadas (región de cada proveedor) | mixto | N3 |
| GAP-07 | Plan de respuesta a brechas con doble notificación (21.719 / 21.663 si aplica) | manual | N3 |
| GAP-08 | Estado de vigencia de la Ley 21.719 verificado en BCN en la fecha de auditoría | manual | N2 |
| GAP-09 | EIPD/DPIA si hay datos sensibles a escala o usuarios UE | manual | N4 |
| GAP-10 | Webhook de pagos verifica firma con cuerpo crudo | determinista (semgrep) + prueba con stripe-cli | N2 |
| GAP-11 | Webhook idempotente por event.id; estado de pago solo desde servidor | mixto | N2 |
| GAP-12 | Montos/precios nunca tomados del cliente | determinista (semgrep) + LLM | N2 |
| GAP-13 | Checkout alojado; sin manejo de datos de tarjeta propios | determinista | N2 |
| GAP-14 | SPF, DKIM y DMARC válidos y alineados en el dominio remitente | determinista (checkdmarc) | N2 |
| GAP-15 | Envío de email asíncrono, con reintento y entorno de prueba (Mailpit) | mixto | N3 |
| GAP-16 | Reset de contraseña: token de un uso, con expiración, sin enumeración de usuarios | mixto | N2 |
| GAP-17 | Unsubscribe RFC 8058 en correos masivos/marketing | determinista | N3 |
| GAP-18 | Manifest y service worker válidos; SW no cachea respuestas autenticadas | mixto | N3 |
| GAP-19 | App nativa: MobSF sin secretos embebidos ni cleartext; MASVS-L1 | determinista | N3 |
| GAP-20 | Tope de gasto configurado en el proveedor LLM + cuota por usuario + max_tokens | mixto | N2 |
| GAP-21 | Modelo de costo unitario LLM e infra por usuario activo vs. ingreso | manual/LLM (ESTIMACIÓN) | N3 |
| GAP-22 | Trazas LLM con tokens y costo por request | determinista | N3 |
| GAP-23 | Evals de regresión del prompt en CI (promptfoo) | determinista | N4 |
| GAP-24 | Sin PII/datos de salud enviados al LLM sin anonimizar ni base legal | mixto (Presidio + LLM) | N2 |
| GAP-25 | Fallback ante caída/deprecación del modelo | mixto | N4 |
| GAP-26 | Inventario de SaaS críticos con titular de la cuenta = dueño del negocio | manual | N2 |
| GAP-27 | Dominio y DNS a nombre del dueño, autorrenovación activa | mixto | N2 |
| GAP-28 | Límites del plan gratuito conocidos (pausa por inactividad, cuotas) | mixto | N2 |
| GAP-29 | Plan de salida documentado y export probado | manual | N4 |
| GAP-30 | RPO/RTO declarados por el dueño | manual | N3 |
| GAP-31 | Copia de seguridad fuera del proveedor principal, cifrada | mixto | N3 |
| GAP-32 | Backup de storage, configuración de auth, variables y DNS | mixto | N3 |
| GAP-33 | Simulacro de restauración con tiempo medido y runbook no técnico | manual | N4 |
| GAP-34 | Inventario de secretos con dueño y fecha de rotación | mixto | N3 |
| GAP-35 | Procedimiento de rotación tras fuga probado | manual | N3 |
| GAP-36 | Previews no usan claves ni BD de producción | determinista (CLI plataforma, solo lectura) | N2 |
| GAP-37 | Log de auditoría de accesos a datos sensibles, append-only | mixto | N3 (N2 si salud) |
| GAP-38 | Eventos de auth (éxito/fallo), cambios de rol y exportaciones registrados | mixto | N3 |
| GAP-39 | Licencias de dependencias compatibles con el modelo de distribución (sin AGPL no deseada) | determinista (SBOM + política) | N3 |
| GAP-40 | Escaneo de coincidencias de licencia en código propio (ScanCode) | determinista | N4 |
| GAP-41 | Assets (fuentes, iconos, imágenes) con licencia registrada | manual | N3 |
| GAP-42 | README de arranque ≤ 5 pasos reproducible + CLAUDE.md/AGENTS.md con arquitectura | mixto | N2 |
| GAP-43 | Runbook de operación en lenguaje no técnico (deploy, rollback, “no carga”) | LLM + manual | N3 |
| GAP-44 | Panel de salud del dueño (uptime, errores, gasto, vencimientos, último backup) | mixto | N3 |
| GAP-45 | Guardarraíles para el agente IA del proyecto (hooks/CLAUDE.md: no prod, no RLS off, no .env) | determinista | N2 |
| GAP-46 | Archivos y funciones bajo umbral de tamaño cognitivo | determinista (lizard/scc) | N3 |
| GAP-47 | Paquete de traspaso: cuentas, ≥2 admins con MFA, ADR, deuda y riesgos aceptados firmados | manual | N3 |
| GAP-48 | Scripts de terceros no se cargan antes del consentimiento | determinista (Playwright) | N3 |
| GAP-49 | Abuso de lógica de negocio (carreras, cupones, límites de plan) contra el flujograma | llm | N3 |
| GAP-50 | security.txt (RFC 9116) y canal de reporte de fallos | determinista | N3 |
| GAP-51 | Fechas/horas almacenadas en UTC y mostradas en zona del usuario | mixto | N2 |
| GAP-52 | Re-auditoría programada barata (osv, gitleaks, scorecard, certificados/dominio) | determinista | N4 |

---

## 4. Señales de madurez (para la escala N1–N5)

- **N1 Prototipo**: corre localmente; sin secretos en repo; existe flujograma; dueño identificado de cada cuenta.
- **N2 MVP con usuarios reales**: RLS/autorización probadas; webhooks firmados; topes de gasto LLM; SPF/DKIM/DMARC; política de privacidad real; previews aislados; guardarraíles del agente.
- **N3 Beta abierta**: derechos del titular funcionando; log de auditoría; RPO/RTO declarados y backup externo; licencias revisadas; runbook no técnico; paquete de traspaso.
- **N4 Producción**: simulacro de restauración medido; evals de prompt en CI; plan de salida; EIPD si corresponde; re-auditoría programada.
- **N5 Escala**: pentest humano, DR multi-región según RTO, costo unitario monitoreado contra ingreso, cumplimiento validado por asesoría legal.

## 5. Limitaciones de este informe

- Las cifras de multas y plazos de notificación chilenos provienen de resúmenes secundarios con discrepancias; **deben verificarse en BCN** antes de incluirlas en un informe al cliente.
- La evidencia de lock-in es de blogs/proveedores (sesgo); se marcó como ESTIMACIÓN.
- No se encontró evidencia cuantitativa de prevalencia de fallas de pagos/emails específicamente en apps generadas por IA: **NO VERIFICADO**.
- Estrellas/actividad de repos consultadas vía `gh api` el 2026-11-17.

## Fuentes

- BCN, Ley 21.719: https://www.bcn.cl/balance-legislativo/detalle/ficha_LEY_21719_2024-12-13 · https://www.bcn.cl/leychile/navegar?idNorma=1209272
- Garrigues (postergación): https://www.garrigues.com/es_ES/noticia/chile-ejecutivo-refuerza-futura-agencia-proteccion-datos-concede-ano-adicional-adaptacion
- Diario Constitucional: https://www.diarioconstitucional.cl/2026/06/12/la-ley-21-719-entra-en-vigor-el-1-de-diciembre-y-expone-vacios-en-regulacion-de-pequenas-empresas/
- Guía de implementación del Gobierno Digital: https://wikiguias.digital.gob.cl/datos-personales/guia-practica-implementacion-nueva-ley-datos-personales
- Prey (salud; doble notificación): https://preyproject.com/es/resources/guia-de-cumplimiento-de-la-ley-de-proteccion-de-datos-para-el-sector-salud · https://preyproject.com/es/blog/doble-notificacion-incidente-ley-21663-ley-21719
- Cariola, Ley 21.663: https://cariola.cl/wp-content/uploads/2024/12/Alerta-Legal_27.12.2024.pdf
- GeoVictoria / Simplo (multas, secundarias): https://www.geovictoria.com/es-cl/blog/nueva-ley-proteccion-de-datos-chile/ · https://simplo.cl/proteccion-datos-personales-ley-21719-empresa/
- GDPR: https://eur-lex.europa.eu/eli/reg/2016/679/oj
- OWASP LLM10:2025: https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/
- OWASP A09:2025: https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Webhook Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Security_Cheat_Sheet.html
- Stripe, firma de webhooks: https://docs.stripe.com/webhooks/signature
- Hookdeck (reintentos Stripe, secundaria): https://hookdeck.com/webhooks/platforms/guide-to-stripe-webhooks-features-and-best-practices
- Requisitos de remitentes Google/Yahoo (secundaria): https://redsift.com/guides/bulk-email-sender-requirements
- Lighthouse 12 / PWA: https://developers.google.cn/speed/docs/insights/release_notes · https://developer.chrome.com/blog/update-install-criteria
- AWS Well-Architected REL13-BP02: https://docs.aws.amazon.com/wellarchitected/latest/framework/rel_planning_for_recovery_disaster_recovery.html
- Licencias y LLM: https://arxiv.org/abs/2502.05023 · https://arxiv.org/abs/2403.15230
- Lock-in (secundarias): https://sacra.com/chat/h/a2b14572-77f5-4bc5-aa80-a6361a4956d3/ · https://moklabs-research.pages.dev/reports/technology/2026-03-19-supabase-exit-strategy
- RFC 9116 security.txt: https://www.rfc-editor.org/rfc/rfc9116 · RFC 8058: https://www.rfc-editor.org/rfc/rfc8058

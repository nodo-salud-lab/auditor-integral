"""R10: portada «primero el dueño» (scripts/render_informe.py: datos_portada, render_portada, portada).

La portada solo reordena y traduce datos de la corrida: estos tests arman estados y hallazgos sintéticos, calculan
gates con gates.calcular (la misma lógica de producción) y comprueban el estado, las cifras y las reglas fail-closed
(palabras prohibidas, sin códigos en la variante dueno, línea P4.b obligatoria en ÁMBAR, nunca `evidencia`).

Regresión opcional con corridas reales: AUDITOR_CORRIDAS_REF=<carpeta> con subcarpetas v7-vulnerable, v7-limpio,
v7-centralmed, v7-rehabilitaencasa y v7-sembrada-r9 (copias de corridas; el test solo lee y re-renderiza la portada).
"""
import json
import os
import re
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import catalogo  # noqa: E402
import gates as gates_mod  # noqa: E402
import render_informe as ri  # noqa: E402
import roadmap as roadmap_mod  # noqa: E402
import utiles  # noqa: E402
import apoyo_corrida as ap  # noqa: E402

INDICE = utiles.indice_controles()
SIN_RED = "osv-scanner: sin red (AUDITOR_SIN_RED): no se consultó el registro"
EVIDENCIA_CANARIO = "EVIDENCIA-QUE-NO-DEBE-SALIR-7f3a"


def h(hid, control, sev="critica", conf="alta", archivo=".env", linea=3, regla="gitleaks:jwt", estado="abierto",
      triage=None):
    return {"id": hid, "control": control, "severidad": sev, "confianza": conf, "estado_hallazgo": estado,
            "ubicacion": {"archivo": archivo, "linea": linea}, "fuente": [{"herramienta": "x", "regla": regla}],
            "evidencia": EVIDENCIA_CANARIO, "triage": triage or {}, "gate": INDICE[control]["gate"],
            "dominio": INDICE[control]["dominio"]}


def escenario(estados, hallazgos, gitleaks="ok", cobertura=None, rm=None, herramientas=None, perfil_tecnico=None):
    """(datos de portada, gates) de un escenario sintético coherente."""
    for e in estados:
        e.setdefault("hallazgos", [x["id"] for x in hallazgos if x["control"] == e["control"]
                                   and e["estado"] == "fail"])
    g = gates_mod.calcular(estados, INDICE, hallazgos, {}, set())
    apl = [e for e in estados if e["estado"] != "no_aplica"]
    rev = [e for e in apl if e["estado"] in ("pass", "fail")]
    cob = round(len(rev) / len(apl), 3) if apl else 0.0
    s = {"global": {"cobertura": cob if cobertura is None else cobertura}}
    resumen = {"herramientas": dict({"gitleaks": {"estado": gitleaks}}, **(herramientas or {}))}
    rm = rm or {"items": [{"control": e["control"]} for e in estados]}
    d = ri.datos_portada(g, estados, hallazgos, s, resumen, rm, INDICE, "estandar", "2026-11-21_0000-abc1234", "app",
                         perfil_tecnico=perfil_tecnico)
    return d, g


def base_ambar():
    """Sin bloqueos: secreto en pass, graves sin revisar por falta de red y por juicio de IA."""
    return [{"control": "SEG-SECRETO-REPO", "estado": "pass"},
            {"control": "SEG-DEPS-EXISTEN", "estado": "no_evaluado", "motivo": SIN_RED},
            {"control": "SEG-DEPS-CVE-CRIT", "estado": "no_evaluado", "motivo": SIN_RED},
            {"control": "SEG-IDOR", "estado": "no_evaluado", "motivo": "requiere juicio LLM (F3)"},
            {"control": "COD-CI-BASICO", "estado": "fail"},
            {"control": "OPS-PRIVACIDAD", "estado": "manual_pendiente", "motivo": "aviso legal"}]


def enteros_fuera_de_codigo(texto):
    t = re.sub(r"`[^`\n]*`", " ", texto)
    t = re.sub(r"\bN[0-5]\b", " ", t)
    return {int(x) for x in re.findall(r"\d+", t)}


class TestEstados(unittest.TestCase):
    def test_arreglar_bloqueo_verdadero(self):
        est = [{"control": "SEG-SECRETO-REPO", "estado": "fail"}, {"control": "SEG-IDOR", "estado": "no_evaluado",
                                                                   "motivo": "requiere juicio LLM (F3)"}]
        d, g = escenario(est, [h("H-aaaaaa1", "SEG-SECRETO-REPO"), h("H-aaaaaa2", "SEG-SECRETO-REPO", linea=5)])
        self.assertEqual(d["estado"], ri.ESTADO_ARREGLAR)
        t = ri.render_portada(d, "dueno")
        self.assertIn("**Estado: HAY QUE ARREGLAR YA**", t)
        self.assertIn("Encontramos un problema que hay que arreglar antes de usar la app", t)
        self.assertIn("`.env:3` (y 1 lugar más en `.env`)", t)
        self.assertIn("Cambia cada clave en su servicio", t)
        self.assertIn("más urgente que borrarla del archivo", t)
        self.assertIn("**NO**, por los problemas de arriba, que impiden usar la app", t)
        self.assertNotIn("SEG-SECRETO-REPO", t)
        self.assertIn("(`SEG-SECRETO-REPO`)", ri.render_portada(d, "informe"))
        hj = ri.render_portada(d, "hoja")
        self.assertTrue(hj.startswith("**Estado: HAY QUE ARREGLAR YA.** Lo primero: «"))
        self.assertIn(": cambia", hj.splitlines()[0])  # R10e: problema y lugar, luego la acción

    def test_confirmar_por_prueba_conserva_conteo_nivel_y_listo(self):
        hs = [h("H-bbbbbb1", "SEG-SECRETO-REPO", conf="media", archivo="server/src/a.test.js", linea=39,
                regla="generic-api-key"),
              h("H-bbbbbb2", "SEG-SECRETO-REPO", conf="media", archivo="tests/fixtures/b.js", linea=2,
                regla="generic-api-key")]
        d, g = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}], hs)
        self.assertEqual(d["estado"], ri.ESTADO_CONFIRMAR)
        self.assertEqual(len(d["bloqueos"]), len(g["global"]["bloqueos"]))
        self.assertEqual(g["global"]["listo_datos_reales"], "NO")
        self.assertEqual(d["nivel_demostrado"], g["global"]["nivel_demostrado"])
        t = ri.render_portada(d, "dueno")
        self.assertIn("HAY QUE CONFIRMAR HOY", t)
        self.assertIn(f"— {ri.ACCION_CONFIRMAR} ({ri.RAZON_PRUEBA[ri.PRUEBA_POR_CONFIRMAR]}).", t)
        self.assertIn("Cómo confirmarlo", t)
        self.assertIn("**NO**, hasta confirmar la alarma", t)
        self.assertNotIn("probablemente no es nada", t)
        self.assertIn("regla genérica", ri.render_portada(d, "informe"))
        self.assertNotIn("regla genérica", t)

    def test_confirmar_por_ia(self):
        hs = [h("H-cccccc1", "SEG-SECRETO-REPO", estado="falso_positivo",
                triage={"veredicto": "falso_positivo", "razon": "x"})]
        est = [{"control": "SEG-SECRETO-REPO", "estado": "no_evaluado",
                "motivo": roadmap_mod.MOTIVO_FP_CRITICO + ": requiere verificación humana", "hallazgos": []}]
        d, g = escenario(est, hs)
        self.assertTrue(g["global"]["bloqueos"][0].get("pendiente_ia"))
        self.assertEqual(d["estado"], ri.ESTADO_CONFIRMAR)
        self.assertEqual(d["bloqueos"][0]["prueba"], ri.PRUEBA_POR_CONFIRMAR_IA)
        self.assertIn(f"{ri.ACCION_CONFIRMAR} ({ri.RAZON_PRUEBA[ri.PRUEBA_POR_CONFIRMAR_IA]}).",
                      ri.render_portada(d, "dueno"))
        self.assertEqual(g["global"]["listo_datos_reales"], "NO")

    def test_bloqueo_mixto_es_firme(self):
        b = {"control": "SEG-SECRETO-REPO"}
        alta_en_prueba = [h("H-1", "SEG-SECRETO-REPO", conf="alta", archivo="tests/a.test.js")]
        media_fuera = [h("H-2", "SEG-SECRETO-REPO", conf="media", archivo="tests/a.test.js"),
                       h("H-3", "SEG-SECRETO-REPO", conf="media", archivo="src/api.js")]
        sin_archivo = [h("H-4", "SEG-SECRETO-REPO", conf="baja", archivo=None)]
        for hs in (alta_en_prueba, media_fuera, sin_archivo):
            self.assertEqual(ri.prueba_bloqueo(b, hs), ri.PRUEBA_FIRME)
        self.assertEqual(ri.prueba_bloqueo(b, [h("H-5", "SEG-SECRETO-REPO", conf="baja", archivo="spec/x.js")]),
                         ri.PRUEBA_POR_CONFIRMAR)

    def test_ambar_cobertura_baja_no_sugiere_aprobacion(self):
        d, _ = escenario(base_ambar(), [h("H-dddddd1", "COD-CI-BASICO", sev="media", archivo=None)])
        self.assertEqual(d["estado"], ri.ESTADO_AMBAR)
        t = ri.render_portada(d, "dueno")
        self.assertIn("SIN BLOQUEOS ENCONTRADOS, REVISIÓN PARCIAL", t)
        self.assertIn("**Esto NO significa que la app sea segura**", t)
        for palabra in ("apto", "sin problemas", "aprobado", "está bien", "verificado"):
            self.assertNotRegex(t.replace("no significa que esté bien", ""), r"(?i)\b" + palabra + r"\b")
        self.assertEqual(ri.palabras_prohibidas(t), [])
        self.assertIn("**sin revisar 3**", t)
        self.assertIn("**NO**: no por un bloqueo", t)

    def test_sin_red_declarado_en_lo_no_revisado(self):
        d, _ = escenario(base_ambar(), [h("H-dddddd2", "COD-CI-BASICO", sev="media", archivo=None)])
        t = ri.render_portada(d, "dueno")
        self.assertIn("(2 sin internet, 1 necesita revisión con IA)", t)
        self.assertIn("1. **Vuelve a correr la auditoría con internet** (pídeselo a quien te ayuda con la parte "
                      "técnica): así se revisan 2 de esos puntos.", t)
        self.assertIn("1. **Vuelve a correr la auditoría con internet** (quien te ayuda con la parte técnica: sin la "
                      "opción `--sin-red`): así se revisan 2 de esos puntos.", ri.render_portada(d, "informe"))
        self.assertIn("· sin internet ·", t)
        self.assertIn("vuelve a correr la auditoría con internet (así se revisan 2 de los 3 puntos",
                      ri.render_portada(d, "hoja"))

    def test_gris_por_gitleaks(self):
        d, _ = escenario(base_ambar(), [h("H-e1", "COD-CI-BASICO", sev="media", archivo=None)], gitleaks="ausente")
        self.assertEqual(d["estado"], ri.ESTADO_GRIS)
        t = ri.render_portada(d, "dueno")
        self.assertIn("NO PUDIMOS REVISAR LO ESENCIAL", t)
        self.assertIn("`brew install gitleaks`", t)

    def test_gris_por_secreto_no_evaluado(self):
        est = base_ambar()
        est[0] = {"control": "SEG-SECRETO-REPO", "estado": "no_evaluado", "motivo": "gitleaks: herramienta ausente"}
        d, _ = escenario(est, [h("H-e2", "COD-CI-BASICO", sev="media", archivo=None)])
        self.assertEqual(d["estado"], ri.ESTADO_GRIS)
        self.assertIn("revisar el detalle técnico", ri.render_portada(d, "dueno"))

    def test_sin_estado_verde(self):
        for etiqueta in (ri.ETIQUETA_ARREGLAR, ri.ETIQUETA_CONFIRMAR, ri.ETIQUETA_GRIS, ri.ETIQUETA_PARCIAL,
                         ri.ETIQUETA_NIVEL, ri.ETIQUETA_SIN_CODIGO):
            self.assertEqual(ri.palabras_prohibidas(etiqueta), [])
            self.assertNotIn("SEGUR", etiqueta.upper())


class TestCifras(unittest.TestCase):
    def setUp(self):
        hs = [h("H-f1", "SEG-SECRETO-REPO"), h("H-f2", "COD-CI-BASICO", sev="media", archivo=None),
              h("H-f3", "SEG-CICD", sev="alta", archivo=".github/workflows/ci.yml", linea=4),
              h("H-f4", "SEG-CICD", sev="media", archivo=".github/workflows/ci.yml", linea=9)]
        est = base_ambar() + [{"control": "SEG-CICD", "estado": "fail"}]
        est[0] = {"control": "SEG-SECRETO-REPO", "estado": "fail"}
        self.est, self.hs = est, hs
        self.d, self.g = escenario(est, hs)

    def test_cifras_iguales_a_gates_estado_y_hallazgos(self):
        d, g, est = self.d, self.g, self.est
        apl = [e for e in est if e["estado"] != "no_aplica"]
        self.assertEqual(d["aplicables"], len(apl))
        self.assertEqual(d["revisados"], sum(1 for e in apl if e["estado"] in ("pass", "fail")))
        self.assertEqual(len(d["bloqueos"]), len(g["global"]["bloqueos"]))
        self.assertEqual(d["n_avisos_legales"], len(g["global"]["avisos_legales"]))
        self.assertEqual(sum(v[0] for v in d["filas_temas"].values()),
                         sum(1 for e in est if e["estado"] == "fail"))
        self.assertEqual(sum(v[1] for v in d["filas_temas"].values()), len(self.hs))
        self.assertEqual(d["graves_aplican"], d["graves_con_problema"] + d["graves_comprobados"]
                         + d["graves_sin_revisar"])
        t = ri.render_portada(d, "informe")
        self.assertIn(f"Revisamos **{d['revisados']} de {d['aplicables']}**", t)
        ns = d["nivel_siguiente"]
        permitidos = {d["revisados"], d["aplicables"], round(d["cobertura"] * 100), d["n_avisos_legales"],
                      len(d["bloqueos"]), d["graves_aplican"], d["graves_con_problema"], d["graves_comprobados"],
                      d["graves_sin_revisar"], ns["aplicables"], ns["evaluados"], len(ns["fallidos"]),
                      len(ns["pendientes"]), len(ns["no_demostrables"]), 1, 5}  # 1 y 5: «el 1», «de N5»
        permitidos |= {x for v in d["filas_temas"].values() for x in v}
        permitidos |= {t_["avisos"] for t_ in d["otros_temas"]} | {t_["en_prueba"] for t_ in d["otros_temas"]}
        permitidos |= {n for _, n in d["ampliar"]} | set(range(1, 6))  # numeración de la lista
        from collections import Counter
        permitidos |= set(Counter(d["motivos_graves"].values()).values())
        permitidos |= {b["extra"] for b in d["bloqueos"]}
        self.assertLessEqual(enteros_fuera_de_codigo(t.split("\n---\n")[0]), permitidos)

    def test_invariante_cobertura_sin_dato(self):
        d, _ = escenario(self.est, self.hs, cobertura=0.999)
        self.assertFalse(d["invariantes_ok"])
        self.assertIn("Cobertura: sin dato", ri.render_portada(d, "dueno"))

    def test_invariante_dominios_sin_dato(self):
        g = gates_mod.calcular(self.est, INDICE, self.hs, {}, set())
        g["dominios"]["SEG"]["niveles"]["N1"]["aplicables"] += 1
        s = {"global": {"cobertura": self.d["cobertura"]}}
        d = ri.datos_portada(g, self.est, self.hs, s, {"herramientas": {"gitleaks": {"estado": "ok"}}},
                             {"items": []}, INDICE)
        self.assertFalse(d["invariantes_ok"])

    def test_invariante_temas_sin_dato(self):
        est = self.est + [{"control": "SEG-ERRORES", "estado": "fail", "hallazgos": []}]
        d, _ = escenario(est, self.hs)
        self.assertFalse(d["invariante_temas"])
        t = ri.render_portada(d, "dueno")
        self.assertIn("Sin dato: los archivos de la corrida no cuadran", t)
        self.assertNotIn("| Gravedad |", t)

    def test_evidencia_nunca_aparece(self):
        for v in ri.VARIANTES_PORTADA:
            self.assertNotIn(EVIDENCIA_CANARIO, ri.render_portada(self.d, v))


class TestReglasDeTexto(unittest.TestCase):
    def test_palabras_prohibidas_y_lista_blanca(self):
        self.assertEqual(ri.palabras_prohibidas("Esto NO significa que la app sea segura: no certifica seguridad."), [])
        self.assertEqual(ri.palabras_prohibidas("Que algo no se haya revisado no significa que esté bien."), [])
        self.assertEqual(ri.palabras_prohibidas("ver `tests/pass_control.js` y node-next-limpio"), [])
        self.assertEqual(ri.palabras_prohibidas("La app es segura"), ["segura"])
        self.assertEqual(ri.palabras_prohibidas("Todo OK y aprobado"), ["aprobado", "OK"])
        self.assertIn("control", ri.palabras_prohibidas("un control quedó en fail"))
        self.assertEqual(ri.palabras_prohibidas("listo ✅"), ["emoji"])

    def test_ambar_sin_linea_p4b_es_error(self):
        with self.assertRaises(ri.PortadaInvalida):
            ri.validar_portada("**Estado: SIN BLOQUEOS ENCONTRADOS, REVISIÓN PARCIAL**\n- Revisamos 1 de 2",
                               ri.ESTADO_AMBAR, "dueno")
        ri.validar_portada("- Puntos que pueden frenar el uso: aplican 1", ri.ESTADO_AMBAR, "dueno")

    def test_dueno_sin_codigos(self):
        with self.assertRaises(ri.PortadaInvalida):
            ri.validar_portada("1. **x** (`SEG-SECRETO-REPO`)", ri.ESTADO_ARREGLAR, "dueno")
        ri.validar_portada("1. **x** (`SEG-SECRETO-REPO`)", ri.ESTADO_ARREGLAR, "informe")

    def test_textos_del_catalogo(self):
        n = 0
        for c in catalogo.cargar_catalogo():
            if "accion_dueno" in c:
                n += 1
                self.assertTrue(c["accion_dueno"].startswith(ri.VERBOS_ACCION_DUENO), c["id"])
                self.assertEqual(ri.palabras_prohibidas(c["accion_dueno"]), [], c["id"])
            if "titulo_dueno" in c:
                self.assertEqual(ri.palabras_prohibidas(c["titulo_dueno"]), [], c["id"])
                self.assertIn("accion_dueno", c, c["id"])
        self.assertGreater(n, 0)

    def test_accion_por_defecto(self):
        self.assertEqual(ri.accion_dueno("X-NO", {}, {"X-NO": "Cumplir «algo»."}), ri.ACCION_SIN_TEXTO)
        self.assertEqual(ri.accion_dueno("X-NO", {}, {}), ri.ACCION_SIN_TEXTO)
        self.assertEqual(ri.accion_dueno("X-NO", {}, {"X-NO": "Usar consultas parametrizadas. Nunca otra cosa."}),
                         "Usar consultas parametrizadas.")

    def test_plural(self):
        self.assertEqual(ri.plural(1, "problema", "problemas"), "problema")
        self.assertEqual(ri.plural(0, "problema", "problemas"), "problemas")

    def test_validar_redaccion(self):
        rm = {"items": []}
        base = {"agente": "redactor-dueno", "por_que_importa": {}, "modelo": "m"}
        ok, _ = ri.validar_redaccion(dict(base, resumen="Revisamos 3 de 9 puntos."), rm, (3, 9))
        self.assertTrue(ok)
        ok, motivo = ri.validar_redaccion(dict(base, resumen="Revisamos varios puntos."), rm, (3, 9))
        self.assertFalse(ok)
        self.assertIn("3 de 9", motivo)
        ok, motivo = ri.validar_redaccion(dict(base, resumen="Revisamos 3 de 9: la app es segura."), rm, (3, 9))
        self.assertFalse(ok)
        self.assertIn("segura", motivo)


PERFIL_VACIO = {"version_esquema": "1", "lenguajes": [], "frameworks": [], "ecosistemas": {}, "docker": False,
                "iac": False, "k8s": False, "ci": False, "limites": {"archivos_vistos": 1, "truncado": False}}


def portada_p2(t):
    """Sección «Qué hacer hoy» de una portada."""
    return re.split(r"### (?:Otros p|P)roblemas encontrados", t.split("### Qué hacer hoy")[1])[0]


class TestR10b(unittest.TestCase):
    """Regresiones de la crítica R10 con minirepos sintéticos (defectos 1 a 7)."""

    # defecto 1 -------------------------------------------------------------------------------------------------
    def test_ruta_con_prefijo_de_codigo_no_rompe_la_portada(self):
        texto = "1. **x**: `data/DAT-2024-pacientes.csv:1` — Saca ese archivo."
        for v in ("dueno", "hoja"):
            self.assertEqual(ri.validar_portada(texto, ri.ESTADO_ARREGLAR, v), texto)
        for malo in ("1. **x** (`SEG-SECRETO-REPO`)", "1. **x** DAT-PII-REPO", "ver `DAT-PII-REPO`"):
            with self.assertRaises(ri.PortadaInvalida):
                ri.validar_portada(malo, ri.ESTADO_ARREGLAR, "dueno")

    def test_bloqueo_en_ruta_con_prefijo_de_codigo(self):
        est = [{"control": "SEG-SECRETO-REPO", "estado": "pass"}, {"control": "DAT-PII-REPO", "estado": "fail"}]
        d, _ = escenario(est, [h("H-pii1", "DAT-PII-REPO", archivo="data/DAT-2024-pacientes.csv", linea=1)])
        for v in ri.VARIANTES_PORTADA:
            ri.render_portada(d, v)
        self.assertIn("`data/DAT-2024-pacientes.csv:1`", ri.render_portada(d, "dueno"))

    def test_portada_invalida_no_deja_sin_informe(self):
        d, _ = escenario(base_ambar(), [h("H-r1", "COD-CI-BASICO", sev="media", archivo=None)])
        avisos = []
        real = ri.render_portada

        def falla(datos, variante="informe"):
            raise ri.PortadaInvalida("palabras prohibidas en la portada (x): seguro")
        try:
            ri.render_portada = falla
            textos = {v: ri._portada_o_reemplazo(d, v, avisos) for v in ri.VARIANTES_PORTADA}
        finally:
            ri.render_portada = real
        self.assertEqual(len(avisos), 3)
        self.assertIn("No pudimos armar el resumen de esta portada", textos["dueno"])
        self.assertIn(f"**Estado: {d['etiqueta']}**", textos["dueno"])
        self.assertIn("- Puntos que pueden frenar el uso:", textos["dueno"])
        self.assertNotIn("Motivo técnico", textos["dueno"])
        self.assertIn("Motivo técnico: `", textos["informe"])
        self.assertTrue(textos["hoja"].startswith(f"**Estado: {d['etiqueta']}.** Lo primero: lee"))
        for v in ("dueno", "hoja"):
            self.assertEqual(ri.palabras_prohibidas(textos[v]), [], v)
            self.assertIsNone(ri._RE_CODIGO_CONTROL.search(textos[v]))

    # defecto 2 -------------------------------------------------------------------------------------------------
    def test_timeout_tiene_motivo_propio_con_prioridad(self):
        nd = [c for c in ("SEG-AUTH-CLIENTE", "DAT-PII-REPO")
              if INDICE[c].get("evidencia_pass") == "no_demostrable_estatico"]
        self.assertTrue(nd)
        for c in nd + ["DAT-SQL-CONCATENADO"]:
            e = {"control": c, "estado": "no_evaluado", "motivo": "semgrep: timeout de la herramienta"}
            self.assertEqual(ri.motivo_llano(e, INDICE), "reintentar", c)
        est = [{"control": "SEG-SECRETO-REPO", "estado": "pass"},
               {"control": "DAT-SQL-CONCATENADO", "estado": "no_evaluado",
                "motivo": "semgrep: timeout de la herramienta"},
               {"control": "SEG-AUTH-CLIENTE", "estado": "no_evaluado",
                "motivo": "semgrep: timeout de la herramienta; bandit: sin datos de la herramienta (no se ejecutó)"}]
        d, _ = escenario(est, [], herramientas={"semgrep": {"estado": "timeout"}})
        self.assertEqual(d["estado"], ri.ESTADO_AMBAR)
        t = ri.render_portada(d, "dueno")
        p2 = portada_p2(t)
        self.assertIn("**Repite la auditoría, con más tiempo si hace falta**: así se revisan 2 de esos puntos. Una "
                      "herramienta del auditor no terminó a tiempo o falló.", p2)
        self.assertNotIn("semgrep", p2)   # R10c: el nombre de la herramienta solo en la variante informe
        self.assertIn("no terminó a tiempo o falló (semgrep).", portada_p2(ri.render_portada(d, "informe")))
        for no in ("Confírmalo tú", "revisión a mano", "Instala", "instalar"):
            self.assertNotIn(no, p2)
        self.assertIn("2 quedaron así porque una herramienta no terminó a tiempo o falló", t)
        self.assertIn("repite la auditoría", ri.render_portada(d, "hoja"))

    def test_gris_por_timeout_de_gitleaks_no_pide_instalar(self):
        d, _ = escenario(base_ambar(), [h("H-e3", "COD-CI-BASICO", sev="media", archivo=None)], gitleaks="timeout")
        self.assertEqual(d["estado"], ri.ESTADO_GRIS)
        for v in ri.VARIANTES_PORTADA:
            t = ri.render_portada(d, v)
            self.assertNotIn("brew install", t)
            self.assertNotIn("instalar gitleaks", t)
            self.assertIn("con más tiempo (gitleaks está instalada", t)

    # defecto 3 (y 7: nunca «quedaron revisados» sin código) ---------------------------------------------------
    def test_sin_codigo(self):
        self.assertTrue(ri.sin_codigo(PERFIL_VACIO))
        self.assertFalse(ri.sin_codigo(None))
        self.assertFalse(ri.sin_codigo({}))
        self.assertFalse(ri.sin_codigo(dict(PERFIL_VACIO, lenguajes=["php"])))
        self.assertFalse(ri.sin_codigo(dict(PERFIL_VACIO, ci=True)))
        self.assertFalse(ri.sin_codigo(dict(PERFIL_VACIO, limites={"truncado": True})))
        # todos los graves comprobados: sin código igual no dice «quedaron revisados»
        est = [{"control": "SEG-SECRETO-REPO", "estado": "pass"}, {"control": "COD-CI-BASICO", "estado": "fail"}]
        for e_extra in ([], [{"control": "SEG-IDOR", "estado": "no_evaluado", "motivo": "requiere juicio LLM (F3)"}]):
            d, _ = escenario(est + e_extra, [h("H-v1", "COD-CI-BASICO", sev="media", archivo=None)],
                             perfil_tecnico=PERFIL_VACIO)
            self.assertEqual(d["estado"], ri.ESTADO_SIN_CODIGO)
            t = ri.render_portada(d, "dueno")
            p1 = t.split("**Estado:")[1].split("### Qué hacer hoy")[0]
            self.assertIn(ri.TEXTO_SIN_CODIGO, p1)
            self.assertNotIn("quedaron revisados", t)
            self.assertNotIn("en lo que pudimos revisar", t)
            self.assertNotIn("a tu app", t)
            self.assertIn("**Revisa que la carpeta sea la correcta**", portada_p2(t))
            self.assertIn("Lo primero: revisa que la carpeta sea la correcta", ri.render_portada(d, "hoja"))
        d, _ = escenario(est, [h("H-v2", "COD-CI-BASICO", sev="media", archivo=None)])
        self.assertNotIn(ri.TEXTO_SIN_CODIGO, ri.render_portada(d, "dueno"))

    def test_sin_codigo_con_bloqueo_no_oculta_el_bloqueo(self):
        d, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}], [h("H-v3", "SEG-SECRETO-REPO",
                                                                                    archivo="README.md")],
                         perfil_tecnico=PERFIL_VACIO)
        self.assertEqual(d["estado"], ri.ESTADO_ARREGLAR)
        t = ri.render_portada(d, "dueno")
        self.assertIn(ri.TEXTO_SIN_CODIGO, t.split("### Qué hacer hoy")[0])
        self.assertIn("Cambia cada clave", portada_p2(t))

    def test_cargar_portada_lee_perfil_tecnico(self):
        import inspect
        self.assertIn("perfil_tecnico.json", inspect.getsource(ri._cargar_portada))
        self.assertIn("perfil_tecnico.json", inspect.getsource(ri.generar))

    # defecto 4 -------------------------------------------------------------------------------------------------
    def test_herramientas_que_no_corrieron_en_p1(self):
        est = [{"control": "SEG-SECRETO-REPO", "estado": "fail"}]
        hs = [h("H-t1", "SEG-SECRETO-REPO")]
        casos = {(("semgrep", "timeout"),): "no pudimos usar semgrep:",
                 (("semgrep", "error"),): "no pudimos usar semgrep:",
                 (("gitleaks", "ausente"), ("semgrep", "ausente")): "no pudimos usar gitleaks ni semgrep:"}
        for herrs, esperado in casos.items():
            hd = {k: {"estado": v} for k, v in herrs}
            d, _ = escenario(est, hs, gitleaks=hd.pop("gitleaks", {}).get("estado", "ok"), herramientas=hd)
            t = ri.render_portada(d, "dueno").split("### Qué hacer hoy")[0]
            self.assertIn(f"Además, {esperado} los problemas pueden ser más.", t)
        d, _ = escenario(est, hs, herramientas={"semgrep": {"estado": "ok"}})
        self.assertNotIn("no pudimos usar", ri.render_portada(d, "dueno"))
        d, _ = escenario(base_ambar(), [h("H-t2", "COD-CI-BASICO", sev="media", archivo=None)],
                         herramientas={"semgrep": {"estado": "timeout"}})
        self.assertNotIn("los problemas pueden ser más", ri.render_portada(d, "dueno"))

    # defecto 5 -------------------------------------------------------------------------------------------------
    def test_confirmar_redaccion(self):
        hs = [h("H-c1", "SEG-SECRETO-REPO", conf="media", archivo="tests/a.test.js", linea=1, regla="generic-api-key")]
        d, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}], hs)
        self.assertEqual(d["estado"], ri.ESTADO_CONFIRMAR)
        dueno, informe, hoja = (ri.render_portada(d, v) for v in ("dueno", "informe", "hoja"))
        self.assertIn("Encontramos una alarma que, si es real, impide usar la app; podría ser una falsa alarma", dueno)
        self.assertNotIn("parece falsa", dueno)
        linea = next(l for l in dueno.splitlines() if l.startswith("1. **"))
        self.assertTrue(linea.endswith(f"— {ri.ACCION_CONFIRMAR} ({ri.RAZON_PRUEBA[ri.PRUEBA_POR_CONFIRMAR]})."))
        self.assertNotIn("Cambia cada clave", linea)
        self.assertNotIn("[confírmalo primero", linea)
        self.assertIn("**cámbiala en el servicio hoy mismo**", dueno)
        self.assertNotIn("fp-verificados", dueno)
        self.assertIn("pídele a quien te ayuda con la parte técnica que la registre como falsa alarma (con nombre, "
                      "fecha y razón) y vuelve a correr la auditoría", dueno)
        self.assertIn("`--fp-verificados`", informe)
        self.assertIn("(ver «Cómo confirmarlo» en `resumen-dueno.md`)", hoja)
        hs2 = hs + [h("H-c2", "SEG-SECRETO-BUNDLE", conf="media", archivo="tests/b.test.js", regla="generic-api-key")]
        d2, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"},
                           {"control": "SEG-SECRETO-BUNDLE", "estado": "fail"}], hs2)
        self.assertEqual((d2["estado"], len(d2["bloqueos"])), (ri.ESTADO_CONFIRMAR, 2))
        self.assertIn("2 alarmas que, si son reales, impiden usar la app; podrían ser falsas alarmas",
                      ri.render_portada(d2, "dueno"))

    # defecto 6 -------------------------------------------------------------------------------------------------
    def test_redaccion_concordancia_y_filas(self):
        est = [{"control": "SEG-SECRETO-REPO", "estado": "pass"},
               {"control": "SEG-LLM-CLAVE", "estado": "no_evaluado", "motivo": "no demostrable en análisis "
                "estático: x"},
               {"control": "DAT-PII-REPO", "estado": "no_evaluado", "motivo": "no demostrable en análisis estático: y"},
               {"control": "COD-CI-BASICO", "estado": "fail"},
               {"control": "OPS-PRIVACIDAD", "estado": "manual_pendiente", "motivo": "aviso legal"}]
        d, g = escenario(est, [h("H-x1", "COD-CI-BASICO", sev="media", archivo=None)])
        self.assertEqual(d["estado"], ri.ESTADO_AMBAR)
        t = ri.render_portada(d, "dueno")
        self.assertEqual(list(d["motivos_graves"].values()).count("no_demostrable"), 2)
        self.assertIn("**Pide a quien te ayuda que confirme a mano** que no pasen estas cosas:", t)
        self.assertIn("Leyendo el código no se puede demostrar.", t)
        self.assertIn("| Crítica | 0 | 0 |", t)
        self.assertIn(ri.NOTA_SIN_CRITICOS, t)
        self.assertEqual(d["n_avisos_legales"], 1)
        self.assertIn(f"De esos {d['aplicables']}, 1 es un aviso legal que siempre revisa una persona.", t)
        self.assertNotIn("incluye", t.split("### Qué pudimos revisar")[1].split("\n")[2])
        self.assertNotIn("nada urgente", t)
        self.assertIn("No hay bloqueos ni problemas de gravedad alta o crítica que arreglar hoy.", t)
        d1, _ = escenario(est[:1] + est[2:], [h("H-x2", "COD-CI-BASICO", sev="media", archivo=None)])
        self.assertEqual(list(d1["motivos_graves"].values()), ["no_demostrable"])
        self.assertIn("que no pase esto:", ri.render_portada(d1, "dueno"))

    def test_ambar_con_alta_matiza_nada_urgente(self):
        est = base_ambar() + [{"control": "SEG-CICD", "estado": "fail"}]
        hs = [h("H-a1", "COD-CI-BASICO", sev="media", archivo=None),
              h("H-a2", "SEG-CICD", sev="alta", archivo=".github/workflows/ci.yml", linea=4)]
        d, _ = escenario(est, hs)
        self.assertEqual(d["estado"], ri.ESTADO_AMBAR)
        t = ri.render_portada(d, "dueno")
        self.assertNotIn("No hay nada urgente", t)
        self.assertIn("No hay bloqueos que arreglar hoy; hay 1 problema de gravedad alta en la tabla de abajo.", t)
        d2, _ = escenario(est, hs)
        d2["invariante_temas"] = False
        self.assertNotIn("No hay nada urgente", ri.render_portada(d2, "dueno"))

    def test_gris_fila_critica_con_nota(self):
        d, _ = escenario(base_ambar(), [h("H-a3", "COD-CI-BASICO", sev="media", archivo=None)], gitleaks="ausente")
        self.assertEqual(d["estado"], ri.ESTADO_GRIS)
        for v in ("dueno", "informe"):
            t = ri.render_portada(d, v)
            self.assertIn("| Crítica | 0 | 0 |", t)
            self.assertIn(ri.NOTA_SIN_CRITICOS, t)
            self.assertNotIn("(encontrados)", t)

    # defecto 7 -------------------------------------------------------------------------------------------------
    def test_deps_sin_manifiestos_sigue_sin_revisar(self):
        """Decisión R10b: «sin manifiestos» no prueba que no haya dependencias (imports sin declarar, vendorizado,
        ecosistemas sin verificador): SEG-DEPS-EXISTEN sigue no_evaluado (fail-closed); la portada no lo traduce
        como revisado."""
        e = {"control": "SEG-DEPS-EXISTEN", "estado": "no_evaluado",
             "motivo": "registro_deps corrió sin hallazgos y sin el pase explícito que exige el control: sin "
                       "manifiestos de dependencias (package.json, requirements, pyproject, Pipfile)"}
        self.assertEqual(ri.motivo_llano(e, INDICE), "evidencia")
        d, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "pass"}, e], [], perfil_tecnico=PERFIL_VACIO)
        self.assertEqual(d["graves_sin_revisar"], 1)
        self.assertNotIn("quedaron revisados", ri.render_portada(d, "dueno"))


class TestIntegracion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import normalizar.run as n_run
        tmp = ap.tmp_dir(cls)
        cls.corrida = ap.preparar_corrida(tmp)
        n_run.main([str(cls.corrida)])
        ri.generar(cls.corrida)
        leer = lambda n: (cls.corrida / n).read_text(encoding="utf-8")  # noqa: E731
        cls.informe, cls.dueno, cls.ruta = leer("informe.md"), leer("resumen-dueno.md"), leer("hoja-de-ruta.md")

    def test_orden_del_informe(self):
        i = self.informe
        self.assertLess(i.index("## Portada"), i.index(ri.TITULO_AVISO_LEGAL))
        self.assertLess(i.index(ri.TITULO_AVISO_LEGAL), i.index("## 1. Veredicto"))
        portada = i[i.index("## Portada"):i.index(ri.TITULO_AVISO_LEGAL)]
        self.assertNotIn(gates_mod.HITOS["N0"], portada)
        self.assertIn(gates_mod.HITOS["N0"], i.split("## 1. Veredicto")[1])

    def test_cifras_del_archivo_igual_a_la_corrida(self):
        est = json.loads((self.corrida / "estado.json").read_text(encoding="utf-8"))["controles"]
        g = json.loads((self.corrida / "gates.json").read_text(encoding="utf-8"))
        apl = [e for e in est if e["estado"] != "no_aplica"]
        rev = sum(1 for e in apl if e["estado"] in ("pass", "fail"))
        self.assertIn(f"Revisamos **{rev} de {len(apl)}**", self.dueno)
        nb = len({b["control"] for b in g["global"]["bloqueos"]})
        self.assertIn(f"Encontramos {'un' if nb == 1 else nb} ", self.dueno)
        self.assertEqual(self.dueno.split("## Portada")[1].split("\n---\n")[0],
                         ri.portada(self.corrida, "dueno").split("## Portada")[1].split("\n---\n")[0])

    def test_portada_invalida_en_generar_escribe_igual_los_tres_archivos(self):
        import contextlib
        import io
        import normalizar.run as n_run
        corrida = ap.preparar_corrida(ap.tmp_dir(self), nombre="corrida-invalida")
        n_run.main([str(corrida)])
        real = ri.validar_portada

        def siempre_falla(texto, estado, variante, proyecto=None):
            raise ri.PortadaInvalida(f"forzado en test ({variante})")
        err = io.StringIO()
        try:
            ri.validar_portada = siempre_falla
            with contextlib.redirect_stderr(err):
                ri.generar(corrida)
        finally:
            ri.validar_portada = real
        for n in ("informe.md", "resumen-dueno.md", "hoja-de-ruta.md"):
            self.assertTrue((corrida / n).is_file(), n)
        self.assertIn("No pudimos armar el resumen de esta portada", (corrida / "resumen-dueno.md").read_text())
        self.assertIn("Lo primero: lee «1. Veredicto»", (corrida / "hoja-de-ruta.md").read_text())
        self.assertIn("## 1. Veredicto", (corrida / "informe.md").read_text())
        self.assertEqual(err.getvalue().count("AVISO: la portada no pasó su validación"), 3)

    def test_dueno_y_hoja(self):
        self.assertNotIn("## En una frase", self.dueno)
        portada = self.dueno.split("## Portada")[1].split("\n---\n")[0]
        self.assertIsNone(ri._RE_CODIGO_CONTROL.search(portada))
        self.assertIn("**Estado: HAY QUE ARREGLAR YA.** Lo primero:", self.ruta)
        self.assertIn("Nivel demostrado: N0 (dato secundario", self.ruta)
        self.assertIn("Lo listado en «Qué hacer hoy» (portada) no se repite aquí.", self.dueno)
        self.assertNotIn(EVIDENCIA_CANARIO, self.dueno)


class TestR10c(unittest.TestCase):
    """Regresiones de la tercera ronda (lector no técnico y verificador), puntos A a L."""

    # A ---------------------------------------------------------------------------------------------------------
    def test_a_avisos_legales_se_refieren_a_los_que_aplican(self):
        d, _ = escenario(base_ambar(), [h("H-A1", "COD-CI-BASICO", sev="media", archivo=None)])
        self.assertEqual(d["n_avisos_legales"], 1)
        for v in ("dueno", "informe"):
            t = ri.render_portada(d, v)
            self.assertIn(f"Revisamos **{d['revisados']} de {d['aplicables']}** puntos que aplican a tu app "
                          f"({ri._pct(d['cobertura'])}). De esos {d['aplicables']}, 1 es un aviso legal que siempre "
                          "revisa una persona.", t)
            self.assertNotIn("de ellos", t)
            self.assertNotRegex(t, r"incluye \d+ avisos? legal")

    # B ---------------------------------------------------------------------------------------------------------
    def test_b_carpeta_sin_codigo_tiene_estado_propio(self):
        est = [{"control": "SEG-SECRETO-REPO", "estado": "pass"}, {"control": "COD-CI-BASICO", "estado": "fail"},
               {"control": "SEG-IDOR", "estado": "no_evaluado", "motivo": "requiere juicio LLM (F3)"},
               {"control": "SEG-DEPS-CVE-CRIT", "estado": "no_evaluado", "motivo": "osv-scanner: herramienta ausente"},
               {"control": "OPS-PRIVACIDAD", "estado": "manual_pendiente", "motivo": "aviso legal"}]
        d, g = escenario(est, [h("H-B1", "COD-CI-BASICO", sev="media", archivo=None)], perfil_tecnico=PERFIL_VACIO,
                         herramientas={"osv-scanner": {"estado": "ausente"}})
        self.assertEqual(d["estado"], ri.ESTADO_SIN_CODIGO)
        self.assertEqual(g["global"]["listo_datos_reales"], "NO")
        self.assertEqual(d["listo"], g["global"]["listo_datos_reales"])
        for v in ("dueno", "informe"):
            t = ri.render_portada(d, v)
            self.assertIn("**Estado: NO HAY CÓDIGO QUE AUDITAR**", t)
            self.assertIn("No encontramos código que auditar: revisa que la carpeta sea la correcta", t)
            for no in ("SIN BLOQUEOS ENCONTRADOS", "REVISIÓN PARCIAL", "En tu caso no hay bloqueos",
                       "comprobados sin problema", "instalar herramientas", "instale", "levantar la app",
                       "app en marcha"):
                self.assertNotIn(no, t, (v, no))
            self.assertIn("¿Lista para datos reales de personas? **NO**: no se auditó ninguna app.", t)
        self.assertTrue(ri.render_portada(d, "hoja").startswith("**Estado: NO HAY CÓDIGO QUE AUDITAR.** Lo primero: "
                                                                 "revisa que la carpeta sea la correcta"))
        # con un bloqueo (un secreto en un README) se mantiene ARREGLAR con la frase antepuesta
        d2, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}],
                          [h("H-B2", "SEG-SECRETO-REPO", archivo="README.md")], perfil_tecnico=PERFIL_VACIO)
        self.assertEqual(d2["estado"], ri.ESTADO_ARREGLAR)
        t2 = ri.render_portada(d2, "dueno")
        self.assertIn(f"{ri.TEXTO_SIN_CODIGO}. Encontramos un problema que hay que arreglar", t2)

    # C ---------------------------------------------------------------------------------------------------------
    def test_c_arreglar_mixto_confirma_antes_de_arreglar(self):
        hs = [h("H-C1", "SEG-SECRETO-REPO", archivo=".env", linea=2),
              h("H-C2", "SEG-SECRETO-BUNDLE", conf="media", archivo="tests/b.test.js", linea=4,
                regla="generic-api-key")]
        d, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"},
                          {"control": "SEG-SECRETO-BUNDLE", "estado": "fail"}], hs)
        self.assertEqual(d["estado"], ri.ESTADO_ARREGLAR)
        self.assertEqual([b["prueba"] for b in d["bloqueos"]].count(ri.PRUEBA_POR_CONFIRMAR), 1)
        for v in ("dueno", "informe"):
            t = ri.render_portada(d, v)
            p2 = portada_p2(t)
            self.assertNotIn("[confírmalo primero", t)
            self.assertIn("— Confirma hoy si es real (aparece solo en archivos de prueba y el detector no está "
                          "seguro); si lo es, ", p2)
            self.assertIn("**Cómo confirmarlo:**", p2)
            self.assertIn("**cámbiala en el servicio hoy mismo**", p2)
            firme = next(l for l in p2.splitlines() if "Confirma hoy" not in l and l[:3] in ("1. ", "2. "))
            self.assertIn("Cambia cada clave en su servicio", firme)
        self.assertIn("vuelve a correr con `--fp-verificados`", ri.render_portada(d, "informe"))
        self.assertNotIn("fp-verificados", ri.render_portada(d, "dueno"))
        # R10c: el firme va primero, así «Empieza por el 1» y «Lo primero» (hoja) apuntan al mismo
        self.assertEqual([b["prueba"] for b in d["bloqueos"]], [ri.PRUEBA_FIRME, ri.PRUEBA_POR_CONFIRMAR])
        t = ri.render_portada(d, "dueno")
        self.assertIn("Encontramos 2 problemas que hay que arreglar antes de usar la app con personas reales "
                      "(uno hay que confirmarlo primero). Empieza por el 1.", t)
        self.assertTrue(next(l for l in t.splitlines() if l.startswith("1. ")).endswith(
            "— Cambia cada clave en su servicio hoy mismo y después sácala del proyecto."))
        self.assertRegex(ri.render_portada(d, "hoja"), r"Lo primero: «[^»]+» \(`[^`]+`\): cambia cada clave")
        # con la clave por confirmar y un bloqueo firme que no es una clave, no se afirma que haya una clave real
        hs3 = [h("H-C3", "DAT-PII-REPO", archivo="data/p.csv", linea=1),
               h("H-C4", "SEG-SECRETO-REPO", conf="media", archivo="tests/c.test.js", regla="generic-api-key")]
        d3, _ = escenario([{"control": "DAT-PII-REPO", "estado": "fail"},
                           {"control": "SEG-SECRETO-REPO", "estado": "fail"}], hs3)
        self.assertEqual(d3["estado"], ri.ESTADO_ARREGLAR)
        self.assertNotIn("más urgente que borrarla", ri.render_portada(d3, "dueno"))
        # todo firme: sin «Cómo confirmarlo»
        d2, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}], hs[:1])
        self.assertNotIn("Cómo confirmarlo", ri.render_portada(d2, "dueno"))

    # D ---------------------------------------------------------------------------------------------------------
    def test_d_nada_urgente_no_existe(self):
        import inspect
        self.assertNotIn("nada urgente", inspect.getsource(ri))
        est = base_ambar() + [{"control": "SEG-CICD", "estado": "fail"}]
        hs = [h("H-D1", "COD-CI-BASICO", sev="media", archivo=None),
              h("H-D2", "SEG-CICD", sev="alta", archivo=".github/workflows/ci.yml", linea=4)]
        d, _ = escenario(est, hs)
        for v in ri.VARIANTES_PORTADA:
            self.assertNotIn("nada urgente", ri.render_portada(d, v))
        self.assertIn("hay 1 problema de gravedad alta en la tabla de abajo", ri.render_portada(d, "dueno"))

    # E ---------------------------------------------------------------------------------------------------------
    def test_e_ambar_verbos_para_el_dueno(self):
        est = [{"control": "SEG-SECRETO-REPO", "estado": "pass"},
               {"control": "SEG-IDOR", "estado": "no_evaluado", "motivo": "requiere juicio LLM (F3)"},
               {"control": "DAT-PII-REPO", "estado": "no_evaluado", "motivo": "no demostrable en análisis estático"},
               {"control": "SEG-DEPS-CVE-CRIT", "estado": "no_evaluado", "motivo": "osv-scanner: herramienta ausente"}]
        d, _ = escenario(est, [], herramientas={"osv-scanner": {"estado": "ausente"}})
        self.assertEqual(d["estado"], ri.ESTADO_AMBAR)
        self.assertEqual(d["herr_instalar"], ["osv-scanner"])
        t = ri.render_portada(d, "dueno")
        p2 = portada_p2(t)
        self.assertIn("**Vuelve a correr la auditoría con revisión asistida por IA**: así se revisa 1 de esos "
                      "puntos.", p2)
        self.assertIn("**Pide a quien te ayuda que confirme a mano** que no pase esto: «", p2)
        self.assertIn("Leyendo el código no se puede demostrar.", p2)
        self.assertIn("**Pide a quien te ayuda que instale osv-scanner**: así se revisa 1 de esos puntos.", p2)
        self.assertIn("(`bin/auditar doctor` muestra cuáles faltan)", portada_p2(ri.render_portada(d, "informe")))
        for viejo in ("Confírmalo tú", "Mirando el código", "Permite la conexión", ": revisa "):
            self.assertNotIn(viejo, t)
        self.assertIn("- Lo que más ampliaría la revisión: instalar osv-scanner (1 punto)", t)
        self.assertIn("Lo primero: vuelve a correr la auditoría con revisión asistida por IA (así se revisa 1 de los 3 "
                      "puntos que pueden frenar el uso y que quedaron sin revisar).", ri.render_portada(d, "hoja"))
        self.assertNotIn("de esos puntos", ri.render_portada(d, "hoja"))
        # sin herramientas ausentes no se pide instalar
        d2, _ = escenario([dict(est[0]), {"control": "SEG-DEPS-CVE-CRIT", "estado": "no_evaluado",
                                          "motivo": "osv-scanner: sin datos de la herramienta"}], [],
                          herramientas={"osv-scanner": {"estado": "ok"}})
        self.assertEqual(d2["herr_instalar"], [])
        t2 = ri.render_portada(d2, "dueno")
        self.assertNotIn("instal", t2)
        self.assertIn("habilitar herramientas que esta vez no corrieron (1 punto)", t2)
        self.assertIn("**Pide a quien te ayuda que habilite las herramientas que esta vez no corrieron**", t2)
        # levantar la app: el verbo es del dueño
        self.assertNotIn("Permite levantar", inspect_fuente())

    # F ---------------------------------------------------------------------------------------------------------
    def test_f_confirmar_concordancia(self):
        hs = [h("H-F1", "SEG-SECRETO-REPO", conf="media", archivo="tests/a.test.js", linea=1, regla="generic-api-key")]
        d, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}], hs)
        t = ri.render_portada(d, "dueno")
        self.assertIn("Encontramos una alarma que, si es real, impide usar la app; podría ser una falsa alarma, pero "
                      "no podemos descartarla sola. Revísala hoy. Mientras nadie la confirme, cuenta como un "
                      "bloqueo.", t)
        self.assertNotIn("Ábrela", t)
        self.assertNotIn("nadie lo confirme", t)

    # G ---------------------------------------------------------------------------------------------------------
    def test_g_problema_que_tambien_impide_el_nivel(self):
        est = base_ambar() + [{"control": "SEG-ENV-EJEMPLO", "estado": "fail"}]
        d, _ = escenario(est, [h("H-G1", "COD-CI-BASICO", sev="media", archivo=None),
                               h("H-G2", "SEG-ENV-EJEMPLO", sev="media", archivo=None,
                                 regla="check:archivos_clave.env_ejemplo_ausente")])
        self.assertEqual(d["estado"], ri.ESTADO_AMBAR)
        ns = d["nivel_siguiente"]
        self.assertEqual(ns["fallidos"], ["SEG-ENV-EJEMPLO"])
        t = ri.render_portada(d, "dueno")
        self.assertIn(f"En tu caso no hay bloqueos, pero hay 1 problema que también impide {ns['nivel']}: falta un "
                      "archivo de ejemplo de configuración (`.env.example`).", t)
        self.assertNotIn("también pesa", t)

    # H ---------------------------------------------------------------------------------------------------------
    def test_h_evidencia_en_llano(self):
        e = {"control": "SEG-DEPS-EXISTEN", "estado": "no_evaluado",
             "motivo": "registro_deps corrió sin hallazgos y sin el pase explícito que exige el control"}
        d, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "pass"}, e], [])
        t = ri.render_portada(d, "dueno")
        self.assertIn("1 se revisó pero la herramienta no dejó la prueba que se pide para darlo por bueno", t)
        self.assertNotIn("pruebas suficientes", t)

    # I ---------------------------------------------------------------------------------------------------------
    def test_i_titulo_de_problemas(self):
        d, _ = escenario(base_ambar(), [h("H-I1", "COD-CI-BASICO", sev="media", archivo=None)])
        t = ri.render_portada(d, "dueno")
        self.assertIn(ri.TITULO_TABLA_PROBLEMAS, t)
        self.assertNotIn("### Otros problemas", t)
        self.assertIn("| Crítica | 0 | 0 |", t)
        d2, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}], [h("H-I2", "SEG-SECRETO-REPO")])
        t2 = ri.render_portada(d2, "dueno")
        # R10d: el mismo título con bloqueos (la tabla los incluye: «Crítica (los de arriba)» es coherente)
        self.assertIn(ri.TITULO_TABLA_PROBLEMAS, t2)
        self.assertNotIn("### Otros problemas", t2)
        self.assertIn("| Crítica (los de arriba) | 1 | 1 |", t2)
        self.assertNotIn(ri.NOTA_SIN_CRITICOS, t2)

    # J ---------------------------------------------------------------------------------------------------------
    def test_j_gris_no_repite_la_causa(self):
        est = base_ambar()
        est[0] = {"control": "SEG-SECRETO-REPO", "estado": "no_evaluado", "motivo": "gitleaks: herramienta ausente"}
        d, _ = escenario(est, [h("H-J1", "COD-CI-BASICO", sev="media", archivo=None)], gitleaks="ausente")
        self.assertEqual(d["estado"], ri.ESTADO_GRIS)
        self.assertIn("gitleaks", d["faltas_gris"])
        self.assertIn("secreto", d["faltas_gris"])
        p1 = ri.render_portada(d, "dueno").split("**Estado:")[1].split("### Qué hacer hoy")[0]
        self.assertEqual(p1.count("claves secretas"), 1)
        self.assertIn("no se pudo usar la herramienta que busca claves secretas", p1)

    # K ---------------------------------------------------------------------------------------------------------
    def test_k_cabecera_del_resumen(self):
        tmpl = (RAIZ / "plantillas" / "resumen-dueno.md.tmpl").read_text(encoding="utf-8")
        self.assertNotIn("una página", tmpl)
        self.assertIn("modo $modo_visible · lo esencial está en la portada; lo de abajo es para quien te ayuda con la "
                      "parte técnica", tmpl)
        self.assertNotIn("**$modo**", (RAIZ / "plantillas" / "informe.md.tmpl").read_text(encoding="utf-8"))
        self.assertNotIn("una página", (RAIZ / "plantillas" / "informe.md.tmpl").read_text(encoding="utf-8"))

    # L ---------------------------------------------------------------------------------------------------------
    def test_l_titulo_de_env_ejemplo_segun_el_caso(self):
        cid = "SEG-ENV-EJEMPLO"
        self.assertNotIn(" o el archivo", INDICE[cid]["titulo_dueno"])
        casos = {"check:archivos_clave.env_ejemplo_ausente": "Falta un archivo de ejemplo de configuración",
                 "check:archivos_clave.env_comiteado": "está guardado en el repositorio",
                 "check:archivos_clave.env_no_ignorado": "no está excluido del repositorio"}
        for regla, esperado in casos.items():
            t, a = ri.titulo_accion_por_caso(cid, [h("H-L", cid, regla=regla)], INDICE)
            self.assertIn(esperado, t, regla)
            self.assertTrue(a.startswith(ri.VERBOS_ACCION_DUENO), a)
            self.assertEqual(ri.palabras_prohibidas(t + " " + a), [])
        mixto = [h("H-L1", cid, regla="check:archivos_clave.env_ejemplo_ausente"),
                 h("H-L2", cid, regla="check:archivos_clave.env_no_ignorado")]
        t, a = ri.titulo_accion_por_caso(cid, mixto, INDICE)
        self.assertEqual(t, "El archivo `.env` con valores reales no está excluido del repositorio y falta un archivo "
                            "de ejemplo de configuración (`.env.example`)")
        self.assertEqual(a, "Agrega `.env` a `.gitignore` antes del próximo commit. Además, crea `.env.example` con "
                            "los nombres de las variables y valores inventados.")
        self.assertNotIn(" o ", t)
        self.assertEqual(ri.titulo_accion_por_caso(cid, [], INDICE)[0], ri.titulo_dueno(cid, INDICE))
        # en la portada, el tema usa el título del caso
        est = base_ambar() + [{"control": cid, "estado": "fail"}]
        hs = [h("H-L3", "COD-CI-BASICO", sev="media", archivo=None),
              h("H-L4", cid, sev="media", archivo=None, regla="check:archivos_clave.env_ejemplo_ausente")]
        d, _ = escenario(est, hs)
        self.assertIn("**Falta un archivo de ejemplo de configuración (`.env.example`)**", ri.render_portada(d, "dueno"))


def item_rm(control, titulo="t", que_hacer="Hacer algo."):
    return {"control": control, "estado": "fail", "severidad": "critica", "titulo": titulo, "esfuerzo": "S",
            "que_hacer": que_hacer, "verificacion": "Corrida nueva."}


class TestR10d(unittest.TestCase):
    """R10d: «graves» frente a «gravedad alta», hoja alineada con la portada, concordancias, estado sin código y tabla."""

    GRAVE = re.compile(r"\b(?:problemas? graves?|alarmas? graves?)\b", re.I)

    def _todas(self, d):
        return {v: ri.render_portada(d, v) for v in ri.VARIANTES_PORTADA}

    # 1 ---------------------------------------------------------------------------------------------------------
    def test_1_sin_graves_que_compitan_con_gravedad_alta(self):
        est = base_ambar() + [{"control": "SEG-CICD", "estado": "fail"}]
        hs = [h("H-d1", "COD-CI-BASICO", sev="media", archivo=None),
              h("H-d2", "SEG-CICD", sev="alta", archivo=".github/workflows/ci.yml", linea=4)]
        d, _ = escenario(est, hs)
        self.assertEqual(d["estado"], ri.ESTADO_AMBAR)
        t = ri.render_portada(d, "dueno")
        p1 = t.split("**Estado:")[1].split("### Qué hacer hoy")[0]
        self.assertIn("No encontramos problemas que impidan usar la app en lo que pudimos revisar.", p1)
        self.assertNotIn("graves", p1)
        self.assertIn("- Puntos que pueden frenar el uso:", t)
        self.assertIn("gravedad alta en la tabla de abajo", t)
        # ninguna rama usa «problema(s)/alarma(s) grave(s)» para el grupo de bloqueos
        casos = [d,
                 escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}], [h("H-d3", "SEG-SECRETO-REPO")])[0],
                 escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}],
                           [h("H-d4", "SEG-SECRETO-REPO", conf="media", archivo="tests/a.test.js",
                              regla="generic-api-key")])[0],
                 escenario(base_ambar(), [h("H-d5", "COD-CI-BASICO", sev="media", archivo=None)],
                           gitleaks="ausente")[0]]
        self.assertEqual([x["estado"] for x in casos],
                         [ri.ESTADO_AMBAR, ri.ESTADO_ARREGLAR, ri.ESTADO_CONFIRMAR, ri.ESTADO_GRIS])
        for x in casos:
            for v, texto in self._todas(x).items():
                self.assertIsNone(self.GRAVE.search(texto), (x["estado"], v))
            self.assertIsNone(self.GRAVE.search(ri.portada_reemplazo(x, "dueno", "x")))
        arreglar = ri.render_portada(casos[1], "dueno")
        self.assertIn("Encontramos un problema que hay que arreglar antes de usar la app con personas reales. "
                      "Empieza por el 1.", arreglar)
        self.assertIn("En tu caso, además, hay un problema abierto que impide usar la app.", arreglar)
        self.assertIn("En tu caso, además, hay una alarma por confirmar que podría impedir usar la app.",
                      ri.render_portada(casos[2], "dueno"))

    # 2 ---------------------------------------------------------------------------------------------------------
    def test_2_hoja_paso_1_empieza_por_lo_primero(self):
        """Repo mixto: roadmap.json pone primero la clave por confirmar; la portada pone primero el bloqueo firme.
        El Paso 1 de la hoja sigue el orden de la portada (solo reordena; roadmap.json no cambia)."""
        hs = [h("H-m1", "SEG-SECRETO-REPO", conf="media", archivo="tests/config.test.js", linea=1,
                regla="generic-api-key"),
              h("H-m2", "DAT-PII-REPO", archivo="data/seed_patients.csv", linea=1)]
        rm = {"items": [item_rm("SEG-SECRETO-REPO", "Sin secretos"), item_rm("DAT-PII-REPO", "Sin PII"),
                        item_rm("SEG-ENV-PUBLICAS", "Sin env públicas")]}
        orden_rm = [i["control"] for i in rm["items"]]
        d, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"},
                          {"control": "DAT-PII-REPO", "estado": "fail"}], hs, rm=rm)
        self.assertEqual(d["estado"], ri.ESTADO_ARREGLAR)
        self.assertEqual(d["bloqueos"][0]["control"], "DAT-PII-REPO")
        primeros = [b["control"] for b in d["bloqueos"]]
        texto = ri.seccion_que_hacer(rm, hs, "N1", maximo=None, primeros=primeros)
        items = re.findall(r"^\d+\. \*\*([A-Z0-9-]+)\*\*", texto, re.M)
        self.assertEqual(items, ["DAT-PII-REPO", "SEG-SECRETO-REPO", "SEG-ENV-PUBLICAS"])
        self.assertEqual([i["control"] for i in rm["items"]], orden_rm)   # roadmap intacto
        hoja = ri.render_portada(d, "hoja")
        self.assertIn(ri._minuscula(ri._sin_punto(d["bloqueos"][0]["accion"])), hoja.splitlines()[0])
        self.assertIn("Lo primero: «" + d["bloqueos"][0]["titulo"], hoja)
        # sin «primeros», el orden es el del roadmap (otras llamadas no cambian)
        self.assertEqual(re.findall(r"^\d+\. \*\*([A-Z0-9-]+)\*\*", ri.seccion_que_hacer(rm, hs, "N1", None),
                                    re.M), orden_rm)
        fuente = inspect_fuente()
        self.assertIn("seccion_que_hacer(rm, hallazgos, sig, maximo=None, primeros=primeros)", fuente)

    # 3 ---------------------------------------------------------------------------------------------------------
    def test_3_revision_a_mano_concordancia(self):
        e1 = {"control": "SEG-DEPS-EXISTEN", "estado": "no_evaluado",
              "motivo": "registro_deps corrió sin hallazgos y sin el pase explícito que exige el control"}
        e2 = {"control": "SEG-ENV-PUBLICAS", "estado": "no_evaluado",
              "motivo": "env_publicas corrió sin hallazgos y sin el pase explícito que exige el control"}
        d1, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "pass"}, e1], [])
        t1 = ri.render_portada(d1, "dueno")
        self.assertIn("**Pide una revisión a mano de este punto**: «", t1)
        self.assertNotIn("estos puntos", t1)
        d2, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "pass"}, e1, e2], [])
        self.assertEqual(list(d2["motivos_graves"].values()).count("evidencia"), 2)
        self.assertIn("**Pide una revisión a mano de estos puntos**: «", ri.render_portada(d2, "dueno"))

    # 4 ---------------------------------------------------------------------------------------------------------
    def test_4_sin_codigo_solo_lo_esencial(self):
        est = [{"control": "SEG-SECRETO-REPO", "estado": "pass"}, {"control": "COD-CI-BASICO", "estado": "fail"},
               {"control": "COD-REPRO", "estado": "fail"},
               {"control": "SEG-IDOR", "estado": "no_evaluado", "motivo": "requiere juicio LLM (F3)"},
               {"control": "OPS-PRIVACIDAD", "estado": "manual_pendiente", "motivo": "aviso legal"}]
        hs = [h("H-v1", "COD-CI-BASICO", sev="alta", archivo=None), h("H-v2", "COD-REPRO", sev="alta", archivo=None)]
        d, _ = escenario(est, hs, perfil_tecnico=PERFIL_VACIO)
        self.assertEqual(d["estado"], ri.ESTADO_SIN_CODIGO)
        for v in ("dueno", "informe"):
            t = ri.render_portada(d, v)
            for no in ("Revisamos", "| Gravedad", "Los más importantes", "README", "Qué pudimos revisar",
                       "Puntos que pueden frenar el uso", "las cifras de abajo", "### El nivel", "### Aviso legal",
                       "Lo que sí encontramos"):
                self.assertNotIn(no, t, (v, no))
            self.assertIn("1. **Revisa que la carpeta sea la correcta**", t)
            lineas = [l for l in t.splitlines() if l.startswith("Nivel demostrado:")]
            self.assertEqual(len(lineas), 1)
            self.assertIn("¿Lista para datos reales de personas? **NO**: no se auditó ninguna app.", lineas[0])
            self.assertIn("1 punto legal que siempre revisa una persona", lineas[0])
        # con un hallazgo real de datos personales (sin bloqueo), se lista
        est2 = est + [{"control": "DAT-PII-TEST", "estado": "fail"}]
        d2, _ = escenario(est2, hs + [h("H-v3", "DAT-PII-TEST", sev="media", archivo="tests/f.json")],
                          perfil_tecnico=PERFIL_VACIO)
        self.assertEqual(d2["estado"], ri.ESTADO_SIN_CODIGO)
        t2 = ri.render_portada(d2, "dueno")
        self.assertIn("### Lo que sí encontramos en esta carpeta", t2)
        bloque = t2.split("### Lo que sí encontramos en esta carpeta")[1].split("Nivel demostrado")[0]
        self.assertEqual(len([l for l in bloque.splitlines() if l.startswith("- **")]), 1)
        self.assertNotIn("README", t2)

    # 5 ---------------------------------------------------------------------------------------------------------
    def test_5_nivel_frases_concretas(self):
        self.assertEqual(ri._probados(6, 0), "se probaron 6 y todos salieron bien")
        self.assertEqual(ri._probados(1, 0), "se probó 1 y salió bien")
        self.assertEqual(ri._probados(0, 0), "todavía no se probó ninguno")
        self.assertEqual(ri._probados(3, 3), "se probaron 3 y los 3 fallaron")
        self.assertEqual(ri._probados(6, 1), "se probaron 6 y falló 1")
        self.assertEqual(ri._probados(6, 2), "se probaron 6 y fallaron 2")
        self.assertEqual(ri._probados(1, 1), "se probó 1 y falló")
        self.assertEqual(ri._sin_revisar_nivel(1, 0), "el que quedó sin revisar se puede probar leyendo el código")
        self.assertEqual(ri._sin_revisar_nivel(1, 1), "el que quedó sin revisar no se puede probar leyendo el código")
        self.assertEqual(ri._sin_revisar_nivel(9, 0), "los 9 sin revisar se pueden probar leyendo el código")
        self.assertEqual(ri._sin_revisar_nivel(9, 9), "ninguno de los 9 sin revisar se puede probar leyendo el código")
        self.assertEqual(ri._sin_revisar_nivel(9, 5), "de los 9 sin revisar, 5 no se pueden probar leyendo el código")
        d1, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "pass"},
                           {"control": "SEG-DEPS-EXISTEN", "estado": "no_evaluado",
                            "motivo": "registro_deps corrió sin hallazgos y sin el pase explícito que exige el control"}],
                          [])
        t1 = ri.render_portada(d1, "dueno")
        self.assertIn("**1 quedó sin revisar**", t1)
        self.assertNotIn("de los 1 ", t1)
        d, _ = escenario(base_ambar(), [h("H-n1", "COD-CI-BASICO", sev="media", archivo=None)])
        self.assertEqual(d["estado"], ri.ESTADO_AMBAR)
        self.assertFalse(d["nivel_siguiente"]["fallidos"])
        t = ri.render_portada(d, "dueno")
        self.assertIn("En tu caso no hay bloqueos: lo que falta es poder revisar esos puntos.", t)
        self.assertNotIn("no se debe a bloqueos", t)
        self.assertNotIn("fallaron 0", t)
        self.assertNotIn("falló 0", t)

    # 6 ---------------------------------------------------------------------------------------------------------
    def test_6_tabla_un_titulo_y_nota(self):
        self.assertNotIn("(encontrados)", inspect_fuente())
        d, _ = escenario(base_ambar(), [h("H-t1", "COD-CI-BASICO", sev="media", archivo=None)])
        t = ri.render_portada(d, "dueno")
        self.assertIn(ri.TITULO_TABLA_PROBLEMAS + "\n\n| Gravedad | Temas | Avisos |", t)
        self.assertIn("| Crítica | 0 | 0 |\n| Media | 1 | 1 |\n\n" + ri.NOTA_SIN_CRITICOS, t)
        d2, _ = escenario([{"control": "SEG-SECRETO-REPO", "estado": "fail"}, {"control": "COD-CI-BASICO",
                                                                                "estado": "fail"}],
                          [h("H-t2", "SEG-SECRETO-REPO"), h("H-t3", "COD-CI-BASICO", sev="media", archivo=None)])
        t2 = ri.render_portada(d2, "dueno")
        self.assertIn(ri.TITULO_TABLA_PROBLEMAS, t2)
        self.assertNotIn("Otros problemas", t2)
        self.assertIn("| Crítica (los de arriba) | 1 | 1 |", t2)


def inspect_fuente():
    import inspect
    return inspect.getsource(ri)


@unittest.skipUnless(os.environ.get("AUDITOR_CORRIDAS_REF"), "AUDITOR_CORRIDAS_REF no definido (regresión opcional)")
class TestRegresionCorridas(unittest.TestCase):
    ESPERADO = {"v7-vulnerable": ri.ESTADO_ARREGLAR, "v7-limpio": ri.ESTADO_AMBAR,
                "v7-centralmed": ri.ESTADO_AMBAR, "v7-rehabilitaencasa": ri.ESTADO_CONFIRMAR,
                "v7-sembrada-r9": ri.ESTADO_ARREGLAR}

    def test_estados(self):
        base = Path(os.environ["AUDITOR_CORRIDAS_REF"])
        for nombre, esperado in self.ESPERADO.items():
            with self.subTest(nombre):
                d = ri._cargar_portada(base / nombre)
                self.assertEqual(d["estado"], esperado)
                self.assertTrue(d["invariantes_ok"])
                self.assertTrue(d["invariante_temas"])
                for v in ri.VARIANTES_PORTADA:
                    ri.render_portada(d, v)


if __name__ == "__main__":
    unittest.main()

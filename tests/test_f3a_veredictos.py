"""F3-A: scripts/veredictos.py — veredictos.jsonl del LLM → estado/gates con reglas duras (PLAN_MAESTRO §3.3, §10 F3).

Criterio F3-4: el LLM NUNCA convierte un fail en pass sin falso_positivo + razón (+ archivo:línea del hallazgo).
Reglas: (a) fail determinista solo cambia con falso_positivo con razón y archivo:línea; (b) 'incierto' = verdadero;
(c) llm/mixto pasa a pass solo con 'pass' que cite archivo:línea y método (y digest completo, sin verificación
humana pendiente, con la parte determinista satisfecha); (d) inválidos se descartan y el control queda no_evaluado
con motivo; (e) nunca toca controles de otro dominio que el del tipo de juicio.
"""
import hashlib
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import digest  # noqa: E402
import estado as estado_mod  # noqa: E402
import gates  # noqa: E402
import validar_schema  # noqa: E402
import veredictos  # noqa: E402

SCHEMA_HALLAZGO = json.loads((RAIZ / "schemas" / "hallazgo.schema.json").read_text(encoding="utf-8"))


def hallazgo(n, control, sev, archivo, linea, dominio="SEG", gate="N2", conf="alta", herramienta="semgrep"):
    fp = hashlib.sha256(f"{n}|{control}|{archivo}".encode()).hexdigest()
    return {"id": f"H-{fp[:12]}", "control": control, "dominio": dominio, "etapa": "E2", "gate": gate,
            "severidad": sev, "confianza": conf, "metodo": "determinista",
            "fuente": [{"herramienta": herramienta, "version": "1", "regla": f"r{n}"}],
            "ubicacion": {"archivo": archivo, "linea": linea}, "evidencia": "x", "fingerprint": fp,
            "estado_hallazgo": "abierto"}


def ver(agente, control, veredicto, razon="razón concreta", **extra):
    v = {"agente": agente, "control": control, "veredicto": veredicto, "razon": razon, "modelo": "modelo-prueba"}
    v.update(extra)
    return v


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)
        self.proyecto = self.tmp / "proyecto"
        (self.proyecto / "src").mkdir(parents=True)
        (self.proyecto / "src" / "api.js").write_text("\n".join(f"linea {i}" for i in range(1, 41)) + "\n",
                                                     encoding="utf-8")
        (self.proyecto / "dist" / "assets").mkdir(parents=True)
        (self.proyecto / "dist" / "assets" / "index.js").write_text("var a=1;\n", encoding="utf-8")
        self.corrida = ap.preparar_corrida(self.tmp, proyecto=self.proyecto, crudo=None)
        (self.corrida / "normalizacion.json").write_text(json.dumps({"checks_pass": [], "estado_checks": {}}),
                                                         encoding="utf-8")
        self.inventario_ok()
        # F3-C: sin flujograma confirmado ni hallazgos, digest.py marca arquitectura omitir_juez (y veredictos.py no
        # acepta su pass). Estas pruebas modelan un juez de arquitectura con su entrada esencial: flujograma
        # confirmado. Sin «banderas», cargar_perfil sigue usando perfil_tecnico.json.
        self.flujograma = {"archivo": "flujograma.mmd", "estado": "confirmado"}
        (self.corrida / "perfil.json").write_text(json.dumps({"flujograma": self.flujograma}), encoding="utf-8")
        self.poner_hallazgos([])

    def tearDown(self):
        ap.limpiar(self.tmp)

    # --- preparación -------------------------------------------------------------------------------------------
    def inventario_ok(self, alcance=None):
        alcance = alcance or {"rutas": 1, "consultas": 0, "codigo_confidencial": 0, "omitidos_tamano": 0,
                              "omitidos_tope": 0}
        fila = {"framework": "express", "ruta": "/api/a/:id", "metodo": "GET", "archivo": "src/api.js", "linea": 10,
                "auth": True, "filtra_por_usuario": True, "tiene_param_id": True, "service_role": False,
                "consultas": [], "sospechosa": False, "motivos": []}
        crudo = self.corrida / "crudo"
        (crudo / "check_rutas_inventario.json").write_text(json.dumps(
            {"check": "rutas_inventario", "estado": "ok", "hallazgos": [], "checks_pass": [], "inventario": [fila],
             "alcance": alcance, "resumen": {"incompleto": []}}), encoding="utf-8")
        (crudo / "check_rutas_inventario.meta.json").write_text(json.dumps(
            {"herramienta": "check:rutas_inventario", "version": "1", "estado": "ok", "alcance": alcance}),
            encoding="utf-8")

    def poner_hallazgos(self, hs):
        texto = "".join(json.dumps(h) + "\n" for h in hs)
        (self.corrida / "hallazgos.jsonl").write_text(texto, encoding="utf-8")
        (self.corrida / "hallazgos_todos.jsonl").write_text(texto, encoding="utf-8")
        digest.generar(self.corrida)

    def poner_veredictos(self, lineas):
        texto = "".join((l if isinstance(l, str) else json.dumps(l)) + "\n" for l in lineas)
        (self.corrida / "veredictos.jsonl").write_text(texto, encoding="utf-8")

    def estado(self):
        return {c["control"]: c for c in estado_mod.generar(self.corrida)["controles"]}

    def decisiones(self):
        return json.loads((self.corrida / "decisiones_ia.json").read_text(encoding="utf-8"))


class TestCriterioF3_4(Base):
    def test_pass_no_convierte_fail_determinista(self):
        h = hallazgo(1, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 12)
        self.poner_hallazgos([h])
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-AUTH-CLIENTE", "pass", ubicaciones=["src/api.js:12"],
                                   metodo="lectura del handler")])
        e = self.estado()["SEG-AUTH-CLIENTE"]
        self.assertEqual(e["estado"], "fail")
        self.assertIn(h["id"], e["hallazgos"])
        d = self.decisiones()
        self.assertEqual(d["aplicadas"], [])
        self.assertRegex(d["descartadas"][0]["motivo"], r"falso_positivo")

    def test_pass_sobre_hallazgo_se_descarta(self):
        h = hallazgo(1, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 12)
        self.poner_hallazgos([h])
        self.poner_veredictos([ver("triage-fp", "SEG-AUTH-CLIENTE", "pass", hallazgo_id=h["id"],
                                   ubicaciones=["src/api.js:12"], metodo="x")])
        self.assertEqual(self.estado()["SEG-AUTH-CLIENTE"]["estado"], "fail")

    def test_falso_positivo_sin_razon_o_sin_ubicacion_no_cambia(self):
        h = hallazgo(1, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 12)
        self.poner_hallazgos([h])
        for extra in ({"razon": "   ", "ubicaciones": ["src/api.js:12"]},
                      {"ubicaciones": ["src/otro.js:12"]},
                      {"ubicaciones": []},
                      {}):
            with self.subTest(extra=extra):
                self.poner_veredictos([ver("triage-fp", "SEG-AUTH-CLIENTE", "falso_positivo", hallazgo_id=h["id"],
                                           **extra)])
                self.assertEqual(self.estado()["SEG-AUTH-CLIENTE"]["estado"], "fail")
                self.assertEqual(len(self.decisiones()["descartadas"]), 1)

    def test_falso_positivo_valido_quita_el_fail(self):
        h = hallazgo(1, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 12)
        self.poner_hallazgos([h])
        self.poner_veredictos([ver("triage-fp", "SEG-AUTH-CLIENTE", "falso_positivo", hallazgo_id=h["id"],
                                   razon="Es un comentario, no código ejecutable.", ubicaciones=["src/api.js:12"])])
        e = self.estado()["SEG-AUTH-CLIENTE"]
        self.assertNotEqual(e["estado"], "fail")
        self.assertNotEqual(e["estado"], "pass")
        a = self.decisiones()["aplicadas"]
        self.assertEqual([x["veredicto"] for x in a], ["falso_positivo"])
        self.assertEqual(a[0]["estado_final"], e["estado"])

    def test_falso_positivo_fuera_del_digest(self):
        hs = [hallazgo(i, "SEG-AUTH-CLIENTE", "alta", "src/api.js", 12) for i in range(30)]
        self.poner_hallazgos(hs)
        fuera = json.loads((self.corrida / "digest" / "triage.json").read_text())["incierto_por_tope"][0]
        self.poner_veredictos([ver("triage-fp", "SEG-AUTH-CLIENTE", "falso_positivo", hallazgo_id=fuera,
                                   ubicaciones=["src/api.js:12"])])
        self.estado()
        d = self.decisiones()
        self.assertRegex(d["descartadas"][0]["motivo"], r"digest")
        self.assertIn(fuera, [x["hallazgo_id"] for x in d["aplicadas"] if x["veredicto"] == "incierto"])

    def test_falso_positivo_critico_integrado(self):
        h = hallazgo(1, "SEG-SECRETO-BUNDLE", "critica", "dist/assets/index.js", 1, gate="N1", herramienta="gitleaks")
        self.poner_hallazgos([h])
        (self.corrida / "crudo" / "gitleaks.json").write_text("[]", encoding="utf-8")
        (self.corrida / "crudo" / "gitleaks.meta.json").write_text(json.dumps(
            {"herramienta": "gitleaks", "version": "8", "estado": "ok",
             "alcance": {"bundles": 1, "archivos": 3, "commits": 0, "historial": 0}}), encoding="utf-8")
        self.assertEqual(self.estado()["SEG-SECRETO-BUNDLE"]["estado"], "fail")
        self.poner_veredictos([ver("triage-fp", "SEG-SECRETO-BUNDLE", "falso_positivo", hallazgo_id=h["id"],
                                   ubicaciones=["dist/assets/index.js:1"])])
        e = self.estado()["SEG-SECRETO-BUNDLE"]
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertRegex(e["motivo"], r"falso positivo crítico")

    def test_falso_positivo_critico_nunca_queda_en_pass(self):
        res = {"pases": {}, "forzar": {}, "fp_criticos": {"SEG-SECRETO-BUNDLE": ["H-abc123"]}, "aplicadas": [],
               "descartadas": []}
        controles = [{"control": "SEG-SECRETO-BUNDLE", "estado": "pass", "motivo": None, "metodo": "determinista",
                      "duracion_s": None, "herramienta": "gitleaks", "hallazgos": []}]
        veredictos.ajustar(controles, res)
        self.assertEqual(controles[0]["estado"], "no_evaluado")
        self.assertRegex(controles[0]["motivo"], r"verificación humana")


class TestIncierto(Base):
    def test_incierto_en_triage_confirma(self):
        self.assertFalse(gates._pendiente_triage({"confianza": "baja", "triage": {"veredicto": "incierto"}}))
        self.assertTrue(gates._pendiente_triage({"confianza": "baja", "triage": None}))

    def test_incierto_de_control_es_fail(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-IDOR", "incierto", severidad_propuesta="baja",
                                   ubicaciones=["src/api.js:10"])])
        e = self.estado()["SEG-IDOR"]
        self.assertEqual(e["estado"], "fail")
        ia = [json.loads(l) for l in (self.corrida / "hallazgos_ia.jsonl").read_text().splitlines()]
        self.assertEqual(len(ia), 1)
        self.assertEqual(ia[0]["severidad"], "critica", "la IA puede subir la severidad, no bajarla")
        self.assertEqual(ia[0]["metodo"], "llm")
        self.assertEqual(validar_schema.validar(ia[0], SCHEMA_HALLAZGO), [])
        self.assertIn(ia[0]["id"], e["hallazgos"])
        g = gates.generar(self.corrida)
        self.assertIn("SEG-IDOR", [b["control"] for b in g["global"]["bloqueos"]])

    def test_triage_incierto_aplicado_al_hallazgo(self):
        h = hallazgo(1, "SEG-SECRETO-BUNDLE", "critica", "dist/assets/index.js", 1, gate="N1", conf="baja",
                     herramienta="gitleaks")
        self.poner_hallazgos([h])
        self.poner_veredictos([ver("triage-fp", "SEG-SECRETO-BUNDLE", "incierto", hallazgo_id=h["id"])])
        g = gates.generar(self.corrida)
        self.assertIn("secreto_vivo", [b["tipo"] for b in g["global"]["bloqueos"]])


class TestPassLLM(Base):
    def test_pass_llm_valido(self):
        self.poner_veredictos([ver("revisor-arquitectura", "SEG-STRIDE", "pass", ubicaciones=["src/api.js:3"],
                                   metodo="STRIDE ligero sobre el flujograma y el inventario")])
        e = self.estado()["SEG-STRIDE"]
        self.assertEqual(e["estado"], "pass")
        self.assertEqual(e["herramienta"], "revisor-arquitectura")
        self.assertRegex(e["motivo"], r"IA")

    def test_pass_sin_metodo_o_sin_ubicacion(self):
        for extra in ({"ubicaciones": ["src/api.js:3"]}, {"metodo": "x"}, {"metodo": " ", "ubicaciones": ["src/api.js:3"]}):
            with self.subTest(extra=extra):
                self.poner_veredictos([ver("revisor-arquitectura", "SEG-STRIDE", "pass", **extra)])
                e = self.estado()["SEG-STRIDE"]
                self.assertEqual(e["estado"], "no_evaluado")
                self.assertRegex(e["motivo"], r"descartad")

    def test_ubicaciones_invalidas(self):
        for u in ("src/no_existe.js:3", "src/api.js:9999", "src/patients/x.js:1", "../fuera.js:1", "/etc/passwd:1",
                  "node_modules/a/index.js:1", "src/api.js:0"):
            with self.subTest(u=u):
                self.poner_veredictos([ver("revisor-arquitectura", "SEG-STRIDE", "pass", ubicaciones=[u], metodo="x")])
                self.assertEqual(self.estado()["SEG-STRIDE"]["estado"], "no_evaluado")

    def test_mixto_exige_parte_determinista(self):
        v = ver("revisor-autorizacion", "SEG-IDOR", "pass", ubicaciones=["src/api.js:10"], metodo="revisé cada ruta")
        self.poner_veredictos([v])
        self.assertEqual(self.estado()["SEG-IDOR"]["estado"], "pass")
        (self.corrida / "crudo" / "check_rutas_inventario.meta.json").unlink()
        self.assertEqual(self.estado()["SEG-IDOR"]["estado"], "no_evaluado")

    def test_digest_incompleto_bloquea_pass(self):
        self.inventario_ok({"rutas": 1, "consultas": 0, "codigo_confidencial": 3, "omitidos_tamano": 0,
                            "omitidos_tope": 0})
        digest.generar(self.corrida)
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-IDOR", "pass", ubicaciones=["src/api.js:10"],
                                   metodo="x")])
        e = self.estado()["SEG-IDOR"]
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertRegex(e["motivo"], r"digest")

    def test_sin_digest_no_hay_pass(self):
        (self.corrida / "digest" / "indice.json").unlink()
        self.poner_veredictos([ver("revisor-arquitectura", "SEG-STRIDE", "pass", ubicaciones=["src/api.js:3"],
                                   metodo="x")])
        self.assertEqual(self.estado()["SEG-STRIDE"]["estado"], "no_evaluado")

    def test_verificacion_humana_no_pasa(self):
        self.poner_veredictos([ver("revisor-ux", "UX-HEURISTICA", "pass", ubicaciones=["src/api.js:3"], metodo="Nielsen",
                                   requiere_verificacion_humana=True)])
        e = self.estado()["UX-HEURISTICA"]
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertRegex(e["motivo"], r"verificación humana")

    def test_determinista_nunca_pasa_por_ia(self):
        self.poner_veredictos([ver("revisor-autorizacion", "SEG-SECRETO-REPO", "pass", ubicaciones=["src/api.js:3"],
                                   metodo="x")])
        self.estado()
        self.assertEqual(self.decisiones()["aplicadas"], [])

    def test_conflicto_fail_gana(self):
        self.poner_veredictos([
            ver("revisor-arquitectura", "SEG-STRIDE", "pass", ubicaciones=["src/api.js:3"], metodo="x"),
            ver("revisor-arquitectura", "SEG-STRIDE", "fail", ubicaciones=["src/api.js:4"])])
        self.assertEqual(self.estado()["SEG-STRIDE"]["estado"], "fail")

    def test_pendiente_de_entrevista_bloquea_pass(self):
        perfil = {"version_esquema": "1", "banderas": {**{b: None for b in (
            "baas", "ssr_serverless", "llm", "pagos", "emails", "docker", "iac", "k8s", "movil", "pwa", "multi_idioma",
            "agente_ia", "datos_personales", "salud", "menores", "ue", "datos_reales_cargados", "usuarios_3m",
            "usuarios_12m")}, "baas": "ninguno"},
            "pendientes_entrevista": {"7": {"controles": ["INF-PLATAFORMA"], "banderas": []}},
            "flujograma": self.flujograma}
        (self.corrida / "perfil.json").write_text(json.dumps(perfil), encoding="utf-8")
        digest.generar(self.corrida)
        self.poner_veredictos([ver("revisor-arquitectura", "INF-PLATAFORMA", "pass", ubicaciones=["src/api.js:3"],
                                   metodo="x")])
        e = self.estado()["INF-PLATAFORMA"]
        self.assertEqual(e["estado"], "no_evaluado")
        self.assertRegex(e["motivo"], r"pregunta 7")


class TestInvalidosYDominio(Base):
    def test_invalidos_descartados_con_motivo(self):
        self.poner_veredictos([
            "esto no es json",
            ver("revisor-arquitectura", "SEG-STRIDE", "aprobado"),
            ver("revisor-arquitectura", "SEG-NO-EXISTE", "fail"),
            ver("redactor-dueno", "OPS-RUNBOOK", "pass", ubicaciones=["src/api.js:1"], metodo="x"),
            ver("revisor-autorizacion", "SEG-IDOR", "verdadero")])
        e = self.estado()
        d = self.decisiones()
        self.assertEqual(len(d["descartadas"]), 5)
        self.assertTrue(all(x["motivo"] for x in d["descartadas"]))
        self.assertEqual(e["SEG-STRIDE"]["estado"], "no_evaluado")
        self.assertRegex(e["SEG-STRIDE"]["motivo"], r"descartad")
        self.assertEqual(e["SEG-IDOR"]["estado"], "no_evaluado")
        self.assertRegex(e["SEG-IDOR"]["motivo"], r"descartad")

    def test_dominio_ajeno_no_se_toca(self):
        base = self.estado()
        self.poner_veredictos([
            ver("revisor-ux", "SEG-IDOR", "pass", ubicaciones=["src/api.js:10"], metodo="x"),
            ver("revisor-autorizacion", "UX-HEURISTICA", "fail"),
            ver("revisor-autorizacion", "INF-PLATAFORMA", "fail")])
        e = self.estado()
        for c in ("SEG-IDOR", "UX-HEURISTICA", "INF-PLATAFORMA"):
            self.assertEqual((e[c]["estado"], e[c]["motivo"]), (base[c]["estado"], base[c]["motivo"]), c)
        self.assertTrue(all("dominio" in x["motivo"] or "componente" in x["motivo"]
                            for x in self.decisiones()["descartadas"]))

    def test_sin_veredictos_nada_cambia_y_se_limpia(self):
        base = json.dumps(estado_mod.generar(self.corrida))
        self.assertFalse((self.corrida / "decisiones_ia.json").exists())
        self.poner_veredictos([ver("revisor-arquitectura", "SEG-STRIDE", "fail")])
        estado_mod.generar(self.corrida)
        self.assertTrue((self.corrida / "hallazgos_ia.jsonl").exists())
        (self.corrida / "veredictos.jsonl").unlink()
        self.assertEqual(json.dumps(estado_mod.generar(self.corrida)), base)
        self.assertFalse((self.corrida / "decisiones_ia.json").exists())
        self.assertFalse((self.corrida / "hallazgos_ia.jsonl").exists())

    def test_determinista(self):
        self.poner_veredictos([ver("revisor-arquitectura", "SEG-STRIDE", "fail", ubicaciones=["src/api.js:4"]),
                               ver("revisor-autorizacion", "SEG-IDOR", "pass", ubicaciones=["src/api.js:10"], metodo="x")])
        gates.generar(self.corrida)
        a = {n: (self.corrida / n).read_bytes() for n in ("estado.json", "gates.json", "decisiones_ia.json",
                                                          "hallazgos_ia.jsonl")}
        gates.generar(self.corrida)
        self.assertEqual(a, {n: (self.corrida / n).read_bytes() for n in a})

    def test_razon_enmascarada(self):
        secreto = "sk_live_" + "Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op"
        self.poner_veredictos([ver("revisor-arquitectura", "SEG-STRIDE", "fail", razon=f"la clave {secreto} se ve")])
        estado_mod.generar(self.corrida)
        for n in ("decisiones_ia.json", "hallazgos_ia.jsonl", "estado.json"):
            self.assertNotIn(secreto, (self.corrida / n).read_text(encoding="utf-8"), n)


class TestInforme(Base):
    def test_seccion_separada(self):
        self.poner_veredictos([ver("revisor-arquitectura", "SEG-STRIDE", "fail", ubicaciones=["src/api.js:4"]),
                               "basura"])
        estado_mod.generar(self.corrida)
        t = veredictos.seccion_informe(self.corrida)
        self.assertIn("SEG-STRIDE", t)
        self.assertIn("revisor-arquitectura", t)
        self.assertRegex(t, r"(?i)descartad")
        self.assertIn("src/api.js:4", t)

    def test_seccion_sin_veredictos(self):
        estado_mod.generar(self.corrida)
        self.assertRegex(veredictos.seccion_informe(self.corrida), r"(?i)no hubo veredictos")


if __name__ == "__main__":
    unittest.main()

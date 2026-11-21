"""Tests de scripts/estado.py: estado por control (pass | fail | no_evaluado | no_aplica | manual_pendiente)."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import estado  # noqa: E402
import utiles  # noqa: E402
import validar_schema  # noqa: E402
from normalizar import run as n_run  # noqa: E402

SCHEMA = json.loads((RAIZ / "schemas" / "estado.schema.json").read_text(encoding="utf-8"))


def ctrl(id_, **kw):
    base = {"id": id_, "titulo": id_, "alias": [], "dominio": id_.split("-")[0], "etapa": "E2", "gate": "N1",
            "severidad_base": "alta", "metodo": "determinista", "herramientas": ["gitleaks"], "condicion": "siempre",
            "bloquea_global": False, "mapea_reglas": [], "esfuerzo": "S", "aplicabilidad": "aplica",
            # Sin «pases vacíos» (test_evidencia_pass.py): estos controles sintéticos prueban la regla «herramienta ok
            # sin hallazgos → pass», que ahora exige declararla (ausencia_suficiente) con precondición de alcance.
            "evidencia_pass": "ausencia_suficiente"}
    base.update(kw)
    base.setdefault("alcance_requerido", [f"{h}.objetos" for h in base["herramientas"]
                                          if h not in base.get("herramientas_parciales", [])])
    return base


def alcance_de(herr):
    """Alcance ≥ 1 para toda herramienta del estado simulado (la precondición no es lo que se prueba aquí)."""
    return {utiles.canon_herramienta(h): {"objetos": 1} for h in (herr or {})}


def hall(control, estado_h="abierto", sev="alta", gate="N1", aceptacion=None, id_="H-aaaaaaaaaaaa"):
    return {"id": id_, "control": control, "severidad": sev, "gate": gate, "estado_hallazgo": estado_h,
            "aceptacion": aceptacion}


def calcular(controles, hallazgos=(), herr=None, pasan=(), modo="estandar", fecha="2026-11-18"):
    indice = {c["id"]: c for c in controles}
    res = estado.calcular(indice, list(hallazgos), herr or {}, set(pasan), modo, fecha, alcance=alcance_de(herr))
    return {r["control"]: r for r in res}


class TestReglas(unittest.TestCase):
    def test_fail_con_hallazgo_abierto(self):
        r = calcular([ctrl("SEG-A")], [hall("SEG-A")], {"gitleaks": "ok"})
        self.assertEqual(r["SEG-A"]["estado"], "fail")
        self.assertEqual(r["SEG-A"]["hallazgos"], ["H-aaaaaaaaaaaa"])

    def test_pass_herramienta_ok_sin_hallazgos(self):
        r = calcular([ctrl("SEG-A")], [], {"gitleaks": "ok"})
        self.assertEqual(r["SEG-A"]["estado"], "pass")
        self.assertEqual(r["SEG-A"]["herramienta"], "gitleaks")

    def test_herramienta_ausente_no_evaluado(self):  # criterio F1-4
        for est in ("ausente", "error", "timeout", "sin_red"):
            r = calcular([ctrl("SEG-A")], [], {"gitleaks": est})
            self.assertEqual(r["SEG-A"]["estado"], "no_evaluado", est)
            self.assertIn(est.replace("_", " "), r["SEG-A"]["motivo"])
        r = calcular([ctrl("SEG-A")], [], {})
        self.assertEqual(r["SEG-A"]["estado"], "no_evaluado")
        self.assertIn("gitleaks", r["SEG-A"]["motivo"])

    def test_estados_de_meta_del_adaptador(self):
        r = calcular([ctrl("SEG-A")], [], {"gitleaks": "parcial"})
        self.assertEqual(r["SEG-A"]["estado"], "no_evaluado")
        self.assertIn("parcial", r["SEG-A"]["motivo"])
        r = calcular([ctrl("SEG-A")], [], {"gitleaks": "no_evaluado"})
        self.assertEqual(r["SEG-A"]["estado"], "no_evaluado")
        r = calcular([ctrl("SEG-A")], [], {"gitleaks": "no_aplica"})
        self.assertEqual(r["SEG-A"]["estado"], "no_aplica")
        self.assertIn("nada que analizar", r["SEG-A"]["motivo"])
        r = calcular([ctrl("SEG-A", herramientas=["gitleaks", "trufflehog"])], [], {"gitleaks": "no_aplica", "trufflehog": "ok"})
        self.assertEqual(r["SEG-A"]["estado"], "pass")

    def test_alternativas_basta_una(self):
        r = calcular([ctrl("SEG-A", herramientas=["gitleaks", "trufflehog"])], [], {"gitleaks": "ok", "trufflehog": "ausente"})
        self.assertEqual(r["SEG-A"]["estado"], "pass")

    def test_fail_aunque_herramienta_ausente(self):
        r = calcular([ctrl("SEG-A")], [hall("SEG-A")], {"gitleaks": "ausente"})
        self.assertEqual(r["SEG-A"]["estado"], "fail")

    def test_checks_pass(self):
        c = ctrl("SEG-LOCK", herramientas=["archivos_clave"], mapea_reglas=["check:archivos_clave.lockfile*"])
        r = calcular([c], [], {}, pasan={"check:archivos_clave.lockfile"})
        self.assertEqual(r["SEG-LOCK"]["estado"], "pass")
        self.assertEqual(r["SEG-LOCK"]["herramienta"], "archivos_clave")

    def test_manual_y_llm(self):
        r = calcular([ctrl("OPS-M", metodo="manual", herramientas=[]), ctrl("SEG-L", metodo="llm", herramientas=["revisor-arquitectura"])])
        self.assertEqual(r["OPS-M"]["estado"], "manual_pendiente")
        self.assertEqual(r["SEG-L"]["estado"], "no_evaluado")
        self.assertIn("juicio LLM no ejecutado en F1", r["SEG-L"]["motivo"])

    def test_mixto_con_agente_llm(self):
        c = ctrl("SEG-X", metodo="mixto", herramientas=["semgrep", "revisor-autorizacion"])
        r = calcular([c], [], {"semgrep": "ok"})
        self.assertEqual(r["SEG-X"]["estado"], "no_evaluado")
        self.assertIn("revisor-autorizacion", r["SEG-X"]["motivo"])
        r = calcular([c], [hall("SEG-X")], {"semgrep": "ok"})
        self.assertEqual(r["SEG-X"]["estado"], "fail")

    def test_mixto_sin_agente_pasa(self):
        c = ctrl("SEG-J", metodo="mixto", herramientas=["semgrep", "gitleaks"])
        self.assertEqual(calcular([c], [], {"semgrep": "ok"})["SEG-J"]["estado"], "pass")

    def test_no_aplica(self):
        r = calcular([ctrl("INF-K8S", aplicabilidad="no_aplica", condicion="k8s")], [], {"gitleaks": "ok"})
        self.assertEqual(r["INF-K8S"]["estado"], "no_aplica")
        self.assertIn("k8s", r["INF-K8S"]["motivo"])

    def test_fuera_de_modo(self):
        r = calcular([ctrl("SEG-N3", gate="N3")], [], {"gitleaks": "ok"}, modo="rapido")
        self.assertEqual(r["SEG-N3"]["estado"], "no_evaluado")
        self.assertIn("rapido", r["SEG-N3"]["motivo"])
        r = calcular([ctrl("SEG-N3", gate="N3")], [], {"gitleaks": "ok"}, modo="estandar")
        self.assertEqual(r["SEG-N3"]["estado"], "pass")

    def test_aplicabilidad_desconocida(self):
        c = ctrl("DAT-S", aplicabilidad="desconocida", condicion="salud == true", herramientas=["entrevista"])
        r = calcular([c], [], {})
        self.assertEqual(r["DAT-S"]["estado"], "no_evaluado")
        self.assertIn("salud", r["DAT-S"]["motivo"])

    def test_falso_positivo_no_cuenta(self):
        r = calcular([ctrl("SEG-A")], [hall("SEG-A", "falso_positivo")], {"gitleaks": "ok"})
        self.assertEqual(r["SEG-A"]["estado"], "pass")

    def test_aceptado_valido(self):
        ac = {"firma": "Enzo", "fecha": "2026-11-01", "vencimiento": "2026-12-31", "razon": "riesgo bajo"}
        r = calcular([ctrl("COD-A", gate="N2")], [hall("COD-A", "aceptado", gate="N2", aceptacion=ac)], {"gitleaks": "ok"})
        self.assertEqual(r["COD-A"]["estado"], "pass")
        self.assertIn("aceptado", r["COD-A"]["motivo"])

    def test_aceptado_vencido_o_critico_n1(self):
        vencida = {"firma": "Enzo", "fecha": "2026-01-01", "vencimiento": "2026-02-01", "razon": "x"}
        r = calcular([ctrl("COD-A", gate="N2")], [hall("COD-A", "aceptado", gate="N2", aceptacion=vencida)], {"gitleaks": "ok"})
        self.assertEqual(r["COD-A"]["estado"], "fail")
        ok = {"firma": "Enzo", "fecha": "2026-11-01", "vencimiento": "2027-01-01", "razon": "x"}
        r = calcular([ctrl("SEG-A", severidad_base="critica")], [hall("SEG-A", "aceptado", sev="critica", aceptacion=ok)],
                     {"gitleaks": "ok"})
        self.assertEqual(r["SEG-A"]["estado"], "fail")
        r = calcular([ctrl("COD-A", gate="N2")], [hall("COD-A", "aceptado", gate="N2", aceptacion=None)], {"gitleaks": "ok"})
        self.assertEqual(r["COD-A"]["estado"], "fail")

    def test_sin_herramienta(self):
        r = calcular([ctrl("COD-Z", herramientas=[])], [], {})
        self.assertEqual(r["COD-Z"]["estado"], "no_evaluado")


class TestCorrida(unittest.TestCase):
    def setUp(self):
        self.tmp = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.tmp)

    def _correr(self, **kw):
        c = ap.preparar_corrida(self.tmp, **kw)
        n_run.main([str(c)])
        p = subprocess.run([sys.executable, str(RAIZ / "scripts" / "estado.py"), str(c)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        datos = json.loads((c / "estado.json").read_text(encoding="utf-8"))
        return c, datos, {r["control"]: r for r in datos["controles"]}

    def test_fixture_app_sembrada(self):
        _, datos, r = self._correr()
        self.assertEqual(validar_schema.validar(datos, SCHEMA), [])
        self.assertIsNone(datos.get("generado"))
        self.assertEqual(r["SEG-SECRETO-REPO"]["estado"], "fail")
        self.assertEqual(r["SEG-SECRETO-BUNDLE"]["estado"], "fail")
        self.assertEqual(r["SEG-DEPS-CVE-CRIT"]["estado"], "fail")
        self.assertEqual(r["SEG-LOCKFILE"]["estado"], "pass")
        self.assertEqual(r["COD-REPRO"]["estado"], "pass")
        self.assertEqual(r["OPS-HEALTH"]["estado"], "fail")
        self.assertEqual(r["SEG-DEPS-EXISTEN"]["estado"], "no_evaluado")
        self.assertIn("timeout", r["SEG-DEPS-EXISTEN"]["motivo"])
        self.assertEqual(r["INF-K8S"]["estado"], "no_aplica")
        self.assertEqual(r["SEG-AUTH-CLIENTE"]["estado"], "no_evaluado")
        self.assertEqual(r["UX-AXE-CRIT"]["estado"], "no_evaluado")
        self.assertEqual(len(r), len(utiles.indice_controles({"banderas": {}})))

    def test_gitleaks_ausente(self):  # criterio F1-4 de punta a punta
        c = ap.preparar_corrida(self.tmp, nombre="sin_gitleaks")
        (c / "crudo" / "gitleaks.json").unlink()
        (c / "crudo" / "gitleaks.meta.json").write_text(json.dumps({"herramienta": "gitleaks", "estado": "ausente"}))
        n_run.main([str(c)])
        estado.main([str(c)])
        r = {x["control"]: x for x in json.loads((c / "estado.json").read_text())["controles"]}
        self.assertEqual(r["SEG-SECRETO-REPO"]["estado"], "no_evaluado")
        self.assertIn("ausente", r["SEG-SECRETO-REPO"]["motivo"])

    def test_check_no_evaluado_por_su_json(self):
        c = ap.preparar_corrida(self.tmp, nombre="check_sin_red")
        (c / "crudo" / "check_registro_deps.meta.json").unlink()
        (c / "crudo" / "check_registro_deps.json").write_text(json.dumps(
            {"estado": "no_evaluado", "motivo": "sin red", "hallazgos": [], "checks_pass": []}))
        n_run.main([str(c)])
        estado.main([str(c)])
        r = {x["control"]: x for x in json.loads((c / "estado.json").read_text())["controles"]}
        self.assertEqual(r["SEG-DEPS-EXISTEN"]["estado"], "no_evaluado")

    def test_modo_rapido(self):
        _, _, r = self._correr(modo="rapido")
        self.assertEqual(r["SEG-CICD"]["estado"], "fail")  # el fallo se informa aunque esté fuera del modo
        self.assertEqual(r["SEG-DEPS-CVE-ALTO"]["estado"], "fail")
        n3 = [x for x in r.values() if x["estado"] == "no_evaluado" and "modo rapido" in (x["motivo"] or "")]
        self.assertTrue(n3)


if __name__ == "__main__":
    unittest.main()

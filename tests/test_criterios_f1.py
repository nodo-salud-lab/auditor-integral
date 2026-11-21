"""Criterios de aceptación de F1 (PLAN_MAESTRO §10):
  F1-2  0 secretos sin enmascarar en cualquier texto destinado al LLM (20 canarios).
  F1-3  dos corridas sobre el mismo crudo → mismos bytes (hallazgos, estado, gates, informe...).
  F1-4  herramienta ausente → no_evaluado (también en test_estado.py).
  F1-5  0 tokens LLM en normalizar/gates/informe (también en test_informe.py).
Los canarios son secretos FALSOS generados al azar para este test.
"""
import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import test_enmascarar as te  # noqa: E402

FASES = [
    ["normalizar/run.py"],
    ["gates.py"],
    ["score.py"],
    ["render_informe.py"],
]
ARTEFACTOS = ["hallazgos.jsonl", "hallazgos_todos.jsonl", "normalizacion.json", "estado.json", "gates.json",
              "score.json", "roadmap.json", "digest/triage.json", "informe.md", "hoja-de-ruta.md", "merged.sarif"]
PARA_LLM = ARTEFACTOS  # todo lo que no es crudo/ puede terminar en un prompt


def correr_fases(corrida):
    for fase in FASES:
        p = subprocess.run([sys.executable, str(RAIZ / "scripts" / fase[0]), "--corrida", str(corrida)],
                           capture_output=True, text=True)
        if p.returncode != 0:
            raise AssertionError(f"{fase[0]}: {p.stderr}")


class TestDeterminismo(unittest.TestCase):  # F1-3
    def setUp(self):
        self.tmp = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.tmp)

    def test_dos_corridas_mismos_bytes(self):
        a = ap.preparar_corrida(self.tmp, nombre="a")
        b = ap.preparar_corrida(self.tmp, nombre="b")
        correr_fases(a)
        correr_fases(b)
        for art in ARTEFACTOS:
            self.assertEqual((a / art).read_bytes(), (b / art).read_bytes(), art)

    def test_repetir_en_la_misma_carpeta(self):
        a = ap.preparar_corrida(self.tmp, nombre="a")
        correr_fases(a)
        antes = {art: (a / art).read_bytes() for art in ARTEFACTOS}
        correr_fases(a)
        for art in ARTEFACTOS:
            self.assertEqual(antes[art], (a / art).read_bytes(), art)

    def test_orden_del_crudo_no_importa(self):
        a = ap.preparar_corrida(self.tmp, nombre="a")
        b = ap.preparar_corrida(self.tmp, nombre="b")
        g = json.loads((b / "crudo" / "gitleaks.json").read_text(encoding="utf-8"))
        (b / "crudo" / "gitleaks.json").write_text(json.dumps(list(reversed(g))), encoding="utf-8")
        correr_fases(a)
        correr_fases(b)
        for art in ("hallazgos.jsonl", "estado.json", "gates.json"):
            self.assertEqual((a / art).read_bytes(), (b / art).read_bytes(), art)

    def test_sin_marcas_de_tiempo(self):
        a = ap.preparar_corrida(self.tmp, nombre="a")
        correr_fases(a)
        for art in ("hallazgos.jsonl", "estado.json", "gates.json"):
            texto = (a / art).read_text(encoding="utf-8")
            self.assertNotRegex(texto, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", art)


class TestCanarios(unittest.TestCase):  # F1-2
    @classmethod
    def setUpClass(cls):
        cls.tmp = ap.tmp_dir(cls)
        cls.canarios = te.canarios()
        proyecto = cls.tmp / "proyecto"
        (proyecto / "src").mkdir(parents=True)
        (proyecto / "dist" / "assets").mkdir(parents=True)
        lineas, ubic = [], []
        for i, c in enumerate(cls.canarios):
            nombre = "api_secret" if i == 16 else f"clave{i}"
            ubic.append(len(lineas) + 1)
            lineas += f'const {nombre} = "{c}";'.split("\n")
        (proyecto / "src" / "config.js").write_text("\n".join(lineas) + "\n", encoding="utf-8")
        (proyecto / "dist" / "assets" / "index-abc.js").write_text(
            "".join(f'var a{i}="{c}";' for i, c in enumerate(cls.canarios[:6])) + "\n", encoding="utf-8")
        gitleaks = []
        for i, (c, l) in enumerate(zip(cls.canarios, ubic)):
            gitleaks.append({"RuleID": "generic-api-key", "File": str(proyecto / "src" / "config.js"), "StartLine": l,
                             "EndLine": l, "StartColumn": 1, "EndColumn": 10, "Match": f'clave{i} = "{c}"',
                             "Secret": c, "Commit": "", "Description": "Generic API Key", "Fingerprint": f"x:{i}"})
        for i, c in enumerate(cls.canarios[:6]):
            gitleaks.append({"RuleID": "generic-api-key", "File": "dist/assets/index-abc.js", "StartLine": 1,
                             "StartColumn": 1 + i * 40, "EndColumn": 40 + i * 40, "Match": c, "Secret": c,
                             "Commit": "", "Description": "Generic API Key"})
        resultados = [{"ruleId": "generic.secrets.security.detected-generic-secret.detected-generic-secret",
                       "message": {"text": f"Secreto detectado: {c}"},
                       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/config.js"},
                                                           "region": {"startLine": l, "snippet": {"text": f'x = "{c}"'}}}}]}
                      for c, l in zip(cls.canarios, ubic)]
        sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep OSS", "semanticVersion": "1.181.0",
                                                                   "rules": []}}, "results": resultados}]}
        checks = {"hallazgos": [{"regla": "check:env_publicas.nombre_sensible", "archivo": ".env", "linea": i + 1,
                                 "mensaje": f"VITE_K{i} sensible", "evidencia": f"VITE_K{i}={c}", "severidad_sugerida": "critica"}
                                for i, c in enumerate(cls.canarios)]
                  + [{"regla": "check:archivos_clave.env_ejemplo_valores", "archivo": ".env.example", "linea": 1,
                      "mensaje": "valor real", "evidencia": 'email: "ana.perez@correo.cl", rut: 12.345.678-5',
                      "severidad_sugerida": "alta"}],
                  "checks_pass": []}
        crudo = cls.tmp / "crudo_canarios"
        crudo.mkdir()
        (crudo / "gitleaks.json").write_text(json.dumps(gitleaks), encoding="utf-8")
        (crudo / "semgrep.sarif").write_text(json.dumps(sarif), encoding="utf-8")
        (crudo / "check_env_publicas.json").write_text(json.dumps(checks), encoding="utf-8")
        for h in ("gitleaks", "semgrep"):
            (crudo / f"{h}.meta.json").write_text(json.dumps({"herramienta": h, "version": "1", "estado": "ok"}))
        cls.corrida = ap.preparar_corrida(cls.tmp, proyecto=proyecto, crudo=crudo)
        correr_fases(cls.corrida)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_hay_hallazgos(self):
        hs = [json.loads(l) for l in (self.corrida / "hallazgos_todos.jsonl").read_text().splitlines() if l]
        self.assertGreaterEqual(len(hs), 20)
        self.assertIn("SEG-SECRETO-BUNDLE", {h["control"] for h in hs})

    def test_ningun_canario_completo_en_artefactos_para_llm(self):
        for art in PARA_LLM:
            texto = (self.corrida / art).read_text(encoding="utf-8")
            for i, c in enumerate(self.canarios):
                self.assertNotIn(c, texto, f"canario {i} completo en {art}")
                self.assertNotIn(te.nucleo(c), texto, f"núcleo del canario {i} en {art}")
                # también escapado como en JSON
                self.assertNotIn(json.dumps(c)[1:-1], texto, f"canario {i} escapado en {art}")

    def test_pii_enmascarada(self):
        for art in PARA_LLM:
            texto = (self.corrida / art).read_text(encoding="utf-8")
            self.assertNotIn("ana.perez@correo.cl", texto, art)
            self.assertNotIn("12.345.678-5", texto, art)

    def test_crudo_si_conserva_el_secreto(self):
        # Control del propio test: el canario está en crudo/ (que nunca va al LLM).
        crudo = (self.corrida / "crudo" / "gitleaks.json").read_text(encoding="utf-8")
        self.assertIn(self.canarios[0], crudo)


if __name__ == "__main__":
    unittest.main()

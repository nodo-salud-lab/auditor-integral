"""Regresiones encontradas al re-auditar «kine us herramienta» (2026-11-18) tras corregir el auditor.

SALIDAS-PROPIAS  osv-scanner recorre el proyecto entero y leyó el SBOM de una corrida anterior
                 (.auditoria/<corrida>/crudo/sbom.cdx.json): duplicó SEG-DEPS-CVE-ALTO y -MEDIO. El
                 normalizador descarta todo registro en .auditoria/ (salidas del propio auditor) y lo cuenta.
CSP-BUILD        la CSP de kine us la inyecta vite.config en el build: el index.html fuente no la trae,
                 dist/index.html sí. csp_connect_solo_self lee también dist/index.html (sin construir nada).
(La regresión de sin_gitignore en sintéticos versionados está en test_aud_sint.py.)
"""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import tempfile  # noqa: E402

import apoyo_corrida as ap  # noqa: E402
import render_informe  # noqa: E402
from normalizar import run as n_run  # noqa: E402


class TestSalidasPropias(unittest.TestCase):
    def _corrida(self, archivo):
        tmp = Path(ap.tmp_dir())
        self.addCleanup(ap.limpiar, tmp)
        c = ap.preparar_corrida(tmp)
        (c / "crudo" / "check_env_publicas.json").write_text(json.dumps({
            "estado": "ok", "motivo": None, "checks_pass": [], "hallazgos": [
                {"regla": "check:env_publicas.valor", "archivo": archivo, "linea": 1,
                 "mensaje": "valor", "evidencia": "MARCA-SALIDA-PROPIA", "severidad_sugerida": "alta"}]}),
            encoding="utf-8")
        return c

    def test_registro_en_auditoria_se_descarta(self):
        c = self._corrida(".auditoria/2026-11-18_0237-8f38a6d/crudo/sbom.cdx.json")
        limitados, todos, resumen = n_run.normalizar(c)
        self.assertNotIn("MARCA-SALIDA-PROPIA", json.dumps(todos))
        self.assertEqual(resumen["excluidos_salidas_auditor"], 1)

    def test_ruta_parecida_no_se_descarta(self):
        c = self._corrida("src/auditoria/x.ts")
        limitados, todos, resumen = n_run.normalizar(c)
        self.assertIn("MARCA-SALIDA-PROPIA", json.dumps(todos))
        self.assertEqual(resumen["excluidos_salidas_auditor"], 0)


class TestCspDelBuild(unittest.TestCase):
    META = ("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; "
            "connect-src 'self' blob: data:\">")

    def test_csp_solo_en_dist(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "index.html").write_text("<html><head></head></html>", encoding="utf-8")
            Path(d, "dist").mkdir()
            Path(d, "dist", "index.html").write_text(self.META, encoding="utf-8")
            self.assertTrue(render_informe.csp_connect_solo_self(d))

    def test_fuente_local_y_build_externo_no_cuenta(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "index.html").write_text(self.META, encoding="utf-8")
            Path(d, "dist").mkdir()
            Path(d, "dist", "index.html").write_text(self.META.replace("data:", "https://x.io"), encoding="utf-8")
            self.assertFalse(render_informe.csp_connect_solo_self(d))

    def test_dist_con_origen_externo_no_cuenta(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "dist").mkdir()
            Path(d, "dist", "index.html").write_text(self.META.replace("data:", "https://x.io"), encoding="utf-8")
            self.assertFalse(render_informe.csp_connect_solo_self(d))


if __name__ == "__main__":
    unittest.main()

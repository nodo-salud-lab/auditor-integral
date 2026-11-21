"""Problemas del verificador sobre la corrección «red» (D1 + O1, investigacion/18-evaluacion-herramienta.md).

1. O1 por --salida: una carpeta de corrida dentro del proyecto pero fuera de .auditoria/ la recorrían en la corrida
   siguiente osv-scanner (sbom.cdx.json), check_sbom (tapaba el fail de SEG-SBOM), check_dockerfile, etc.
   `bin/auditar` rechaza ese --salida (exit 2) antes de crear nada; dentro de <proyecto>/.auditoria/ o fuera del
   proyecto sigue valiendo.
2. El motivo por control cita el `error` del meta de un adaptador no_evaluado/parcial (p. ej. «sin red
   (AUDITOR_SIN_RED)…» de osv-scanner en SEG-DEPS-CVE-CRIT), no el texto genérico. Nunca produce pass.
3. El atajo determinista de skills/auditar/SKILL.md (`auditar all`) exige la misma confirmación de red y --sin-red.
4. El alias AUDITOR_REGISTRO_SIN_RED (solo registro_deps) no dice «sin red (AUDITOR_SIN_RED…»: el resto de la
   corrida sí pudo usar la red.
5. docs/ACTIVAR.md documenta --sin-red y ya no dice que AUDITOR_SIN_RED no tiene efecto.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import estado  # noqa: E402
import registro_deps  # noqa: E402
from test_estado import ctrl  # noqa: E402

sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
AUDITAR = RAIZ / "bin" / "auditar"
TEXTO_SIN_RED = "sin red (AUDITOR_SIN_RED)"
ERROR_OSV = ("sin red (AUDITOR_SIN_RED): no hay base OSV local descargada (se obtiene con osv-scanner "
             "--download-offline-databases, que requiere red); no se consultó la API de OSV")


def tmp_dir():
    TMP_BASE.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(dir=TMP_BASE))


def entorno():
    env = {k: v for k, v in os.environ.items() if not k.startswith("AUDITOR_")}
    env.update(TMPDIR=str(TMP_BASE), GIT_CEILING_DIRECTORIES=str(TMP_BASE))
    return env


# ----------------------------------------------------------------------------- 1. --salida dentro del proyecto

class TestSalidaDentroDelProyecto(unittest.TestCase):
    def setUp(self):
        self.dir = tmp_dir()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.proy = self.dir / "proy"
        self.proy.mkdir()
        (self.proy / "package.json").write_text('{"dependencies": {}}', encoding="utf-8")

    def auditar(self, *args, cwd=None):
        return subprocess.run(["bash", str(AUDITAR), *map(str, args)], capture_output=True, text=True,
                              env=entorno(), timeout=120, cwd=cwd)

    def test_rechaza_salida_en_el_proyecto_fuera_de_auditoria(self):
        salida = self.proy / "salidas" / "r1"
        r = self.auditar("stack", self.proy, "--salida", salida)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn(".auditoria", r.stderr)
        self.assertFalse((self.proy / "salidas").exists(), "no debe crear nada dentro del proyecto")

    def test_rechaza_salida_relativa_desde_el_proyecto(self):
        r = self.auditar("scan", ".", "--salida", "salidas/r2", "--sin-red", cwd=self.proy)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse((self.proy / "salidas").exists())

    def test_rechaza_la_raiz_del_proyecto(self):
        r = self.auditar("stack", self.proy, "--salida", self.proy)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_rechaza_via_enlace_simbolico(self):
        enlace = self.dir / "enlace"
        enlace.symlink_to(self.proy, target_is_directory=True)
        r = self.auditar("stack", self.proy, "--salida", enlace / "salidas" / "r1")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse((self.proy / "salidas").exists())

    def test_acepta_salida_dentro_de_auditoria(self):
        salida = self.proy / ".auditoria" / "mi-corrida"
        r = self.auditar("stack", self.proy, "--salida", salida)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((salida / "run.json").is_file())

    def test_acepta_salida_fuera_del_proyecto(self):
        salida = self.dir / "afuera" / "r1"
        r = self.auditar("stack", self.proy, "--salida", salida)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((salida / "run.json").is_file())

    def test_acepta_hermano_con_prefijo_comun(self):
        """«proy-salidas» no está dentro de «proy» aunque comparta prefijo."""
        salida = self.dir / "proy-salidas" / "r1"
        r = self.auditar("stack", self.proy, "--salida", salida)
        self.assertEqual(r.returncode, 0, r.stderr)


# ----------------------------------------------------------------------------- 2. motivo del meta del adaptador

class TestMotivoDeAdaptador(unittest.TestCase):
    def calcular(self, herr, motivos):
        c = ctrl("SEG-DEPS-CVE-CRIT", herramientas=["osv-scanner", "trivy"])
        res = estado.calcular({c["id"]: c}, [], herr, set(), "estandar", "2026-11-19", alcance={}, motivos=motivos)
        return res[0]

    def test_motivos_adaptadores_lee_error_de_metas(self):
        d = tmp_dir()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        (d / "crudo").mkdir()
        (d / "crudo" / "osv.meta.json").write_text(json.dumps(
            {"herramienta": "osv-scanner", "estado": "no_evaluado", "error": ERROR_OSV}), encoding="utf-8")
        (d / "crudo" / "semgrep.meta.json").write_text(json.dumps(
            {"herramienta": "semgrep", "estado": "ok", "error": ""}), encoding="utf-8")
        m = estado.motivos_adaptadores(d)
        self.assertIn(TEXTO_SIN_RED, m.get("osv-scanner", ""))
        self.assertNotIn("semgrep", m)

    def test_no_evaluado_cita_sin_red(self):
        r = self.calcular({"osv-scanner": "no_evaluado"}, {"osv-scanner": ERROR_OSV})
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertIn(f"osv-scanner: no evaluado: {TEXTO_SIN_RED}", r["motivo"])
        self.assertNotIn("p. ej. sin red", r["motivo"])

    def test_parcial_cita_sin_red(self):
        motivo = ("sin red (AUDITOR_SIN_RED): se usó la base OSV local (--offline), que puede estar incompleta o "
                  "desactualizada; no basta para un pass")
        r = self.calcular({"osv-scanner": "parcial"}, {"osv-scanner": motivo})
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertIn(f"osv-scanner: ejecución parcial: {TEXTO_SIN_RED}", r["motivo"])

    def test_nunca_pass(self):
        for est in ("no_evaluado", "parcial", "error"):
            r = self.calcular({"osv-scanner": est, "trivy": "ok"}, {"osv-scanner": ERROR_OSV})
            self.assertNotEqual(r["estado"], "pass", est)

    def test_generar_de_punta_a_punta(self):
        d = tmp_dir()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        c = d / "corrida"
        (c / "crudo").mkdir(parents=True)
        (c / "run.json").write_text(json.dumps({"id": "x", "modo": "estandar", "fases": {}}), encoding="utf-8")
        (c / "normalizacion.json").write_text(json.dumps({"checks_pass": []}), encoding="utf-8")
        (c / "hallazgos.jsonl").write_text("", encoding="utf-8")
        (c / "crudo" / "osv.meta.json").write_text(json.dumps(
            {"herramienta": "osv-scanner", "estado": "no_evaluado", "error": ERROR_OSV}), encoding="utf-8")
        ctrls = {x["control"]: x for x in estado.generar(c)["controles"]}
        r = ctrls["SEG-DEPS-CVE-CRIT"]
        self.assertEqual(r["estado"], "no_evaluado")
        self.assertIn(TEXTO_SIN_RED, r["motivo"])


# ----------------------------------------------------------------------------- 3. SKILL.md: atajo `all`

class TestSkillAtajo(unittest.TestCase):
    def test_atajo_all_exige_confirmacion_y_sin_red(self):
        texto = (RAIZ / "skills" / "auditar" / "SKILL.md").read_text(encoding="utf-8")
        lineas = [l for l in texto.splitlines() if re.search(r"auditar[`\"]? all\b", l)]
        self.assertTrue(lineas, "no se encontró el atajo `auditar all`")
        for l in lineas:
            self.assertIn("--sin-red", l, l)
        # el párrafo del atajo remite a la confirmación de red
        bloque = texto.split("## Reglas duras", 1)[0]
        self.assertRegex(bloque, r"(?i)confirm\w+[^.]*red|red[^.]*confirm\w+")


# ----------------------------------------------------------------------------- 4. alias de registro_deps

class TestAliasRegistro(unittest.TestCase):
    def test_alias_no_se_presenta_como_sin_red_global(self):
        env = {k: v for k, v in os.environ.items() if k not in ("AUDITOR_SIN_RED", "AUDITOR_REGISTRO_SIN_RED")}
        env["AUDITOR_REGISTRO_SIN_RED"] = "1"
        with mock.patch.dict(os.environ, env, clear=True):
            m = registro_deps.motivo_sin_red()
        self.assertTrue(m)
        self.assertNotIn("AUDITOR_SIN_RED", m.replace("AUDITOR_REGISTRO_SIN_RED", ""))
        self.assertNotIn("sin red (", m)
        self.assertIn("AUDITOR_REGISTRO_SIN_RED", m)
        self.assertIn("solo", m)

    def test_cli_alias_motivo_sin_envoltorio(self):
        d = tmp_dir()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        (d / "p").mkdir()
        (d / "p" / "package.json").write_text('{"dependencies": {"react": "18.3.1"}}', encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not k.startswith("AUDITOR_")}
        env.update(AUDITOR_REGISTRO_SIN_RED="1", PATH="/usr/bin:/bin")
        p = subprocess.run([sys.executable, "-I", str(RAIZ / "scripts" / "checks" / "registro_deps.py"),
                            str(d / "p"), str(d / "c" / "crudo")], capture_output=True, text=True, timeout=60, env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        datos = json.loads((d / "c" / "crudo" / "check_registro_deps.json").read_text())
        self.assertEqual(datos["estado"], "no_evaluado")
        self.assertTrue(datos["motivo"].startswith("registro no consultado (AUDITOR_REGISTRO_SIN_RED=1"), datos["motivo"])
        self.assertNotIn("sin red (", datos["motivo"])

    def test_global_sigue_diciendo_sin_red(self):
        env = {k: v for k, v in os.environ.items() if k not in ("AUDITOR_SIN_RED", "AUDITOR_REGISTRO_SIN_RED")}
        env["AUDITOR_SIN_RED"] = "1"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertIn(TEXTO_SIN_RED, registro_deps.motivo_sin_red())


# ----------------------------------------------------------------------------- 5. docs/ACTIVAR.md

class TestActivarDoc(unittest.TestCase):
    def test_documenta_sin_red(self):
        texto = (RAIZ / "docs" / "ACTIVAR.md").read_text(encoding="utf-8")
        self.assertIn("--sin-red", texto)
        for l in texto.splitlines():
            if "AUDITOR_SIN_RED" in l:
                self.assertNotRegex(l, r"(?i)sin efecto|no la lee|ningún script la lee", l)
        for herr in ("osv", "semgrep", "zizmor", "registro_deps"):
            self.assertIn(herr, texto)
        self.assertIn("AUDITOR_REGISTRO_SIN_RED", texto)


if __name__ == "__main__":
    unittest.main()

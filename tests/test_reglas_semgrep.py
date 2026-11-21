"""Tests de las reglas propias reglas/semgrep/vibe-coding/*.yaml y de su alineación con el catálogo.

- `semgrep --test` sobre la carpeta (cada regla tiene su archivo anotado con // ruleid: y // ok:).
- semgrep antepone la ruta del archivo de reglas al check_id (…reglas.semgrep.vibe-coding.<id>):
  cada regla debe mapear, vía catalogo.control_por_regla, al control declarado en su metadata.
- Los mapea_reglas "semgrep:vibe-coding.*" del catálogo deben tener su regla (y viceversa).
"""
import os
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
REGLAS = RAIZ / "reglas" / "semgrep" / "vibe-coding"
SEMGREP = shutil.which("semgrep")
sys.path.insert(0, str(RAIZ / "scripts"))
import catalogo  # noqa: E402

ESPERADAS = {"auth-solo-cliente", "service-role-cliente", "monto-desde-body", "sql-concatenado",
             "eval-dinamico", "catch-vacio", "cors-comodin-credenciales", "findmany-sin-take",
             # F1 exige 10 reglas propias (PLAN_MAESTRO §10); agregadas en la corrección post-verificación:
             "jwt-sin-verificar", "comando-concatenado"}


def reglas_yaml():
    """{id: control de metadata} leyendo los YAML de forma simple (sin dependencias)."""
    salida = {}
    for p in sorted(REGLAS.glob("*.yaml")):
        texto = p.read_text(encoding="utf-8")
        rid = re.search(r"^\s*-\s*id:\s*(\S+)", texto, re.M).group(1)
        control = re.search(r"^\s*control:\s*(\S+)", texto, re.M).group(1)
        salida[rid] = (control, p)
    return salida


class TestReglasVibeCoding(unittest.TestCase):
    def test_estan_las_diez_con_su_archivo_de_prueba(self):
        r = reglas_yaml()
        self.assertEqual(set(r), ESPERADAS)
        for rid, (_, p) in r.items():
            self.assertEqual(p.stem, rid, "el id debe ser igual al nombre del archivo (sin prefijo)")
            pruebas = [x for x in REGLAS.glob(f"{rid}.*") if x.suffix in (".js", ".jsx", ".ts", ".tsx")]
            self.assertEqual(len(pruebas), 1, rid)
            texto = pruebas[0].read_text(encoding="utf-8")
            self.assertIn(f"ruleid: {rid}", texto)
            self.assertIn(f"ok: {rid}", texto)

    def test_mapean_al_control_declarado(self):
        cat = catalogo.cargar_catalogo()
        ids_catalogo = {c["id"] for c in cat}
        for rid, (control, _) in reglas_yaml().items():
            self.assertIn(control, ids_catalogo)
            check_id = f"Users.x.PROYECTOS.auditor-integral.reglas.semgrep.vibe-coding.{rid}"
            self.assertEqual(catalogo.control_por_regla("semgrep", check_id, cat), control, rid)

    def test_catalogo_no_referencia_reglas_inexistentes(self):
        referidas = set()
        for c in catalogo.cargar_catalogo():
            for p in c.get("mapea_reglas", []):
                if p.startswith("semgrep:vibe-coding."):
                    referidas.add(p.split("semgrep:vibe-coding.", 1)[1])
        self.assertEqual(referidas, ESPERADAS)

    # El mismo binario decide el skip y se ejecuta (antes: skip con el PATH del llamador y ejecución con un PATH fijo
    # de Homebrew; con semgrep en pipx, un venv o Linux CI daba ERROR en vez de correr o saltarse).
    @unittest.skipUnless(SEMGREP, "semgrep no instalado")
    def test_semgrep_test(self):
        r = subprocess.run([SEMGREP, "--test", "--metrics=off", "--disable-version-check", str(REGLAS)],
                           capture_output=True, text=True, timeout=300,
                           env={"PATH": os.environ.get("PATH", ""),
                                "SEMGREP_ENABLE_VERSION_CHECK": "0", "HOME": str(Path.home())})
        salida = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, salida[-2000:])
        self.assertRegex(salida, r"10/10: ✓ All tests passed")


if __name__ == "__main__":
    unittest.main()

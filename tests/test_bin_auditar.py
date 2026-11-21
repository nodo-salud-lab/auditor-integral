"""Tests de bin/auditar y scripts/corrida.py: carpeta de corrida, run.json y no tocar el proyecto."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))

import corrida  # noqa: E402

AUDITAR = RAIZ / "bin" / "auditar"
FIX = RAIZ / "tests" / "fixtures" / "stacks"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
GIT = ["git", "-c", "user.name=prueba", "-c", "user.email=prueba@example.invalid", "-c", "commit.gpgsign=false"]


def git(cwd, *args):
    return subprocess.run([*GIT, *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


def auditar(*args, env=None):
    return subprocess.run([str(AUDITAR), *map(str, args)], capture_output=True, text=True, env=env, timeout=300)


def instantanea(ruta):
    """Archivos y contenido del proyecto, sin .auditoria/ ni .git/."""
    res = {}
    for p in sorted(Path(ruta).rglob("*")):
        rel = p.relative_to(ruta).as_posix()
        if rel.startswith((".auditoria", ".git/")) or rel == ".git":
            continue
        res[rel] = p.read_bytes() if p.is_file() else None
    return res


class BaseTmp(unittest.TestCase):
    def setUp(self):
        TMP_BASE.mkdir(parents=True, exist_ok=True)
        self.tmp = Path(tempfile.mkdtemp(dir=TMP_BASE))
        self.env = dict(os.environ, TMPDIR=str(self.tmp))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def repo(self, fixture="vite_supabase"):
        destino = self.tmp / "proyecto"
        shutil.copytree(FIX / fixture, destino)
        git(destino, "init", "-q")
        git(destino, "add", "-A")
        git(destino, "commit", "-q", "-m", "inicial")
        return destino


class TestCorrida(BaseTmp):
    def test_id_con_commit(self):
        p = self.repo()
        d = corrida.crear(p, "rapido")
        commit7 = git(p, "rev-parse", "--short=7", "HEAD")
        self.assertRegex(d.name, r"^\d{4}-\d{2}-\d{2}_\d{4}-" + commit7 + "$")
        self.assertEqual(d.parent, p.resolve() / ".auditoria")
        run = json.loads((d / "run.json").read_text())
        self.assertEqual(run["commit7"], commit7)
        self.assertEqual(run["modo"], "rapido")
        self.assertIsNone(run["git_sucio"])  # no se usa git status (git_seguro)
        self.assertEqual(run["version_esquema"], "1")

    def test_sin_git(self):
        p = self.tmp / "sin"
        shutil.copytree(FIX / "estatico", p)
        d = corrida.crear(p, "estandar")
        self.assertTrue(d.name.endswith("-sin-git"))
        self.assertIsNone(json.loads((d / "run.json").read_text())["commit"])

    def test_exclude_idempotente(self):
        p = self.repo()
        corrida.crear(p, "rapido")
        corrida.crear(p, "rapido")
        exclude = (p / ".git" / "info" / "exclude").read_text().splitlines()
        self.assertEqual(exclude.count(".auditoria/"), 1)

    def test_registrar_fase(self):
        p = self.repo()
        d = corrida.crear(p, "rapido")
        corrida.registrar_fase(d, "stack", "ok", 0, 0.5)
        corrida.registrar_fase(d, "scan", "pendiente", 3, 0.0, "falta scripts/ejecutar_scanners.sh")
        run = json.loads((d / "run.json").read_text())
        self.assertEqual(run["fases"]["stack"]["estado"], "ok")
        self.assertEqual(run["fases"]["scan"]["detalle"], "falta scripts/ejecutar_scanners.sh")

    def test_modo_invalido(self):
        with self.assertRaises(ValueError):
            corrida.crear(self.repo(), "turbo")


class TestBinAuditar(BaseTmp):
    def test_ayuda_y_subcomando_invalido(self):
        r = auditar("--help", env=self.env)
        self.assertEqual(r.returncode, 0)
        for s in ("doctor", "stack", "scan", "normalize", "gates", "report", "all"):
            self.assertIn(s, r.stdout)
        self.assertEqual(auditar("volar", env=self.env).returncode, 2)
        self.assertEqual(auditar("stack", ".", "--modo", "turbo", env=self.env).returncode, 2)

    def test_stack_crea_corrida_y_no_toca_el_proyecto(self):
        p = self.repo()
        antes = instantanea(p)
        r = auditar("stack", p, "--modo", "rapido", env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        d = Path(r.stdout.strip().splitlines()[-1])
        self.assertTrue((d / "perfil_tecnico.json").is_file())
        self.assertEqual(json.loads((d / "perfil_tecnico.json").read_text())["baas"], "supabase")
        run = json.loads((d / "run.json").read_text())
        self.assertEqual(run["fases"]["stack"]["estado"], "ok")
        # nada cambió fuera de .auditoria/ y el árbol git sigue limpio
        self.assertEqual(antes, instantanea(p))
        self.assertEqual(git(p, "status", "--porcelain"), "")
        self.assertIn(".auditoria/", (p / ".git" / "info" / "exclude").read_text())

    def test_doctor_a_stdout_y_a_corrida(self):
        r = auditar("doctor", env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("gitleaks", json.loads(r.stdout)["herramientas"])
        salida = self.tmp / "corrida_externa"
        r = auditar("doctor", "--salida", salida, env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((salida / "herramientas.json").is_file())

    def test_salida_explicita(self):
        p = self.repo("fastapi")
        salida = self.tmp / "afuera"
        r = auditar("stack", p, "--salida", salida, env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue((salida / "perfil_tecnico.json").is_file())
        self.assertTrue((salida / "run.json").is_file())
        self.assertFalse((p / ".auditoria").exists())

    def test_fases_pendientes_sin_script(self):
        """scan/normalize/gates/report llaman a scripts de otro componente; si faltan, lo dicen (exit 3)."""
        p = self.repo()
        d = Path(auditar("stack", p, env=self.env).stdout.strip().splitlines()[-1])
        raiz_falsa = self.tmp / "plugin"
        shutil.copytree(RAIZ / "bin", raiz_falsa / "bin")
        shutil.copytree(RAIZ / "scripts", raiz_falsa / "scripts",
                        ignore=shutil.ignore_patterns("ejecutar_scanners.sh", "gates.py", "score.py",
                                                      "render_informe.py", "run.py"))
        r = subprocess.run([str(raiz_falsa / "bin" / "auditar"), "scan", str(p), "--salida", str(d)],
                           capture_output=True, text=True, env=self.env)
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("ejecutar_scanners.sh", r.stderr)
        run = json.loads((d / "run.json").read_text())
        self.assertEqual(run["fases"]["scan"]["estado"], "pendiente")

    def test_orquestacion_con_scripts_falsos(self):
        """`all` invoca los scripts con los nombres EXACTOS y la convención --corrida/--proyecto/--modo."""
        p = self.repo()
        raiz_falsa = self.tmp / "plugin"
        shutil.copytree(RAIZ / "bin", raiz_falsa / "bin")
        shutil.copytree(RAIZ / "scripts", raiz_falsa / "scripts")
        bitacora = self.tmp / "llamadas.log"
        falsos = {
            "scripts/ejecutar_scanners.sh": "bash",
            "scripts/normalizar/run.py": "python",
            "scripts/gates.py": "python",
            "scripts/score.py": "python",
            "scripts/render_informe.py": "python",
        }
        for rel, tipo in falsos.items():
            ruta = raiz_falsa / rel
            ruta.parent.mkdir(parents=True, exist_ok=True)
            if tipo == "bash":
                ruta.write_text(f'#!/usr/bin/env bash\necho "{rel} $* modo=$AUDITOR_MODO" >> "{bitacora}"\n')
            else:
                ruta.write_text("import os, sys\n"
                                f"open({str(bitacora)!r}, 'a').write({rel!r} + ' ' + ' '.join(sys.argv[1:]) + "
                                "' corrida=' + os.environ['AUDITOR_CORRIDA'] + '\\n')\n")
        r = subprocess.run([str(raiz_falsa / "bin" / "auditar"), "all", str(p), "--modo", "estandar"],
                           capture_output=True, text=True, env=self.env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        d = Path(r.stdout.strip().splitlines()[-1])
        llamadas = bitacora.read_text().splitlines()
        self.assertEqual([l.split()[0] for l in llamadas], list(falsos))
        self.assertIn(f"--proyecto {p.resolve()}", llamadas[0])
        self.assertIn(f"--corrida {d}", llamadas[0])
        self.assertIn("--modo estandar", llamadas[0])
        self.assertIn("modo=estandar", llamadas[0])
        self.assertIn(f"corrida={d}", llamadas[1])
        for f in ("run.json", "herramientas.json", "perfil_tecnico.json"):
            self.assertTrue((d / f).is_file(), f)
        run = json.loads((d / "run.json").read_text())
        for fase in ("doctor", "stack", "scan", "normalize", "gates", "report"):
            self.assertEqual(run["fases"][fase]["estado"], "ok", fase)
        self.assertEqual(git(p, "status", "--porcelain"), "")

    def test_scan_sin_corrida_previa_falla_claro(self):
        p = self.repo()
        r = auditar("gates", p, env=self.env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("auditar stack", r.stderr)


class TestMensajesCli(BaseTmp):
    """H-14 / U-2: errores del primer uso con la acción probable, --version y --help orientado a uso."""

    def test_carpeta_como_subcomando_sugiere_all(self):
        p = self.tmp / "mi proyecto"
        p.mkdir()
        r = auditar(p, env=self.env)
        self.assertEqual(r.returncode, 2)
        self.assertIn(f'¿quiso decir: auditar all "{p}"?', r.stderr)
        self.assertFalse((p / ".auditoria").exists())

    def test_opciones_en_ingles_sugieren(self):
        for opcion, sugerida in (("--mode", "--modo"), ("--output", "--salida"), ("--offline", "--sin-red")):
            with self.subTest(opcion=opcion):
                r = auditar("all", self.tmp, opcion, env=self.env)
                self.assertEqual(r.returncode, 2)
                self.assertIn(f"¿quiso decir {sugerida}?", r.stderr)
        self.assertFalse((self.tmp / ".auditoria").exists())

    def test_version(self):
        r = auditar("--version", env=self.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        version = json.loads((RAIZ / ".claude-plugin" / "plugin.json").read_text())["version"]
        self.assertEqual(r.stdout.strip(), f"auditor-integral {version}")

    def test_ayuda_con_ejemplos_sin_convencion_interna(self):
        r = auditar("--help", env=self.env)
        self.assertEqual(r.returncode, 0)
        self.assertIn('auditar all "/ruta/al/proyecto"', r.stdout)
        self.assertIn("--version", r.stdout)
        self.assertNotIn("AUDITOR_PROYECTO", r.stdout)
        self.assertNotIn("Convención para los scripts de fase", r.stdout)

    def test_corrida_como_ruta(self):
        p = self.repo()
        c = Path(auditar("stack", p, env=self.env).stdout.strip().splitlines()[-1])
        self.assertTrue((c / "run.json").is_file())
        for sub, rc in (("report", 4), ("gates", 4), ("digest", 4), ("all", 2), ("stack", 2)):
            with self.subTest(sub=sub):
                r = auditar(sub, c, env=self.env)
                self.assertEqual(r.returncode, rc, r.stderr)
                self.assertIn("esa carpeta es una corrida", r.stderr)
                self.assertIn(f'auditar {sub} "{p.resolve()}"', r.stderr)
                self.assertNotIn("ejecute primero 'auditar stack", r.stderr)
        self.assertFalse((c / ".auditoria").exists())


if __name__ == "__main__":
    unittest.main()

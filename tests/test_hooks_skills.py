"""Tests de hooks/hooks.json + hooks/proteger_escritura.py y de los SKILL.md de auditar y auditar-doctor."""
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402

HOOK = RAIZ / "hooks" / "proteger_escritura.py"


def hook(entrada, activo=True, cwd=None, extra_env=None):
    env = {k: v for k, v in os.environ.items() if k != "AUDITAR_ACTIVO"}
    if activo:
        env["AUDITAR_ACTIVO"] = "1"
    env.update(extra_env or {})
    texto = entrada if isinstance(entrada, str) else json.dumps(entrada)
    p = subprocess.run([sys.executable, str(HOOK)], input=texto, capture_output=True, text=True, env=env,
                       cwd=cwd or str(RAIZ), timeout=30)
    salida = json.loads(p.stdout) if p.stdout.strip() else None
    return p.returncode, salida


def decision(salida):
    if salida is None:
        return "allow"
    return salida["hookSpecificOutput"]["permissionDecision"]


def evento(tool, ruta, cwd="/proyecto", campo="file_path"):
    return {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": cwd, "tool_input": {campo: ruta}}


class TestHook(unittest.TestCase):
    def test_inactivo_permite_todo(self):
        code, out = hook(evento("Write", "/proyecto/src/a.js"), activo=False)
        self.assertEqual(code, 0)
        self.assertEqual(decision(out), "allow")

    def test_activo_dentro_de_auditoria(self):
        for tool in ("Write", "Edit", "MultiEdit"):
            code, out = hook(evento(tool, "/proyecto/.auditoria/2026-11-18_0000-abc1234/informe.md"))
            self.assertEqual((code, decision(out)), (0, "allow"), tool)

    def test_activo_fuera_bloquea(self):
        for tool in ("Write", "Edit", "MultiEdit"):
            code, out = hook(evento(tool, "/proyecto/src/a.js"))
            self.assertEqual(code, 0)
            self.assertEqual(decision(out), "deny", tool)
            self.assertIn(".auditoria", out["hookSpecificOutput"]["permissionDecisionReason"])
            self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")

    def test_ruta_relativa_contra_cwd(self):
        self.assertEqual(decision(hook(evento("Write", ".auditoria/x/a.md"))[1]), "allow")
        self.assertEqual(decision(hook(evento("Write", "src/a.js"))[1]), "deny")

    def test_escape_con_puntos(self):
        self.assertEqual(decision(hook(evento("Write", "/proyecto/.auditoria/../src/a.js"))[1]), "deny")
        self.assertEqual(decision(hook(evento("Write", "/proyecto/.auditoria-falsa/a.js"))[1]), "deny")

    def test_notebook(self):
        e = evento("NotebookEdit", "/proyecto/n.ipynb", campo="notebook_path")
        self.assertEqual(decision(hook(e)[1]), "deny")

    def test_otras_herramientas_no_se_tocan(self):
        e = {"tool_name": "Bash", "cwd": "/proyecto", "tool_input": {"command": "ls"}}
        self.assertEqual(decision(hook(e)[1]), "allow")

    def test_entrada_invalida_activo_bloquea(self):
        code, out = hook("{no es json")
        self.assertEqual(code, 0)
        self.assertEqual(decision(out), "deny")

    def test_sin_ruta_activo_bloquea(self):
        e = {"tool_name": "Write", "cwd": "/proyecto", "tool_input": {}}
        self.assertEqual(decision(hook(e)[1]), "deny")

    def test_marcador_activa(self):
        tmp = ap.tmp_dir()
        try:
            (tmp / ".auditoria").mkdir()
            (tmp / ".auditoria" / ".auditar_activo").write_text("1")
            e = evento("Write", str(tmp / "src" / "a.js"), cwd=str(tmp))
            self.assertEqual(decision(hook(e, activo=False, extra_env={"CLAUDE_PROJECT_DIR": str(tmp)})[1]), "deny")
        finally:
            ap.limpiar(tmp)


class TestHooksJson(unittest.TestCase):
    def test_formato(self):
        datos = json.loads((RAIZ / "hooks" / "hooks.json").read_text(encoding="utf-8"))
        pre = datos["hooks"]["PreToolUse"]
        self.assertEqual(len(pre), 1)
        matcher = pre[0]["matcher"]
        for tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            self.assertRegex(tool, f"^({matcher})$")
        cmd = pre[0]["hooks"][0]
        self.assertEqual(cmd["type"], "command")
        self.assertIn("${CLAUDE_PLUGIN_ROOT}/hooks/proteger_escritura.py", cmd["command"])
        self.assertTrue(HOOK.is_file())


def frontmatter(texto):
    m = re.match(r"^---\n(.*?)\n---\n", texto, re.S)
    if not m:
        return None
    campos = {}
    for linea in m.group(1).splitlines():
        if ":" in linea and not linea.startswith(" "):
            k, v = linea.split(":", 1)
            campos[k.strip()] = v.strip()
    return campos


class TestSkills(unittest.TestCase):
    def leer(self, nombre):
        return (RAIZ / "skills" / nombre / "SKILL.md").read_text(encoding="utf-8")

    def test_frontmatter_y_largo(self):
        for nombre in ("auditar", "auditar-doctor"):
            texto = self.leer(nombre)
            fm = frontmatter(texto)
            self.assertIsNotNone(fm, nombre)
            self.assertEqual(fm.get("name"), nombre)
            self.assertGreater(len(fm.get("description", "")), 40)
            self.assertLessEqual(len(texto.splitlines()), 150, nombre)

    def test_auditar_contrato(self):
        t = self.leer("auditar")
        for clave in ("bin/auditar", "all", "--modo", "informe.md", "gates.json", "crudo/", "SÍNTESIS", "ESTIMACIÓN",
                      "confirmación", "no certifica"):
            self.assertIn(clave, t, clave)

    def test_doctor_no_instala(self):
        t = self.leer("auditar-doctor")
        self.assertIn("bin/auditar doctor", t)
        self.assertRegex(t, r"(?i)sin ejecutar|no instal")


if __name__ == "__main__":
    unittest.main()

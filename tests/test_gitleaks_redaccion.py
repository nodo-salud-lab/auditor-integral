"""O3 / privacidad: crudo/gitleaks*.json no debe guardar secretos en texto plano.

- gitleaks.sh corre gitleaks con --redact=100 y además post-procesa el crudo (gitleaks_redactar.py):
  Secret/Match/Line quedan enmascarados (enmascarar.py) aunque el binario ignore --redact.
- Para no perder el enmascarado por «secretos conocidos» ni la confianza por prefijo de proveedor, el
  post-proceso recupera el valor desde el archivo (columnas de gitleaks) y guarda solo datos no reversibles:
  AuditorHuella (máscara pública + longitud + scrypt con sal) y AuditorProveedor (bool).
- Fail-closed: si el post-proceso falla, el crudo se borra y el meta queda en error.

Todos los secretos son canarios generados al azar (no son válidos).
"""
import json
import os
import secrets
import shutil
import stat
import string
import subprocess
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "tests"))

import enmascarar as em  # noqa: E402
import utiles  # noqa: E402
from normalizar import comun  # noqa: E402
from normalizar import gitleaks as n_gitleaks  # noqa: E402

ADAPT = RAIZ / "scripts" / "adaptadores"
REDACTAR = ADAPT / "gitleaks_redactar.py"
sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
TMP_BASE.mkdir(parents=True, exist_ok=True)


def azar(n, alfabeto=string.ascii_letters + string.digits):
    return "".join(secrets.choice(alfabeto) for _ in range(n))


def generico():
    # Sin prefijo de proveedor, con dígitos y letras (lo detecta generic-api-key por entropía). R10d: letras y dígitos
    # alternados: un tramo aleatorio de solo letras podía formar una «stopword» de gitleaks (p. ej. «when», «jade»)
    # y generic-api-key descartaba el hallazgo (≈2 de cada 300 valores: test inestable). Con a lo más dos letras
    # seguidas no se forma ninguna y el valor sigue siendo aleatorio (3000/3000 detectados con gitleaks 8.30.1).
    return "Zq" + azar(10, string.digits) + "".join(azar(1, string.ascii_letters) + azar(1, string.digits)
                                                    for _ in range(10))


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = TMP_BASE / f"redac_{self.id().split('.')[-1]}_{azar(6)}"
        self.proy = self.dir / "proyecto"
        self.crudo = self.dir / "corrida" / "crudo"
        self.proy.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.env = dict(os.environ, TMPDIR=str(TMP_BASE), GIT_CEILING_DIRECTORIES=str(TMP_BASE))

    def escribir(self, rel, texto):
        p = self.proy / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(texto, encoding="utf-8")
        return p

    def correr(self, env=None):
        return subprocess.run(["bash", str(ADAPT / "gitleaks.sh"), str(self.proy), str(self.crudo)],
                              capture_output=True, text=True, env=env or self.env, timeout=300)

    def texto_crudo(self):
        return "\n".join(p.read_text(errors="replace") for p in self.crudo.rglob("*") if p.is_file())

    def meta(self):
        return json.loads((self.crudo / "gitleaks.meta.json").read_text())


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks no instalado")
class TestAdaptadorReal(Base):
    def test_crudo_sin_secretos_en_claro_y_con_huella(self):
        pat, gen, dist = "ghp_" + azar(36), generico(), "ghp_" + azar(36)
        self.escribir("src/config.js", f"// x\nexport const token = '{pat}'\nAPI_KEY={gen}\n")
        self.escribir("dist/assets/index.js", f'const t="{dist}";\n')
        subprocess.run(["git", "init", "-q", str(self.proy)], check=True, env=self.env)
        hist = "ghp_" + azar(36)
        h = self.escribir("viejo.js", f"\nconst t = '{hist}'\n")
        git = ["git", "-C", str(self.proy), "-c", "user.email=a@b.c", "-c", "user.name=t", "-c", "commit.gpgsign=false"]
        subprocess.run(git + ["add", "viejo.js"], check=True, env=self.env)
        subprocess.run(git + ["commit", "-qm", "x"], check=True, env=self.env)
        h.unlink()
        subprocess.run(git + ["commit", "-qam", "borra"], check=True, env=self.env)

        r = self.correr()
        self.assertEqual(r.returncode, 0, r.stderr)
        m = self.meta()
        self.assertEqual(m["estado"], "ok", m)
        for e in m["ejecuciones"]:
            self.assertIn("--redact=100", e["comando"], e)
        todo = self.texto_crudo()
        for s in (pat, gen, dist, hist):
            self.assertNotIn(s, todo)
            self.assertNotIn(s[6:-6], todo)
        arbol = json.loads((self.crudo / "gitleaks.json").read_text())
        self.assertEqual(len(arbol), 2)
        for x in arbol:
            self.assertTrue(x.get("AuditorHuella"), x)          # recuperado y con huella
            self.assertIn("****", x["Secret"])
            self.assertIsInstance(x.get("AuditorProveedor"), bool)
        por_regla = {x["RuleID"]: x for x in arbol}
        self.assertEqual(por_regla["github-pat"]["Secret"], em.enmascarar_valor(pat))
        self.assertTrue(por_regla["github-pat"]["AuditorProveedor"])
        self.assertFalse(por_regla["generic-api-key"]["AuditorProveedor"])
        hist_json = json.loads((self.crudo / "gitleaks-git.json").read_text())
        viejo = [x for x in hist_json if x["File"] == "viejo.js"]
        self.assertTrue(viejo and all(x.get("AuditorHuella") for x in viejo), viejo)
        bundle = json.loads((self.crudo / "gitleaks-bundle.json").read_text())
        self.assertEqual(bundle[0]["Secret"], em.enmascarar_valor(dist))
        # los secretos conocidos siguen sirviendo para enmascarar otros textos (digest, informe…)
        conocidos = em.secretos_de_corrida(self.crudo.parent)
        texto = f"a {gen} b {pat} c"
        self.assertEqual(em.enmascarar_texto(texto, conocidos), em.enmascarar_texto(texto, [gen, pat]))
        self.assertNotIn(gen, em.enmascarar_texto(texto, conocidos))


def _falso_que_ignora_redact(directorio, reporte):
    """gitleaks falso: ignora --redact y escribe `reporte` (texto plano) en --report-path."""
    fuente = Path(directorio) / "reporte.json"
    fuente.write_text(json.dumps(reporte), encoding="utf-8")
    ruta = Path(directorio) / "gitleaks"
    ruta.write_text("#!/bin/bash\n"
                    'if [ "$1" = version ]; then echo 8.30.1; exit 0; fi\n'
                    'r=""; while [ $# -gt 0 ]; do [ "$1" = --report-path ] && r="$2"; shift; done\n'
                    f'cp "{fuente}" "$r"; exit 10\n')
    ruta.chmod(ruta.stat().st_mode | stat.S_IXUSR)
    return ruta


class TestDefensaPostProceso(Base):
    def test_binario_que_ignora_redact_no_deja_secretos(self):
        gen = generico()
        self.escribir("server/k.js", f"x\nAPI_KEY={gen}\n")
        rep = [{"RuleID": "generic-api-key", "File": "server/k.js", "StartLine": 2, "EndLine": 2,
                "StartColumn": 2, "EndColumn": 9 + len(gen), "Secret": gen, "Match": f"API_KEY={gen}",
                "Line": f"API_KEY={gen}", "Description": "d", "Commit": "", "Fingerprint": "server/k.js:generic-api-key:2"}]
        bindir = self.dir / "bin"; bindir.mkdir()
        env = dict(self.env, AUDITOR_BIN_GITLEAKS=str(_falso_que_ignora_redact(bindir, rep)))
        r = self.correr(env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn(gen, self.texto_crudo())
        d = json.loads((self.crudo / "gitleaks.json").read_text())
        self.assertEqual(d[0]["Secret"], em.enmascarar_valor(gen))
        self.assertNotIn(gen, d[0]["Match"] + d[0]["Line"])
        self.assertTrue(d[0]["AuditorHuella"])
        self.assertIs(d[0]["AuditorProveedor"], False)
        self.assertEqual(d[0]["Fingerprint"], "server/k.js:generic-api-key:2")

    def test_post_proceso_que_falla_borra_el_crudo(self):
        bindir = self.dir / "bin"; bindir.mkdir()
        # lista con un elemento que no es objeto: el post-proceso no puede garantizar el enmascarado
        env = dict(self.env, AUDITOR_BIN_GITLEAKS=str(_falso_que_ignora_redact(bindir, ["ghp_" + azar(36)])))
        r = self.correr(env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.crudo / "gitleaks.json").exists())
        m = self.meta()
        self.assertEqual(m["estado"], "error", m)
        self.assertIn("enmascar", m["error"])


class TestRedactarScript(Base):
    def _redactar(self, datos, *extra):
        ruta = self.dir / "r.json"
        ruta.write_text(json.dumps(datos), encoding="utf-8")
        r = subprocess.run([sys.executable, "-I", str(REDACTAR), str(ruta), "--base", str(self.proy), *extra],
                           capture_output=True, text=True)
        return r, ruta

    def test_recupera_desde_redactado_con_columnas_de_gitleaks(self):
        gen = generico()
        self.escribir("a.js", f"const s = \"{gen}\";\n  API_KEY={gen}\n")
        datos = [  # línea 1: columnas exactas; línea >1: gitleaks las corre en +1 (cuenta el salto)
            {"RuleID": "generic-api-key", "File": "a.js", "StartLine": 1, "EndLine": 1, "StartColumn": 12,
             "EndColumn": 11 + len(gen) + 1, "Secret": "REDACTED", "Match": 'REDACTED"'},
            {"RuleID": "generic-api-key", "File": "a.js", "StartLine": 2, "EndLine": 2, "StartColumn": 4,
             "EndColumn": 3 + 8 + len(gen), "Secret": "REDACTED", "Match": "API_KEY=REDACTED"}]
        r, ruta = self._redactar(datos)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(ruta.read_text())
        for x in out:
            self.assertEqual(x["Secret"], em.enmascarar_valor(gen))
            self.assertTrue(x["AuditorHuella"])
        self.assertEqual(out[1]["Match"], "API_KEY=" + em.enmascarar_valor(gen))

    def test_sin_recuperar_queda_redacted_y_sin_huella(self):
        datos = [{"RuleID": "generic-api-key", "File": "no-existe.js", "StartLine": 1, "EndLine": 1,
                  "StartColumn": 1, "EndColumn": 20, "Secret": "REDACTED", "Match": "k=REDACTED"}]
        r, ruta = self._redactar(datos)
        self.assertEqual(r.returncode, 0, r.stderr)
        out = json.loads(ruta.read_text())
        self.assertEqual(out[0]["Secret"], "REDACTED")
        self.assertNotIn("AuditorHuella", out[0])
        self.assertNotIn("AuditorProveedor", out[0])

    def test_entrada_invalida_falla_y_no_reescribe(self):
        r, ruta = self._redactar({"no": "lista"})
        self.assertNotEqual(r.returncode, 0)


class TestHuellasEnmascarar(unittest.TestCase):
    def test_huella_enmascara_igual_que_el_valor(self):
        for s in ("sk_live_" + azar(24), generico(), azar(12), "ghp_" + azar(36)):
            h = em.huella_secreto(s)
            self.assertNotIn(s, json.dumps(h))
            obj = em.Huella.desde(h)
            t = f'x="{s}" y {s}\nz{s}z'
            self.assertEqual(em.enmascarar_texto(t, [obj]), em.enmascarar_texto(t, [s]))
            once = em.enmascarar_texto(t, [obj])
            self.assertEqual(em.enmascarar_texto(once, [obj]), once)  # idempotente

    def test_huella_corta_no_se_guarda(self):
        self.assertIsNone(em.huella_secreto("abc12345"))  # <= 8: la máscara no deja prefijo

    def test_huella_invalida_se_ignora(self):
        self.assertIsNone(em.Huella.desde({"v": 1, "mascara": "x"}))
        self.assertIsNone(em.Huella.desde("texto"))


class TestNormalizarRedactado(Base):
    def _reg(self, secreto_campo, extra, archivo="dist/assets/x.js"):
        d = dict({"RuleID": "generic-api-key", "File": archivo, "StartLine": 1, "Secret": secreto_campo,
                  "Match": f"k={secreto_campo}", "Description": "d"}, **extra)
        ruta = self.dir / "gitleaks.json"
        ruta.write_text(json.dumps([d]), encoding="utf-8")
        return n_gitleaks.leer(ruta, {"proyecto": None, "metas": {}})[0]

    def test_confianza_usa_bandera_de_proveedor(self):
        self.assertEqual(self._reg("Zq12****abcd", {"AuditorProveedor": False})["confianza"], "baja")
        self.assertEqual(self._reg("sk_live_****abcd", {"AuditorProveedor": True})["confianza"], "media")

    def test_redactado_sin_bandera_no_baja_la_confianza(self):
        # fail-closed: sin saber si tenía prefijo de proveedor, no se presume texto minificado
        self.assertEqual(self._reg("REDACTED", {})["confianza"], "media")
        self.assertEqual(self._reg("Zq12****abcd", {})["confianza"], "media")

    def test_fingerprint_y_evidencia_iguales_antes_y_despues(self):
        gen = generico()
        self.escribir("server/k.js", f"x\nAPI_KEY={gen}\n")
        plano = {"RuleID": "generic-api-key", "File": "server/k.js", "StartLine": 2, "EndLine": 2,
                 "StartColumn": 2, "EndColumn": 9 + len(gen), "Secret": gen, "Match": f"API_KEY={gen}",
                 "Description": "d"}
        indice = utiles.indice_controles({"banderas": {}})
        ctx = {"proyecto": self.proy, "metas": {}}
        a = self.dir / "a"; a.mkdir()
        (a / "gitleaks.json").write_text(json.dumps([plano]))
        h_antes = comun.construir(n_gitleaks.leer(a / "gitleaks.json", ctx)[0], indice,
                                  n_gitleaks.secretos(a / "gitleaks.json"))
        b = self.dir / "b"; b.mkdir()
        red = dict(plano, Secret="REDACTED", Match="API_KEY=REDACTED")
        (b / "gitleaks.json").write_text(json.dumps([red]))
        r = subprocess.run([sys.executable, "-I", str(REDACTAR), str(b / "gitleaks.json"), "--base", str(self.proy)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        h_despues = comun.construir(n_gitleaks.leer(b / "gitleaks.json", ctx)[0], indice,
                                    n_gitleaks.secretos(b / "gitleaks.json"))
        self.assertEqual(h_antes["fingerprint"], h_despues["fingerprint"])
        self.assertEqual(h_antes["evidencia"], h_despues["evidencia"])
        self.assertEqual(h_antes["confianza"], h_despues["confianza"])
        self.assertNotIn(gen, json.dumps(h_despues))


# --- Verificador (regresión): columnas de gitleaks en BYTES UTF-8 y Match sin contexto fijo ---------------------
MB_PREFIJO = 'const m="Contraseña inválida, inténtelo de nuevo: ñandú"; const T="'


def _col_bytes(linea_txt, ini_char, num_linea):
    """Columna gitleaks 8.30.1 (1-based, en bytes; +1 en líneas > 1) del carácter `ini_char` de la línea."""
    return len(linea_txt[:ini_char].encode("utf-8")) + 1 + (1 if num_linea > 1 else 0)


class TestMultibyteYMatchExacto(Base):
    def _redactar(self, datos):
        ruta = self.dir / "r.json"
        ruta.write_text(json.dumps(datos), encoding="utf-8")
        r = subprocess.run([sys.executable, "-I", str(REDACTAR), str(ruta), "--base", str(self.proy)],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(ruta.read_text())

    def _hallazgo(self, lineas, num, secreto, regla, match_pre="", match_suf=""):
        txt = lineas[num - 1]
        i = txt.index(secreto) - len(match_pre)
        largo = len(match_pre) + len(secreto) + len(match_suf)
        ini = _col_bytes(txt, i, num)
        fin = ini + len((match_pre + secreto + match_suf).encode("utf-8")) - 1
        return {"RuleID": regla, "File": "src/a.js", "StartLine": num, "EndLine": num, "StartColumn": ini,
                "EndColumn": fin, "Secret": "REDACTED", "Match": match_pre + "REDACTED" + match_suf,
                "Description": "d", "_largo": largo}

    def _verificar_recuperado(self, x, secreto):
        self.assertEqual(x["Secret"], em.enmascarar_valor(secreto), "máscara del valor real")
        h = em.Huella.desde(x.get("AuditorHuella"))
        self.assertIsNotNone(h, x)
        self.assertTrue(h._es(secreto), "la huella debe corresponder al secreto real")
        self.assertIs(x.get("AuditorProveedor"), True)
        self.assertNotIn(secreto, json.dumps(x, ensure_ascii=False))

    def test_multibyte_antes_del_secreto_en_linea_1_y_2(self):
        hf, gh, emo = "hf_" + azar(34, string.ascii_letters), "ghp_" + azar(36), "hf_" + azar(34, string.ascii_letters)
        lineas = [MB_PREFIJO + hf + '";', 'const e="áéíóú"; const G="' + gh + '";',
                  'const a="🔑🔑🔑"; const T="' + emo + '";', ""]
        self.escribir("src/a.js", "\n".join(lineas))
        datos = [self._hallazgo(lineas, 1, hf, "huggingface-access-token"),
                 self._hallazgo(lineas, 2, gh, "github-pat"),
                 self._hallazgo(lineas, 3, emo, "huggingface-access-token")]
        for d in datos:
            d.pop("_largo")
        out = self._redactar(datos)
        for x, s in zip(out, (hf, gh, emo)):
            self._verificar_recuperado(x, s)

    def test_match_sin_contexto_con_columnas_corridas_no_acepta_otro_valor(self):
        # columnas desplazadas 1 byte: la ventana no es el secreto; sin contexto fijo no hay cómo validarla
        dop = "dop_v1_" + azar(64, "0123456789abcdef")
        lineas = ['const aviso="sesión"; const DO=' + dop + " ;", ""]
        self.escribir("src/a.js", "\n".join(lineas))
        d = self._hallazgo(lineas, 1, dop, "digitalocean-pat")
        d.pop("_largo")
        d["StartColumn"] += 1
        d["EndColumn"] += 1
        x = self._redactar([d])[0]
        self.assertEqual(x["Secret"], "REDACTED")
        self.assertNotIn("AuditorHuella", x)
        self.assertNotIn("AuditorProveedor", x)

    def test_match_exacto_con_columnas_correctas_se_recupera(self):
        dop = "dop_v1_" + azar(64, "0123456789abcdef")
        lineas = ["// x", 'const aviso="sesión"; const DO=' + dop + " ;", ""]
        self.escribir("src/a.js", "\n".join(lineas))
        d = self._hallazgo(lineas, 2, dop, "digitalocean-pat")
        d.pop("_largo")
        self._verificar_recuperado(self._redactar([d])[0], dop)


class TestNormalizarNoRecuperado(Base):
    def test_redactado_sin_huella_no_usa_la_linea_del_working_tree(self):
        # defensa fail-closed: si la recuperación falló, la línea del archivo tiene el secreto en claro
        hf = "hf_" + azar(34, string.ascii_letters)
        self.escribir("src/a.js", MB_PREFIJO + hf + '";\n')
        d = {"RuleID": "huggingface-access-token", "File": "src/a.js", "StartLine": 1, "EndLine": 1,
             "StartColumn": 73, "EndColumn": 110, "Secret": "REDACTED", "Match": "REDACTED", "Description": "d"}
        ruta = self.dir / "gitleaks.json"
        ruta.write_text(json.dumps([d]), encoding="utf-8")
        reg = n_gitleaks.leer(ruta, {"proyecto": self.proy, "metas": {}})[0]
        h = comun.construir(reg, utiles.indice_controles({"banderas": {}}), n_gitleaks.secretos(ruta))
        self.assertNotIn(hf, json.dumps(reg, ensure_ascii=False))
        self.assertNotIn(hf, json.dumps(h, ensure_ascii=False))
        self.assertNotIn(hf[3:-3], json.dumps(h, ensure_ascii=False))


@unittest.skipUnless(shutil.which("gitleaks"), "gitleaks no instalado")
class TestMultibyteReal(Base):
    def test_gitleaks_real_multibyte_bundle_y_match_exacto(self):
        hf, gh, emo = "hf_" + azar(34, string.ascii_letters), "ghp_" + azar(36), "hf_" + azar(34, string.ascii_letters)
        dop, bun = "dop_v1_" + azar(64, "0123456789abcdef"), "hf_" + azar(34, string.ascii_letters)
        self.escribir("src/config.js", MB_PREFIJO + hf + '";\nconst e="áéíóú"; const G="' + gh + '";\n')
        self.escribir("src/e.js", '// x\nconst a="🔑🔑🔑"; const T="' + emo + '";\n')
        self.escribir("src/cfg.js", '// x\nconst aviso="sesión"; const DO=' + dop + " ;\n")
        self.escribir("dist/assets/index-abc.js", "var a=1;" * 150 + 'Iniciar sesión con contraseña; año; '
                      'información válida;var k="' + bun + '";')
        r = self.correr()
        self.assertEqual(r.returncode, 0, r.stderr)
        todo = self.texto_crudo()
        valores = {"hf": hf, "gh": gh, "emo": emo, "dop": dop, "bun": bun}
        for s in valores.values():
            self.assertNotIn(s, todo)
        hallazgos = (json.loads((self.crudo / "gitleaks.json").read_text())
                     + json.loads((self.crudo / "gitleaks-bundle.json").read_text()))
        recuperados = set()
        for x in hallazgos:
            h = em.Huella.desde(x.get("AuditorHuella"))
            self.assertIsNotNone(h, x)
            nombre = [k for k, s in valores.items() if h._es(s)]
            self.assertEqual(len(nombre), 1, x)
            self.assertIs(x.get("AuditorProveedor"), True, x)
            recuperados.add(nombre[0])
        self.assertEqual(recuperados, set(valores))


if __name__ == "__main__":
    unittest.main()

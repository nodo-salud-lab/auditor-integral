"""AUD-SINT (Anexo C del brazo C): rutas de datos SINTÉTICOS declaradas por el creador en
config/confidencial.toml, sección [sinteticos].

- DAT-PII-REPO sobre esas rutas → severidad info con la nota «declarado sintético por el creador,
  verificar» (sin el crítico `trackeado` ni bloqueo global).
- Inspector de cabecera DICOM (stdlib): lee SOLO PatientName, PatientID y PatientBirthDate de archivos
  dentro de rutas declaradas sintéticas, y solo informa si parecen vacíos o ficticios; sus valores nunca
  se escriben en ningún artefacto.
Los valores de cabecera son FALSOS y llevan un canario aleatorio por corrida.
"""
import json
import os
import secrets
import string
import struct
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import datos_confidenciales as dc  # noqa: E402

sys.path.insert(0, str(RAIZ / "tests"))
from tmp_tests import TMP_BASE  # noqa: E402  (temporales fuera del árbol del proyecto)
TMP_BASE.mkdir(parents=True, exist_ok=True)
GIT_ID = ["-c", "user.name=prueba", "-c", "user.email=prueba@example.invalid", "-c", "commit.gpgsign=false"]
EXPLICITA_LE = "1.2.840.10008.1.2.1"
IMPLICITA_LE = "1.2.840.10008.1.2"


def azar(n=10):
    return "".join(secrets.choice(string.ascii_uppercase) for _ in range(n))


def git(proy, *args):
    return subprocess.run(["git", *GIT_ID, "-C", str(proy), *args], capture_output=True, text=True,
                          env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(TMP_BASE)), check=True)


def _par(texto, relleno=b" "):
    b = texto.encode("ascii") if isinstance(texto, str) else texto
    return b + relleno if len(b) % 2 else b


def _elem_explicito(grupo, elem, vr, valor):
    v = _par(valor, b"\0" if vr in ("UI", "OB") else b" ")
    if vr in ("OB", "OW", "SQ", "UN", "UT"):
        return struct.pack("<HH", grupo, elem) + vr.encode() + b"\0\0" + struct.pack("<I", len(v)) + v
    return struct.pack("<HH", grupo, elem) + vr.encode() + struct.pack("<H", len(v)) + v


def _elem_implicito(grupo, elem, valor):
    v = _par(valor)
    return struct.pack("<HHI", grupo, elem, len(v)) + v


def dicom(nombre=None, pid=None, nacimiento=None, sintaxis=EXPLICITA_LE):
    meta_cuerpo = _elem_explicito(0x0002, 0x0010, "UI", sintaxis)
    meta = _elem_explicito(0x0002, 0x0000, "UL", b"") [:6] + struct.pack("<H", 4) + struct.pack("<I", len(meta_cuerpo))
    meta += meta_cuerpo
    implicita = sintaxis == IMPLICITA_LE
    datos = b""
    campos = [(0x0008, 0x0060, "CS", "US"), (0x0010, 0x0010, "PN", nombre), (0x0010, 0x0020, "LO", pid),
              (0x0010, 0x0030, "DA", nacimiento)]
    for g, e, vr, val in campos:
        if val is None:
            continue
        datos += _elem_implicito(g, e, val) if implicita else _elem_explicito(g, e, vr, val)
    pix = b"\x00" * 64
    datos += _elem_implicito(0x7FE0, 0x0010, pix) if implicita else _elem_explicito(0x7FE0, 0x0010, "OB", pix)
    return b"\0" * 128 + b"DICM" + meta + datos


class TestConfig(unittest.TestCase):
    def test_config_por_defecto_tiene_seccion_sinteticos_vacia(self):
        conf = dc.cargar()
        self.assertIn("sinteticos", conf)
        self.assertEqual(conf["sinteticos"], [])  # la lista la decide el creador, no el auditor

    def test_cargar_lee_sinteticos(self):
        tmp = Path(ap.tmp_dir())
        self.addCleanup(ap.limpiar, tmp)
        ruta = tmp / "c.toml"
        ruta.write_text('carpetas = ["datos-reales"]\narchivos = ["*.dcm"]\n\n[sinteticos]\n'
                        'rutas = ["pruebas/sinteticos/", "fixtures/fantoma.dcm"]\n', encoding="utf-8")
        conf = dc.cargar(ruta)
        self.assertEqual(conf["sinteticos"], ["pruebas/sinteticos", "fixtures/fantoma.dcm"])
        self.assertTrue(dc.es_sintetico_declarado("pruebas/sinteticos/dicom/a.dcm", conf))
        self.assertTrue(dc.es_sintetico_declarado("fixtures/fantoma.dcm", conf))
        self.assertFalse(dc.es_sintetico_declarado("otra/pruebas/sinteticos/a.dcm", conf))  # anclado a la raíz
        self.assertFalse(dc.es_sintetico_declarado("pruebas/sinteticos2/a.dcm", conf))
        self.assertFalse(dc.es_sintetico_declarado("pruebas/a.dcm", conf))


class TestInspectorDicom(unittest.TestCase):
    def setUp(self):
        self.dir = Path(ap.tmp_dir(self))
        self.addCleanup(ap.limpiar, self.dir)

    def _ins(self, contenido):
        p = self.dir / f"{azar()}.dcm"
        p.write_bytes(contenido)
        return dc.inspeccionar_cabecera_dicom(p)

    def test_ficticio_explicito(self):
        r = self._ins(dicom("PACIENTE^FICTICIO", "11.111.111-1"))
        self.assertEqual(r["veredicto"], "ficticio")
        self.assertEqual(sorted(r["tags_leidos"]), ["PatientID", "PatientName"])

    def test_ficticio_implicito_y_vacios(self):
        r = self._ins(dicom("ANON", "", "", sintaxis=IMPLICITA_LE))
        self.assertEqual(r["veredicto"], "ficticio")
        r = self._ins(dicom("TEST^PRUEBA", "SINTETICO-0001"))
        self.assertEqual(r["veredicto"], "ficticio")

    def test_valor_real_no_se_confirma_ni_se_expone(self):
        canario = "PEREZ^" + azar()
        r = self._ins(dicom(canario, "12.345.678-5", "19800101"))
        self.assertEqual(r["veredicto"], "no_ficticio")
        texto = json.dumps(r)
        for v in (canario, "12.345.678-5", "19800101", "PEREZ"):
            self.assertNotIn(v, texto)

    def test_apellido_que_contiene_test_no_es_ficticio(self):
        self.assertEqual(self._ins(dicom("TESTA^" + azar(), "12.345.678-5"))["veredicto"], "no_ficticio")

    def test_no_dicom(self):
        self.assertEqual(self._ins(b"hola mundo")["veredicto"], "no_dicom")

    def test_sin_tags_de_paciente_es_ficticio_por_vacio(self):
        r = self._ins(dicom())
        self.assertEqual(r["veredicto"], "ficticio")
        self.assertEqual(r["tags_leidos"], [])


class TestCheckSinteticos(unittest.TestCase):
    def setUp(self):
        self.dir = Path(ap.tmp_dir(self))
        self.addCleanup(ap.limpiar, self.dir)
        self.proy = self.dir / "proy"
        self.conf_ruta = self.dir / "conf.toml"
        self.conf_ruta.write_text('carpetas = ["datos-reales"]\narchivos = ["*.dcm"]\n\n[sinteticos]\n'
                                  'rutas = ["pruebas/sinteticos"]\n', encoding="utf-8")
        self.conf = dc.cargar(self.conf_ruta)

    def _escribir(self, rel, contenido):
        p = self.proy / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(contenido)

    def _commit(self):
        git(self.proy, "init", "-q")
        git(self.proy, "add", "-A")
        git(self.proy, "commit", "-q", "-m", "x")

    def _analizar(self):
        with mock.patch.object(dc, "cargar", return_value=self.conf):
            return dc.analizar(self.proy)

    def test_sintetico_declarado_es_info_sin_critico(self):
        self._escribir("pruebas/sinteticos/a.dcm", dicom("PACIENTE^FICTICIO", "11.111.111-1"))
        self._escribir("pruebas/sinteticos/dicom/b.dcm", dicom("ANON", "11.111.111-1"))
        self._commit()
        res = self._analizar()
        self.assertEqual([h for h in res["hallazgos"] if h["regla"].endswith(".trackeado")], [])
        sint = [h for h in res["hallazgos"] if h["regla"] == "check:datos_confidenciales.sintetico_declarado"]
        self.assertEqual(len(sint), 2)
        for h in sint:
            self.assertEqual(h["severidad_sugerida"], "info")
            self.assertIn("declarado sintético por el creador, verificar", h["mensaje"])
            self.assertIn("ficticia", h["evidencia"])
        self.assertIn("check:datos_confidenciales.no_trackeado", [p["regla"] for p in res["checks_pass"]])
        inv = {i["ruta"]: i for i in res["inventario"]}
        self.assertIs(inv["pruebas/sinteticos/a.dcm"]["sintetico_declarado"], True)

    def test_sintetico_con_cabecera_no_ficticia_sigue_critico(self):
        canario = "SOTO^" + azar()
        self._escribir("pruebas/sinteticos/a.dcm", dicom(canario, "12.345.678-5", "19800101"))
        self._commit()
        res = self._analizar()
        trk = [h for h in res["hallazgos"] if h["regla"] == "check:datos_confidenciales.trackeado"]
        self.assertEqual(len(trk), 1)
        self.assertEqual(trk[0]["severidad_sugerida"], "critica")
        self.assertIn("no se pudo confirmar", trk[0]["evidencia"])
        self.assertNotIn(canario, json.dumps(res))
        self.assertNotIn("12.345.678-5", json.dumps(res))

    def test_no_declarado_no_se_abre_y_sigue_critico(self):
        self._escribir("otros/c.dcm", dicom("PACIENTE^FICTICIO", "11.111.111-1"))
        self._commit()
        abrir = open
        base = os.path.realpath(self.proy) + os.sep

        def vigilado(f, *a, **kw):
            if isinstance(f, (str, bytes, os.PathLike)) and os.path.realpath(os.fsdecode(f)).startswith(
                    base + "otros"):
                raise AssertionError(f"se abrió un archivo confidencial no declarado sintético: {f}")
            return abrir(f, *a, **kw)
        with mock.patch("builtins.open", vigilado):
            res = self._analizar()
        trk = [h for h in res["hallazgos"] if h["regla"] == "check:datos_confidenciales.trackeado"]
        self.assertEqual([h["archivo"] for h in trk], ["otros/c.dcm"])

    def test_mezcla_en_carpeta_confidencial(self):
        # Una carpeta confidencial con un archivo declarado y otro no: el no declarado mantiene el crítico.
        self.conf = {"carpetas": ["datos-reales"], "archivos": [], "sinteticos": ["datos-reales/sint"]}
        self._escribir("datos-reales/sint/a.csv", b"x\n")
        self._escribir("datos-reales/p.csv", b"y\n")
        self._commit()
        res = self._analizar()
        trk = [h for h in res["hallazgos"] if h["regla"] == "check:datos_confidenciales.trackeado"]
        self.assertEqual(len(trk), 1)
        self.assertIn("1", trk[0]["evidencia"])

    def test_sintetico_versionado_no_es_sin_gitignore(self):
        # Re-auditoría de kine us (2026-11-18): un sintético declarado y VERSIONADO (re-incluido con
        # !pruebas/sinteticos/** tras *.dcm) no es «sin versionar ni ignorado»: no debe salir sin_gitignore.
        self._escribir(".gitignore", b"*.dcm\n!pruebas/sinteticos/**\n")
        self._escribir("pruebas/sinteticos/a.dcm", dicom("PACIENTE^FICTICIO", "11.111.111-1"))
        self._commit()
        res = self._analizar()
        reglas = [h["regla"] for h in res["hallazgos"]]
        self.assertNotIn("check:datos_confidenciales.sin_gitignore", reglas)
        self.assertIn("check:datos_confidenciales.sintetico_declarado", reglas)

    def test_sintetico_no_versionado_ni_ignorado_sigue_sin_gitignore(self):
        self._escribir(".gitignore", b"*.dcm\n!pruebas/sinteticos/**\n")
        self._escribir("pruebas/sinteticos/a.dcm", dicom("PACIENTE^FICTICIO", "11.111.111-1"))
        self._commit()
        self._escribir("pruebas/sinteticos/nuevo.dcm", dicom("ANON", "11.111.111-1"))
        res = self._analizar()
        sg = [h for h in res["hallazgos"] if h["regla"] == "check:datos_confidenciales.sin_gitignore"]
        self.assertEqual([h["archivo"] for h in sg], ["pruebas/sinteticos/nuevo.dcm"])
        self.assertEqual(sg[0]["severidad_sugerida"], "alta")

    def test_cli_no_escribe_valores_de_cabecera(self):
        canario = "PACIENTE^FICTICIO" + azar()
        self._escribir("pruebas/sinteticos/a.dcm", dicom(canario, "11.111.111-1"))
        self._commit()
        crudo = self.dir / "crudo"
        r = subprocess.run([sys.executable, str(RAIZ / "scripts" / "checks" / "datos_confidenciales.py"),
                            str(self.proy), str(crudo)], capture_output=True, text=True,
                           env=dict(os.environ, AUDITOR_CONFIDENCIAL=str(self.conf_ruta)))
        self.assertEqual(r.returncode, 0, r.stderr)
        texto = (crudo / "check_datos_confidenciales.json").read_text(encoding="utf-8")
        self.assertIn("sintetico_declarado", texto)
        self.assertNotIn(canario, texto)
        self.assertNotIn("11.111.111-1", texto)
        self.assertNotIn(canario, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()

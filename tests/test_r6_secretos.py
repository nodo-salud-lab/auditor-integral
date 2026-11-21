"""Ronda 6, grupo «secretos» (verificación real 2026-11-20: el nivel global salía N0 en todas las corridas porque los
bloqueos de secretos se apoyaban en falsos positivos).

Cubre:
  (1a) gitleaks excluye siempre entornos virtuales y cachés de herramientas (arbol.toml + pyvenv.cfg dinámico) y la
       búsqueda de bundles no entra en ellos; las carpetas de build ignoradas se siguen escaneando como bundle.
  (1b) en un repo git, un secreto en un archivo IGNORADO y nunca versionado queda marcado AuditorGit = "ignorado" y se
       normaliza con confianza baja y regla «secreto-local-ignorado:…» (visible, sin bloqueo); no versionado pero no
       ignorado, ignorado con historial, versionado, desconocido y sin_git siguen contando (fail-closed).
       Las carpetas ignoradas se escanean aparte con presupuesto propio: si se agota, el meta lo dice (timeout) y el
       estado global no baja (lo ignorado no cuenta para el repo).
  (2)  JWT con role anon → AuditorJwtRol "anon" → confianza baja y etiqueta «clave pública por diseño»; service_role,
       otro e ilegible no cambian.
  (3)  complejidad y duplicacion no cuentan código de entornos virtuales (pyvenv.cfg, lib/python*/site-packages,
       .nox, .tox, site-packages).
  (4)  con_timeout.py: un PermissionError de os.killpg al cortar no convierte el timeout en error (sigue siendo 124).
Todos los secretos son canarios generados al azar (no son válidos).
"""
import base64
import json
import os
import secrets
import shutil
import signal
import stat
import string
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts"))
sys.path.insert(0, str(RAIZ / "scripts" / "adaptadores"))
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import con_timeout  # noqa: E402
import gates  # noqa: E402
import gitleaks_redactar  # noqa: E402
import utiles  # noqa: E402
from normalizar import comun as n_comun  # noqa: E402
from normalizar import gitleaks as n_gitleaks  # noqa: E402
import comun as c_comun  # noqa: E402
import complejidad  # noqa: E402
import duplicacion  # noqa: E402
from tmp_tests import TMP_BASE  # noqa: E402

TMP_BASE.mkdir(parents=True, exist_ok=True)
ADAPT = RAIZ / "scripts" / "adaptadores"


def azar(n, alfabeto=string.ascii_letters + string.digits):
    return "".join(secrets.choice(alfabeto) for _ in range(n))


def generico():
    return "Zq" + azar(10, string.digits) + azar(28)


def jwt(payload):
    cuerpo = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + cuerpo + "." + azar(43, string.ascii_letters + string.digits + "-_")


def jwt_rol(rol):
    return jwt({"iss": "supabase", "ref": azar(20).lower(), "role": rol, "iat": 1700000000, "exp": 2000000000})


def git(proy, *args):
    subprocess.run(["git", "-C", str(proy), *args], check=True, capture_output=True,
                   env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(TMP_BASE), GIT_CONFIG_NOSYSTEM="1"))


def commit(proy, msg="c"):
    git(proy, "-c", "user.email=a@b.c", "-c", "user.name=t", "commit", "-qm", msg)


class BaseProyecto(unittest.TestCase):
    def setUp(self):
        self.dir = TMP_BASE / f"r6sec_{self.id().split('.')[-1]}_{azar(6)}"
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


# ----------------------------------------------------------------------------- (2) rol del JWT

class TestRolJwt(unittest.TestCase):
    def test_roles(self):
        self.assertEqual(n_gitleaks.rol_jwt(jwt_rol("anon")), "anon")
        self.assertEqual(n_gitleaks.rol_jwt(jwt_rol("service_role")), "service_role")
        self.assertEqual(n_gitleaks.rol_jwt(jwt_rol("authenticated")), "otro")
        self.assertEqual(n_gitleaks.rol_jwt(jwt({"sub": "x"})), "otro")  # sin role: no se presume anon
        self.assertEqual(n_gitleaks.rol_jwt('"' + jwt_rol("anon") + '"'), "anon")  # comillas alrededor

    def test_ilegible_y_no_jwt(self):
        self.assertEqual(n_gitleaks.rol_jwt("eyJhbGciOiJIUzI1NiJ9.@@no-base64@@.firma"), "ilegible")
        self.assertEqual(n_gitleaks.rol_jwt("eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(b"no json").decode().rstrip("=") + ".f"),
                         "ilegible")
        self.assertEqual(n_gitleaks.rol_jwt(jwt([1, 2])), "ilegible")  # payload que no es objeto
        self.assertIsNone(n_gitleaks.rol_jwt(generico()))
        self.assertIsNone(n_gitleaks.rol_jwt("a.b.c"))
        self.assertIsNone(n_gitleaks.rol_jwt(""))

    def test_redactar_usa_el_mismo_criterio(self):
        self.assertIs(gitleaks_redactar.rol_jwt, n_gitleaks.rol_jwt)

    def test_service_role_sigue_siendo_proveedor(self):
        self.assertTrue(n_gitleaks.con_prefijo_de_proveedor(jwt_rol("service_role")))
        self.assertFalse(n_gitleaks.con_prefijo_de_proveedor(jwt_rol("anon")))


class TestRedactarMarcaRol(BaseProyecto):
    def hallazgo(self, valor, regla="jwt", archivo="src/a.js"):
        return {"RuleID": regla, "File": archivo, "StartLine": 1, "Secret": valor, "Match": f'k = "{valor}"',
                "Line": f'const k = "{valor}";'}

    def test_marca_rol_y_no_deja_el_valor(self):
        anon, srv, otro = jwt_rol("anon"), jwt_rol("service_role"), jwt_rol("authenticated")
        datos = [self.hallazgo(anon), self.hallazgo(srv), self.hallazgo(otro), self.hallazgo(generico(), "generic-api-key")]
        texto = gitleaks_redactar.procesar(datos, str(self.proy), None)
        for v in (anon, srv, otro):
            self.assertNotIn(v, texto)
        self.assertNotIn(anon.split(".")[1], texto)  # tampoco el payload
        res = json.loads(texto)
        self.assertEqual([d.get("AuditorJwtRol") for d in res], ["anon", "service_role", "otro", None])

    def test_regla_jwt_sin_valor_recuperable_es_ilegible(self):
        d = {"RuleID": "jwt", "File": "no/existe.js", "StartLine": 1, "Secret": "REDACTED", "Match": "REDACTED"}
        res = json.loads(gitleaks_redactar.procesar([d], str(self.proy), None))
        self.assertEqual(res[0]["AuditorJwtRol"], "ilegible")

    def test_rol_por_archivo(self):
        anon1, anon2, srv = jwt_rol("anon"), jwt_rol("anon"), jwt_rol("service_role")
        f = gitleaks_redactar.rol_jwt_por_archivo
        self.assertEqual(f(f'a="{anon1}";b=\'{anon2}\''.encode()), "anon")
        self.assertIsNone(f(f'a="{anon1}";b="{srv}"'.encode()))  # mezcla: no se presume nada
        self.assertEqual(f(f'b="{srv}"'.encode()), "service_role")
        self.assertIsNone(f(b"sin jwt aqui"))
        # Un JWT escondido tras un guion dentro de otro candidato también se ve (búsqueda solapada).
        h, p, s = srv.split(".")
        oculto = f'x="{anon1}";y="{h}.{anon1.split(".")[1]}-{h}.{p}.{s}"'.encode()
        self.assertIsNone(f(oculto))
        # Payload con caracteres fuera de base64url (la regla de gitleaks admite / y \\): ilegible, no anon.
        self.assertIsNone(f(f'a="{anon1}";b="{h}.ey{azar(20)}/{azar(5)}.{s}"'.encode()))

    def test_jwt_no_recuperable_usa_el_rol_comun_del_archivo(self):
        self.escribir("dist/app.js.map", "{" + f'"k":"{jwt_rol("anon")}","j":"{jwt_rol("anon")}"' + "}")
        self.escribir("dist/mixto.js.map", "{" + f'"k":"{jwt_rol("anon")}","j":"{jwt_rol("service_role")}"' + "}")
        base = {"RuleID": "jwt", "StartLine": 1, "EndLine": 1, "StartColumn": 1, "EndColumn": 2, "Secret": "REDACTED",
                "Match": "REDACTED'"}
        res = json.loads(gitleaks_redactar.procesar([dict(base, File="dist/app.js.map"), dict(base, File="dist/mixto.js.map"),
                                                     dict(base, File="dist/no-existe.map")], str(self.proy), None))
        self.assertEqual([d["AuditorJwtRol"] for d in res], ["anon", "ilegible", "ilegible"])

    def test_recuperar_por_contexto_cuando_las_columnas_no_sirven(self):
        valor = generico()
        relleno = "x" * 5000
        self.escribir("dist/a.map", relleno + f'"_callRefresh","{valor}",' + relleno + f'"_callRefresh","{valor}"')
        d = {"RuleID": "generic-api-key", "File": "dist/a.map", "StartLine": 1, "EndLine": 1, "StartColumn": 3,
             "EndColumn": 40, "Secret": "REDACTED", "Match": '_callRefresh","REDACTED"'}
        res = json.loads(gitleaks_redactar.procesar([dict(d)], str(self.proy), None))[0]
        self.assertTrue(res.get("AuditorHuella"))
        self.assertIs(res.get("AuditorProveedor"), False)
        self.assertNotIn(valor, json.dumps(res))
        # Dos valores distintos con el mismo contexto: ambiguo, no se recupera.
        self.escribir("dist/b.map", f'"_callRefresh","{generico()}",' + relleno + f'"_callRefresh","{generico()}"')
        res = json.loads(gitleaks_redactar.procesar([dict(d, File="dist/b.map")], str(self.proy), None))[0]
        self.assertEqual(res["Secret"], "REDACTED")
        self.assertNotIn("AuditorProveedor", res)
        # Contexto débil (solo comillas): no se usa este respaldo.
        self.escribir("dist/c.map", relleno + f'"{valor}"')
        res = json.loads(gitleaks_redactar.procesar([dict(d, File="dist/c.map", Match='"REDACTED"')],
                                                    str(self.proy), None))[0]
        self.assertEqual(res["Secret"], "REDACTED")

    def test_campos_auditor_del_reporte_se_descartan(self):
        # Un reporte no puede traer su propia marca: solo gitleaks_redactar.py la escribe.
        d = {"RuleID": "generic-api-key", "File": "x.js", "StartLine": 1, "Secret": "REDACTED", "Match": "REDACTED",
             "AuditorJwtRol": "anon", "AuditorGit": "ignorado"}
        res = json.loads(gitleaks_redactar.procesar([d], str(self.proy), None))
        self.assertNotIn("AuditorJwtRol", res[0])
        self.assertNotIn("AuditorGit", res[0])


# ----------------------------------------------------------------------------- (1b) estado git

class TestEstadoGit(BaseProyecto):
    def setUp(self):
        super().setUp()
        self._env = mock.patch.dict(os.environ, {"GIT_CEILING_DIRECTORIES": str(TMP_BASE)})
        self._env.start()
        self.addCleanup(self._env.stop)

    def repo(self):
        self.escribir(".gitignore", "local/\n.env.local\nviejo.env\n")
        self.escribir("src/a.js", "x\n")
        self.escribir("viejo.env", "x\n")
        git(self.proy, "init", "-q")
        git(self.proy, "add", "-f", ".gitignore", "src/a.js", "viejo.env")
        commit(self.proy)
        git(self.proy, "rm", "-q", "--cached", "viejo.env")
        commit(self.proy, "saca viejo")
        self.escribir("local/token.json", "x\n")
        self.escribir(".env.local", "x\n")
        self.escribir("nuevo.txt", "x\n")

    def test_clasificacion(self):
        self.repo()
        eg = gitleaks_redactar.EstadoGit(self.proy)
        self.assertEqual(eg.de("src/a.js"), "versionado")
        self.assertEqual(eg.de("./src/a.js"), "versionado")
        self.assertEqual(eg.de("nuevo.txt"), "no_versionado")  # se subiría con git add .
        self.assertEqual(eg.de("local/token.json"), "ignorado")
        self.assertEqual(eg.de(".env.local"), "ignorado")
        self.assertEqual(eg.de("viejo.env"), "ignorado_con_historial")
        self.assertEqual(eg.de("/abs/ruta"), "desconocido")
        self.assertEqual(eg.de("../fuera"), "desconocido")
        self.assertEqual(eg.de(None), "desconocido")

    def test_fuera_de_git(self):
        self.escribir("a.js", "x\n")
        self.assertEqual(gitleaks_redactar.EstadoGit(self.proy).de("a.js"), "sin_git")

    def test_git_que_falla_es_desconocido(self):
        self.repo()
        eg = gitleaks_redactar.EstadoGit(self.proy)
        with mock.patch.object(gitleaks_redactar.git_seguro, "ejecutar", return_value=(None, None)):
            self.assertEqual(eg.de("local/token.json"), "desconocido")

    def test_procesar_solo_marca_sin_commit_y_con_la_opcion(self):
        self.repo()
        d1 = {"RuleID": "generic-api-key", "File": "local/token.json", "StartLine": 1, "Secret": generico(), "Match": "m"}
        d2 = dict(d1, Commit="a" * 40, Secret=generico())
        res = json.loads(gitleaks_redactar.procesar([d1, d2], str(self.proy), None, estado_git=True))
        self.assertEqual(res[0]["AuditorGit"], "ignorado")
        self.assertNotIn("AuditorGit", res[1])
        res = json.loads(gitleaks_redactar.procesar([dict(d1, Secret=generico())], str(self.proy), None))
        self.assertNotIn("AuditorGit", res[0])


# ----------------------------------------------------------------------------- normalizar

class TestNormalizar(unittest.TestCase):
    def leer(self, datos, archivo="gitleaks.json"):
        d = TMP_BASE / f"r6norm_{azar(8)}"
        d.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        ruta = d / archivo
        ruta.write_text(json.dumps(datos), encoding="utf-8")
        return n_gitleaks.leer(ruta, {"proyecto": None, "metas": {}, "confidencial": None})

    def base(self, **kw):
        d = {"RuleID": "generic-api-key", "File": "local/token.json", "StartLine": 2, "Secret": "Zq12****abcd",
             "Match": '"api_key": "Zq12****abcd"', "Description": "Generic API Key", "AuditorProveedor": False}
        d.update(kw)
        return d

    def test_ignorado_baja_y_etiqueta(self):
        r = self.leer([self.base(AuditorGit="ignorado")])[0]
        self.assertEqual(r["confianza"], "baja")
        self.assertEqual(r["regla"], "secreto-local-ignorado:generic-api-key")
        self.assertTrue(r["evidencia"].startswith("secreto local no versionado (ignorado por git)"))
        self.assertIn("no hace falta rotar", r["evidencia"])
        self.assertNotIn("rotar la credencial", r["mensaje"].lower())

    def test_otros_estados_git_no_cambian(self):
        for estado in ("versionado", "no_versionado", "ignorado_con_historial", "desconocido", "sin_git", None):
            with self.subTest(estado=estado):
                kw = {} if estado is None else {"AuditorGit": estado}
                r = self.leer([self.base(**kw)])[0]
                self.assertEqual(r["regla"], "generic-api-key")
                self.assertEqual(r["confianza"], "media")

    def test_ignorado_con_commit_no_cambia(self):
        r = self.leer([self.base(AuditorGit="ignorado", Commit="b" * 40)])[0]
        self.assertEqual(r["regla"], "generic-api-key")

    def test_anon_baja_tambien_en_bundle_y_historial(self):
        for archivo, extra in (("src/supabase.js", {}), ("dist/assets/app.js", {}), ("src/supabase.js", {"Commit": "c" * 40})):
            with self.subTest(archivo=archivo, extra=extra):
                r = self.leer([self.base(RuleID="jwt", File=archivo, AuditorJwtRol="anon", **extra)])[0]
                self.assertEqual(r["confianza"], "baja")
                self.assertEqual(r["regla"], "jwt-anon-publico:jwt")
                self.assertTrue(r["evidencia"].startswith("clave pública por diseño"))

    def test_service_role_otro_e_ilegible_no_cambian(self):
        for rol in ("service_role", "otro", "ilegible"):
            with self.subTest(rol=rol):
                r = self.leer([self.base(RuleID="jwt", File="src/a.js", AuditorJwtRol=rol, AuditorGit="versionado")])[0]
                self.assertEqual(r["regla"], "jwt")
                self.assertEqual(r["confianza"], "alta")

    def test_reporte_antiguo_con_valor_en_claro(self):
        anon = jwt_rol("anon")
        r = self.leer([self.base(RuleID="jwt", File="src/a.js", Secret=anon, Match=anon)])[0]
        self.assertEqual(r["regla"], "jwt-anon-publico:jwt")
        r = self.leer([self.base(RuleID="jwt", File="src/a.js", Secret=jwt_rol("service_role"))])[0]
        self.assertEqual(r["regla"], "jwt")

    def test_mapeo_y_bloqueo(self):
        """Las reglas con prefijo (anon, local ignorado) van a SEG-SECRETO-LOCAL (severidad baja, sin bloqueo) y el
        secreto real sigue en SEG-SECRETO-REPO. Con confianza baja no bloquean solas (AUD-SEC), y con un secreto real
        en el mismo control el bloqueo se mantiene.
        DECISIONES.md #12 (integración de la ronda 6): antes este test exigía que los tres hallazgos quedaran en
        SEG-SECRETO-REPO («hoy siguen ahí»), porque el catálogo aún no tenía control propio. La integración agregó
        SEG-SECRETO-LOCAL con mapea_reglas gitleaks:jwt-anon-publico:* y gitleaks:secreto-local-ignorado:*, que por
        especificidad ganan sobre gitleaks:*; el test se actualiza a esa decisión sin relajar el caso del secreto
        real ni el de AUD-SEC."""
        perfil = utiles.cargar_perfil(TMP_BASE)  # sin perfil en esa carpeta: catálogo completo
        indice = utiles.indice_controles(perfil)
        anon = self.leer([self.base(RuleID="jwt", File="src/a.js", AuditorJwtRol="anon")])[0]
        local = self.leer([self.base(AuditorGit="ignorado")])[0]
        real = self.leer([self.base(File="src/b.js", AuditorGit="versionado")])[0]
        hs = [n_comun.construir(r, indice) for r in (anon, local, real)]
        self.assertEqual([h["control"] for h in hs], ["SEG-SECRETO-LOCAL", "SEG-SECRETO-LOCAL", "SEG-SECRETO-REPO"])
        self.assertEqual([h["severidad"] for h in hs[:2]], ["baja", "baja"])
        self.assertEqual(hs[2]["severidad"], "critica")
        por_id = {h["id"]: h for h in hs}
        # AUD-SEC sigue valiendo para hallazgos de confianza baja dentro de un control de secreto
        self.assertTrue(gates._secreto_sin_confirmar("SEG-SECRETO-REPO", [hs[0]["id"], hs[1]["id"]], por_id))
        self.assertFalse(gates._secreto_sin_confirmar("SEG-SECRETO-REPO", [h["id"] for h in hs], por_id))
        # Un triage que confirma el hallazgo devuelve el bloqueo (fail-closed).
        confirmado = dict(hs[0], triage={"veredicto": "verdadero"})
        self.assertFalse(gates._secreto_sin_confirmar("SEG-SECRETO-REPO", [confirmado["id"]], {confirmado["id"]: confirmado}))


# ----------------------------------------------------------------------------- (1) adaptador real

def _jsons(crudo, nombre):
    p = crudo / nombre
    return json.loads(p.read_text()) if p.is_file() else []


@unittest.skipUnless(shutil.which("gitleaks") and shutil.which("git"), "gitleaks o git no instalados")
class TestAdaptadorGitleaks(BaseProyecto):
    def correr(self, env=None):
        return subprocess.run(["bash", str(ADAPT / "gitleaks.sh"), str(self.proy), str(self.crudo)],
                              capture_output=True, text=True, env=env or self.env, timeout=300)

    def sembrar(self):
        self.aws = "AKIA" + azar(16, string.ascii_uppercase + "234567")
        self.escribir(".pytest_cache/v/cache/nodeids", json.dumps([f"tests/t.py::test_k[{self.aws}]"]) + "\n")
        self.escribir(".mypy_cache/x.json", f'{{"api_key": "{generico()}"}}\n')
        self.escribir(".venv312/pyvenv.cfg", "home = /usr/bin\n")
        self.escribir(".venv312/lib/python3.12/site-packages/pkg/build/m.py", f'api_key = "{generico()}"\n')
        self.escribir(".nox/paquete/lib/m.py", f'api_key = "{generico()}"\n')
        self.escribir("supabase/.temp/env/docker.env", f"JWT={jwt_rol('service_role')}\n")
        self.escribir("local/token.json", f'{{\n  "api_key": "{generico()}"\n}}\n')
        self.escribir(".env.local", f"SERVICE_API_KEY={generico()}\n")
        self.escribir("src/config.js", f'export const ANON = "{jwt_rol("anon")}";\n')
        self.escribir("src/admin.js", f'export const SRV = "{jwt_rol("service_role")}";\n')
        self.escribir("dist/app.js", f'const k="{jwt_rol("anon")}";\n')

    def test_repo_git(self):
        self.sembrar()
        self.escribir(".gitignore", ".pytest_cache/\n.mypy_cache/\n.venv312/\n.nox/\nsupabase/.temp/\nlocal/\n"
                                    ".env.local\ndist/\n")
        git(self.proy, "init", "-q")
        git(self.proy, "add", ".gitignore", "src")
        commit(self.proy)
        self.escribir("nuevo.txt", f'api_key = "{generico()}"\n')  # sin seguimiento y NO ignorado
        r = self.correr()
        self.assertEqual(r.returncode, 0, r.stderr)
        meta = json.loads((self.crudo / "gitleaks.meta.json").read_text())
        self.assertEqual(meta["estado"], "ok", meta.get("error"))
        self.assertEqual(meta["excluidas_venv"], [".venv312"])
        self.assertEqual(meta["ignoradas"]["estado"], "ok")
        self.assertGreaterEqual(meta["ignoradas"]["escaneadas"], 1)
        arbol = _jsons(self.crudo, "gitleaks.json")
        por_archivo = {d["File"]: d for d in arbol}
        for excluido in (".pytest_cache", ".mypy_cache", ".venv312", ".nox", "supabase/.temp"):
            self.assertFalse([f for f in por_archivo if f.startswith(excluido)], (excluido, sorted(por_archivo)))
        self.assertEqual(por_archivo["local/token.json"]["AuditorGit"], "ignorado")
        self.assertEqual(por_archivo[".env.local"]["AuditorGit"], "ignorado")
        self.assertEqual(por_archivo["nuevo.txt"]["AuditorGit"], "no_versionado")
        self.assertEqual(por_archivo["src/config.js"]["AuditorGit"], "versionado")
        self.assertEqual(por_archivo["src/config.js"]["AuditorJwtRol"], "anon")
        self.assertEqual(por_archivo["src/admin.js"]["AuditorJwtRol"], "service_role")
        # dist/ ignorado sigue escaneándose como bundle; la carpeta build/ dentro del entorno virtual no.
        self.assertEqual(meta["carpetas_bundle"], ["dist"])
        bundle = _jsons(self.crudo, "gitleaks-bundle.json")
        self.assertEqual([(d["File"], d.get("AuditorJwtRol")) for d in bundle], [("dist/app.js", "anon")])
        self.assertNotIn(self.aws, "\n".join(p.read_text(errors="replace") for p in self.crudo.rglob("*") if p.is_file()))

    def test_sin_git_todo_cuenta_salvo_entornos(self):
        self.sembrar()
        r = self.correr()
        self.assertEqual(r.returncode, 0, r.stderr)
        meta = json.loads((self.crudo / "gitleaks.meta.json").read_text())
        self.assertEqual(meta["ignoradas"]["estado"], "no_aplica")
        por_archivo = {d["File"]: d for d in _jsons(self.crudo, "gitleaks.json")}
        self.assertEqual(por_archivo["local/token.json"]["AuditorGit"], "sin_git")
        self.assertIn(".env.local", por_archivo)
        self.assertFalse([f for f in por_archivo if f.startswith((".pytest_cache", ".venv312", ".nox", "supabase/.temp"))])

    def test_secreto_versionado_en_carpeta_ignorada_cuenta(self):
        # La carpeta está ignorada pero tiene un archivo versionado: no se separa del escaneo principal.
        self.escribir(".gitignore", "conf/\n")
        self.escribir("conf/a.env", f"OTHER_API_KEY={generico()}\n")
        git(self.proy, "init", "-q")
        git(self.proy, "add", "-f", ".gitignore", "conf/a.env")
        commit(self.proy)
        self.correr()
        meta = json.loads((self.crudo / "gitleaks.meta.json").read_text())
        self.assertEqual(meta["ignoradas"]["carpetas"], 0)
        por_archivo = {d["File"]: d for d in _jsons(self.crudo, "gitleaks.json")}
        self.assertEqual(por_archivo["conf/a.env"]["AuditorGit"], "versionado")


class TestPresupuestoIgnoradas(BaseProyecto):
    """Con un gitleaks falso que se cuelga en la carpeta ignorada: el escaneo principal termina, el meta registra
    el timeout del escaneo de ignoradas y el estado global sigue ok (lo ignorado no cuenta para el repo)."""

    @unittest.skipUnless(shutil.which("git"), "git no instalado")
    def test_timeout_de_ignoradas_no_baja_el_estado(self):
        falsos = self.dir / "bin"
        falsos.mkdir()
        f = falsos / "gitleaks"
        f.write_text('#!/bin/bash\n[ "$1" = version ] && { echo 8.30.1; exit 0; }\n'
                     'r=""; for a in "$@"; do [ "$p" = --report-path ] && r="$a"; p="$a"; done\n'
                     'case "$2" in ./pesada) sleep 30;; esac\n'
                     'echo "[]" > "$r"; exit 0\n')
        f.chmod(f.stat().st_mode | stat.S_IXUSR)
        self.escribir(".gitignore", "pesada/\n")
        self.escribir("pesada/x.bin", "x\n")
        self.escribir("a.js", "x\n")
        git(self.proy, "init", "-q")
        git(self.proy, "add", ".gitignore", "a.js")
        commit(self.proy)
        env = dict(self.env, AUDITOR_BIN_GITLEAKS=str(f), AUDITOR_GITLEAKS_IGNORADAS_S="2")
        inicio = time.monotonic()
        r = self.correr_con(env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(time.monotonic() - inicio, 25)
        meta = json.loads((self.crudo / "gitleaks.meta.json").read_text())
        self.assertEqual(meta["ignoradas"]["estado"], "timeout")
        self.assertIn("pesada", meta["ignoradas"]["motivo"])
        self.assertEqual(meta["estado"], "ok")
        modos = {e["modo"]: e["estado"] for e in meta["ejecuciones"]}
        self.assertEqual(modos.get("ignoradas"), "timeout")
        self.assertEqual(modos.get("dir"), "ok")

    def correr_con(self, env):
        return subprocess.run(["bash", str(ADAPT / "gitleaks.sh"), str(self.proy), str(self.crudo)],
                              capture_output=True, text=True, env=env, timeout=120)


# ----------------------------------------------------------------------------- (3) complejidad y duplicación

COMPLEJA = "def f(x):\n" + "".join(f"    if x == {i}:\n        x += {i}\n" for i in range(40)) + "    return x\n"


class TestEntornosVirtuales(BaseProyecto):
    def test_dirs_excluidos(self):
        for d in (".nox", ".tox", ".ruff_cache", "site-packages", ".venv", "venv", ".pytest_cache", ".mypy_cache"):
            self.assertIn(d, c_comun.DIRS_EXCLUIDOS)

    def test_es_entorno_virtual(self):
        self.escribir("e1/pyvenv.cfg", "home = /usr\n")
        (self.proy / "e2/lib/python3.12/site-packages").mkdir(parents=True)
        (self.proy / "lib/python").mkdir(parents=True)
        self.assertTrue(complejidad.es_entorno_virtual(self.proy / "e1"))
        self.assertTrue(complejidad.es_entorno_virtual(self.proy / "e2"))
        self.assertFalse(complejidad.es_entorno_virtual(self.proy))
        self.assertFalse(complejidad.es_entorno_virtual(self.proy / "lib"))

    def sembrar(self):
        self.escribir("src/propio.py", COMPLEJA)
        self.escribir(".venv312/pyvenv.cfg", "home = /usr\n")
        self.escribir(".venv312/lib/python3.12/site-packages/x/m.py", COMPLEJA)
        self.escribir(".venv312/bin/script.py", COMPLEJA)
        self.escribir("entorno/lib/python3.11/site-packages/y/m.py", COMPLEJA)
        self.escribir("entorno/lib/python3.11/otro.py", COMPLEJA)
        self.escribir(".nox/paquete/m.py", COMPLEJA)
        self.escribir(".tox/py312/m.py", COMPLEJA)

    def test_complejidad_no_cuenta_entornos(self):
        self.sembrar()
        res = complejidad.analizar(self.proy)
        archivos = {h["archivo"] for h in res["hallazgos"]}
        self.assertEqual(archivos, {"src/propio.py"})

    def test_duplicacion_no_cuenta_entornos(self):
        self.sembrar()
        self.escribir("src/copia.py", COMPLEJA.replace("def f", "def g"))
        res = duplicacion.analizar(self.proy)
        archivos = {h["archivo"] for h in res["hallazgos"] if h.get("archivo")}
        self.assertTrue(archivos, res)  # el clon propio sí se detecta
        self.assertTrue(all(a.startswith("src/") for a in archivos), archivos)
        textos = json.dumps(res)
        for ruta in (".venv312", "entorno/lib", ".nox", ".tox"):
            self.assertNotIn(ruta, textos)


# ----------------------------------------------------------------------------- (4) con_timeout

class TestConTimeoutEperm(unittest.TestCase):
    def setUp(self):
        self.senales = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        self.addCleanup(lambda: [signal.signal(s, h) for s, h in self.senales.items()])

    def test_permission_error_al_matar_sigue_siendo_timeout(self):
        real = os.killpg

        def killpg_eperm(pgid, sig):
            real(pgid, sig)  # la señal llega, pero el sistema responde EPERM (como macOS con zombis)
            raise PermissionError(1, "Operation not permitted")

        with mock.patch.object(con_timeout.os, "killpg", side_effect=killpg_eperm), \
                mock.patch("sys.stderr") as err:
            codigo = con_timeout.main(["0.5", "sleep", "30"])
        self.assertEqual(codigo, 124)
        salida = "".join(str(c.args[0]) for c in err.write.call_args_list)
        self.assertIn("tiempo agotado", salida)
        self.assertIn("EPERM", salida)

    def test_eperm_solo_en_el_ultimo_sigkill(self):
        real = os.killpg
        llamadas = []

        def killpg(pgid, sig):
            llamadas.append(sig)
            if len(llamadas) >= 2:
                raise PermissionError(1, "Operation not permitted")
            real(pgid, sig)

        with mock.patch.object(con_timeout.os, "killpg", side_effect=killpg), mock.patch("sys.stderr"):
            self.assertEqual(con_timeout.main(["0.5", "sleep", "30"]), 124)

    def test_sin_timeout_no_cambia(self):
        with mock.patch("sys.stderr"):
            self.assertEqual(con_timeout.main(["5", "bash", "-c", "exit 3"]), 3)

    def test_senal_grupo_inexistente(self):
        self.assertEqual(con_timeout._senal_grupo(2 ** 22 + 12345, 0), "sin_grupo")


if __name__ == "__main__":
    unittest.main()


class TestEvasionesCritica(unittest.TestCase):
    """Pases falsos que encontró la crítica adversarial de la ronda 6 (DECISIONES.md #12)."""

    leer = TestNormalizar.leer
    base = TestNormalizar.base

    def test_ignorado_con_prefijo_de_proveedor_no_baja(self):
        r = self.leer([self.base(AuditorGit="ignorado", AuditorProveedor=True)])[0]
        self.assertEqual(r["regla"], "generic-api-key")
        self.assertNotEqual(r["confianza"], "baja")

    def test_ignorado_sin_saber_prefijo_no_baja(self):
        d = self.base(AuditorGit="ignorado")
        d.pop("AuditorProveedor")
        r = self.leer([d])[0]
        self.assertEqual(r["regla"], "generic-api-key")

    def test_ignorado_valor_en_claro_con_prefijo_no_baja(self):
        d = self.base(AuditorGit="ignorado", Secret="sk_live_" + azar(24))
        d.pop("AuditorProveedor")
        self.assertEqual(self.leer([d])[0]["regla"], "generic-api-key")

    def test_ignorado_en_carpeta_publicable_no_baja(self):
        for archivo in ("www/config.js", "public/env.js", "app/static/k.js", "dist/app.js"):
            with self.subTest(archivo=archivo):
                r = self.leer([self.base(AuditorGit="ignorado", File=archivo)])[0]
                self.assertEqual(r["regla"], "generic-api-key")

    def test_ignorado_local_sin_prefijo_sigue_bajando(self):
        for archivo in ("datos/demo/identidad.json", "server/data/jaas.pk", ".env.local"):
            with self.subTest(archivo=archivo):
                r = self.leer([self.base(AuditorGit="ignorado", File=archivo)])[0]
                self.assertEqual(r["regla"], "secreto-local-ignorado:generic-api-key")

    def test_jwt_anon_ajeno_a_supabase_es_otro(self):
        self.assertEqual(n_gitleaks.rol_jwt(jwt({"iss": "mi-backend", "role": "anon"})), "otro")
        self.assertEqual(n_gitleaks.rol_jwt(jwt({"role": "anon"})), "otro")

    def test_jwt_anon_con_privilegios_es_otro(self):
        for extra in ({"admin": True}, {"scope": "*"}, {"app_metadata": {"role": "service_role"}}):
            with self.subTest(extra=extra):
                p = {"iss": "supabase", "ref": "abc", "role": "anon", **extra}
                self.assertEqual(n_gitleaks.rol_jwt(jwt(p)), "otro")

    def test_jwt_role_duplicado_es_ilegible(self):
        for cuerpo in ('{"iss":"supabase","role":"anon","role":"service_role"}',
                       '{"iss":"supabase","role":"service_role","role":"anon"}'):
            with self.subTest(cuerpo=cuerpo):
                seg = base64.urlsafe_b64encode(cuerpo.encode()).decode().rstrip("=")
                self.assertEqual(n_gitleaks.rol_jwt("eyJhbGciOiJIUzI1NiJ9." + seg + ".firma"), "ilegible")

    def test_jwt_anon_supabase_sigue_siendo_anon(self):
        self.assertEqual(n_gitleaks.rol_jwt(jwt_rol("anon")), "anon")
        self.assertEqual(n_gitleaks.rol_jwt(jwt({"iss": "supabase-demo", "role": "anon", "exp": 1})), "anon")

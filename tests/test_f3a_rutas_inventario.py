"""F3-A: scripts/checks/rutas_inventario.py — inventario ruta → handler → consulta → ¿auth? ¿filtra por dueño?

Contrato (PLAN_MAESTRO §3.2, §9 «4a Autorización»): Express, Next (app/ y pages/api), FastAPI, Flask y consultas
del cliente Supabase, con archivo:línea; filas sospechosas (parámetro sin pertenencia, mutación sin auth,
service_role). Solo lee código fuente, respeta confidencial.toml y NUNCA da pass por sí mismo.
"""
import json
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RAIZ / "scripts" / "checks"))
sys.path.insert(0, str(RAIZ / "tests"))

import apoyo_corrida as ap  # noqa: E402
import rutas_inventario as ri  # noqa: E402


def escribir(base, rel, texto):
    p = Path(base) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(texto, encoding="utf-8")
    return p


def filas(res, **filtro):
    return [f for f in res["inventario"] if all(f.get(k) == v for k, v in filtro.items())]


class TestExpress(unittest.TestCase):
    def setUp(self):
        self.dir = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.dir)

    def test_ruta_con_id_sin_pertenencia_es_sospechosa(self):
        escribir(self.dir, "server/rutas.js", (
            "const express = require('express');\n"
            "const router = express.Router();\n"
            "router.get('/api/citas/:id', async (req, res) => {\n"
            "  const cita = await db.query('SELECT * FROM citas WHERE id = $1', [req.params.id]);\n"
            "  res.json(cita);\n"
            "});\n"))
        res = ri.analizar(self.dir)
        f = filas(res, ruta="/api/citas/:id")
        self.assertEqual(len(f), 1, res["inventario"])
        f = f[0]
        self.assertEqual((f["framework"], f["metodo"], f["archivo"], f["linea"]), ("express", "GET", "server/rutas.js", 3))
        self.assertTrue(f["tiene_param_id"])
        self.assertFalse(f["auth"])
        self.assertFalse(f["filtra_por_usuario"])
        self.assertIn("id_sin_pertenencia", f["motivos"])
        self.assertTrue(f["sospechosa"])
        self.assertTrue(f["consultas"], "la consulta del handler queda asociada a la ruta")

    def test_ruta_con_auth_y_filtro_por_dueno_no_es_sospechosa(self):
        escribir(self.dir, "server/rutas.js", (
            "router.get('/api/citas/:id', requireAuth, async (req, res) => {\n"
            "  const cita = await Cita.findOne({ where: { id: req.params.id, userId: req.user.id } });\n"
            "  res.json(cita);\n"
            "});\n"))
        f = filas(ri.analizar(self.dir), ruta="/api/citas/:id")[0]
        self.assertTrue(f["auth"])
        self.assertTrue(f["filtra_por_usuario"])
        self.assertFalse(f["sospechosa"])
        self.assertEqual(f["motivos"], [])

    def test_mutacion_sin_auth(self):
        escribir(self.dir, "api/index.ts", (
            "app.post('/api/pagos', async (req, res) => {\n"
            "  await crearPago(req.body);\n"
            "  res.sendStatus(201);\n"
            "});\n"))
        f = filas(ri.analizar(self.dir), ruta="/api/pagos")[0]
        self.assertEqual(f["metodo"], "POST")
        self.assertIn("mutacion_sin_auth", f["motivos"])

    def test_admin_sin_rol(self):
        escribir(self.dir, "server/rutas/admin.js", (
            "router.get('/pacientes', async (req, res) => {\n"
            "  res.json(await pool.query('SELECT * FROM pacientes'));\n"
            "});\n"))
        escribir(self.dir, "server/rutas/panel.js", (
            "router.get('/admin/stats', requireAuth, requireRole('admin'), async (req, res) => {\n"
            "  res.json(await pool.query('SELECT count(*) FROM citas'));\n"
            "});\n"))
        res = ri.analizar(self.dir)
        self.assertIn("admin_sin_rol", filas(res, ruta="/pacientes")[0]["motivos"])
        self.assertNotIn("admin_sin_rol", filas(res, ruta="/admin/stats")[0]["motivos"])

    def test_auth_global_por_use(self):
        escribir(self.dir, "api/index.js", (
            "router.use(authenticate);\n"
            "router.delete('/items/:id', async (req, res) => {\n"
            "  await Item.destroy({ where: { id: req.params.id, owner_id: req.user.id } });\n"
            "});\n"))
        f = filas(ri.analizar(self.dir), ruta="/items/:id")[0]
        self.assertTrue(f["auth"])
        self.assertNotIn("mutacion_sin_auth", f["motivos"])


class TestNext(unittest.TestCase):
    def setUp(self):
        self.dir = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.dir)

    def test_app_router(self):
        escribir(self.dir, "app/api/citas/[id]/route.ts", (
            "import { db } from '@/lib/db';\n"
            "export async function GET(req: Request, { params }) {\n"
            "  return Response.json(await db.cita.findUnique({ where: { id: params.id } }));\n"
            "}\n"
            "export async function DELETE(req, { params }) {\n"
            "  const session = await getServerSession();\n"
            "  await db.cita.delete({ where: { id: params.id, userId: session.user.id } });\n"
            "}\n"))
        res = ri.analizar(self.dir)
        get = filas(res, ruta="/api/citas/[id]", metodo="GET")[0]
        self.assertEqual((get["framework"], get["linea"]), ("next-app", 2))
        self.assertIn("id_sin_pertenencia", get["motivos"])
        dele = filas(res, ruta="/api/citas/[id]", metodo="DELETE")[0]
        self.assertTrue(dele["auth"])
        self.assertTrue(dele["filtra_por_usuario"])
        self.assertFalse(dele["sospechosa"])

    def test_src_app_y_pages_api(self):
        escribir(self.dir, "src/app/api/salud/route.js", "export const GET = async () => Response.json({ok: true});\n")
        escribir(self.dir, "pages/api/usuarios/[uid].ts", (
            "export default async function handler(req, res) {\n"
            "  if (req.method === 'PUT') {\n"
            "    await prisma.user.update({ where: { id: req.query.uid }, data: req.body });\n"
            "  }\n"
            "}\n"))
        res = ri.analizar(self.dir)
        self.assertTrue(filas(res, ruta="/api/salud", metodo="GET"))
        put = filas(res, ruta="/api/usuarios/[uid]", framework="next-pages")
        self.assertTrue(put, res["inventario"])
        self.assertEqual(put[0]["metodo"], "PUT")
        self.assertIn("mutacion_sin_auth", put[0]["motivos"])
        self.assertIn("id_sin_pertenencia", put[0]["motivos"])


class TestPython(unittest.TestCase):
    def setUp(self):
        self.dir = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.dir)

    def test_fastapi(self):
        escribir(self.dir, "app/main.py", (
            "from fastapi import FastAPI, Depends\n"
            "app = FastAPI()\n"
            "@app.get('/citas/{cita_id}')\n"
            "def ver(cita_id: int):\n"
            "    return db.query(Cita).get(cita_id)\n"
            "\n"
            "@app.delete('/citas/{cita_id}')\n"
            "def borrar(cita_id: int, user = Depends(get_current_user)):\n"
            "    db.query(Cita).filter(Cita.id == cita_id, Cita.user_id == user.id).delete()\n"))
        res = ri.analizar(self.dir)
        ver = filas(res, ruta="/citas/{cita_id}", metodo="GET")[0]
        self.assertEqual((ver["framework"], ver["linea"]), ("fastapi", 3))
        self.assertIn("id_sin_pertenencia", ver["motivos"])
        borrar = filas(res, ruta="/citas/{cita_id}", metodo="DELETE")[0]
        self.assertTrue(borrar["auth"])
        self.assertTrue(borrar["filtra_por_usuario"])

    def test_flask(self):
        escribir(self.dir, "web/app.py", (
            "from flask import Flask\n"
            "app = Flask(__name__)\n"
            "@app.route('/notas/<int:nota_id>', methods=['GET', 'POST'])\n"
            "def nota(nota_id):\n"
            "    return Nota.query.get(nota_id)\n"
            "\n"
            "@app.route('/perfil')\n"
            "@login_required\n"
            "def perfil():\n"
            "    return current_user.nombre\n"))
        res = ri.analizar(self.dir)
        n = filas(res, ruta="/notas/<int:nota_id>")
        self.assertEqual(sorted(f["metodo"] for f in n), ["GET", "POST"])
        self.assertTrue(all("id_sin_pertenencia" in f["motivos"] for f in n))
        self.assertTrue(any("mutacion_sin_auth" in f["motivos"] for f in n))
        p = filas(res, ruta="/perfil")[0]
        self.assertTrue(p["auth"])


class TestSupabase(unittest.TestCase):
    def setUp(self):
        self.dir = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.dir)

    def test_consultas_con_y_sin_filtro(self):
        escribir(self.dir, "src/datos.js", (
            "export async function cargar(id) {\n"
            "  const { data } = await supabase.from('citas').select('*').eq('id', id);\n"
            "  return data;\n"
            "}\n"
            "export async function mias(uid) {\n"
            "  return supabase.from('citas').select('*').eq('user_id', uid);\n"
            "}\n"
            "export async function borrar(id) {\n"
            "  return supabase\n"
            "    .from('notas')\n"
            "    .delete()\n"
            "    .eq('id', id);\n"
            "}\n"))
        res = ri.analizar(self.dir)
        c = filas(res, framework="supabase")
        por_linea = {f["linea"]: f for f in c}
        self.assertEqual(sorted(por_linea), [2, 6, 10], c)
        self.assertEqual((por_linea[2]["tabla"], por_linea[2]["operacion"]), ("citas", "select"))
        self.assertFalse(por_linea[2]["filtra_por_usuario"])
        self.assertIn("id_sin_pertenencia", por_linea[2]["motivos"])
        self.assertTrue(por_linea[6]["filtra_por_usuario"])
        self.assertFalse(por_linea[6]["sospechosa"])
        self.assertEqual(por_linea[10]["operacion"], "delete")
        self.assertIn("mutacion_sin_filtro_dueno", por_linea[10]["motivos"])

    def test_service_role(self):
        escribir(self.dir, "src/admin.ts", (
            "const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);\n"
            "export const todo = () => admin.from('perfiles').select('*');\n"))
        res = ri.analizar(self.dir)
        f = filas(res, framework="supabase")[0]
        self.assertTrue(f["service_role"])
        self.assertIn("service_role", f["motivos"])


class TestAlcanceYConfidencial(unittest.TestCase):
    def setUp(self):
        self.dir = ap.tmp_dir(self)

    def tearDown(self):
        ap.limpiar(self.dir)

    def test_nunca_da_pass_ni_hallazgos(self):
        escribir(self.dir, "server.js", "app.get('/api/x/:id', (req, res) => res.json(x));\n")
        res = ri.analizar(self.dir)
        self.assertEqual(res["checks_pass"], [])
        self.assertEqual(res["hallazgos"], [])
        self.assertEqual(res["estado"], "ok")
        self.assertEqual(res["alcance"]["rutas"], 1)

    def test_sin_rutas_no_evaluado(self):
        escribir(self.dir, "src/util.js", "export const suma = (a, b) => a + b;\n")
        res = ri.analizar(self.dir)
        self.assertEqual(res["estado"], "no_evaluado")
        self.assertTrue(res["motivo"])

    def test_confidencial_no_se_lee_y_se_cuenta(self):
        # DECISIONES #12 (ronda 6): src/patients/ es una carpeta AMBIGUA y su código se analiza; el caso confidencial
        # pasa a una carpeta inequívoca (src/datos-reales/).
        escribir(self.dir, "src/datos-reales/rutas.js", "app.get('/api/fichas/:id', (req, res) => res.json(SECRETO_CLINICO));\n")
        escribir(self.dir, "src/ok.js", "app.get('/api/x', auth, (req, res) => res.json(1));\n")
        res = ri.analizar(self.dir)
        texto = json.dumps(res)
        self.assertNotIn("SECRETO_CLINICO", texto)
        self.assertNotIn("/api/fichas", texto)
        self.assertEqual(res["alcance"]["codigo_confidencial"], 1)

    def test_excluye_node_modules_tests_y_lockfiles(self):
        escribir(self.dir, "node_modules/lib/index.js", "app.get('/nm/:id', (req, res) => 1);\n")
        escribir(self.dir, "dist/bundle.js", "app.get('/dist/:id', (req, res) => 1);\n")
        escribir(self.dir, "package-lock.json", "{\"x\": \"app.get('/lock/:id')\"}\n")
        escribir(self.dir, "src/a.js", "app.get('/a', auth, (req, res) => 1);\n")
        rutas = {f.get("ruta") for f in ri.analizar(self.dir)["inventario"]}
        self.assertEqual(rutas, {"/a"})

    def test_main_escribe_crudo_con_alcance_en_meta(self):
        escribir(self.dir, "server.js", "app.get('/api/x/:id', (req, res) => res.json(x));\n")
        crudo = Path(self.dir) / "crudo_salida"
        self.assertEqual(ri.main([str(self.dir / "server.js").rsplit("/", 1)[0], str(crudo)]), 0)
        datos = json.loads((crudo / "check_rutas_inventario.json").read_text(encoding="utf-8"))
        meta = json.loads((crudo / "check_rutas_inventario.meta.json").read_text(encoding="utf-8"))
        self.assertEqual(datos["check"], "rutas_inventario")
        self.assertEqual(meta["alcance"]["rutas"], 1)
        self.assertEqual(meta["herramienta"], "check:rutas_inventario")

    def test_registrado_en_tareas(self):
        texto = (RAIZ / "scripts" / "ejecutar_scanners.sh").read_text(encoding="utf-8")
        self.assertIn("rutas_inventario|check|checks/rutas_inventario.py|check_rutas_inventario|check:rutas_inventario",
                      texto)


if __name__ == "__main__":
    unittest.main()

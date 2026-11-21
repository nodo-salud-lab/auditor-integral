// Pruebas de la regla sql-concatenado (semgrep --test).
router.get('/buscar', async (req, res) => {
  // ruleid: sql-concatenado
  const r = await pool.query("SELECT id FROM usuarios WHERE email = '" + req.query.email + "'")
  res.json(r.rows)
})

router.get('/anual/:anio', async (req, res) => {
  // ruleid: sql-concatenado
  const r = await pool.query(`SELECT * FROM sesiones WHERE extract(year from fecha) = ${req.params.anio}`)
  res.json(r.rows)
})

async function porNombre(db, nombre) {
  const sql = 'DELETE FROM notas WHERE autor = ' + nombre
  // ruleid: sql-concatenado
  return db.execute(sql)
}

async function crudo(prisma, id) {
  // ruleid: sql-concatenado
  return prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE id = ${id}`)
}

async function seguro(pool, prisma, id) {
  // ok: sql-concatenado
  await pool.query('SELECT * FROM usuarios WHERE id = $1', [id])
  // ok: sql-concatenado
  await pool.query(`SELECT * FROM usuarios ORDER BY creado DESC`)
  // ok: sql-concatenado
  await pool.query('SELECT * FROM usuarios ' + 'WHERE activo = true')
  // ok: sql-concatenado
  return prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${id}`
}

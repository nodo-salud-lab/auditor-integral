// Pruebas de la regla monto-desde-body (semgrep --test).
router.post('/crear', async (req, res) => {
  const intento = await stripe.paymentIntents.create({
    // ruleid: monto-desde-body
    amount: req.body.monto,
    currency: 'clp',
  })
  res.json({ clientSecret: intento.client_secret })
})

router.post('/crear-numero', async (req, res) => {
  const { monto } = req.body
  const intento = await stripe.paymentIntents.create({
    // ruleid: monto-desde-body
    amount: Number(monto),
    currency: 'clp',
  })
  res.json(intento)
})

router.post('/checkout', async (req, res) => {
  const sesion = await stripe.checkout.sessions.create({
    line_items: [{
      // ruleid: monto-desde-body
      price_data: { currency: 'usd', unit_amount: req.body.precio, product_data: { name: 'x' } },
      quantity: 1,
    }],
  })
  res.json(sesion)
})

router.post('/crear-v2', async (req, res) => {
  const { rows } = await pool.query('SELECT precio FROM sesiones WHERE id = $1', [req.body.sesionId])
  const intento = await stripe.paymentIntents.create({
    // ok: monto-desde-body
    amount: rows[0].precio,
    currency: 'clp',
    metadata: { sesionId: req.body.sesionId },
  })
  res.json(intento)
})

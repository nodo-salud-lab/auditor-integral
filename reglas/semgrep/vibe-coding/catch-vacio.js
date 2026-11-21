// Pruebas de la regla catch-vacio (semgrep --test).
router.post('/crear', async (req, res) => {
  try {
    const intento = await stripe.paymentIntents.create({ amount: 1000, currency: 'clp' })
    res.json({ clientSecret: intento.client_secret })
  // ruleid: catch-vacio
  } catch (e) {}
})

function cargar() {
  // ruleid: catch-vacio
  fetch('/api/datos').catch(() => {})
}

function conManejo(texto) {
  try {
    return JSON.parse(texto)
  // ok: catch-vacio
  } catch (error) {
    console.warn('JSON inválido', error.message)
    return null
  }
}

function promesaConManejo() {
  // ok: catch-vacio
  return fetch('/api').catch((e) => console.error(e))
}

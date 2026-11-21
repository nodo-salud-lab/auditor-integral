// Pruebas de la regla eval-dinamico (semgrep --test).
const vm = require('node:vm')

function indicador(req, res) {
  // ruleid: eval-dinamico
  const valor = eval(req.body.formula)
  // ruleid: eval-dinamico
  const f = new Function('a', req.query.cuerpo)
  // ruleid: eval-dinamico
  setTimeout('actualizar(' + req.query.id + ')', 100)
  // ruleid: eval-dinamico
  vm.runInNewContext(req.body.codigo, {})
  res.json({ valor, f })
}

function seguro(texto) {
  // ok: eval-dinamico
  eval('1 + 1')
  // ok: eval-dinamico
  setTimeout(() => actualizar(), 100)
  // ok: eval-dinamico
  setTimeout(actualizar, 100)
  // ok: eval-dinamico
  return JSON.parse(texto)
}

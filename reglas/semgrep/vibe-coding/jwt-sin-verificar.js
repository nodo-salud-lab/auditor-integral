// Pruebas de la regla jwt-sin-verificar (semgrep --test).
const jwt = require('jsonwebtoken')
import * as jwt2 from 'jsonwebtoken'

function usuarioDesdeToken(req) {
  const token = req.headers.authorization.split(' ')[1]
  // ruleid: jwt-sin-verificar
  const datos = jwt.decode(token)
  // ruleid: jwt-sin-verificar
  const otro = jwt.verify(token, process.env.SECRETO, { algorithms: ['HS256', 'none'] })
  // ruleid: jwt-sin-verificar
  const viejo = jwt.verify(token, process.env.SECRETO, { ignoreExpiration: true })
  // ruleid: jwt-sin-verificar
  const sinFirma = jwt2.decode(token)
  return { datos, otro, viejo, sinFirma }
}

function seguro(token) {
  // ok: jwt-sin-verificar
  return jwt.verify(token, process.env.SECRETO, { algorithms: ['HS256'] })
}

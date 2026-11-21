// Pruebas de la regla auth-solo-cliente (semgrep --test).
import { Navigate } from 'react-router-dom'

export function RutaPrivada({ children }) {
  // ruleid: auth-solo-cliente
  const esAdmin = localStorage.getItem('esAdmin') === 'true'
  if (!esAdmin) return <Navigate to="/login" replace />
  return children
}

export function guardarRol(usuario) {
  if (usuario.email.endsWith('@empresa.cl')) {
    // ruleid: auth-solo-cliente
    localStorage.setItem('isAdmin', 'true')
  }
  // ruleid: auth-solo-cliente
  sessionStorage.setItem('role', usuario.role)
  // ruleid: auth-solo-cliente
  return window.localStorage.premium === 'si'
}

export function preferencias() {
  // ok: auth-solo-cliente
  localStorage.setItem('tema', 'oscuro')
  // ok: auth-solo-cliente
  return localStorage.getItem('idioma')
}

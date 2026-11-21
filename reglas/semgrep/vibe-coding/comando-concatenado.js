// Pruebas de la regla comando-concatenado (semgrep --test).
const cp = require('child_process')
const { execSync } = require('node:child_process')
import { exec } from 'node:child_process'

function convertir(req, res) {
  // ruleid: comando-concatenado
  cp.exec('pdftotext ' + req.body.archivo + ' salida.txt', () => res.end())
  // ruleid: comando-concatenado
  execSync(`convert ${req.query.imagen} -resize 50% chica.png`)
  // ruleid: comando-concatenado
  cp.spawn('ls ' + req.query.dir, { shell: true })
  // ruleid: comando-concatenado
  exec('pdftotext /srv/' + req.query.archivo + ' -', () => res.end())
}

function seguro(req, patron, texto) {
  // ok: comando-concatenado
  cp.execFile('pdftotext', [req.body.archivo, 'salida.txt'])
  // ok: comando-concatenado
  cp.exec('ls -la')
  // ok: comando-concatenado
  cp.spawn('ls', [req.query.dir])
  // ok: comando-concatenado
  cp.spawn('ls ' + req.query.dir)
  // ok: comando-concatenado
  return patron.exec('prefijo' + texto)
}

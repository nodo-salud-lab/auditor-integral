// Pruebas de la regla findmany-sin-take (semgrep --test).
export async function listar(prisma: any, usuarioId: string) {
  // ruleid: findmany-sin-take
  const todas = await prisma.cita.findMany()
  // ruleid: findmany-sin-take
  const filtradas = await prisma.cita.findMany({ where: { usuarioId } })
  // ok: findmany-sin-take
  const pagina = await prisma.cita.findMany({ where: { usuarioId }, take: 50, skip: 0 })
  // ok: findmany-sin-take
  const una = await prisma.cita.findFirst({ where: { usuarioId } })
  return { todas, filtradas, pagina, una }
}

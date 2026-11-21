// Pruebas de la regla service-role-cliente (semgrep --test).
import { createClient } from '@supabase/supabase-js'

export const supabaseAdmin = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  // ruleid: service-role-cliente
  import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY,
)

// ruleid: service-role-cliente
const otra = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY

// ok: service-role-cliente
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY)

// ok: service-role-cliente
const servidor = process.env.SUPABASE_SERVICE_ROLE_KEY

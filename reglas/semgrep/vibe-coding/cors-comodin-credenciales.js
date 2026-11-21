// Pruebas de la regla cors-comodin-credenciales (semgrep --test).
const app = express()

// ruleid: cors-comodin-credenciales
app.use(cors({ origin: '*', credentials: true }))

// ruleid: cors-comodin-credenciales
app.use(cors({ credentials: true, origin: true }))

// ruleid: cors-comodin-credenciales
app.use(cors({ origin: (origen, cb) => cb(null, true), credentials: true }))

// ok: cors-comodin-credenciales
app.use(cors({ origin: 'https://agenda.example.cl', credentials: true }))

// ok: cors-comodin-credenciales
app.use(cors({ origin: '*' }))

// ok: cors-comodin-credenciales
app.use(cors({ origin: ['https://a.example.cl'], credentials: false }))

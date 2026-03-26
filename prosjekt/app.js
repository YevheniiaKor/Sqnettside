// Importerer innebygd modul 'path' for trygg bygging av filstier
const path = require('path'); // Hjelper med OS-uavhengige filstier

// Importerer Express for å lage HTTP-server og ruter
const express = require('express'); // Web-rammeverk for Node

// Importerer sqlite3 for å jobbe mot en SQLite-databasefil
const sqlite3 = require('sqlite3').verbose(); // Aktiverer mer logging for sqlite3

// Importerer bcrypt for sikker hashing av passord
const bcrypt = require('bcrypt'); // Kan byttes til 'bcryptjs' hvis install feiler

// Importerer express-session for enkel sesjonshåndtering (IKKE bruk MemoryStore i prod)
const session = require('express-session'); // Håndterer sesjonsdata på server

// Oppretter en ny Express-applikasjon
const app = express(); // Lager en app-instans

// Definerer porten appen skal kjøre på, 3000 som standard
const PORT = process.env.PORT || 3000; // Leser fra miljøvariabel eller bruker 3000

// Setter antall salt-runder for bcrypt (sikkerhet vs. ytelse)
const SALT_ROUNDS = 12; // 12 er et fornuftig utgangspunkt

// Angir full sti til databasefilen 'app.db' i prosjektroten
const dbFile = path.join(__dirname, 'app.db'); // Bygger absolutt sti til DB-filen

// Åpner (eller oppretter) SQLite-databasen
const db = new sqlite3.Database(dbFile, (openErr) => { // Åpner databasen og får en callback ved feil
  if (openErr) { // Sjekker om noe gikk galt
    console.error('Klarte ikke å åpne databasen:', openErr); // Logger feilen
    process.exit(1); // Avslutter prosessen for å unngå halvferdig oppstart
  } else {
    console.log('Databasen er åpnet:', dbFile); // Bekrefter at databasen er åpnet
  }
}); // Slutt på Database-konstruktør

// Kjører initialisering for å sikre at tabeller finnes
db.serialize(() => { // Kjører SQL-kommandoer sekvensielt i riktig rekkefølge
  const fs = require('fs'); // Importerer 'fs' for filoperasjoner
  const schemaPath = path.join(__dirname, 'db', 'schema.sql'); // Full sti til schema.sql

  // Slår på foreign key-støtte (nyttig om du senere får relasjoner)
  db.exec('PRAGMA foreign_keys = ON;', (fkErr) => { // Kaller PRAGMA for FK
    if (fkErr) { // Hvis PRAGMA feiler
      console.warn('Kunne ikke aktivere foreign_keys:', fkErr); // Logger en advarsel
    }

    // Sjekker om schema.sql finnes
    if (fs.existsSync(schemaPath)) { // Hvis filen finnes
      try { // Prøver å lese og kjøre schema
        const schemaSQL = fs.readFileSync(schemaPath, 'utf8'); // Leser hele schema.sql som tekst
        db.exec(schemaSQL, (execErr) => { // Kjører alle SQL-setningene i schema
          if (execErr) { // Hvis kjøring av schema feiler
            console.error('Feil ved kjøring av schema.sql:', execErr); // Logger feilen
            process.exit(1); // Avslutter prosessen
          } else {
            console.log('Database-skjema lastet fra db/schema.sql'); // Bekrefter OK
          }
        }); // Slutt db.exec(schemaSQL)
      } catch (readErr) { // Fanger feil ved lesing av fil
        console.error('Klarte ikke å lese db/schema.sql:', readErr); // Logger feilen
        process.exit(1); // Avslutter prosessen
      }
    } else { // Hvis schema.sql ikke finnes
      console.warn('Fant ikke db/schema.sql – oppretter tabell "users" automatisk'); // Informerer om fallback

      // SQL for å opprette tabellen 'users' med created_at inkludert
      const bootstrapSQL = `
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL,
          created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
      `; // Slutt på bootstrapSQL

      db.exec(bootstrapSQL, (bootstrapErr) => { // Kjører fallback-skjema
        if (bootstrapErr) { // Hvis noe går galt
          console.error('Feil ved opprettelse av standardtabeller:', bootstrapErr); // Logger feilen
          process.exit(1); // Avslutter prosessen
        } else {
          console.log('Opprettet tabellen "users" automatisk'); // Bekrefter OK
        }
      }); // Slutt db.exec(bootstrapSQL)
    } // Slutt if existsSync
  }); // Slutt db.exec(PRAGMA)
}); // Slutt db.serialize

// Konfigurerer EJS som templatemotor
app.set('view engine', 'ejs'); // Forteller Express å bruke EJS

// Angir at EJS-filer ligger i mappen "views" i prosjektet
app.set('views', path.join(__dirname, 'views')); // Setter absolutt sti til views

// Legger til middleware for å parse URL-enkodet skjema (fra <form method="post">)
app.use(express.urlencoded({ extended: true })); // Gjør req.body tilgjengelig for skjema

// Serverer statiske filer (CSS, bilder, JS) fra mappen "public"
app.use(express.static(path.join(__dirname, 'public'))); // Gjør /public tilgjengelig på rot

// Setter opp sesjoner (NB: ikke bruk standard MemoryStore i produksjon)
app.use(
  session({
    secret: 'dev-session-secret', // Nøkkel for å signere cookies (bytt i prod)
    resave: false, // Ikke lagre sesjonen på nytt hvis ingenting endres
    saveUninitialized: false, // Ikke opprett sesjon før noe settes
    cookie: { // Konfigurerer cookie-egenskaper
      httpOnly: true, // Hindrer JS fra å lese cookie (XSS-beskyttelse)
      secure: false, // Sett til true bak HTTPS i produksjon
      maxAge: 1000 * 60 * 60 * 8, // Levetid 8 timer
    },
  })
); // Slutt app.use(session)

// Lager en hjelpe-middleware som krever innlogging
function ensureAuthenticated(req, res, next) { // Definerer funksjonen
  if (req.session && req.session.userId) { // Sjekker at brukerId finnes i sesjonen
    return next(); // Slipper gjennom hvis innlogget
  }
  return res.redirect('/login?error=Du+m%C3%A5+logge+inn+f%C3%B8rst'); // Sender til login hvis ikke
} // Slutt ensureAuthenticated

// Rute for rot: videresender basert på innloggingsstatus
app.get('/', (req, res) => { // Håndterer GET /
  if (req.session && req.session.userId) { // Sjekker innlogging
    return res.redirect('/dashboard'); // Sender til dashboard hvis innlogget
  }
  return res.redirect('/login'); // Sender til login hvis ikke
}); // Slutt rute /

// Rute: Registreringsskjema (GET)
app.get('/register', (req, res) => { // Håndterer GET /register
  const error = req.query.error || null; // Leser ev. feilmelding
  const success = req.query.success || null; // Leser ev. suksessmelding
  return res.render('register', { error, success }); // Renderer register.ejs med meldinger
}); // Slutt rute /register (GET)

// Rute: Innsending av registreringsskjema (POST)
app.post('/register', async (req, res) => { // Håndterer POST /register
  const { email, password } = req.body; // Henter e-post og passord fra skjema

  if (!email || !password) { // Sjekker at feltene er fylt ut
    return res.redirect('/register?error=Vennligst+fyll+inn+alle+feltene'); // Gir feilmelding
  }
  if (password.length < 8) { // Sjekker minimum passordlengde
    return res.redirect('/register?error=Passordet+m%C3%A5+v%C3%A6re+minst+8+tegn'); // Gir feilmelding
  }

  try { // Prøver registreringsflyten
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => { // Sjekker om e-post finnes
      if (err) { // Håndterer databasefeil
        console.error('DB-feil under oppslag av e-post:', err); // Logger
        return res.redirect('/register?error=En+feil+oppstod.+Pr%C3%B8v+igjen'); // Gir generell feilmelding
      }

      if (row) { // Hvis e-post allerede er i bruk
        return res.redirect('/register?error=E-posten+er+allerede+i+bruk'); // Gir feilmelding
      }

      try { // Prøver å hashe passordet
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS); // Lager sikker hash

        db.run( // Setter inn ny bruker i databasen
          'INSERT INTO users (email, password_hash) VALUES (?, ?)', // SQL med parametere
          [email, passwordHash], // Verdier erstatter ?
          function (insertErr) { // Callback etter forsøk på innsetting
            if (insertErr) { // Hvis innsetting feiler
              console.error('DB-feil ved opprettelse av bruker:', insertErr); // Logger
              return res.redirect('/register?error=Kunne+ikke+opprette+bruker'); // Feilmelding
            }
            return res.redirect('/login?success=Bruker+opprettet.+Logg+inn'); // OK-beskjed
          }
        ); // Slutt db.run
      } catch (hashErr) { // Fanger feil ved hashing
        console.error('Hash-feil:', hashErr); // Logger
        return res.redirect('/register?error=En+feil+oppstod+ved+hashing'); // Feilmelding
      }
    }); // Slutt db.get
  } catch (outerErr) { // Ekstra sikkerhet: uventede feil
    console.error('Uventet feil i register:', outerErr); // Logger
    return res.redirect('/register?error=Uventet+feil'); // Generisk feilmelding
  }
}); // Slutt rute /register (POST)

// Rute: Login-skjema (GET)
app.get('/login', (req, res) => { // Håndterer GET /login
  const error = req.query.error || null; // Leser feilmelding om satt
  const success = req.query.success || null; // Leser suksessmelding om satt
  return res.render('login', { error, success }); // Renderer login.ejs
}); // Slutt rute /login (GET)

// Rute: Innsending av login-skjema (POST)
app.post('/login', (req, res) => { // Håndterer POST /login
  const { email, password } = req.body; // Leser e-post og passord

  if (!email || !password) { // Sjekker at begge feltene er fylt
    return res.redirect('/login?error=Vennligst+fyll+inn+e-post+og+passord'); // Feilmelding
  }

  db.get( // Henter brukeren fra databasen
    'SELECT id, email, password_hash FROM users WHERE email = ?', // SQL-spørring
    [email], // Setter e-post som parameter
    async (err, user) => { // Callback med resultat
      if (err) { // Håndterer DB-feil
        console.error('DB-feil ved innlogging:', err); // Logger
        return res.redirect('/login?error=En+feil+oppstod.+Pr%C3%B8v+igjen'); // Feilmelding
      }

      if (!user) { // Hvis bruker ikke finnes
        return res.redirect('/login?error=Feil+e-post+eller+passord'); // Generisk feilmelding
      }

      try { // Prøver å sammenligne passord
        const match = await bcrypt.compare(password, user.password_hash); // Sjekker hash
        if (match) { // Hvis passord er korrekt
          req.session.userId = user.id; // Lagrer bruker-ID i sesjonen
          return res.redirect('/dashboard'); // Sender til dashboard
        } // Slutt if match

        return res.redirect('/login?error=Feil+e-post+eller+passord'); // Feil passord
      } catch (compareErr) { // Fanger feil ved sammenligning
        console.error('Feil ved passordsjekk:', compareErr); // Logger
        return res.redirect('/login?error=En+feil+oppstod+ved+innlogging'); // Feilmelding
      }
    }
  ); // Slutt db.get
}); // Slutt rute /login (POST)

// Rute: Dashboard (kun for innloggede brukere)
app.get('/dashboard', ensureAuthenticated, (req, res) => { // Beskytter ruta
  db.get( // Henter data for innlogget bruker
    'SELECT id, email, created_at FROM users WHERE id = ?', // Velger kolonnene som trengs
    [req.session.userId], // Setter inn brukerens id fra sesjon
    (err, user) => { // Callback med resultatet
      if (err) { // Håndterer DB-feil
        console.error('DB-feil ved henting av bruker:', err); // Logger feilen
        return res.redirect('/login?error=En+feil+oppstod.+Logg+inn+igjen'); // Sender til login
      }
      if (!user) { // Hvis ingen bruker funnet
        req.session.destroy(() => { // Ødelegger sesjonen
          return res.redirect('/login?error=Sesjonen+er+utl%C3%B8pt.+Logg+inn+igjen'); // Ber om ny innlogging
        }); // Slutt destroy
        return; // Stopper videre kjøring
      }
      return res.render('dashboard', { user }); // Renderer dashboard.ejs med brukerdata
    }
  ); // Slutt db.get
}); // Slutt rute /dashboard

// Rute: Logout (POST for å unngå utilsiktede kall via GET)
app.post('/logout', ensureAuthenticated, (req, res) => { // Håndterer POST /logout
  req.session.destroy((err) => { // Ødelegger sesjonen
    if (err) { // Hvis noe går galt
      console.error('Feil ved logout:', err); // Logger feilen
    }
    res.clearCookie('connect.sid'); // Sletter sesjons-cookien i nettleseren
    return res.redirect('/login?success=Du+er+logget+ut'); // Viser beskjed ved login
  }); // Slutt destroy callback
}); // Slutt rute /logout

// Starter HTTP-serveren på valgt port
app.listen(PORT, () => { // Kaller listen for å starte server
  console.log(`Server kjører på http://localhost:${PORT}`); // Logger at serveren er i gang
}); // Slutt app.listen
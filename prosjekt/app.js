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

// RUTE: Konto-side (GET) - viser skjema for å oppdatere e-post/passord og slette konto
app.get('/account', ensureAuthenticated, (req, res) => { // Definerer GET /account, kun for innloggede brukere via ensureAuthenticated
  const error = req.query.error || null; // Leser evt. feilmelding fra querystring (f.eks. ?error=...)
  const success = req.query.success || null; // Leser evt. suksessmelding fra querystring (f.eks. ?success=...)

  db.get( // Utfører en SELECT i databasen for å hente informasjon om innlogget bruker
    'SELECT id, email, created_at FROM users WHERE id = ?', // SQL som henter id, e-post og opprettelsestidspunkt
    [req.session.userId], // Setter inn brukerens ID fra sesjonen som parameter til SQL-spørringen
    (err, user) => { // Callback som kjøres når databasen svarer
      if (err) { // Sjekker om det oppstod en databasefeil
        console.error('DB-feil ved henting av bruker (account):', err); // Logger databasefeilen i konsollen for debugging
        return res.redirect('/login?error=En+feil+oppstod.+Logg+inn+igjen'); // Sender bruker til login med feilmelding
      }
      if (!user) { // Sjekker om bruker ikke ble funnet (kan skje hvis bruker slettes mens sesjonen lever)
        req.session.destroy(() => { // Ødelegger sesjonen trygt siden bruker ikke finnes
          return res.redirect('/login?error=Sesjonen+er+utl%C3%B8pt.+Logg+inn+igjen'); // Ber bruker logge inn på nytt
        }); // Slutt på req.session.destroy callback
        return; // Stopper videre kjøring i denne ruten
      }
      return res.render('account', { user, error, success }); // Renderer account.ejs og sender med brukerdata og eventuelle meldinger
    } // Slutt på callback for db.get
  ); // Slutt på db.get
}); // Slutt på rute /account (GET)


// RUTE: Oppdatering av konto (POST) - endring av e-post og/eller passord
app.post('/account/update', ensureAuthenticated, async (req, res) => { // Definerer POST /account/update for innloggede brukere
  const { email, current_password, new_password, new_password_confirm } = req.body; // Destrukturerer felter fra skjemaet (POST-body)
  const trimmedEmail = (email || '').trim().toLowerCase(); // Trimmer og normaliserer e-post til små bokstaver (kan være tom)
  const userId = req.session.userId; // Leser innlogget brukers ID fra sesjonen

  if (!current_password) { // Krever at nåværende passord er oppgitt for alle endringer (sikkerhet)
    return res.redirect('/account?error=Du+m%C3%A5+skrive+inn+n%C3%A5v%C3%A6rende+passord'); // Sender feilmelding hvis passord mangler
  }

  db.get( // Henter brukerens nåværende data for å verifisere passord og sammenligne e-post
    'SELECT id, email, password_hash FROM users WHERE id = ?', // SQL som henter id, e-post og hashet passord
    [userId], // Setter inn brukerens ID i SQL-spørringen
    async (err, user) => { // Callback (merket async for å kunne bruke await på bcrypt)
      if (err) { // Sjekker om vi fikk en databasefeil
        console.error('DB-feil ved oppdatering av konto:', err); // Logger feilen i konsollen
        return res.redirect('/account?error=En+feil+oppstod.+Pr%C3%B8v+igjen'); // Viser generell feilmelding til bruker
      }
      if (!user) { // Sjekker om bruker ikke finnes (f.eks. slettet)
        return res.redirect('/login?error=Logg+inn+p%C3%A5+nytt'); // Ber bruker logge inn på nytt
      }

      try { // Starter try-blokk for passordsjekk og videre oppdateringslogikk
        const passOK = await bcrypt.compare(current_password, user.password_hash); // Sammenligner oppgitt nåværende passord med lagret hash
        if (!passOK) { // Hvis passordet ikke stemmer
          return res.redirect('/account?error=Feil+n%C3%A5v%C3%A6rende+passord'); // Avbryt og vis feilmelding
        }

        // Håndter endring av e-post først, hvis ny e-post er oppgitt og den er ulik dagens
        if (trimmedEmail && trimmedEmail !== user.email) { // Sjekker om bruker vil endre e-post
          if (!trimmedEmail.includes('@')) { // Enkel validering av e-postformat (kan utvides)
            return res.redirect('/account?error=Ugyldig+e-postadresse'); // Viser feilmelding ved ugyldig e-post
          }

          return db.get( // Sjekker om den nye e-posten allerede er i bruk av en annen bruker
            'SELECT id FROM users WHERE email = ? AND id != ?', // SQL for å finne ev. annen bruker med samme e-post
            [trimmedEmail, userId], // Setter inn ny e-post og ekskluderer nåværende bruker-ID
            async (dupErr, dupRow) => { // Callback for duplikatsjekk
              if (dupErr) { // Sjekker databasefeil ved duplikatsjekk
                console.error('DB-feil ved e-post-duplikat-sjekk:', dupErr); // Logger feilen
                return res.redirect('/account?error=En+feil+oppstod.+Pr%C3%B8v+igjen'); // Returnerer feilmelding
              }
              if (dupRow) { // Hvis en annen bruker har samme e-post
                return res.redirect('/account?error=E-posten+er+allerede+i+bruk'); // Avbryt og si ifra at e-posten er opptatt
              }

              let finalUpdates = []; // Lager liste over kolonner som skal oppdateres i denne operasjonen
              let finalParams = []; // Lager liste over verdier som hører til plassholderne i SQL

              finalUpdates.push('email = ?'); // Legger til at e-post skal oppdateres
              finalParams.push(trimmedEmail); // Legger til ny e-postverdi

              // Sjekker om passord også skal endres i samme skjema-innsending
              if ((new_password || '').length > 0 || (new_password_confirm || '').length > 0) { // Hvis ett av passordfeltene er fylt ut
                if (new_password !== new_password_confirm) { // Sjekker at nytt passord og bekreftelse er like
                  return res.redirect('/account?error=Nytt+passord+og+bekreftelse+stemmer+ikke'); // Viser feilmelding ved mismatch
                }
                if ((new_password || '').length < 8) { // Sjekker minimumslengde for nytt passord
                  return res.redirect('/account?error=Passordet+m%C3%A5+v%C3%A6re+minst+8+tegn'); // Feil hvis for kort passord
                }
                const newHash = await bcrypt.hash(new_password, SALT_ROUNDS); // Hasher det nye passordet med angitt antall salt-runder
                finalUpdates.push('password_hash = ?'); // Legger til at passord_hash skal oppdateres
                finalParams.push(newHash); // Legger til den nye hash-verdien
              }

              if (finalUpdates.length === 0) { // Sjekker om det faktisk er noe å oppdatere
                return res.redirect('/account?error=Ingenting+%C3%A5+oppdatere'); // Avslutter hvis ingen endringer
              }

              finalParams.push(userId); // Legger til bruker-ID for WHERE-betingelsen
              const sql = `UPDATE users SET ${finalUpdates.join(', ')} WHERE id = ?`; // Bygger dynamisk UPDATE-setning med valgte kolonner

              db.run( // Kjører selve UPDATE-spørringen mot databasen
                sql, // Sender inn den dynamisk bygde SQL-strengen
                finalParams, // Sender inn parameterlisten i samme rekkefølge som plassholderne
                function (updateErr) { // Callback som kjøres etter forsøk på oppdatering
                  if (updateErr) { // Sjekker om oppdatering feilet
                    console.error('DB-feil ved oppdatering:', updateErr); // Logger databasefeilen
                    return res.redirect('/account?error=Kunne+ikke+oppdatere+konto'); // Gir feilmelding til bruker
                  }
                  return res.redirect('/account?success=Konto+oppdatert'); // Går tilbake med suksessbeskjed ved OK
                } // Slutt på callback for db.run
              ); // Slutt på db.run
            } // Slutt på callback for duplikatsjekk
          ); // Slutt på db.get for duplikatsjekk
        } // Slutt på blokk for e-post-endring

        // Dersom e-post ikke skal endres, sjekk om passord skal endres alene
        if ((new_password || '').length > 0 || (new_password_confirm || '').length > 0) { // Ser om passordfelt er fylt ut
          if (new_password !== new_password_confirm) { // Validerer at nytt passord og bekreftelse matcher
            return res.redirect('/account?error=Nytt+passord+og+bekreftelse+stemmer+ikke'); // Feilmelding ved mismatch
          }
          if ((new_password || '').length < 8) { // Sjekker minimumslengde
            return res.redirect('/account?error=Passordet+m%C3%A5+v%C3%A6re+minst+8+tegn'); // Feilmelding hvis for kort
          }
          const newHash = await bcrypt.hash(new_password, SALT_ROUNDS); // Hasher nytt passord
          db.run( // Utfører oppdatering av kun passordet
            'UPDATE users SET password_hash = ? WHERE id = ?', // SQL for å oppdatere passord-hashen
            [newHash, userId], // Parametre: ny hash og brukerens ID
            function (updateErr) { // Callback som kjøres etter oppdateringsforsøk
              if (updateErr) { // Sjekker om det oppstod en databasefeil
                console.error('DB-feil ved passordoppdatering:', updateErr); // Logger databasefeilen
                return res.redirect('/account?error=Kunne+ikke+oppdatere+passord'); // Feilmelding til bruker
              }
              return res.redirect('/account?success=Passord+oppdatert'); // Suksessmelding ved vellykket oppdatering
            } // Slutt på callback for db.run
          ); // Slutt på db.run
          return; // Avslutter ruten fordi vi allerede har svart til klienten
        } // Slutt på blokk for passord-endring uten e-post-endring

        // Hvis verken e-post eller passord skal endres, si ifra
        return res.redirect('/account?error=Ingenting+%C3%A5+oppdatere'); // Gir tydelig beskjed om at ingen felter ble endret
      } catch (cmpErr) { // Fanger uventede feil i try-blokken (typisk hashing/sammenligning)
        console.error('Feil under validering/oppdatering:', cmpErr); // Logger feilen i konsollen
        return res.redirect('/account?error=Uventet+feil.+Pr%C3%B8v+igjen'); // Viser generisk feilmelding til bruker
      } // Slutt på try/catch
    } // Slutt på callback for db.get
  ); // Slutt på db.get
}); // Slutt på rute /account/update (POST)


// RUTE: Slett konto (POST) - sletter innlogget bruker etter passordbekreftelse
app.post('/account/delete', ensureAuthenticated, (req, res) => { // Definerer POST /account/delete, kun for innloggede brukere
  const { password } = req.body; // Leser passordet som brukeren har skrevet inn i skjemaet
  const userId = req.session.userId; // Leser innlogget brukers ID fra sesjonen

  if (!password) { // Krever at passord er oppgitt for å kunne slette kontoen
    return res.redirect('/account?error=Du+m%C3%A5+oppgi+passord+for+%C3%A5+slette+kontoen'); // Viser feilmelding hvis passord mangler
  }

  db.get( // Henter brukerens lagrede passord-hash for å verifisere passordet
    'SELECT id, password_hash FROM users WHERE id = ?', // SQL for å hente passord-hash
    [userId], // Setter inn brukerens ID som parameter
    async (err, user) => { // Callback (async for å bruke await på bcrypt)
      if (err) { // Sjekker om databasen returnerte en feil
        console.error('DB-feil ved sletting:', err); // Logger feilen for feilsøking
        return res.redirect('/account?error=En+feil+oppstod.+Pr%C3%B8v+igjen'); // Viser generell feilmelding til bruker
      }
      if (!user) { // Sjekker om bruker ikke finnes
        return res.redirect('/login?error=Logg+inn+p%C3%A5+nytt'); // Sender bruker til login-siden for ny innlogging
      }

      try { // Starter try-blokk for passordsammenligning og sletting
        const passOK = await bcrypt.compare(password, user.password_hash); // Sammenligner oppgitt passord med hash fra databasen
        if (!passOK) { // Hvis passordet ikke er korrekt
          return res.redirect('/account?error=Feil+passord%2C+kan+ikke+slette+konto'); // Viser feilmelding og avbryter
        }

        db.run( // Utfører sletting av brukerkonto fra databasen
          'DELETE FROM users WHERE id = ?', // SQL som sletter raden med gitt ID
          [userId], // Sender inn brukerens ID som parameter
          function (delErr) { // Callback som kjøres etter slettingen
            if (delErr) { // Sjekker om databasen ga feil ved sletting
              console.error('DB-feil ved sletting av bruker:', delErr); // Logger databasefeilen
              return res.redirect('/account?error=Kunne+ikke+slette+konto'); // Viser feilmelding til bruker
            }
            req.session.destroy((sessErr) => { // Ødelegger sesjonen etter vellykket sletting
              if (sessErr) { // Sjekker om det oppstod feil ved ødeleggelse av sesjon
                console.error('Feil ved ødeleggelse av sesjon etter sletting:', sessErr); // Logger feilen i konsollen
              }
              res.clearCookie('connect.sid'); // Sletter sesjons-cookien i nettleseren
              return res.redirect('/login?success=Kontoen+er+slettet'); // Sender bruker til login-siden med suksessmelding
            }); // Slutt på req.session.destroy callback
          } // Slutt på callback for db.run (DELETE)
        ); // Slutt på db.run (DELETE)
      } catch (cmpErr) { // Fanger uventede feil under bcrypt.compare
        console.error('Feil ved passordsjekk under sletting:', cmpErr); // Logger feilen
        return res.redirect('/account?error=Uventet+feil.+Pr%C3%B8v+igjen'); // Viser generisk feilmelding til bruker
      } // Slutt på try/catch
    } // Slutt på callback for db.get
  ); // Slutt på db.get
}); // Slutt på rute /account/delete (POST)

// Starter HTTP-serveren på valgt port
app.listen(PORT, () => { // Kaller listen for å starte server
  console.log(`Server kjører på http://localhost:${PORT}`); // Logger at serveren er i gang
}); // Slutt app.listen
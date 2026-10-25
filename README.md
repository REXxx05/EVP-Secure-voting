# EVP – Electronic Voting Platform

This is our group project for COSC2539 Secure Software Systems (Assignment 3).
It's a prototype of an online voting system for an Australian federal election,
built with security in mind at every layer (frontend, API, database and CI).

It's a student prototype, so all the data in it is fake test data.

## Team

| Name | GitHub | SRs |
|------|--------|-----|
| Yashvardhan Gharge | REXxx05 | SR-02, SR-05, SR-08, SR-09, SR-10 |
| Dhanush | | SR-01, SR-03, SR-04, SR-07, SR-19 |
| shambhu |  | SR-13, SR-14, SR-16, SR-17, SR-18 
| vinuthna | Vinuthna1R | SR-06, SR-11, SR-12, SR-15, SR-20 |

Each SR has its own GitHub Issue with the full details and acceptance criteria.

## Tech stack

- **Frontend:** plain HTML, CSS and JavaScript (served by Express)
- **Backend:** Node.js + Express (REST API), HTTPS only (TLS 1.3)
- **Database:** PostgreSQL 16, running in Docker
- **Testing:** Jest + Supertest

## Folder structure

```
backend/
  src/
    app.js          sets up the Express app
    server.js       starts the HTTPS server
    config/         database connection and TLS settings
    routes/         API endpoints
    middleware/     checks that run before requests (auth, roles etc.)
    security/       crypto code (encryption, hashing, signatures)
    models/         database queries
    services/       main logic (voting, tallying)
  scripts/          maintenance scripts (e.g. key rotation)
  tests/            unit and integration tests
frontend/           HTML pages, css/ and js/
database/
  01_schema.sql     creates the tables
  02_seed.sql       fake test data
  setup/            creates the limited app database user
certs/              your local HTTPS certificate (not on GitHub)
docs/               report drafts and diagrams
```

## How to run it locally

You need **Node.js (LTS)**, **Docker Desktop**, **Git** and **mkcert** installed.

**1. Clone the repo** (or `git pull` if you already have it)

**2. Install the backend packages**
```bash
cd backend
npm install
cd ..
```

**3. Make your own `.env` file**
```bash
cp .env.example .env
```
Then open `.env` and replace every `change-me`:
- `DB_PASSWORD` and `DB_ADMIN_PASSWORD`: just make up two different passwords (they're only for your local database)
- `JWT_SECRET` and `DATA_ENCRYPTION_KEY`: these need to be random. Run this twice and paste one result into each:
```bash
  node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Never commit your `.env` or share it with anyone. It's already in `.gitignore`.

**3b. Make a local HTTPS certificate** (the server only runs over HTTPS)

Install mkcert first (Mac, Windows and Linux: see github.com/FiloSottile/mkcert). Then from the project root:
```bash
mkcert -install
mkdir -p certs
mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1 ::1
```
The `certs/` folder is in `.gitignore`, so your private key never goes on GitHub.

**4. Start the database** (open Docker Desktop first)
```bash
docker compose up -d
```
Wait about 10 seconds, then create the limited app user:
```bash
bash database/setup/create_roles.sh
```

**5. Run the backend**
```bash
cd backend
npm run dev
```
Go to **https://localhost:3000** (with the s). You should see the home page with "API status: ok".

**6. Run the tests**
```bash
npm test
```

## Adding your own database tables

Don't edit `01_schema.sql` for your own SR. Add a new numbered file in `database/` instead,
e.g. `03_audit_log.sql`. If someone already used that number, just use the next one.

The files only run when the database is first created, so reset it after adding one:
```bash
docker compose down -v
docker compose up -d
bash database/setup/create_roles.sh
```
If the backend needs access to your new table, add a GRANT for it in `database/setup/roles.sql`.

## Rate limiting (SR-19)

The API limits how many requests one client can make, so a flood or a password-guessing attack cannot stop real voters. Blocked requests get HTTP 429.

| Limiter | What it counts | Default limit | Setting in `.env` |
| --- | --- | --- | --- |
| API | all `/api` requests per IP address | 300 per minute | `RATE_LIMIT_API_MAX` |
| Login, per IP | login attempts per IP address | 30 per 15 minutes | `RATE_LIMIT_LOGIN_IP_MAX` |
| Login, per account | failed logins per username | 10 per 15 minutes | `RATE_LIMIT_LOGIN_ACCOUNT_MAX` |

The settings are optional. If they are missing, the defaults above are used. The limiters live in `backend/src/middleware/rateLimiters.js` and are tested in `backend/tests/unit/rateLimiters.test.js` and `backend/tests/integration/rateLimit.test.js`.

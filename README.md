# Maxis Data Center Inventory â€” Server Edition

Node.js (v22.13 or newer) + SQLite web application with a real server-side login, shared data for all users, and a port you choose.

## Requirements
Node.js **22.13 or newer** (24 is fine). SQLite is built into Node, so there is nothing to compile â€” no Visual Studio or Python needed on Windows.

## Quick start
```bash
npm install
cp .env.example .env      # then edit PORT=... (any free port)
npm start                 # open http://<server-ip>:<PORT>
```
First visit: create the **administrator** account. Then open your profile (top right) to add people.

## Enable HTTPS
The same port serves **either** HTTP **or** HTTPS. To switch to HTTPS, give the server a certificate in `.env` and restart:
```
SSL_PFX_FILE=cert.pfx            # Windows .pfx file placed next to server.js
SSL_PFX_PASSPHRASE=your-password
# or, for PEM files:  SSL_CERT_FILE=cert.pem   SSL_KEY_FILE=key.pem
```
Then open `https://<server>:<PORT>`. The startup message changes from `http://` to `https://`.

**Which certificate?**
- *Company use:* ask IT for a certificate for your server name (internal CA), or use Let's Encrypt (e.g. win-acme on Windows) if the server has a public domain name.
- *Testing only (browser shows a warning):* in PowerShell as Administrator:
```powershell
$c = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddYears(2)
$password = ConvertTo-SecureString "choose-a-password" -AsPlainText -Force
Export-PfxCertificate -Cert $c -FilePath .\cert.pfx -Password $password
```
Then set the same password in `.env`:
```
SSL_PFX_FILE=cert.pfx
SSL_PFX_PASSPHRASE=choose-a-password
```
The certificate and `.env` file stay on the machine running the application; do not commit either one.

Alternative: keep Node on HTTP and let IIS / Nginx / Caddy provide HTTPS in front of it (see the production checklist).

## Viewing and resetting accounts
Passwords are stored as one-way hashes, so nobody can read them. You can list accounts and reset a password from the project folder:
```
npm run users -- list
npm run users -- reset <username> <new-password>
npm run users -- create <username> <password> admin
```
Usernames are lower-case. Passwords are at least 8 characters.

## If login fails
1. `npm run users -- list` â€” check the username exists (none listed = open the site once and create the administrator).
2. Check the server window: failed logins print `[login] failed for "name" (no such user / wrong password)`.
3. Make sure `COOKIE_SECURE` is `auto` (or `false`) when you use `http://`. `true` forces secure cookies, which browsers reject over plain HTTP.
4. Reset the password with the `reset` command above.

## Choosing the port
Edit `PORT` in `.env` and restart. With Docker the same `PORT` is used for the published port. Open that port in the server firewall, e.g. `sudo ufw allow 8080/tcp`.

## Access levels (enforced on the server)
| Role | Can do |
|---|---|
| **Admin** | Everything: view, add, edit, import, export, delete, manage users and roles (can promote others to admin) |
| **User** | View, add, edit, import, export |
| **Viewer** | View and export only |

Admins grant access from **Profile â†’ Access control**. Everyone can change their own password there.

## Run with Docker
```bash
cp .env.example .env && nano .env
docker compose up -d --build
```
Data persists in `./data` (the SQLite database). Back it up by copying `data/inventory.db`.

## Run as a service (without Docker)
Use a process manager so it restarts on reboot, e.g. PM2:
```bash
npm i -g pm2 && pm2 start server.js --name dc-inventory && pm2 save && pm2 startup
```

## Production checklist
- Serve over **HTTPS** (put Nginx/Caddy/IIS in front, proxy to `http://127.0.0.1:<PORT>`), then set `COOKIE_SECURE=true` and `TRUST_PROXY=1`.
- Keep `data/` out of Git and back it up regularly (`data/inventory.db`, plus `data/.secret` if you did not set `JWT_SECRET`).
- Use strong admin passwords. Passwords are stored as salted scrypt hashes; login attempts are rate-limited.
- Roles are checked on every request; removing a user or changing a role takes effect immediately.

Example Nginx block:
```nginx
server {
  listen 443 ssl;
  server_name inventory.example.com;
  # ssl_certificate / ssl_certificate_key ...
  client_max_body_size 10m;
  location / { proxy_pass http://127.0.0.1:8080; proxy_set_header Host $host; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Proto $scheme; }
}
```

## Using an online (PostgreSQL) database
By default data is stored in a local SQLite file. To use an online database instead, set `DATABASE_URL` in `.env` â€” the app then uses PostgreSQL automatically (tables are created on first start).

1. **Create a PostgreSQL database** with your provider (Azure Database for PostgreSQL, AWS RDS, Google Cloud SQL, Supabase, Neon, or your own server). Create an empty database, e.g. `dcinv`, plus a user with a strong password.
2. **Allow your server to connect**: add the server's public IP to the database firewall / allow-list, and use the provider's SSL setting.
3. **Edit `.env`**:
   ```
   DATABASE_URL=postgres://username:password@your-db-host:5432/dcinv
   DATABASE_SSL=true
   ```
   (If the password has special characters such as `@` or `#`, URL-encode them, e.g. `@` â†’ `%40`.)
4. **Move your existing data** (stop the server first):
   ```
   npm install
   npm run migrate
   ```
   This copies all users (with their password hashes) and inventory from the local SQLite file to PostgreSQL. It is safe to run twice; nothing is duplicated. Your SQLite file is left untouched as a backup.
5. **Start the server** (`npm start`). The startup line shows `Database: PostgreSQL <host>:<port>/<db>`. Log in with your existing accounts.
6. **Backups** are now handled by the database provider (enable automatic backups and point-in-time restore there).

`npm run users -- list` and the other account commands work against whichever database `.env` points to. To go back to the local file, empty `DATABASE_URL` and restart.

Self-hosted alternative: `docker compose -f docker-compose.postgres.yml up -d --build` runs PostgreSQL and the app together.

## Scaling up later
- With PostgreSQL the data is no longer tied to one machine. Logins are stateless signed tokens, so you can run several copies of the app (several servers or containers) behind a load balancer. Set the **same `JWT_SECRET`** on every copy and use the same `DATABASE_URL`.
- Other growth options: SSO/LDAP login, audit history (the `updated_by` / `updated_at` columns already record who changed each item), more fields, reports.

## Importing your Excel/CSV
Use **Import** (Admin/User). The importer recognises headers such as `EQUIPMENT/MATERIALS`, `SERIAL NUMBER`, `ROW`, `RACK`, `U#`, `OWNER`, `USER`, a location column or sheet-tab names, and `PDU A` / `PDU B`. Empty rack slots become **Inactive** "Empty slot" rows; only a repeated serial number is considered a duplicate for serialised devices. Devices without a serial are matched by location, row, rack, U position, and model. See `public/sample-template.csv`.
Data from the old browser-only version is not moved automatically: **Export** from the old version, then **Import** here.

## API (all under `/api`, JSON, cookie session)
`POST /auth/setup Â· /auth/login Â· /auth/logout` Â· `GET /auth/status` Â· `POST /me/password` Â· `GET/POST /items` Â· `PUT/DELETE /items/:id` Â· `POST /items/import Â· /items/delete` Â· `DELETE /items` Â· `GET/POST /users` Â· `PATCH/DELETE /users/:username` (admin only)


## 3D Data Center

Open it from the green **3D Data Center** button in the inventory header (or the banner on the Dashboard).

- Floor plan of every rack in a location and row; click a rack to see it in detail.
- Click any device (in the rack or in its device list) to open its **details** page in the inventory.
- **Add device / Add rack / Assistant** write straight into the inventory, so nothing is coded by hand.
- Admins and users can delete a rack from **Edit rack**. This permanently deletes the rack and all devices assigned to it after confirmation. Viewers cannot see or use this action.
- Needs `public/vendor/three.min.js` (included). The server must be started with `npm start`; do not open the HTML files directly.

### AI assistant

The **Assistant** panel can answer questions about data-center concepts and the
inventory currently visible in the 3D view. Add-device and add-rack requests
remain separate, confirmation-based actions; the AI does not execute commands
or make inventory changes.

Configure the shared OpenAI-compatible Kimi chat endpoint through the local
Caddy gateway in `.env`:

```
KIMI_URL=http://127.0.0.1:8090/v1/chat/completions
KIMI_MODEL=Kimi-K2.7-Code
KIMI_CA_CERT_PATH=
KIMI_API_KEY=
```

`KIMI_API_KEY` is optional when the internal service does not require
authentication. The browser never receives this key. The dashboard, inventory
page and 3D view all use this same endpoint and model. The endpoint must accept
`POST /v1/chat/completions` using the OpenAI-compatible request and response
shape. Restart the Node server after changing these values.

The supplied `kimi-ca.pem` is installed in the project root for direct HTTPS
use if the internal root CA becomes available. The recommended setup is the
local Caddy listener above, which lets Caddy handle the upstream TLS connection.

On Windows PowerShell, executables in the current directory must be prefixed
with `.\`. From the folder containing Caddy, start it with:

```powershell
Set-Location C:\Users\Administrator\Downloads
.\caddy_windows_amd64.exe run --config .\Caddyfile
```

Alternatively, run it from any folder with absolute paths:

```powershell
& 'C:\Users\Administrator\Downloads\caddy_windows_amd64.exe' run --config 'C:\Users\Administrator\Downloads\Caddyfile'
```

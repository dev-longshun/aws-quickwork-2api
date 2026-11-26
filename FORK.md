# Fork notes (dev-longshun)

This fork tracks `jasonxu114514/aws-quickwork-2api` and adds:

## Remote authorization links

Console → **授权链接 / Authorization links** generates `/authorize/<token>` links.
Send one to whoever holds an Amazon Quick account; they open it on their own
computer, sign in, and paste the two `localhost:18080` callback URLs back into
the page. The account is stored like a console sign-in. The recipient never
needs the console password and cannot see any data.

- One link authorizes one account; default lifetime 7 days, 10 sign-in attempts.
- Tickets live in the `auth_tickets` SQLite table; in-progress sign-ins are in
  memory and fall back to "not opened" after a restart or timeout.
- Code: `internal/store/tickets.go`, `internal/admin/tickets.go`,
  `internal/admin/static/authorize.*`, plus the tickets page in the console.

## Image

`.github/workflows/fork-image.yml` builds `ghcr.io/dev-longshun/aws-quickwork-2api:beta`
(linux/amd64) on every push to `main`.

## Syncing upstream

```bash
git fetch upstream
git merge upstream/main   # resolve conflicts, keep fork files
git push origin main
```

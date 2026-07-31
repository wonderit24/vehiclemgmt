# Migrate DELSPARK to Supabase

This project uses SQLite locally (`delspark.db`) and PostgreSQL in production through Supabase.

## 1. Create the Supabase database

1. Go to [Supabase](https://supabase.com) and create an account.
2. Select **New project**, choose a name and a strong database password, then create the project.
3. Wait until its database is active.
4. Click **Connect** in the project dashboard.
5. Copy the **Transaction pooler** URI. It uses port `6543` and begins with `postgresql://` or `postgres://`.

Keep this value private. It is your database password in URL form.

## 2. Copy local data

In PowerShell, open this folder and run:

```powershell
python -m pip install -r requirements.txt
$env:DATABASE_URL='paste-the-Supabase-transaction-pooler-URL-here'
python migrate_sqlite_to_supabase.py
Remove-Item Env:DATABASE_URL
```

The migration copies password hashes, users, vehicles, parking logs and activity logs. It prints a record count on success.

Run it only once. If you intentionally need to discard the target DELSPARK data and import again, add `--replace`:

```powershell
python migrate_sqlite_to_supabase.py --replace
```

## 3. Configure Vercel

In Vercel → your DELSPARK project → **Settings → Environment Variables**, create:

```text
DATABASE_URL = the same Supabase Transaction pooler URI
DELSPARK_SECRET_KEY = a long random secret value
```

Select **Production**, save, then redeploy. Do not use the Supabase project URL or anon key as `DATABASE_URL`.

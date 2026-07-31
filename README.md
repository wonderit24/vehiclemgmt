# DELSPARK Vehicle Management System

DELSPARK manages parking for the Faculty of Science and Faculty of Management Science at Delta State University, Abraka.

## Run the project

```powershell
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

The first start creates `delspark.db`, a local SQLite database containing users, vehicles, gate logs, and activity logs.

## Seeded logins

| Role | Email | Password |
| --- | --- | --- |
| Super Administrator | admin@delsu.edu.ng | Admin@123 |
| Parking Administrator | ukpabi@delsu.edu.ng | Parking@123 |
| Security Officer | eze@delsu.edu.ng | Security@123 |
| Vehicle Owner | chisom@delsu.edu.ng | Owner@123 |

Change these passwords and set a strong `DELSPARK_SECRET_KEY` before deployment.

## Role permissions

- Super Administrator: all administration, users, settings, vehicles, gate operations, and reports.
- Parking Administrator: vehicles, allocations, parking operations, and reports.
- Security Officer: vehicle check-in and check-out only.
- Vehicle Owner: view their own registered vehicles.

All server routes check the authenticated user role; hiding an interface item is never the only permission control.

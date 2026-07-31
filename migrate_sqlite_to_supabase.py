"""Copy DELSPARK local SQLite data into a Supabase PostgreSQL database.

Run from PowerShell after setting DATABASE_URL to Supabase's Transaction pooler URL:
    python migrate_sqlite_to_supabase.py

Use --replace only for a fresh target database when you want to overwrite
existing DELSPARK application data there.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCE = ROOT / "delspark.db"


def fail(message: str):
    print(f"ERROR: {message}")
    raise SystemExit(1)


def table_rows(connection: sqlite3.Connection, table: str):
    try:
        return connection.execute(f"SELECT * FROM {table}").fetchall()
    except sqlite3.OperationalError:
        return []


def main():
    parser = argparse.ArgumentParser(description="Migrate DELSPARK SQLite data to Supabase PostgreSQL.")
    parser.add_argument("--source", default=str(DEFAULT_SOURCE), help="Path to delspark.db")
    parser.add_argument("--replace", action="store_true", help="Delete existing DELSPARK data in the target before import")
    args = parser.parse_args()

    if not os.environ.get("DATABASE_URL", "").startswith(("postgres://", "postgresql://")):
        fail("Set DATABASE_URL to your Supabase PostgreSQL Transaction pooler URL before running this script.")
    source_path = Path(args.source).resolve()
    if not source_path.is_file():
        fail(f"SQLite source file was not found: {source_path}")

    # app.py owns the production schema and database adapter.
    from app import db, initialise_database

    source = sqlite3.connect(source_path)
    source.row_factory = sqlite3.Row
    initialise_database()

    source_users = table_rows(source, "users")
    source_vehicles = table_rows(source, "vehicles")
    source_parking_logs = table_rows(source, "parking_logs")
    source_activity_logs = table_rows(source, "activity_logs")

    with db() as target:
        if args.replace:
            target.execute("DELETE FROM activity_logs")
            target.execute("DELETE FROM parking_logs")
            target.execute("DELETE FROM vehicles")
            target.execute("DELETE FROM users")

        target.execute("CREATE TABLE IF NOT EXISTS migration_history (source_name TEXT PRIMARY KEY, migrated_at TEXT NOT NULL)")
        previous = target.execute("SELECT source_name FROM migration_history WHERE source_name = ?", (source_path.name,)).fetchone()
        if previous and not args.replace:
            fail("This SQLite file was already migrated. Use --replace only if you deliberately want to replace target data.")

        user_ids = {}
        for user in source_users:
            target_user = target.execute(
                """INSERT INTO users (name,email,password_hash,role,faculty_scope,active,created_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT (email) DO UPDATE SET name=EXCLUDED.name,password_hash=EXCLUDED.password_hash,
                   role=EXCLUDED.role,faculty_scope=EXCLUDED.faculty_scope,active=EXCLUDED.active
                   RETURNING id""",
                (user["name"], user["email"], user["password_hash"], user["role"], user["faculty_scope"], user["active"], user["created_at"]),
            ).fetchone()
            user_ids[user["id"]] = target_user["id"]

        vehicle_ids = {}
        for vehicle in source_vehicles:
            target_vehicle = target.execute(
                """INSERT INTO vehicles (plate,model,owner_name,faculty,category,colour,owner_user_id,active,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT (plate) DO UPDATE SET model=EXCLUDED.model,owner_name=EXCLUDED.owner_name,
                   faculty=EXCLUDED.faculty,category=EXCLUDED.category,colour=EXCLUDED.colour,
                   owner_user_id=EXCLUDED.owner_user_id,active=EXCLUDED.active
                   RETURNING id""",
                (vehicle["plate"], vehicle["model"], vehicle["owner_name"], vehicle["faculty"], vehicle["category"], vehicle["colour"], user_ids.get(vehicle["owner_user_id"]), vehicle["active"], vehicle["created_at"]),
            ).fetchone()
            vehicle_ids[vehicle["id"]] = target_vehicle["id"]

        for log in source_parking_logs:
            vehicle_id = vehicle_ids.get(log["vehicle_id"])
            if vehicle_id:
                target.execute(
                    "INSERT INTO parking_logs (vehicle_id,zone,space_code,check_in_at,check_out_at,recorded_by) VALUES (?,?,?,?,?,?)",
                    (vehicle_id, log["zone"], log["space_code"], log["check_in_at"], log["check_out_at"], user_ids.get(log["recorded_by"])),
                )

        for log in source_activity_logs:
            target.execute(
                "INSERT INTO activity_logs (user_id,action,detail,created_at) VALUES (?,?,?,?)",
                (user_ids.get(log["user_id"]), log["action"], log["detail"], log["created_at"]),
            )

        target.execute("INSERT INTO migration_history (source_name,migrated_at) VALUES (?,CURRENT_TIMESTAMP) ON CONFLICT (source_name) DO UPDATE SET migrated_at=EXCLUDED.migrated_at", (source_path.name,))

    source.close()
    print("Migration complete.")
    print(f"Users: {len(source_users)} | Vehicles: {len(source_vehicles)} | Parking logs: {len(source_parking_logs)} | Activity logs: {len(source_activity_logs)}")


if __name__ == "__main__":
    main()

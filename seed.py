"""
Seed script — generates demo data so the app has something to show.
Run with: make seed  (or: python seed.py)
"""

import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path
from werkzeug.security import generate_password_hash

DB_PATH = Path(__file__).parent / "data" / "app.db"

def seed():
    db = sqlite3.connect(str(DB_PATH))
    db.execute("PRAGMA foreign_keys=ON")
    now = datetime.now(timezone.utc)

    # Check if already seeded
    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count > 1:
        print("Database already has data. Skipping seed.")
        db.close()
        return

    print("Seeding demo data...")

    # Create demo users
    users = [
        ("Alice Chen", "alice@example.com"),
        ("Bob Smith", "bob@example.com"),
        ("Carol Davis", "carol@example.com"),
    ]
    user_ids = []
    for name, email in users:
        cursor = db.execute(
            "INSERT INTO users (name, email, password_hash, email_verified, created) VALUES (?, ?, ?, ?, ?)",
            (name, email, generate_password_hash("password123"), 1, (now - timedelta(days=5)).isoformat())
        )
        user_ids.append(cursor.lastrowid)
        print(f"  Created user: {name} ({email}) — password: password123")

    # Create demo notes for each user
    notes_data = [
        (user_ids[0], "Project Ideas", "## App Ideas\n\n- Task tracker with Kanban board\n- Recipe sharing platform\n- Habit tracker with streaks\n\nNeed to pick one and **start building**.", 7),
        (user_ids[0], "Meeting Notes", "Met with the team today. Key takeaways:\n\n1. Launch deadline is end of month\n2. Need to finalise the API design\n3. Alice will handle the frontend", 3),
        (user_ids[1], "Reading List", "Books to read:\n\n- *Designing Data-Intensive Applications*\n- *The Pragmatic Programmer*\n- *Clean Code*\n\n> Start with DDIA — everyone recommends it.", 10),
        (user_ids[1], "Quick Notes", "Remember to update the `.env` file before deploying.\n\nAlso check the backup schedule.", 1),
        (user_ids[2], "Deploy Checklist", "Before deploying:\n\n- [ ] Run tests\n- [ ] Update requirements.txt\n- [ ] Check .env on server\n- [ ] Run migrations\n- [ ] Restart service", 2),
    ]
    for uid, title, body, days_ago in notes_data:
        ts = (now - timedelta(days=days_ago)).isoformat()
        db.execute(
            "INSERT INTO notes (user_id, title, body, created, updated) VALUES (?, ?, ?, ?, ?)",
            (uid, title, body, ts, ts)
        )

    db.commit()
    db.close()
    print(f"Seeded {len(users)} users and {len(notes_data)} notes.")
    print("\nDemo logins:")
    print("  admin@example.com / changeme  (admin)")
    print("  alice@example.com / password123")
    print("  bob@example.com   / password123")
    print("  carol@example.com / password123")

if __name__ == "__main__":
    seed()

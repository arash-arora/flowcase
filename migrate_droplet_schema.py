
from sqlalchemy import text
from __init__ import create_app, db

app = create_app()

with app.app_context():
    with db.engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE droplet ADD COLUMN registry_username VARCHAR(255)"))
            print("Added registry_username column")
        except Exception as e:
            print(f"Failed to add registry_username (maybe exists): {e}")
            
        try:
            conn.execute(text("ALTER TABLE droplet ADD COLUMN registry_password VARCHAR(255)"))
            print("Added registry_password column")
        except Exception as e:
            print(f"Failed to add registry_password (maybe exists): {e}")
            
        conn.commit()
    print("Migration completed.")

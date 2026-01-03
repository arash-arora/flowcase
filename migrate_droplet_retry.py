
from sqlalchemy import text
from __init__ import create_app, db

app = create_app()

def add_column(column_sql, column_name):
    try:
        with app.app_context():
            with db.engine.connect() as conn:
                try:
                    conn.execute(text(column_sql))
                    conn.commit()
                    print(f"Added {column_name} column")
                except Exception as e:
                    print(f"Failed to add {column_name}: {e}")
    except Exception as e:
        print(f"Connection error for {column_name}: {e}")

if __name__ == "__main__":
    add_column("ALTER TABLE droplet ADD COLUMN registry_username VARCHAR(255)", "registry_username")
    add_column("ALTER TABLE droplet ADD COLUMN registry_password VARCHAR(255)", "registry_password")
    print("Migration retry completed.")

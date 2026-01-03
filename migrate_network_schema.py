
from sqlalchemy import text
from __init__ import create_app, db

app = create_app()

with app.app_context():
    with db.engine.connect() as conn:
        try:
            # Create docker_network table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS docker_network (
                    id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(80) NOT NULL UNIQUE,
                    subnet VARCHAR(40),
                    gateway VARCHAR(40),
                    driver VARCHAR(20)
                )
            """))
            print("Created docker_network table")
        except Exception as e:
            print(f"Failed to create docker_network table: {e}")

        try:
            # Add network_id to droplet table
            conn.execute(text("ALTER TABLE droplet ADD COLUMN network_id VARCHAR(36) REFERENCES docker_network(id)"))
            print("Added network_id column to droplet table")
        except Exception as e:
            print(f"Failed to add network_id column to droplet: {e}")
            
        conn.commit()
    print("Migration completed.")

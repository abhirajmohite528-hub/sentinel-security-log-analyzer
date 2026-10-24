from database.db import initialize_database, DB_PATH

initialize_database()

print("Sentinel database initialized successfully!")
print(f"Database location: {DB_PATH}")
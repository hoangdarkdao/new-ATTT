import mysql.connector
import bcrypt
import os
from dotenv import load_dotenv
load_dotenv()

db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'blog_db')
}
print("Connecting to database with config:", db_config)

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except Exception as e:
        print(f"Database error: {e}")
        return None
    
conn = get_db_connection()
cursor = conn.cursor(dictionary=True)

users = [
    # ("admin2", "admin@blog.local", "admin123", "Blog Administrator"),
    ("user2", "user2@blog.local", "password123", "Second user")
]

for username, email, password, bio in users:

    hashed = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    ).decode()

    cursor.execute(
        """
        INSERT INTO users
        (username, email, password, bio)
        VALUES (%s, %s, %s, %s)
        """,
        (username, email, hashed, bio)
    )

conn.commit()

# Posts
# posts = [
#     (
#         "Welcome to Our Blog",
#         "This is the first post on our blog. Feel free to explore and comment!",
#         1
#     ),
#     (
#         "Security Testing",
#         "A post about security testing and authentication mechanisms.",
#         2
#     )
# ]

# cursor.executemany("""
# INSERT INTO posts(title, content, user_id)
# VALUES (%s, %s, %s)
# """, posts)

# # Comments
# comments = [
#     (
#         "Great post! Thanks for sharing.",
#         1,
#         2
#     ),
#     (
#         "Very informative article.",
#         2,
#         1
#     )
# ]

# cursor.executemany("""
# INSERT INTO comments(content, post_id, user_id)
# VALUES (%s, %s, %s)
# """, comments)

conn.commit()
from flask import Flask, request
import sqlite3
from pathlib import Path

app = Flask(__name__)

DB_FILE = Path("users.db")


def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT
        )
    """)

    cursor.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123', 'admin@example.com')"
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users VALUES (2, 'user', 'userpass', 'user@example.com')"
    )

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return """
    <h1>Vulnerable Web Application</h1>
    <form action="/login" method="post">
        Username: <input type="text" name="username"><br>
        Password: <input type="password" name="password"><br>
        <input type="submit" value="Login">
    </form>
    <br>
    <a href="/search">Search Users</a>
    """


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)

    user = cursor.fetchone()
    conn.close()

    if user:
        return f"Welcome {user[1]}! Your email is {user[3]}"

    return "Invalid credentials"


@app.route("/search")
def search():
    query = request.args.get("q", "")

    return f"""
    <h1>Search Results</h1>
    <form>
        <input type="text" name="q" value="{query}">
        <input type="submit" value="Search">
    </form>
    <p>You searched for: {query}</p>
    """


if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="127.0.0.1", port=5000)

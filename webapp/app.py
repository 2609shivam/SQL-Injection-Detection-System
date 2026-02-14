from flask import Flask, render_template, request
import sqlite3

app = Flask(__name__)

def get_db():
    return sqlite3.connect("database.db")

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ INTENTIONALLY VULNERABLE QUERY
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    print("[DEBUG] Executing:", query)

    cursor.execute(query)
    result = cursor.fetchone()

    conn.close()
                
    if result:
        return render_template("dashboard.html", user=username)
    else:
        return "Login failed"

@app.route("/search")
def search():
    q = request.args.get("q", "")

    conn = get_db()
    cursor = conn.cursor()

    # ❌ INTENTIONALLY VULNERABLE QUERY (GET parameter)
    query = f"SELECT id, username, password FROM users WHERE username LIKE '%{q}%'"
    print("[DEBUG] Executing:", query)

    try:
        cursor.execute(query)
        results = cursor.fetchall()
    except Exception as e:
        conn.close()
        return f"SQL Error: {e}"

    conn.close()
    return {
        "query": query,
        "results": results
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

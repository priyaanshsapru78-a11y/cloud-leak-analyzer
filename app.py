from flask import Flask, render_template, request, redirect, session
from aws_scan import run_scan
from db import init_db
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "secret123"

init_db()

# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user"] = username
            return redirect("/")
        else:
            return "Invalid credentials"

    return render_template("login.html")


# SIGNUP
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
        except:
            return "User already exists"

        conn.close()
        return redirect("/login")

    return render_template("signup.html")


# HOME
@app.route("/", methods=["GET", "POST"])
def home():
    if "user" not in session:
        return redirect("/login")

    output = []

    if request.method == "POST":
        bucket = request.form["bucket"]
        output = run_scan(bucket)

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        for item in output:
            cursor.execute(
                "INSERT INTO scans (username, bucket_name, result) VALUES (?, ?, ?)",
                (session["user"], bucket, item)
            )

        conn.commit()
        conn.close()

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT bucket_name, result FROM scans WHERE username=?", (session["user"],))
    history = cursor.fetchall()
    conn.close()

    # Risk counts
    critical = sum(1 for r in output if "CRITICAL" in r)
    high = sum(1 for r in output if "HIGH" in r)
    medium = sum(1 for r in output if "MEDIUM" in r)
    low = sum(1 for r in output if "LOW" in r)

    return render_template(
        "index.html",
        results=output,
        history=history,
        user=session["user"],
        critical=critical,
        high=high,
        medium=medium,
        low=low
    )


# LOGOUT
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect("/login")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

import os
import sqlite3
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
import bcrypt
from database import get_db_connection, init_db
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.urandom(24)
csrf = CSRFProtect(app)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

@app.before_request
def setup():
    init_db()

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("使用者名稱與密碼不可為空。")
            return render_template("register.html")

        if len(password) < 8:
            flash("密碼長度至少需 8 個字元。")
            return render_template("register.html")

        password_salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode("utf-8"), password_salt)

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            flash("註冊成功，請登入。")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("該使用者名稱已被註冊。")
        finally:
            conn.close()

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if not user:
            flash("帳號或密碼錯誤。")
            conn.close()
            return render_template("login.html")

        now = datetime.now()

        if user["locked_until"]:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if now < locked_until:
                remaining_minutes = int((locked_until - now).total_seconds() // 60) + 1
                flash(f"登入失敗次數過多，帳號已鎖定。請於 {remaining_minutes} 分鐘後再試。")
                conn.close()
                return render_template("login.html")
            else:
                conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                    (user["id"],)
                )
                conn.commit()

        is_valid = bcrypt.checkpw(password.encode("utf-8"), user["password_hash"])

        if is_valid:
            conn.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user["id"],)
            )
            conn.commit()
            conn.close()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        else:
            attempts = user["failed_attempts"] + 1
            if attempts >= MAX_FAILED_ATTEMPTS:
                lock_time = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                conn.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (attempts, lock_time.isoformat(), user["id"])
                )
                flash(f"密碼錯誤達 {MAX_FAILED_ATTEMPTS} 次，帳號已被鎖定 15 分鐘。")
            else:
                conn.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?",
                    (attempts, user["id"])
                )
                remain = MAX_FAILED_ATTEMPTS - attempts
                flash(f"帳號或密碼錯誤。剩餘嘗試次數：{remain} 次。")

            conn.commit()
            conn.close()
            return render_template("login.html")

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("請先登入系統。")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route("/logout")
def logout():
    session.clear()
    flash("您已成功登出。")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)

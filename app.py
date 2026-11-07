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
# 抽取重複出現的模板路徑為常數 (fix S1192)
TEMPLATE_REGISTER = "register.html"
TEMPLATE_LOGIN = "login.html"

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
            return render_template(TEMPLATE_REGISTER)

        if len(password) < 8:
            flash("密碼長度至少需 8 個字元。")
            return render_template(TEMPLATE_REGISTER)

        password_salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode("utf-8"), password_salt)

        try:
            with get_db_connection() as conn:
                conn.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                conn.commit()
            flash("註冊成功，請登入。")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("該使用者名稱已被註冊。")

    return render_template(TEMPLATE_REGISTER)

def check_user_lockout(user, now):
    """檢查使用者是否被鎖定，回傳 (is_locked, message_or_None)"""
    if not user["locked_until"]:
        return False, None
    
    locked_until = datetime.fromisoformat(user["locked_until"])
    if now < locked_until:
        remaining_minutes = int((locked_until - now).total_seconds() // 60) + 1
        return True, f"登入失敗次數過多，帳號已鎖定。請於 {remaining_minutes} 分鐘後再試。"
    return False, None

def handle_failed_login(conn, user, now):
    """處理登入失敗邏輯與連續錯誤鎖定"""
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

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method != "POST":
        return render_template(TEMPLATE_LOGIN)

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    conn = get_db_connection()
    user = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if not user:
        flash("帳號或密碼錯誤。")
        conn.close()
        return render_template(TEMPLATE_LOGIN)

    now = datetime.now()
    is_locked, lock_message = check_user_lockout(user, now)
    if is_locked:
        flash(lock_message)
        conn.close()
        return render_template(TEMPLATE_LOGIN)

    if bcrypt.checkpw(password.encode("utf-8"), user["password_hash"]):
        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],)
        )
        conn.commit()
        conn.close()

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("dashboard"))

    handle_failed_login(conn, user, now)
    conn.close()
    return render_template(TEMPLATE_LOGIN)

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
    is_debug = os.environ.get("FLASK_DEBUG", "False").lower() in ("true", "1")
    app.run(debug=is_debug)

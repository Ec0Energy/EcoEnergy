import os
import secrets
from contextlib import contextmanager
from pathlib import Path

from flask import Flask, abort, redirect, render_template, request, session, url_for
import mysql.connector
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("ECOENERGY_SECRET_KEY") or secrets.token_hex(32),
        MYSQL_HOST=os.environ.get("MYSQL_HOST", "localhost"),
        MYSQL_USER=os.environ.get("MYSQL_USER", "root"),
        MYSQL_PASSWORD=os.environ.get("MYSQL_PASSWORD", ""),
        MYSQL_DATABASE=os.environ.get("MYSQL_DATABASE", "ecoenergy"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    if test_config:
        app.config.update(test_config)

    def connect_db():
        return mysql.connector.connect(
            host=app.config["MYSQL_HOST"],
            user=app.config["MYSQL_USER"],
            password=app.config["MYSQL_PASSWORD"],
            database=app.config["MYSQL_DATABASE"],
        )

    @contextmanager
    def db_connection():
        connection = connect_db()
        try:
            yield connection
        finally:
            connection.close()

    def current_user():
        user_id = session.get("user_id")
        if user_id is None:
            return None
        with db_connection() as connection:
            cursor = connection.cursor(dictionary=True)
            try:
                cursor.execute(
                    "SELECT id, name, email FROM users WHERE id = %s",
                    (user_id,),
                )
                return cursor.fetchone()
            finally:
                cursor.close()

    @app.context_processor
    def inject_user():
        return {"current_user": current_user()}

    @app.get("/")
    @app.get("/index.html")
    def home():
        return render_template("index.html")

    @app.get("/pages/<page_name>.html")
    def pages(page_name):
        template_path = BASE_DIR / "templates" / "pages" / f"{page_name}.html"
        if Path(page_name).name != page_name or not template_path.is_file():
            abort(404)
        return render_template(f"pages/{page_name}.html")

    @app.post("/register")
    def register():
        name = request.form.get("nombre", "").strip()
        email = request.form.get("correo", "").strip().lower()
        password = request.form.get("contrasena", "")
        confirmation = request.form.get("confirmar_contrasena", "")

        if not name or len(name) > 100 or not email or len(email) > 254:
            return redirect(url_for("pages", page_name="registrarse", error="datos"))
        if len(password) < 8:
            return redirect(url_for("pages", page_name="registrarse", error="contrasena"))
        if password != confirmation:
            return redirect(url_for("pages", page_name="registrarse", error="confirmacion"))

        try:
            with db_connection() as connection:
                cursor = connection.cursor()
                try:
                    cursor.execute(
                        """
                        INSERT INTO users (name, email, password_hash)
                        VALUES (%s, %s, %s)
                        """,
                        (name, email, generate_password_hash(password)),
                    )
                    user_id = cursor.lastrowid
                    connection.commit()
                finally:
                    cursor.close()
        except mysql.connector.IntegrityError:
            return redirect(url_for("pages", page_name="registrarse", error="correo"))

        session.clear()
        session["user_id"] = user_id
        return redirect(url_for("home", mensaje="cuenta-creada"))

    @app.post("/login")
    def login():
        email = request.form.get("correo", "").strip().lower()
        password = request.form.get("contrasena", "")
        with db_connection() as connection:
            cursor = connection.cursor(dictionary=True)
            try:
                cursor.execute(
                    "SELECT id, password_hash FROM users WHERE email = %s",
                    (email,),
                )
                user = cursor.fetchone()
            finally:
                cursor.close()

        if user is None or not check_password_hash(user["password_hash"], password):
            return redirect(url_for("pages", page_name="iniciarSesion", error="credenciales"))

        session.clear()
        session["user_id"] = user["id"]
        return redirect(url_for("home", mensaje="sesion-iniciada"))

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("home"))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

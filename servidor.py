from flask import Flask, request, jsonify, session, redirect, url_for
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "clave_secreta_super_segura"

DB_NAME = "usuarios.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()

@app.route("/registro", methods=["POST"])
def registro():
    data = request.get_json()

    usuario = data.get("usuario")
    contraseña = data.get("contraseña")

    if not usuario or not contraseña:
        return jsonify({"error": "Faltan datos"}), 400

    password_hash = generate_password_hash(contraseña)

    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO usuarios (usuario, password) VALUES (?, ?)",
            (usuario, password_hash)
        )

        conn.commit()
        conn.close()

        return jsonify({"mensaje": "Usuario registrado correctamente"}), 201

    except sqlite3.IntegrityError:
        return jsonify({"error": "El usuario ya existe"}), 400


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    usuario = data.get("usuario")
    contraseña = data.get("contraseña")

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password FROM usuarios WHERE usuario = ?",
        (usuario,)
    )

    result = cursor.fetchone()
    conn.close()

    if result and check_password_hash(result[0], contraseña):
        session["usuario"] = usuario
        return jsonify({"mensaje": "Login exitoso"}), 200
    else:
        return jsonify({"error": "Credenciales incorrectas"}), 401


@app.route("/tareas", methods=["GET"])
def tareas():
    if "usuario" not in session:
        return "No autorizado", 401

    return f"""
    <h1>Bienvenido {session['usuario']}</h1>
    <p>Accediste correctamente a tus tareas.</p>
    """


@app.route("/logout")
def logout():
    session.pop("usuario", None)
    return jsonify({"mensaje": "Sesión cerrada"})


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
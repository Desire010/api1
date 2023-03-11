from flask import Flask, request, jsonify
from dotenv import load_dotenv
from argon2 import PasswordHasher
import os
import psycopg2

app = Flask(__name__)


# Charge les variables d'environnement du fichier .env
load_dotenv()

# Récupère les variables d'environnement pour se connecter à la base de données
db_host = os.getenv("DATABASE_HOST")
db_port = os.getenv("DATABASE_PORT")
db_name = os.getenv("DATABASE_NAME")
db_user = os.getenv("DATABASE_USER")
db_password = os.getenv("DATABASE_PASSWORD")

# Connexion à la base de données PostgreSQL
conn = psycopg2.connect(
    host=db_host,
    port=db_port,
    database=db_name,
    user=db_user,
    password=db_password
)

# Création d'une table d'utilisateurs
cur = conn.cursor()
cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    )
""")
conn.commit()
ph = PasswordHasher()

# Création d'un utilisateur
@app.route('/', methods=['POST'])
def create_user():
    data = request.get_json()
    username = data['username']
    password = data['password']
    # Hacher le mot de passe avant de le stocker dans la base de données
    hashed_password = ph.hash(password)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO users (username, password) VALUES (%s, %s)
    """, (username, hashed_password))
    conn.commit()
    return jsonify({'message': 'Utilisateur créé'})

# Connexion d'un utilisateur
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    cur = conn.cursor()
    cur.execute("""
        SELECT password FROM users WHERE username = %s
    """, (username,))
    result = cur.fetchone()
    if result:
         # Vérifier le mot de passe en utilisant la fonction de vérification de hachage Argon2
        try:
            ph.verify(result[0], password)
            return jsonify({'message': 'Connexion réussie'})
        except:
            return jsonify({'message': 'Nom d\'utilisateur ou mot de passe incorrect'})
    else:
        return jsonify({'message': 'Nom d\'utilisateur ou mot de passe incorrect'})

if __name__ == '__main__':
    app.run()

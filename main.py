from flask import Flask, request, jsonify
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import sqlite3

app = Flask(__name__)

# Initialize SQLite Database
conn = sqlite3.connect('totally_not_my_privateKeys.db', check_same_thread=False)
cursor = conn.cursor()

# Create table with specified schema
cursor.execute('''
CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)
''')
conn.commit()

# Function to save keys to the database
def save_key(private_key, expiration_time):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    exp_timestamp = expiration_time.timestamp()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp_timestamp))
    conn.commit()

# Generate and save an expired key and a valid key
def initialize_keys():
    expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    save_key(expired_key, datetime.utcnow() - timedelta(hours=1))  # Expired key

    valid_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    save_key(valid_key, datetime.utcnow() + timedelta(hours=1))  # Valid key

initialize_keys()

@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired', 'false').lower() == 'true'
    now = datetime.now().timestamp()

    if expired:
        cursor.execute("SELECT key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1", (now,))
    else:
        cursor.execute("SELECT key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1", (now,))

    key_pem = cursor.fetchone()[0]
    private_key = serialization.load_pem_private_key(key_pem.encode('utf-8'), password=None, backend=default_backend())

    # Generate and return the JWT using the fetched private key
    payload = {'username': 'fakeuser', 'exp': datetime.utcnow() + timedelta(minutes=5)}
    token = jwt.encode(payload, private_key, algorithm='RS256')
    return jsonify(token=token)

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    jwks_keys = []
    now = datetime.now().timestamp()

    cursor.execute("SELECT key FROM keys WHERE exp > ?", (now,))
    for (key_pem,) in cursor.fetchall():
        public_key = serialization.load_pem_private_key(key_pem.encode('utf-8'), password=None, backend=default_backend()).public_key()
        # Convert the public_key to JWKS format and append to jwks_keys
        # This conversion depends on how you choose to represent your keys in JWKS format

    return jsonify(keys=jwks_keys)

if __name__ == '__main__':
    app.run(port=8080, debug=True)


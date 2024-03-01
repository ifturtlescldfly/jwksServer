from flask import Flask, request, jsonify  # Import necessary Flask classes
from datetime import datetime, timedelta  # Import datetime classes for handling expiration times
from cryptography.hazmat.primitives import serialization  # Import serialization for key handling
from cryptography.hazmat.primitives.asymmetric import rsa  # Import RSA for key generation
from cryptography.hazmat.backends import default_backend  # Import the default backend for cryptographic operations
import jwt  # Import the JWT library to generate tokens

app = Flask(__name__)  # Initialize a Flask application

# Dictionary to store RSA keys with their corresponding expiration time
# Structure: {key_id: (public_key, private_key, expiration_time)}
keys = {}

# Function to generate an RSA key pair and store it with an expiration time
def generate_rsa_key():
    # Generate a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Common public exponent used for RSA keys
        key_size=2048,  # The size of the key in bits
        backend=default_backend()  # Use the default cryptographic backend
    )
    public_key = private_key.public_key()  # Derive the public key from the private key
    key_id = str(len(keys) + 1)  # Generate a simple key ID based on the current number of keys
    expiration_time = datetime.utcnow() + timedelta(days=30)  # Set the key to expire in 30 days from now

    # Store the key with its ID and expiration time in the `keys` dictionary
    keys[key_id] = (public_key, private_key, expiration_time)
    return key_id  # Return the key ID for reference

# Define a Flask route for the JWKS endpoint
@app.route('/jwks', methods=['GET'])
def jwks():
    jwks_keys = []  # Initialize an empty list to store JWKS formatted keys
    # Iterate over each key in the `keys` dictionary
    for kid, (public_key, _, expiration_time) in keys.items():
        # Only include keys that haven't expired yet
        if datetime.utcnow() < expiration_time:
            # Append the public key in JWKS format to the `jwks_keys` list
            jwks_keys.append({
                "kid": kid,  # Key ID
                "kty": "RSA",  # Key Type
                "alg": "RS256",  # Algorithm used for the key
                "use": "sig",  # Key usage (signature)
                "n": public_key.public_numbers().n,  # RSA modulus
                "e": public_key.public_numbers().e  # RSA public exponent
            })
    return jsonify(keys=jwks_keys)  # Return the list of keys in JWKS format as JSON

# Define a Flask route for the authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired')  # Check for the 'expired' query parameter
    if expired:
        key_id = list(keys.keys())[0]  # Use the first key if an expired token is requested
    else:
        key_id = generate_rsa_key()  # Generate a new key otherwise

    # Retrieve the private key and expiration time for the specified key ID
    private_key = keys[key_id][1]
    expiration_time = keys[key_id][2]

    # Define the payload for the JWT, including the expiration time
    payload = {'username': 'fakeuser', 'exp': expiration_time}
    # Encode the payload into a JWT using the private key and RS256 algorithm
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': key_id})

    return jsonify(token=token)  # Return the JWT as JSON

# Main block to run the Flask application
if __name__ == '__main__':
    app.run(port=8080)  # Start the Flask server on port 8080

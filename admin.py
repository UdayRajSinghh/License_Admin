from flask import Flask, render_template, request
import json
import base64
import os
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

AES_KEY = bytes.fromhex('08bfb5a91d43c4d48600fee85fed9cfe52f945dcca1533a328cd2a1b1ef2942f')


def load_or_generate_private_key(filename='private_key.pem'):
    try:
        with open(filename, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        print("Loaded existing private key.")
    except FileNotFoundError:
        print("No private key found. Generating a new one...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(filename, 'wb') as f:
            f.write(pem)
        print(f"Generated and saved new private key to {filename}.")
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        with open('public_key.pem', 'w') as f:
            f.write(public_pem)
        print("Public key saved as 'public_key.pem'.")
    return private_key

PRIVATE_KEY = load_or_generate_private_key()

def encrypt_data(data):
    # Generate a random IV
    iv = os.urandom(16)
    
    # Create an encryptor
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad the data to be a multiple of 16 bytes (AES block size)
    padded_data = data + b'\x00' * (16 - (len(data) % 16))
    
    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return the IV and encrypted data
    return iv + encrypted_data

def generate_license(hardware_id, duration_days):
    try:
        duration = int(duration_days)
        if duration <= 0:
            return False, "Duration must be a positive number of days.", None, None
        
        # Get current date as start date
        start_date = datetime.now().strftime('%Y-%m-%d')
        
        # Calculate expiration date
        expiration_date = (datetime.now() + timedelta(days=duration)).strftime('%Y-%m-%d')
        
        # Create license data
        license_data = json.dumps({
            'hardware_id': hardware_id,
            'start_date': start_date,
            'expiration_date': expiration_date
        }).encode('utf-8')
        
        # First sign the license data
        signature = PRIVATE_KEY.sign(
            license_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        # Prepare the data package: signature length + signature + license data
        signature_length = len(signature)
        data_package = signature_length.to_bytes(4, byteorder='big') + signature + license_data
        
        # Encrypt the entire data package
        encrypted_package = encrypt_data(data_package)
        
        # Encode to base64 for easy transport
        license_key = base64.b64encode(encrypted_package).decode('utf-8')
        
        return True, license_key, start_date, expiration_date
    except ValueError:
        return False, "Invalid duration. Please enter a number of days (e.g., 180 for 6 months).", None, None
    except Exception as e:
        return False, f"Error generating license: {str(e)}", None, None

@app.route('/', methods=['GET', 'POST'])
def index():
    license_key = None
    message = None
    start_date = None
    expiration_date = None

    if request.method == 'POST':
        hardware_id = request.form.get('hardware_id')
        duration_days = request.form.get('duration_days')
        
        if hardware_id and duration_days:
            success, result, start_date, expiration_date = generate_license(hardware_id, duration_days)
            if success:
                license_key = result
                message = f"License key generated successfully! Valid from {start_date} to {expiration_date}."
            else:
                message = result
        else:
            message = "Please provide both Hardware ID and Duration."

    return render_template('index.html', license_key=license_key, message=message)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
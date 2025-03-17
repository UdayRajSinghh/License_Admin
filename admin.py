from flask import Flask, render_template, request
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

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

def generate_license(hardware_id, duration_days):
    try:
        duration = int(duration_days)
        if duration <= 0:
            return False, "Duration must be a positive number of days."
        
        license_data = json.dumps({
            'hardware_id': hardware_id,
            'duration_days': duration
        }).encode('utf-8')
        
        signature = PRIVATE_KEY.sign(
            license_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        # Store signature length as the first 4 bytes
        signature_length = len(signature)
        combined_data = signature_length.to_bytes(4, byteorder='big') + signature + license_data
        
        license_key = base64.b64encode(combined_data).decode('utf-8')
        return True, license_key
    except ValueError:
        return False, "Invalid duration. Please enter a number of days (e.g., 180 for 6 months)."
    except Exception as e:
        return False, f"Error generating license: {str(e)}"

@app.route('/', methods=['GET', 'POST'])
def index():
    license_key = None
    message = None

    if request.method == 'POST':
        hardware_id = request.form.get('hardware_id')
        duration_days = request.form.get('duration_days')
        
        if hardware_id and duration_days:
            success, result = generate_license(hardware_id, duration_days)
            if success:
                license_key = result
                message = "License key generated successfully!"
            else:
                message = result
        else:
            message = "Please provide both Hardware ID and Duration."

    return render_template('index.html', license_key=license_key, message=message)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)

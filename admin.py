from flask import Flask, render_template, request
import uuid
import base64
from datetime import datetime, timedelta

app = Flask(__name__)

def generate_license_key(hardware_id, validity_days):
    license_uuid = str(uuid.uuid4())
    license_data = f"{license_uuid}-{validity_days}"
    license_key = base64.urlsafe_b64encode(license_data.encode()).decode().rstrip("=")
    expiry_date = datetime.now() + timedelta(days=validity_days)
    return license_key, expiry_date.strftime("%Y-%m-%d")

@app.route("/", methods=["GET", "POST"])
def index():
    license_key = None
    expiry_date = None
    if request.method == "POST":
        hardware_id = request.form["hardware_id"]
        validity_days = int(request.form["validity_days"])
        license_key, expiry_date = generate_license_key(hardware_id, validity_days)
    return render_template("admin.html", license_key=license_key, expiry_date=expiry_date)

if __name__ == "__main__":
    app.run(debug=True, port=2000)
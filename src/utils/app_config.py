import os
from config import config
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

env = os.getenv("FLASK_ENV", "development")
base_url = os.getenv("BASE_URL", "http://localhost:5000")  # Default to localhost if not set
# app_config = config[env]

app = Flask(__name__, static_folder="./build")

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, "index.html")
    
    
app.config["BASE_URL"] = base_url  # Set base URL for the backend
CORS(app, resources={r"/*": {"origins": "*"}})

print(f"Flask is running in {env} mode with base URL: {base_url}")


# # API route : Most Important Code !!!!!!!!!!!!

@app.route("/api/data", methods=["GET"])
def get_data():

    return jsonify({"message": "Hello from Flask API!"})

# app.config.from_object(app_config)

print(f"FLASK_ENV: {os.getenv('FLASK_ENV')}")
print(f"BASE_URL: {os.getenv('BASE_URL')}")
print(f"DEBUG: {os.getenv('DEBUG')}")
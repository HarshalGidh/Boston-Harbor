import os
from config import config
from flask import Flask, jsonify, request, send_from_directory

env = os.getenv("FLASK_ENV", "development")
base_url = os.getenv("BASE_URL", "http://localhost:5000")  # Default to localhost if not set
app_config = config[env]

# app = Flask(__name__)

app = Flask(__name__, static_folder="../bostonHarbor/build")

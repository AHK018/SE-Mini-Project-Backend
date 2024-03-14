from datetime import datetime
import uuid
import bcrypt
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_pymongo import PyMongo
import os
import pandas as pd
import socket
from flask_bcrypt import check_password_hash
from flask_bcrypt import Bcrypt

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
app.config["MONGO_URI"] = (
    "mongodb+srv://SE:admin@se.nfq8vlo.mongodb.net/TestMongo?retryWrites=true&w=majority"
)

mongo = PyMongo(app)

app.config['JWT_SECRET_KEY'] = 'super-secret'
jwt = JWTManager(app)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    user = mongo.db.Users.find_one(
        {"email": data.get("username")}
    )
    
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    mac_address = ":".join(
            [
                "{:02x}".format((uuid.getnode() >> elements) & 0xFF)
                for elements in range(0, 2 * 6, 2)
            ][::-1]
        )

    user_data = pd.DataFrame({'Host Name': [hostname], 'IP Address':ip_address,'Mac Address':mac_address,'Timestamp': [datetime.now()]})

    excel_file_path = 'user_info.xlsx'
    if os.path.exists(excel_file_path):
        existing_data = pd.read_excel(excel_file_path)
        user_data = pd.concat([existing_data, user_data], ignore_index=True)

    user_data.to_excel(excel_file_path, index=False)

    if user and check_password_hash(user["password"], data.get("password")):
        payload = {
            "email": user["email"],
            "user" : user["user"],
        }
        
        access_token = create_access_token(identity=payload)
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()

    existing_user = mongo.db.users.find_one({"email": data["email"]})
    if existing_user:
        return jsonify({"error": "User with this email already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")

    new_user = {
        "email": data["email"],
        "password": hashed_password,
        "user": "user",
    }

    mongo.db.Users.insert_one(new_user)

    return jsonify({"message": "User successfully registered"}), 201


@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run(debug=True,port=5000)


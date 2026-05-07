from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS  # Added to allow the HTML file to talk to this server
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# This is the "stamp" the server uses to sign tokens. 
# NEVER hardcode this in production; use environment variables!
app.config['SECRET_KEY'] = 'my_super_secret_developer_key'

# Our mock database (In a real app, this would be PostgreSQL, MongoDB, etc.)
users_db = {}

# ==========================================
# STEP 1: REGISTRATION (Saving to Database)
# ==========================================
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Email and password are required!"}), 400

    if email in users_db:
        return jsonify({"message": "User already exists!"}), 400

    # HASH THE PASSWORD! Never save plain text.
    hashed_password = generate_password_hash(password)
    
    # Save the user to our mock database
    users_db[email] = {
        "email": email,
        "password": hashed_password
    }
    
    return jsonify({"message": "Successfully registered!"}), 201

# ==========================================
# STEP 2: LOGIN (Generating the Token)
# ==========================================
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Look up the user in the database
    user = users_db.get(email)

    if not user:
        return jsonify({"message": "User not found!"}), 404

    # Verify the password against the stored hash
    if check_password_hash(user['password'], password):
        # Passwords match! Let's create the wristband (JWT)
        payload = {
            'email': email,
            # Token expires in 30 minutes
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) 
        }
        
        # Encode the token using our secret key
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({"token": token}), 200

    return jsonify({"message": "Invalid password!"}), 401

# ==========================================
# STEP 3: THE BOUNCER (Token Verification)
# ==========================================
# We create a custom decorator to protect our routes.
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if the token is passed in the Authorization header
        if 'Authorization' in request.headers:
            # The format is usually "Bearer <token>"
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Decode the token using our secret key
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_db.get(data['email'])
            
            if not current_user:
                return jsonify({'message': 'User associated with token no longer exists!'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired! Please log in again.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401

        # Pass the verified user data down to the route
        return f(current_user, *args, **kwargs)
    
    return decorated

# ==========================================
# STEP 4: PROTECTED ROUTE (Using the Token)
# ==========================================
@app.route('/profile', methods=['GET'])
@token_required  # Notice our bouncer is attached here!
def profile(current_user):
    # This code ONLY runs if the token was perfectly valid
    return jsonify({
        "message": "Welcome to the VIP area!",
        "user_data": {
            "email": current_user['email']
        }
    })

if __name__ == '__main__':
    # Run the server on http://127.0.0.1:5000
    app.run(debug=True)
import sqlite3
import ipinfo
from flask import Flask, request, jsonify, render_template, g
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_cors import CORS

access_token = "af3441c4c64a95"
app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'BMKbkb_U-n5_UuCQ1wWPs_nGt96lpGwgWWI68l7Vg8U'
jwt = JWTManager(app)


def get_loc(city=False, region=False, country=False):
    details = ipinfo.getHandler(access_token).getDetails()
    result = {}
    if city:
        result['city'] = details.city
    if region:
        result['region'] = details.region
    if country:
        result['country'] = details.country
    return result


# Connect to SQLite database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('user.db')
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


# Create table for users if not exists
def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


@app.before_request
def before_request():
    get_db()


@app.teardown_request
def teardown_request(exception):
    close_db()


@app.route('/create_account', methods=['POST'])
def create_account():
    new_username = request.json.get('username', None)
    new_password = request.json.get('password', None)
    if not new_username or not new_password:
        return jsonify({"message": "Username and password are required"}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", (new_username, new_password))
    db.commit()
    return jsonify({"message": "Account created successfully"}), 200


@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT id, password FROM users WHERE username = ?', (username,))
    user = cur.fetchone()
    if user and user['password'] == password:
        access_token = create_access_token(identity=user['id'])
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401


@app.route('/add_friend', methods=['POST'])
@jwt_required()
def add_friend():
    current_user_id = get_jwt_identity()  # Retrieve user id from JWT token
    friend_username = request.json.get('friend_username', None)
    if not friend_username:
        return jsonify({"message": "Friend username not provided"}), 400

    db = get_db()
    cur = db.cursor()

    # Find friend's id based on username
    cur.execute('SELECT id FROM users WHERE username = ?', (friend_username,))
    friend = cur.fetchone()
    if not friend:
        return jsonify({"message": "Friend not found"}), 404

    # Check if friendship already exists
    cur.execute('SELECT friends FROM users WHERE id = ?', (current_user_id,))
    current_user_friends = cur.fetchone()['friends']
    if current_user_friends:
        current_user_friends_list = current_user_friends.split(',')
    else:
        current_user_friends_list = []

    if str(friend['id']) in current_user_friends_list:
        return jsonify({"message": "Friend already added"}), 400

    # Add friend to the current user's friend list
    if current_user_friends:
        new_friends_list = current_user_friends + ',' + str(friend['id'])
    else:
        new_friends_list = str(friend['id'])

    cur.execute('UPDATE users SET friends = ? WHERE id = ?', (new_friends_list, current_user_id))
    db.commit()

    return jsonify({"message": "Friend added successfully"}), 200


@app.route('/friends', methods=['GET'])
@jwt_required()
def get_friends():
    current_user_id = get_jwt_identity()  # Get the current user's ID from JWT
    db = get_db()
    cur = db.cursor()

    # Retrieve the friend IDs for the current user
    cur.execute('SELECT friends FROM users WHERE id = ?', (current_user_id,))
    result = cur.fetchone()
    if not result:
        return jsonify({"message": "User not found"}), 404

    friend_ids_str = result[0]

    if friend_ids_str:
        friend_ids = friend_ids_str.split(',')  # Split the string to get individual friend IDs
        friends = []

        for friend_id in friend_ids:
            # Retrieve the username associated with each friend ID
            cur.execute('SELECT username FROM users WHERE id = ?', (friend_id,))
            friend = cur.fetchone()
            if friend:
                friends.append(friend['username'])

    else:
        friends = []

    return jsonify({"friends": friends}), 200


@app.route('/start_conversation', methods=['POST'])
@jwt_required()
def start_conversation():
    current_user_id = get_jwt_identity()  # Get the current user's ID from JWT
    recipient_username = request.json.get('recipient', None)
    message = request.json.get('message', None)
    if not recipient_username or not message:
        return jsonify({"message": "Recipient and message are required"}), 400

    # Directly send the message to the client-side JavaScript
    return jsonify({
        "sender": get_username(current_user_id),
        "recipient": recipient_username,
        "message": message
    }), 200


def get_username(user_id):
    db = get_db()
    cur = db.cursor()
    cur.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = cur.fetchone()
    return user['username'] if user else None


@app.route('/')
def index():
    location = get_loc(city=True)
    return render_template('index.html', location=location)


if __name__ == '__main__':
    app.run(port=5000)

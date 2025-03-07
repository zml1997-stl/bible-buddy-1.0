# app.py - Complete Application
import os
import uuid
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, join_room, leave_room, emit
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai
from dotenv import load_dotenv
import threading
import requests

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///bible_study.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socketio = SocketIO(app, cors_allowed_origins="*")
db = SQLAlchemy(app)

# Configure Gemini API
genai.configure(api_key=os.getenv('GEMINI_API_KEY', 'your-gemini-api-key'))

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class StudyRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    is_private = db.Column(db.Boolean, default=False)
    access_code = db.Column(db.String(20))
    current_topic = db.Column(db.String(200))
    current_scripture = db.Column(db.String(200))

class StudySession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('study_room.id'))
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    summary = db.Column(db.Text)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    session_id = db.Column(db.Integer, db.ForeignKey('study_session.id'))
    is_ai = db.Column(db.Boolean, default=False)

class Prayer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_answered = db.Column(db.Boolean, default=False)
    is_private = db.Column(db.Boolean, default=False)

# Active sessions tracking
active_rooms = {}
active_users = {}

# Bible API Functions
def fetch_bible_verse(reference):
    try:
        api_url = f"https://bible-api.com/{reference}?translation=kjv"
        response = requests.get(api_url)
        data = response.json()
        return data['text']
    except Exception as e:
        return f"Error fetching verse: {str(e)}"

def get_random_verse():
    common_verses = [
        "John 3:16", "Romans 8:28", "Jeremiah 29:11", "Philippians 4:13",
        "Psalm 23:1", "Proverbs 3:5-6", "Isaiah 40:31", "Matthew 6:33"
    ]
    import random
    reference = random.choice(common_verses)
    return {"reference": reference, "text": fetch_bible_verse(reference)}

# AI Pastor Functions
def get_ai_response(prompt, context=None):
    try:
        model = genai.GenerativeModel('gemini-1.5-flash')
        system_prompt = """You are an AI Pastor assistant. Provide biblically accurate,
        theological insights. Be supportive and educational. Acknowledge different
        denominational views when appropriate. Use markdown for structure when helpful."""
        
        conversation_context = [{"role": "system", "content": system_prompt}]
        if context:
            conversation_context += context
            
        conversation_context.append({"role": "user", "content": prompt})
        response = model.generate_content(conversation_context)
        return response.text
    except Exception as e:
        return f"AI Error: {str(e)}"

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        if User.query.filter((User.username == username) | (User.email == email)).first():
            return render_template('register.html', error='Username/Email exists')
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user, daily_verse=get_random_verse())

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# WebSocket Handlers
@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        return False
    user_id = session['user_id']
    if user_id not in active_users:
        active_users[user_id] = {'rooms': set(), 'username': session['username']}

@socketio.on('join')
def handle_join(data):
    room_id = data['room_id']
    user_id = session['user_id']
    username = session['username']
    
    join_room(room_id)
    if room_id not in active_rooms:
        active_rooms[room_id] = {'users': set(), 'messages': []}
    active_rooms[room_id]['users'].add(user_id)
    active_users[user_id]['rooms'].add(room_id)
    
    emit('user_joined', {'username': username}, room=room_id)
    emit('room_users', {'users': [active_users[uid]['username'] for uid in active_rooms[room_id]['users']]}, room=room_id)

@socketio.on('leave')
def handle_leave(data):
    room_id = data['room_id']
    user_id = session['user_id']
    username = session['username']
    
    leave_room(room_id)
    if room_id in active_rooms and user_id in active_rooms[room_id]['users']:
        active_rooms[room_id]['users'].remove(user_id)
        emit('user_left', {'username': username}, room=room_id)
    if user_id in active_users and room_id in active_users[user_id]['rooms']:
        active_users[user_id]['rooms'].remove(room_id)

@socketio.on('send_message')
def handle_message(data):
    if 'user_id' not in session:
        return
    
    room_id = data['room_id']
    message_content = data['message']
    user_id = session['user_id']
    username = session['username']
    
    new_message = Message(
        content=message_content,
        user_id=user_id,
        session_id=data['session_id'],
        is_ai=False
    )
    db.session.add(new_message)
    db.session.commit()
    
    emit('new_message', {
        'id': new_message.id,
        'content': message_content,
        'username': username,
        'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
        'is_ai': False
    }, room=room_id)
    
    if '@pastor' in message_content.lower() or '?' in message_content:
        threading.Thread(target=process_ai_response, args=(room_id, data['session_id'], message_content)).start()

def process_ai_response(room_id, session_id, message_content):
    try:
        ai_response = get_ai_response(message_content)
        new_message = Message(
            content=ai_response,
            session_id=session_id,
            is_ai=True
        )
        db.session.add(new_message)
        db.session.commit()
        
        socketio.emit('new_message', {
            'id': new_message.id,
            'content': ai_response,
            'username': 'AI Pastor',
            'timestamp': new_message.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'is_ai': True
        }, room=room_id)
    except Exception as e:
        print(f"AI Error: {str(e)}")

# Initialization
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host='0.0.0.0', port=port)

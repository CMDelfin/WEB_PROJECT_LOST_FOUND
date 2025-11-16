from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from models import db, User, Item, Message as ChatMessage, Contact
from dotenv import load_dotenv
from datetime import datetime
from werkzeug.utils import secure_filename
import pytz
import os
import random

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')

db_type = os.getenv('DB_TYPE', 'mysql')
if db_type == 'mysql':
    user = os.getenv('DB_USER', 'root')
    password = os.getenv('DB_PASSWORD', '')
    host = os.getenv('DB_HOST', 'localhost')
    name = os.getenv('DB_NAME', 'lost_found_db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{user}:{password}@{host}/{name}"
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lostfound.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
mail = Mail(app)

try:
    LOCAL_TZ = pytz.timezone("Asia/Manila")
except Exception:
    LOCAL_TZ = pytz.UTC

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def to_local_time(dt):
    if dt.tzinfo is None:
        dt = pytz.UTC.localize(dt)
    return dt.astimezone(LOCAL_TZ)

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png','jpg','jpeg','gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        if request.is_json:
            data = request.get_json()
            username = data.get('username', '').strip()
            email = data.get('email', '').strip().lower()
            phone = data.get('phone')
            password = data.get('password', '')

            if username.lower() == 'Admin' or User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
                return jsonify({'status': 'error', 'message': 'Username or email already taken'})

            otp = random.randint(100000, 999999)
            session['pending_user'] = {'username': username, 'email': email, 'phone': phone, 'password': password}
            session['otp'] = str(otp)

            try:
                    msg = Message(
                        subject="Trackr - Verify Your Email Address",
                        sender=app.config['MAIL_DEFAULT_SENDER'],
                        recipients=[email],
                        body=f"""Hello {username},

                Thank you for registering with Trackr! To complete your registration, please use the following One-Time Password (OTP):

                {otp}

                This code is valid for a limited time. Please do not share it with anyone.

                If you did not request this, please ignore this email.

                Best regards,
                The Trackr Team
                """
                    )
                    mail.send(msg)
            except Exception as e:
                    return jsonify({'status': 'error', 'message': f"Failed to send OTP: {e}"})

            return jsonify({'status': 'otp_sent'})


        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form.get('phone')
        password = request.form['password']
        flash('Please use the registration form properly.', 'warning')
        return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    if not data or 'otp' not in data:
        return jsonify({'status': 'error', 'message': 'OTP required'})

    entered_otp = data.get('otp')
    if 'otp' not in session or entered_otp != session['otp']:
        return jsonify({'status': 'error', 'message': 'Invalid OTP'})

    pending = session['pending_user']
    hashed_password = bcrypt.generate_password_hash(pending['password']).decode('utf-8')
    user = User(username=pending['username'], email=pending['email'], phone=pending['phone'], password=hashed_password)
    db.session.add(user)
    db.session.commit()

    contact_entry = Contact(name=pending['username'], email=pending['email'], phone=pending['phone'])
    db.session.add(contact_entry)
    db.session.commit()

    session.pop('otp')
    session.pop('pending_user')

    return jsonify({'status': 'success', 'message': 'Registration complete'})

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data or 'email' not in data:
        return jsonify({'status': 'error', 'message': 'Email required'})

    email = data.get('email').strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'status': 'error', 'message': "No account found with that email."})

    otp = random.randint(100000, 999999)
    session['reset_email'] = email
    session['reset_otp'] = str(otp)
    session.pop('reset_verified', None)

    try:
        msg = Message(
            subject="Trackr - Password Reset OTP",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email],
            body=f"""Hello {user.username},

            We received a request to reset your Trackr password. Use the following One-Time Password (OTP) to proceed:

            {otp}

            If you didn't request this, please ignore this message.

            Best,
            Trackr Team
            """
        )
        mail.send(msg)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to send OTP: {e}'})

    return jsonify({'status': 'otp_sent'})


@app.route('/verify_reset_otp', methods=['POST'])
def verify_reset_otp():
    data = request.get_json()
    if not data or 'otp' not in data:
        return jsonify({'status': 'error', 'message': 'OTP required'})

    entered = data.get('otp', '').strip()
    if 'reset_otp' not in session or 'reset_email' not in session:
        return jsonify({'status': 'error', 'message': 'No password reset in progress'})

    if entered != session.get('reset_otp'):
        return jsonify({'status': 'error', 'message': 'Invalid OTP'})
    
    session['reset_verified'] = True
    session.pop('reset_otp', None)

    return jsonify({'status': 'verified'})


@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    if not data or 'new_password' not in data:
        return jsonify({'status': 'error', 'message': 'New password required'})

    if 'reset_verified' not in session or not session.get('reset_verified'):
        return jsonify({'status': 'error', 'message': 'OTP not verified'})

    email = session.get('reset_email')
    if not email:
        return jsonify({'status': 'error', 'message': 'No reset email found'})

    new_password = data.get('new_password', '').strip()
    if len(new_password) < 6:
        return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'})

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'})

    hashed = bcrypt.generate_password_hash(new_password).decode('utf-8')
    user.password = hashed
    db.session.commit()

    session.clear()

    return jsonify({'status': 'success', 'message': 'Password updated'})


@app.route('/login_request_otp', methods=['POST'])
def login_request_otp():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    user = User.query.filter_by(email=email).first()
    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'status': 'error', 'message': 'Invalid email or password'})

    if user.username.lower() == 'admin':
        login_user(user)
        return jsonify({
            'status': 'success',
            'redirect': url_for('admin_dashboard')
        })

    otp = random.randint(100000, 999999)
    session['login_user_id'] = user.id
    session['login_otp'] = str(otp)

    try:
        msg = Message(
            subject="Trackr - Login OTP",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email],
            body=f"Hello {user.username},\n\nYour login OTP is: {otp}\n\nIf you did not request this, ignore."
        )
        mail.send(msg)
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Failed to send OTP: {e}'})

    return jsonify({'status': 'otp_sent'})

@app.route('/login_verify_otp', methods=['POST'])
def login_verify_otp():
    data = request.get_json()
    entered_otp = data.get('otp', '').strip()

    if 'login_user_id' not in session or 'login_otp' not in session:
        return jsonify({'status': 'error', 'message': 'No login attempt found'})

    if entered_otp != session['login_otp']:
        return jsonify({'status': 'error', 'message': 'Invalid OTP'})

    user_id = session.pop('login_user_id')
    session.pop('login_otp')
    user = User.query.get(user_id)
    login_user(user)

    redirect_url = url_for('dashboard') if user.username.lower() != 'admin' else url_for('admin_dashboard')
    return jsonify({'status': 'success', 'redirect': redirect_url})

@app.route('/login', methods=['GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.username.lower() == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        flash('Invalid email or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/')
def index():
    total_lost = Item.query.filter_by(status='lost').count()
    total_found = Item.query.filter_by(status='found').count()
    total_resolved = Item.query.filter_by(is_resolved=True).count()
    total_items = Item.query.count()
    return render_template('index.html', total_lost=total_lost, total_found=total_found,
                           total_resolved=total_resolved, total_items=total_items)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.username.lower() == 'admin':
        return redirect(url_for('admin_dashboard'))
    selected_category = request.args.get('category', '')
    query = Item.query.filter_by(user_id=current_user.id)
    if selected_category:
        query = query.filter_by(category=selected_category)
    items = query.all()
    return render_template('dashboard.html', items=items)

@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if current_user.username.lower() == 'admin':
        flash('Admins cannot report items.', 'warning')
        return redirect(url_for('admin_dashboard'))

    categories = ["Electronics", "Clothing", "Documents", "Accessories", "Bags", "Keys", "Pets", "Others"]

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        location = request.form['location']
        status = request.form['status']
        category = request.form['category']

        image_filename = None

        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"{datetime.utcnow().timestamp()}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                image_filename = filename

        new_item = Item(
            name=name,
            description=description,
            location=location,
            status=status,
            category=category,
            image_filename=image_filename,
            user_id=current_user.id
        )

        db.session.add(new_item)
        db.session.commit()

        flash('Item added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_item.html', categories=categories)


@app.route('/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def edit_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        flash("You can't edit someone else's item!", 'danger')
        return redirect(url_for('dashboard'))
    categories = ["Electronics", "Clothing", "Documents", "Accessories", "Bags", "Keys", "Pets", "Others"]
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        location = request.form['location']
        status = request.form['status']
        category = request.form['category']

        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filename = f"{datetime.utcnow().timestamp()}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                item.image_filename = filename

        db.session.commit()
        flash('Item updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_items.html', item=item, categories=categories)

@app.route('/delete_item/<int:item_id>')
@login_required
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)
    if item.user_id != current_user.id:
        flash("You can't delete someone else's item!", 'danger')
        return redirect(url_for('dashboard'))
    db.session.delete(item)
    db.session.commit()
    flash('Item deleted!', 'info')
    return redirect(url_for('dashboard'))

@app.route('/view_items')
def view_items():
    search = request.args.get('search', '')
    selected_category = request.args.get('category', '')
    selected_status = request.args.get('status', '')
    query = Item.query
    if search:
        query = query.filter(Item.name.like(f'%{search}%') |
                             Item.description.like(f'%{search}%') |
                             Item.location.like(f'%{search}%'))
    if selected_category:
        query = query.filter_by(category=selected_category)
    if selected_status:
        query = query.filter_by(status=selected_status)
    items = query.all()
    categories = ["Electronics", "Clothing", "Documents", "Accessories", "Bags", "Keys", "Pets", "Others"]
    total_items = len(items)
    total_lost = sum(1 for item in items if item.status == 'lost')
    total_found = sum(1 for item in items if item.status == 'found')
    total_resolved = sum(1 for item in items if item.is_resolved)
    return render_template('view_items.html', items=items,
                           total_items=total_items,
                           total_lost=total_lost,
                           total_found=total_found,
                           total_resolved=total_resolved,
                           categories=categories,
                           selected_category=selected_category,
                           selected_status=selected_status)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.username.lower() != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    selected_category = request.args.get('category', '')
    categories = ["Electronics", "Clothing", "Documents", "Accessories", "Bags", "Keys", "Pets", "Others"]
    if selected_category and selected_category != "All":
        items = Item.query.filter_by(category=selected_category).all()
    else:
        items = Item.query.all()
    users = User.query.all()
    return render_template('admin.html', items=items, users=users,
                           categories=categories, selected_category=selected_category)

@app.route('/admin/toggle_resolved/<int:item_id>', methods=['POST'])
@login_required
def admin_toggle_resolved(item_id):
    if current_user.username.lower() != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    item = Item.query.get_or_404(item_id)
    item.is_resolved = not item.is_resolved
    db.session.commit()
    flash(f"Item '{item.name}' marked as {'resolved' if item.is_resolved else 'unresolved'}.", 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_item(item_id):
    if current_user.username.lower() != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    item = Item.query.get_or_404(item_id)
    categories = ["Electronics", "Clothing", "Documents", "Accessories", "Bags", "Keys", "Pets", "Others"]

    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.location = request.form['location']
        item.status = request.form['status']
        item.category = request.form['category']
        db.session.commit()
        flash('Item updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_items.html', item=item, categories=categories)

@app.route('/admin_edit_user', methods=['POST'])
def admin_edit_user():
    data = request.get_json()
    user_id = data.get('id')
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    phone = data.get('phone', '').strip()

    if not username or not email:
        return jsonify({'status':'error','message':'Username and email are required'}), 400

    import re
    if not re.match(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
        return jsonify({'status':'error','message':'Invalid email format'}), 400

    user = User.query.get(user_id)
    if not user:
        return jsonify({'status':'error','message':'User not found'}), 404

    user.username = username
    user.email = email
    user.phone = phone

    try:
        db.session.commit()
        return jsonify({'status':'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status':'error','message':'Database error: '+str(e)}), 500

@app.route('/admin_delete_user', methods=['POST'])
def admin_delete_user():
    data = request.get_json()
    user_id = data.get('id')
    user = User.query.get(user_id)
    if not user:
        return jsonify({'status':'error','message':'User not found'}), 404

    try:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'status':'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status':'error','message':'Database error: '+str(e)}), 500


@app.route('/admin/delete_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def admin_delete_item(item_id):
    if current_user.username.lower() != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Item deleted successfully!', 'info')
    return redirect(url_for('admin_dashboard'))

@app.route('/messages', methods=['GET', 'POST'])
@login_required
def messages():
    admin_user = User.query.filter(User.username.ilike('admin')).first()
    if not admin_user:
        flash('Admin user not found', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            msg = ChatMessage(sender_id=current_user.id, receiver_id=admin_user.id, content=content)
            db.session.add(msg)
            db.session.commit()
            flash('Message sent!', 'success')
            return redirect(url_for('messages'))

    msgs = ChatMessage.query.filter(
        ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == admin_user.id)) |
        ((ChatMessage.sender_id == admin_user.id) & (ChatMessage.receiver_id == current_user.id))
    ).order_by(ChatMessage.timestamp.asc()).all()

    for msg in msgs:
        msg.timestamp = to_local_time(msg.timestamp)
        if msg.receiver_id == current_user.id and msg.sender_id == admin_user.id and not msg.is_read:
            msg.is_read = True
    db.session.commit()

    return render_template('messages_user.html', messages=msgs, admin_user=admin_user)

@app.route('/admin/messages')
@login_required
def admin_messages():
    if current_user.username.lower() != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    users = User.query.filter(User.username != 'admin').all()
    selected_user_id = request.args.get('selected_user_id', type=int)
    selected_user = None
    msgs = []

    if selected_user_id:
        selected_user = User.query.get(selected_user_id)
        msgs = ChatMessage.query.filter(
            ((ChatMessage.sender_id == selected_user.id) & (ChatMessage.receiver_id == current_user.id)) |
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.receiver_id == selected_user.id))
        ).order_by(ChatMessage.timestamp.asc()).all()

        for msg in msgs:
            msg.timestamp = to_local_time(msg.timestamp)
            if msg.receiver_id == current_user.id and not msg.is_read:
                msg.is_read = True
        db.session.commit()

    return render_template('messages_admin.html', messages=msgs, users=users, selected_user=selected_user)

@app.route('/admin/send_message', methods=['POST'])
@login_required
def admin_send_message():
    if current_user.username.lower() != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    content = request.form.get('content')
    receiver_id = int(request.form.get('receiver_id'))
    if content:
        msg = ChatMessage(sender_id=current_user.id, receiver_id=receiver_id, content=content)
        db.session.add(msg)
        db.session.commit()
        flash('Message sent!', 'success')
    return redirect(url_for('admin_messages', selected_user_id=receiver_id))

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form.get('phone')
        contact_entry = Contact(name=name, email=email, phone=phone)
        db.session.add(contact_entry)
        db.session.commit()
        flash('Contact added successfully!', 'success')

        admin_email = os.getenv('MAIL_USERNAME', 'your_email@example.com')
        try:
            msg = Message(subject=f"New Contact: {name}",
                          sender=app.config['MAIL_DEFAULT_SENDER'],
                          recipients=[admin_email],
                          body=f"Name: {name}\nEmail: {email}\nPhone: {phone}")
            mail.send(msg)
        except Exception as e:
            print(f"Email send failed: {e}")

        return redirect(url_for('contact'))

    contacts = Contact.query.order_by(Contact.timestamp.desc()).all()
    return render_template('contact.html', contacts=contacts)

@app.route('/admin/contacts')
@login_required
def admin_contacts():
    if current_user.username.lower() != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    contacts = Contact.query.order_by(Contact.timestamp.desc()).all()
    return render_template('contacts_admin.html', contacts=contacts)

if __name__ == '__main__':
    app.run(debug=True)
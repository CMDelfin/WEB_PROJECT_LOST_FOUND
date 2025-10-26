from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Item
from dotenv import load_dotenv
import os

# ================== INITIAL SETUP ==================
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback_secret_key')

# Database Configuration
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

# Initialize Extensions
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================== ROUTES ==================

@app.route('/')
def index():
    return render_template('index.html')

# ---------- AUTH ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        # Prevent manual registration of 'admin'
        if username.lower() == 'admin':
            flash('You cannot register with this username.', 'danger')
            return redirect(url_for('register'))

        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
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

# ---------- USER DASHBOARD ----------
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.username.lower() == 'admin':
        return redirect(url_for('admin_dashboard'))

    items = Item.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', items=items)


@app.route('/add_item', methods=['GET', 'POST'])
@login_required
def add_item():
    if current_user.username.lower() == 'admin':
        flash('Admins cannot report items.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        location = request.form['location']
        status = request.form['status']

        item = Item(
            name=name,
            description=description,
            location=location,
            status=status,
            user_id=current_user.id
        )
        db.session.add(item)
        db.session.commit()
        flash('Item added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('add_item.html')


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

# ---------- PUBLIC VIEW ----------
@app.route('/view_items')
def view_items():
    search = request.args.get('search', '')
    if search:
        items = Item.query.filter(
            Item.name.like(f'%{search}%') |
            Item.description.like(f'%{search}%') |
            Item.location.like(f'%{search}%')
        ).all()
    else:
        items = Item.query.all()
    return render_template('view_items.html', items=items)

# ---------- ADMIN DASHBOARD ----------
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.username.lower() != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    items = Item.query.all()
    users = User.query.all()
    return render_template('admin.html', items=items, users=users)


@app.route('/admin/edit_item/<int:item_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_item(item_id):
    if current_user.username.lower() != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    item = Item.query.get_or_404(item_id)

    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.location = request.form['location']
        item.status = request.form['status']
        db.session.commit()
        flash('Item updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_edit_item.html', item=item)


@app.route('/admin/delete_item/<int:item_id>')
@login_required
def admin_delete_item(item_id):
    if current_user.username.lower() != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash('Item deleted successfully.', 'info')
    return redirect(url_for('admin_dashboard'))


# ---------- TOGGLE RESOLVED STATUS ----------
@app.route('/admin/toggle_resolved/<int:item_id>', methods=['POST'])
@login_required
def admin_toggle_resolved(item_id):
    if current_user.username.lower() != 'admin':
        flash("Unauthorized access!", 'danger')
        return redirect(url_for('dashboard'))

    item = Item.query.get_or_404(item_id)
    item.is_resolved = not item.is_resolved
    db.session.commit()

    flash('Item status updated successfully!', 'success')
    return redirect(url_for('admin_dashboard'))


# ================== RUN APP ==================
if __name__ == '__main__':
    app.run(debug=True)

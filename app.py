from flask import Flask, render_template, request,url_for, redirect, session, flash, make_response
from flask_mail import Mail, Message
import mysql.connector
import bcrypt
import random
import config
import os
import razorpay
import traceback
import sqlite3
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
# Initialize Razorpay client
razorpay_client = razorpay.Client(auth=(config.RAZORPAY_KEY_ID,config.RAZORPAY_KEY_SECRET))
from utils.pdf_generator import generate_pdf
app = Flask(__name__)
app.secret_key = config.SECRET_KEY
s = URLSafeTimedSerializer(app.secret_key)
# ================= UPLOAD CONFIG =================
app.config['UPLOAD_FOLDER'] = 'static/uploads/product_images'
app.config['ADMIN_UPLOAD_FOLDER'] = 'static/uploads/admin_profiles'
app.config['USER_UPLOAD_FOLDER'] = 'static/uploads/user_profiles'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB limit

# ---------------- EMAIL CONFIGURATION ----------------
app.config['MAIL_SERVER'] = config.MAIL_SERVER
app.config['MAIL_PORT'] = config.MAIL_PORT
app.config['MAIL_USE_TLS'] = config.MAIL_USE_TLS
app.config['MAIL_USERNAME'] = config.MAIL_USERNAME
app.config['MAIL_PASSWORD'] = config.MAIL_PASSWORD
mail = Mail(app)

# ---------------- RAZORPAY ----------------
razorpay_client = razorpay.Client(
    auth=(config.RAZORPAY_KEY_ID, config.RAZORPAY_KEY_SECRET)
)

# ---------------- DATABASE CONNECTION ----------------
def get_db_connection():
    conn = sqlite3.connect('smartcart.db')
    conn.row_factory = sqlite3.Row  # allows dictionary-style access
    return conn


# =====================================================
# ROUTE 1: HOME
# =====================================================
@app.route('/')
def home():
    return render_template('home.html')


# =====================================================
# ROUTE 2: ADMIN SIGNUP (SEND OTP)
# =====================================================
@app.route('/admin-signup', methods=['GET', 'POST'])
def admin_signup():

    if request.method == "GET":
        return render_template("admin/admin_signup.html")

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT admin_id FROM admin WHERE email=?", (email,))
    existing_admin = cursor.fetchone()
    conn.close()

    if existing_admin:
        flash("This email is already registered. Please login instead.", "danger")
        return redirect('/admin-signup')

    session['signup_name'] = name
    session['signup_email'] = email
    session['signup_role'] = 'admin'

    otp = random.randint(100000, 999999)
    session['otp'] = otp

    message = Message(
        subject="SmartCart Admin OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP for SmartCart Admin Registration is: {otp}"
    mail.send(message)

    flash("OTP sent to your email!", "success")
    return redirect('/verify-otp')


# =====================================================
# ROUTE 3: VERIFY OTP + SAVE ADMIN
# =====================================================
@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():

    if request.method == 'GET':
        return render_template("admin/verify_otp.html")

    user_otp = request.form['otp']
    password = request.form['password']

    if str(session.get('otp')) != str(user_otp):
        flash("Invalid OTP. Try again!", "danger")
        return redirect('/verify-otp')

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO admin (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )

    conn.commit()
    conn.close()

    session.pop('otp', None)
    session.pop('signup_name', None)
    session.pop('signup_email', None)
    session.pop('signup_role', None)

    flash("Admin Registered Successfully!", "success")
    return redirect('/admin-login')


# =====================================================
# ROUTE 4: ADMIN LOGIN
# =====================================================
@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():

    if request.method == 'GET':
        return render_template("admin/admin_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE email=?", (email,))
    admin = cursor.fetchone()
    conn.close()

    if admin is None:
        flash("Email not found! Please register first.", "danger")
        return redirect('/admin-login')

    if not bcrypt.checkpw(password.encode('utf-8'), admin['password']):
        flash("Incorrect password! Try again.", "danger")
        return redirect('/admin-login')

    session['admin_id'] = admin['admin_id']
    session['admin_name'] = admin['name']
    session['admin_email'] = admin['email']

    flash("Login Successful!", "success")
    return redirect('/admin-dashboard')


# =====================================================
# ROUTE 5: ADMIN DASHBOARD
# =====================================================
@app.route('/admin-dashboard')
def admin_dashboard():

    if 'admin_id' not in session:
        flash("Please login to access dashboard!", "danger")
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch categories
    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    # Dynamic query
    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append(f"%{search}%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    query += " ORDER BY product_id DESC"

    cursor.execute(query, params)
    products = cursor.fetchall()

    conn.close()

    return render_template(
        "admin/dashboard.html",
        admin_name=session['admin_name'],
        products=products,
        categories=categories
    )


# =====================================================
# ROUTE 6: ADMIN LOGOUT
# =====================================================
@app.route('/admin-logout')
def admin_logout():

    session.pop('admin_id', None)
    session.pop('admin_name', None)
    session.pop('admin_email', None)

    flash("Logged out successfully.", "success")
    return redirect('/')
# =================================================================
# ROUTE 7: SHOW ADD PRODUCT PAGE
# =================================================================
@app.route('/admin/add-item', methods=['GET'])
def add_item_page():
    if 'admin_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/admin-login')
    return render_template("admin/add_item.html")

# =================================================================
# ROUTE 8: ADD PRODUCT
# =================================================================
@app.route('/admin/add-item', methods=['POST'])
def add_item():
    if 'admin_id' not in session:
        return redirect('/admin-login')

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    image_file = request.files['image']

    if image_file.filename == "":
        flash("Upload image!", "danger")
        return redirect('/admin/add-item')

    filename = secure_filename(image_file.filename)
    image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (name, description, category, price, image) VALUES (?, ?, ?, ?, ?)",
        (name, description, category, price, filename)
    )
    conn.commit()
    conn.close()

    flash("Product added successfully!", "success")
    return redirect('/admin-dashboard')

# =================================================================
# ROUTE 9: ITEM LIST
# =================================================================
@app.route('/admin/item-list')
def item_list():
    if 'admin_id' not in session:
        return redirect('/admin-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category = ?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()

    conn.close()

    return render_template(
        "admin/item_list.html",
        products=products,
        categories=categories
    )

# =================================================================
# ROUTE 10: VIEW SINGLE ITEM
# =================================================================
@app.route('/admin/view-item/<int:item_id>')
def view_item(item_id):
    if 'admin_id' not in session:
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()
    conn.close()

    if not product:
        return redirect('/admin/item-list')

    return render_template("admin/view_item.html", product=product)

# =================================================================
# ROUTE 11: SHOW UPDATE PAGE
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['GET'])
def update_item_page(item_id):
    if 'admin_id' not in session:
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()
    conn.close()

    if not product:
        return redirect('/admin/item-list')

    return render_template("admin/update_item.html", product=product)

# =================================================================
# ROUTE 12: UPDATE ITEM
# =================================================================
@app.route('/admin/update-item/<int:item_id>', methods=['POST'])
def update_item(item_id):
    if 'admin_id' not in session:
        return redirect('/admin-login')

    name = request.form['name']
    description = request.form['description']
    category = request.form['category']
    price = request.form['price']
    new_image = request.files['image']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()

    if not product:
        conn.close()
        return redirect('/admin/item-list')

    old_image_name = product['image']

    if new_image and new_image.filename != "":
        new_filename = secure_filename(new_image.filename)
        new_image.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))

        old_path = os.path.join(app.config['UPLOAD_FOLDER'], old_image_name)
        if os.path.exists(old_path):
            os.remove(old_path)

        final_image = new_filename
    else:
        final_image = old_image_name

    cursor.execute("""
        UPDATE products
        SET name=?, description=?, category=?, price=?, image=?
        WHERE product_id=?
    """, (name, description, category, price, final_image, item_id))

    conn.commit()
    conn.close()

    flash("Product updated!", "success")
    return redirect('/admin/item-list')

# =================================================================
# ROUTE 13: DELETE ITEM
# =================================================================
@app.route('/admin/delete-item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    if 'admin_id' not in session:
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT image FROM products WHERE product_id = ?", (item_id,))
    product = cursor.fetchone()

    if product:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product['image'])
        if os.path.exists(image_path):
            os.remove(image_path)

        cursor.execute("DELETE FROM products WHERE product_id = ?", (item_id,))
        conn.commit()

    conn.close()
    flash("Product deleted!", "success")
    return redirect('/admin-dashboard')

# =================================================================
# ROUTE 14: ADMIN PROFILE
# =================================================================
@app.route('/admin/profile', methods=['GET'])
def admin_profile():
    if 'admin_id' not in session:
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (session['admin_id'],))
    admin = cursor.fetchone()
    conn.close()

    return render_template("admin/admin_profile.html", admin=admin)

# =================================================================
# ROUTE 15: UPDATE ADMIN PROFILE
# =================================================================
@app.route('/admin/profile', methods=['POST'])
def admin_profile_update():
    if 'admin_id' not in session:
        return redirect('/admin-login')

    admin_id = session['admin_id']
    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admin WHERE admin_id = ?", (admin_id,))
    admin = cursor.fetchone()

    old_image = admin['profile_image']

    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
    else:
        hashed_password = admin['password']

    if new_image and new_image.filename != "":
        filename = secure_filename(new_image.filename)
        new_image.save(os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], filename))

        if old_image:
            old_path = os.path.join(app.config['ADMIN_UPLOAD_FOLDER'], old_image)
            if os.path.exists(old_path):
                os.remove(old_path)

        final_image = filename
    else:
        final_image = old_image

    cursor.execute("""
        UPDATE admin
        SET name=?, email=?, password=?, profile_image=?
        WHERE admin_id=?
    """, (name, email, hashed_password, final_image, admin_id))

    conn.commit()
    conn.close()

    session['admin_name'] = name
    session['admin_email'] = email

    flash("Profile updated!", "success")
    return redirect('/admin/profile')

# =================================================================
# ROUTE 16: ADMIN FORGOT PASSWORD
# =================================================================
@app.route("/admin/forgot", methods=["GET", "POST"])
def admin_forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE email = ?", (email,))
        admin = cursor.fetchone()
        conn.close()

        if not admin:
            flash("Admin email not found!", "danger")
            return redirect(url_for("admin_forgot_password"))

        token = s.dumps(email, salt="admin-password-reset")
        reset_link = url_for("admin_reset_password", token=token, _external=True)

        msg = Message(
            subject="Admin Password Reset",
            sender=config.MAIL_USERNAME,
            recipients=[email],
            body=f"""
Hello {admin['name']},

Click below to reset password:
{reset_link}

Valid for 5 minutes.
"""
        )
        mail.send(msg)

        flash("Reset link sent!", "success")
        return redirect(url_for("admin_login"))

    return render_template("admin/admin_forgot_password.html")
# =================================================================
# ROUTE 17: ADMIN RESET PASSWORD
# =================================================================
@app.route("/admin/reset/<token>", methods=["GET", "POST"])
def admin_reset_password(token):
    try:
        email = s.loads(token, salt="admin-password-reset", max_age=300)
    except SignatureExpired:
        flash("Reset link expired!", "danger")
        return redirect(url_for("admin_forgot_password"))
    except BadSignature:
        flash("Invalid reset link!", "danger")
        return redirect(url_for("admin_forgot_password"))

    if request.method == "POST":
        new_password = bcrypt.hashpw(
            request.form["password"].encode("utf-8"),
            bcrypt.gensalt()
        )

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE admin SET password=? WHERE email=?", (new_password, email))
        conn.commit()
        conn.close()

        flash("Admin password reset successfully!", "success")
        return redirect(url_for("admin_login"))

    return render_template("admin/admin_reset_password.html")


# ======================================================
# ROUTE 18: GLOBAL ADMIN CONTEXT
# ======================================================
@app.context_processor
def inject_admin():
    if 'admin_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM admin WHERE admin_id=?", (session['admin_id'],))
        admin = cursor.fetchone()
        conn.close()
        return dict(admin=admin)
    return dict(admin=None)


# =============================================================
# ROUTE 19: USER REGISTER
# =============================================================
@app.route('/user-register', methods=['GET', 'POST'])
def user_register():
    if request.method == "GET":
        return render_template("user/user_register.html")

    name = request.form['name']
    email = request.form['email']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users WHERE email=?", (email,))
    existing_user = cursor.fetchone()
    conn.close()

    if existing_user:
        flash("Email already registered!", "danger")
        return redirect('/user-register')

    session['signup_name'] = name
    session['signup_email'] = email
    session['signup_role'] = 'user'

    otp = random.randint(100000, 999999)
    session['otp'] = otp

    message = Message(
        subject="SmartCart User OTP",
        sender=config.MAIL_USERNAME,
        recipients=[email]
    )
    message.body = f"Your OTP is: {otp}"
    mail.send(message)

    flash("OTP sent!", "success")
    return redirect('/user-verify-otp')


# =============================================================
# ROUTE 20: USER OTP VERIFY
# =============================================================
@app.route('/user-verify-otp', methods=['GET', 'POST'])
def user_verify_otp():
    if request.method == 'GET':
        return render_template("user/user_verify_otp.html")

    if str(session.get('otp')) != request.form['otp']:
        flash("Invalid OTP!", "danger")
        return redirect('/user-verify-otp')

    hashed_password = bcrypt.hashpw(
        request.form['password'].encode(),
        bcrypt.gensalt()
    )

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
        (session['signup_name'], session['signup_email'], hashed_password)
    )
    conn.commit()
    conn.close()

    session.clear()

    flash("User registered successfully!", "success")
    return redirect('/user-login')


# =========================================================
# ROUTE 21: USER LOGIN
# =========================================================
@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'GET':
        return render_template("user/user_login.html")

    email = request.form['email']
    password = request.form['password']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email=?", (email,))
    user = cursor.fetchone()
    conn.close()

    if not user:
        flash("Email not found!", "danger")
        return redirect('/user-login')

    if not bcrypt.checkpw(password.encode(), user['password']):
        flash("Incorrect password!", "danger")
        return redirect('/user-login')

    session['user_id'] = user['user_id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']

    flash("Login Successful!", "success")
    return redirect(url_for('user_home'))


# ===========================================================
# ROUTE 22: USER HOME
# ===========================================================
@app.route('/user-home')
def user_home():
    if 'user_id' not in session:
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category=?"
        params.append(category_filter)


    cursor.execute(query, params)
    products = cursor.fetchall()
    conn.close()

    return render_template(
        "user/user_home.html",
        products=products,
        categories=categories,
        user_name=session.get('user_name')
    )


# ===========================================================
# ROUTE 23: USER PRODUCTS
# ===========================================================
@app.route('/user/products')
def user_products():
    if 'user_id' not in session:
        return redirect('/user-login')

    search = request.args.get('search', '')
    category_filter = request.args.get('category', '')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT category FROM products")
    categories = cursor.fetchall()

    query = "SELECT * FROM products WHERE 1=1"
    params = []

    if search:
        query += " AND name LIKE ?"
        params.append("%" + search + "%")

    if category_filter:
        query += " AND category=?"
        params.append(category_filter)

    cursor.execute(query, params)
    products = cursor.fetchall()
    conn.close()

    return render_template("user/user_products.html", products=products, categories=categories)


# ===========================================================
# ROUTE 24: USER PRODUCT DETAILS
# ===========================================================
@app.route('/user/product/<int:product_id>')
def user_product_details(product_id):
    if 'user_id' not in session:
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()
    conn.close()

    if not product:
        return redirect('/user/products')

    return render_template("user/product_details.html", product=product)
# =================================================================
# ROUTE 25: USER FORGOT PASSWORD (SQLite Version)
# =================================================================
@app.route("/user/forgot", methods=["GET", "POST"])
def user_forgot_password():
    if request.method == "POST":
        email = request.form["email"]

        conn = get_db_connection()
        conn.row_factory = sqlite3.Row   # Enables dict-style access
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if not user:
            flash("User email not found!", "danger")
            return redirect(url_for("user_forgot_password"))

        # 🔐 Generate reset token
        token = s.dumps(email, salt="user-password-reset")

        reset_link = url_for(
            "user_reset_password",
            token=token,
            _external=True
        )

        msg = Message(
            subject="Password Reset Request",
            sender="likhitharavi03@gmail.com",
            recipients=[email],
            body=f"""
Hello {user['name']},

Click the link below to reset your password:
{reset_link}

This link is valid for 5 minutes.
"""
        )
        mail.send(msg)

        flash("Password reset link sent to your email!", "success")
        return redirect(url_for("user_login"))

    return render_template("user/user_forgot_password.html")


# ===========================================================
# ROUTE 26: USER RESET PASSWORD
# ===========================================================
@app.route("/user/reset/<token>", methods=["GET", "POST"])
def user_reset_password(token):
    try:
        email = s.loads(token, salt="user-password-reset", max_age=300)
    except:
        flash("Invalid or expired link!", "danger")
        return redirect(url_for("user_forgot_password"))

    if request.method == "POST":
        new_password = bcrypt.hashpw(
            request.form["password"].encode(),
            bcrypt.gensalt()
        )

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET password=? WHERE email=?", (new_password, email))
        conn.commit()
        conn.close()

        flash("Password reset successful!", "success")
        return redirect(url_for("user_login"))

    return render_template("user/user_reset_password.html")


# ===========================================================
# ROUTE 27: USER LOGOUT
# ===========================================================
@app.route('/user-logout')
def user_logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect('/')
# ===============================================================
# ROUTE 28:SHOW USER PROFILE
# ===============================================================
USER_UPLOAD_FOLDER = 'static/uploads/user_profiles'
app.config['USER_UPLOAD_FOLDER'] = USER_UPLOAD_FOLDER

@app.route('/user/profile', methods=['GET'])
def user_profile():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    conn = get_db_connection()

    user = conn.execute(
        "SELECT * FROM users WHERE user_id = ?",
        (user_id,)
    ).fetchone()

    conn.close()

    return render_template("user/user_profile.html", user=user)

# ===============================================================
# ROUTE 29: UPDATE USER PROFILE
# ===============================================================
@app.route('/user/profile', methods=['POST'])
def user_profile_update():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    user_id = session['user_id']

    name = request.form['name']
    email = request.form['email']
    new_password = request.form['password']
    new_image = request.files['profile_image']

    conn = get_db_connection()

    # Get existing user
    user = conn.execute(
        "SELECT * FROM users WHERE user_id = ?",
        (user_id,)
    ).fetchone()

    old_image_name = user['profile_image']

    # Password update
    if new_password:
        hashed_password = bcrypt.hashpw(
            new_password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
    else:
        hashed_password = user['password']

    # Image update
    if new_image and new_image.filename != "":
        import uuid, os
        from werkzeug.utils import secure_filename

        filename = str(uuid.uuid4()) + "_" + secure_filename(new_image.filename)
        image_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], filename)
        new_image.save(image_path)

        if old_image_name:
            old_path = os.path.join(app.config['USER_UPLOAD_FOLDER'], old_image_name)
            if os.path.exists(old_path):
                os.remove(old_path)

        final_image_name = filename
    else:
        final_image_name = old_image_name

    # Update SQLite
    conn.execute("""
        UPDATE users
        SET name = ?,
            email = ?,
            password = ?,
            profile_image = ?
        WHERE user_id = ?
    """, (name, email, hashed_password, final_image_name, user_id))

    conn.commit()
    conn.close()

    session['user_name'] = name
    session['user_email'] = email
    session['user_image'] = final_image_name

    flash("Profile updated successfully!", "success")
    return redirect('/user/profile')


# ===========================================================
# ROUTE 30: ADD TO CART
# ===========================================================
@app.route('/user/add-to-cart/<int:product_id>')
def add_to_cart(product_id):

    if 'user_id' not in session:
        return redirect('/user-login')

    if 'cart' not in session:
        session['cart'] = {}

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE product_id=?", (product_id,))
    product = cursor.fetchone()
    conn.close()

    if not product:
        return redirect(request.referrer)

    cart = session['cart']
    pid = str(product_id)

    if pid in cart:
        cart[pid]['quantity'] += 1
    else:
        cart[pid] = {
            'name': product['name'],
            'price': float(product['price']),
            'image': product['image'],
            'quantity': 1
        }

    session['cart'] = cart
    flash("Item added to cart!", "success")
    return redirect(request.referrer)


# ===========================================================
# ROUTE 30: VIEW CART
# ===========================================================
@app.route('/user/cart')
def view_cart():
    if 'user_id' not in session:
        return redirect('/user-login')

    cart = session.get('cart', {})
    grand_total = sum(item['price'] * item['quantity'] for item in cart.values())

    return render_template("user/cart.html", cart=cart, grand_total=grand_total)
# =================================================================
# ROUTE 31: INCREASE QUANTITY
# =================================================================
@app.route('/user/cart/increase/<pid>')
def increase_quantity(pid):
    cart = session.get('cart', {})
    if pid in cart:
        cart[pid]['quantity'] += 1
    session['cart'] = cart
    return redirect('/user/cart')


# =================================================================
# ROUTE 32: DECREASE QUANTITY
# =================================================================
@app.route('/user/cart/decrease/<pid>')
def decrease_quantity(pid):
    cart = session.get('cart', {})
    if pid in cart:
        cart[pid]['quantity'] -= 1
        if cart[pid]['quantity'] <= 0:
            cart.pop(pid)
    session['cart'] = cart
    return redirect('/user/cart')


# =================================================================
# ROUTE 33: REMOVE ITEM
# =================================================================
@app.route('/user/cart/remove/<pid>')
def remove_from_cart(pid):
    cart = session.get('cart', {})
    if pid in cart:
        cart.pop(pid)
    session['cart'] = cart
    flash("Item removed!", "success")
    return redirect('/user/cart')


# ======================================================
# ROUTE 34: GLOBAL USER CONTEXT
# ======================================================
@app.context_processor
def inject_user():
    if 'user_id' in session:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id=?", (session['user_id'],))
        user = cursor.fetchone()
        conn.close()
        return dict(user=user)
    return dict(user=None)


# ===============================================================
# ROUTE 35: CREATE RAZORPAY ORDER
# ===============================================================
@app.route('/user/pay')
def user_pay():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    cart = session.get('cart', {})
    if not cart:
        flash("Cart is empty!", "danger")
        return redirect('/user/products')

    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    razorpay_order = razorpay_client.order.create({
        "amount": int(total_amount * 100),
        "currency": "INR",
        "payment_capture": 1
    })

    session['razorpay_order_id'] = razorpay_order['id']

    return render_template(
        "user/payment.html",
        key_id=config.RAZORPAY_KEY_ID,
        amount=total_amount,
        order_id=razorpay_order['id']
    )


# ===============================================================
# ROUTE 36: PAYMENT SUCCESS (AJAX)
# ===============================================================
@app.route('/user/payment-success', methods=['POST'])
def payment_success():

    data = request.get_json()

    if 'user_id' not in session:
        return jsonify({"redirect_url": "/user-login"})

    cart = session.get('cart', {})
    address_data = session.get('delivery_address')

    if not cart or not address_data:
        return jsonify({"redirect_url": "/user/products"})

    conn = get_db_connection()
    cursor = conn.cursor()

    total_amount = sum(item['price'] * item['quantity'] for item in cart.values())

    cursor.execute("""
        INSERT INTO orders 
        (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status,
         name, phone, address, city, pincode)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session['user_id'],
        data.get("order_id"),
        data.get("payment_id"),
        total_amount,
        "paid",
        address_data['name'],
        address_data['phone'],
        address_data['address'],
        address_data['city'],
        address_data['pincode']
    ))

    order_id = cursor.lastrowid

    for pid, item in cart.items():
        cursor.execute("""
            INSERT INTO order_items 
            (order_id, product_id, quantity, price)
            VALUES (?, ?, ?, ?)
        """, (
            order_id,
            pid,
            item['quantity'],
            item['price']
        ))

    conn.commit()
    conn.close()

    session.pop('cart', None)
    session.pop('delivery_address', None)

    return jsonify({
        "redirect_url": url_for('order_success', order_db_id=order_id)
    })
# ------------------------------
# ROUTE 37: Verify Payment and Store Order (SQLite)
# ------------------------------
@app.route('/verify-payment', methods=['POST'])
def verify_payment():

    if 'user_id' not in session:
        flash("Please login to complete the payment.", "danger")
        return redirect('/user-login')

    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_signature = request.form.get('razorpay_signature')

    if not (razorpay_payment_id and razorpay_order_id and razorpay_signature):
        flash("Payment verification failed (missing data).", "danger")
        return redirect('/user/cart')

    payload = {
        'razorpay_order_id': razorpay_order_id,
        'razorpay_payment_id': razorpay_payment_id,
        'razorpay_signature': razorpay_signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(payload)
    except Exception as e:
        app.logger.error("Razorpay verification failed: %s", str(e))
        flash("Payment verification failed. Contact support.", "danger")
        return redirect('/user/cart')

    # ------------------------------
    # Store Order in SQLite
    # ------------------------------

    user_id = session['user_id']
    cart = session.get('cart', {})

    if not cart:
        flash("Cart is empty. Cannot create order.", "danger")
        return redirect('/user/products')

    total_amount = sum(
        item['price'] * item['quantity']
        for item in cart.values()
    )

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # ✅ Insert into orders table
        cursor.execute("""
            INSERT INTO orders
            (user_id, razorpay_order_id, razorpay_payment_id, amount, payment_status)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id,
            razorpay_order_id,
            razorpay_payment_id,
            total_amount,
            'paid'
        ))

        order_db_id = cursor.lastrowid

        # ✅ Insert order items
        for pid_str, item in cart.items():
            product_id = int(pid_str)

            cursor.execute("""
                INSERT INTO order_items
                (order_id, product_id, product_name, quantity, price)
                VALUES (?, ?, ?, ?, ?)
            """, (
                order_db_id,
                product_id,
                item['name'],
                item['quantity'],
                item['price']
            ))

        conn.commit()

        # ✅ Clear session cart
        session.pop('cart', None)
        session.pop('razorpay_order_id', None)

        flash("Payment successful and order placed!", "success")
        return redirect(f"/user/order-success/{order_db_id}")

    except Exception as e:
        conn.rollback()
        app.logger.error("Order storage failed: %s\n%s", str(e), traceback.format_exc())
        flash("Error saving order. Contact support.", "danger")
        return redirect('/user/cart')

    finally:
        cursor.close()
        conn.close()


# ===============================================================
# ROUTE 38: MY ORDERS
# ===============================================================
@app.route('/user/my-orders')
def my_orders():

    if 'user_id' not in session:
        flash("Please login!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM orders 
        WHERE user_id=?
        ORDER BY created_at DESC
    """, (session['user_id'],))

    orders = cursor.fetchall()
    conn.close()

    return render_template("user/my_orders.html", orders=orders)


# ===============================================================
# ROUTE 39: ORDER SUCCESS
# ===============================================================

@app.route('/user/order-success/<int:order_db_id>')
def order_success(order_db_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row   # ✅ Important for it.name
    cursor = conn.cursor()

    # ---------------------------------------------------
    # 1️⃣ Get Order (Only if belongs to logged-in user)
    # ---------------------------------------------------
    cursor.execute("""
        SELECT *
        FROM orders
        WHERE order_id=? AND user_id=?
    """, (order_db_id, session['user_id']))

    order = cursor.fetchone()

    if not order:
        conn.close()
        flash("Order not found!", "danger")
        return redirect('/user/my-orders')

    # ---------------------------------------------------
    # 2️⃣ Get Order Items WITH Product Name
    # ---------------------------------------------------
    cursor.execute("""
        SELECT 
            p.name AS name,
            oi.quantity AS quantity,
            oi.price AS price
        FROM order_items oi
        JOIN products p 
            ON oi.product_id = p.product_id
        WHERE oi.order_id=?
    """, (order_db_id,))

    items = cursor.fetchall()

    conn.close()

    # ---------------------------------------------------
    # 3️⃣ Render Page
    # ---------------------------------------------------
    return render_template(
        "user/order_success.html",
        order=order,
        items=items
    )

# ---------------------------------------------------
# ROUTE 40: DELIVERY ADDRESS
# ---------------------------------------------------
@app.route('/user/address', methods=['GET', 'POST'])
def delivery_address():

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    if request.method == 'POST':

        session['delivery_address'] = {
            "name": request.form.get("name"),
            "phone": request.form.get("phone"),
            "address": request.form.get("address"),
            "city": request.form.get("city"),
            "pincode": request.form.get("pincode")
        }

        return redirect(url_for('user_pay'))

    return render_template("user/add_address.html")
# ---------------------------------------------------
# ROUTE 41: INVOICE PDF (SQLite)
# ---------------------------------------------------
@app.route("/user/download-invoice/<int:order_id>")
def download_invoice(order_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # ✅ Get Order
    cursor.execute("""
        SELECT * FROM orders
        WHERE order_id=? AND user_id=?
    """, (order_id, session['user_id']))

    order = cursor.fetchone()

    if not order:
        conn.close()
        flash("Order not found!", "danger")
        return redirect('/user/my-orders')

    # ✅ Get Order Items
    cursor.execute("""
        SELECT p.name, oi.quantity, oi.price
        FROM order_items oi
        JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id=?
    """, (order_id,))

    items = cursor.fetchall()

    conn.close()

    html = render_template(
        "user/invoice.html",
        order=order,
        items=items
    )

    pdf = generate_pdf(html)

    if pdf is None:
        flash("Error generating invoice.", "danger")
        return redirect('/user/my-orders')

    response = make_response(pdf.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=invoice_{order_id}.pdf'

    return response

# ---------------------------------------------------
# ROUTE 42: DELETE ORDER (SQLite)
# ---------------------------------------------------
@app.route("/user/delete-order/<int:order_id>")
def delete_order(order_id):

    if 'user_id' not in session:
        flash("Please login first!", "danger")
        return redirect('/user-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # 🔐 Make sure user owns this order
    cursor.execute("""
        SELECT order_id FROM orders
        WHERE order_id=? AND user_id=?
    """, (order_id, session['user_id']))

    order = cursor.fetchone()

    if not order:
        conn.close()
        flash("Order not found!", "danger")
        return redirect('/user/my-orders')

    # 🔥 Delete order items first
    cursor.execute("DELETE FROM order_items WHERE order_id=?", (order_id,))

    # 🔥 Then delete order
    cursor.execute("DELETE FROM orders WHERE order_id=?", (order_id,))

    conn.commit()
    conn.close()

    flash("Order deleted successfully.", "success")
    return redirect('/user/my-orders')
# ===============================================================
# ROUTE 42: ADMIN VIEW ALL ORDERS
# ===============================================================
@app.route('/admin/orders')
def admin_orders():

    if 'admin_id' not in session:
        flash("Please login as admin!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT o.order_id, o.user_id, o.amount, 
               o.payment_status, o.order_status, o.created_at,
               u.name AS username
        FROM orders o
        LEFT JOIN users u ON o.user_id = u.user_id
        ORDER BY o.created_at DESC
    """)

    orders = cursor.fetchall()
    conn.close()

    return render_template("admin/order_list.html", orders=orders)

#================================================================
#ROUTE 43:Admin: View Single Order with Items
# ================================================================

@app.route('/admin/order/<int:order_id>')
def admin_order_details(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    conn = get_db_connection()
    cursor = conn.cursor()

    # Get order info
    cursor.execute("""
        SELECT *
        FROM orders
        WHERE order_id = ?
    """, (order_id,))
    order = cursor.fetchone()

    # ✅ FIXED: Join products table to get product name
    cursor.execute("""
        SELECT 
            oi.quantity,
            oi.price,
            p.name AS product_name
        FROM order_items oi
        JOIN products p ON oi.product_id = p.product_id
        WHERE oi.order_id = ?
    """, (order_id,))

    items = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template(
        "admin/order_details.html",
        order=order,
        items=items
    )


# ===============================================================
# ROUTE 44: ADMIN UPDATE ORDER STATUS
# ===============================================================
@app.route("/admin/update-order-status/<int:order_id>", methods=['POST'])
def update_order_status(order_id):

    if 'admin_id' not in session:
        flash("Please login!", "danger")
        return redirect('/admin-login')

    new_status = request.form.get('status')

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("UPDATE orders SET order_status=? WHERE order_id=?",
                   (new_status, order_id))

    conn.commit()
    conn.close()

    flash("Order status updated successfully!", "success")
    return redirect(f"/admin/order/{order_id}")


# =====================================================
# MAIN
# =====================================================
if __name__ == "__main__":
    app.run(debug=True)

from flask import Flask, render_template, url_for, redirect, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField, FloatField, IntegerField
from wtforms import BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, InputRequired, Length, ValidationError, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from functools import wraps
from flask_bcrypt import Bcrypt
from flask_bcrypt import check_password_hash
from datetime import datetime
from flask import jsonify
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import generate_csrf


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///grocery.db"
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager(app)
login_manager.login_view = 'user_login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(Users, int(user_id))


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    carts = db.relationship('Cart', backref='user', lazy=True)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class UserLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login as User')

class AdminLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login as Admin')

def create_initial_admin():
    admin_username = "admin"
    admin_password = "admin_password"  # Replace with a secure password
    
    # Check if admin user already exists
    admin = Users.query.filter_by(username=admin_username, role='admin').first()
    if admin:
        print("Admin user already exists.")
    else:
        hashed_password = bcrypt.generate_password_hash(admin_password).decode('utf-8')
        admin = Users(username=admin_username, password=hashed_password, role='admin')
        db.session.add(admin)
        db.session.commit()
        print("Initial admin user created.")

@app.route('/',  methods=['GET', 'POST'])
def index():
    categories = Category.query.all()
    return render_template('index.html', categories=categories)

@app.route('/search', methods=['GET'])
def search():
    search_query = request.args.get('q')  # Get the search query from the URL parameter
    if search_query:
        products = Product.query.filter(Product.name.ilike(f'%{search_query}%')).all()
    else:
        products = []

    return render_template('search_results.html', products=products, search_query=search_query)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = Users(username=form.username.data, password=hashed_password, role='user')
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('user_login'))
    return render_template('register.html', form=form)


@app.route('/user-login', methods=['GET', 'POST'])
def user_login():
    form = UserLoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('user_dashboard'))
        else:
            flash('Login unsuccessful. Please check username and password.', 'danger')
    return render_template('user_login.html', form=form)

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data) and user.role == 'admin':
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Admin login unsuccessful. Please check username and password.', 'danger')
    return render_template('admin_login.html', form=form)




@app.route('/user-dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    categories = Category.query.all()
    return render_template('user_dashboard.html', categories=categories)

@app.route('/admin-dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if current_user.role == 'admin':
        return render_template('admin_dashboard.html')
    else:
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('user_login'))

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)

    products = db.relationship('Product', backref='category', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    manufacture_date = db.Column(db.Date)
    expiry_date = db.Column(db.Date)
    unit = db.Column(db.String(50))
    rate_per_unit = db.Column(db.String(50))  # For example, "Rs/Kg", "Rs/Litre"
    price = db.Column(db.Float, nullable=False)
    available_quantity = db.Column(db.Float, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    carts = db.relationship('Cart', backref='product', lazy=True)
    user_products = db.relationship('UserProduct', backref='product', lazy=True)

class CategoryForm(FlaskForm):
    name = StringField('Category Name', validators=[DataRequired()])
    submit = SubmitField('save')

class ProductForm(FlaskForm):
    name = StringField('Product Name', validators=[DataRequired()])
    manufacture_date = DateField('Manufacture Date', validators=[DataRequired()])
    expiry_date = DateField('Expiry Date', validators=[DataRequired()])
    unit = SelectField('Unit', choices=[
        ('Rs/Kg', 'Rs/Kg'),
        ('Rs/Litre', 'Rs/Litre'),
        ('Rs/dozen', 'Rs/dozen'),
        ('Rs/gram', 'Rs/gram'),
        ('Rs/one piece', 'Rs/one piece')
    ], validators=[DataRequired()])
    rate_per_unit = StringField('Rate per Unit', validators=[DataRequired()])
    price = FloatField('Price', validators=[DataRequired()])
    available_quantity = FloatField('Available Quantity', validators=[DataRequired()])
    submit = SubmitField('Create Product')

@app.route('/admin-dashboard/create-category', methods=['GET', 'POST'])
@login_required
def create_category():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))

    form = CategoryForm()
    if form.validate_on_submit():
        new_category = Category(name=form.name.data)
        db.session.add(new_category)
        db.session.commit()
        flash('New category created successfully!', 'success')
        return redirect(url_for('categories'))
    
    # categories = Category.query.all()
    return render_template('create_category.html',  form=form)

@app.route('/admin-dashboard/categories', methods=['GET', 'POST'])
@login_required
def categories():
    categories = Category.query.all()
    return render_template('categories.html', categories=categories)

@app.route('/admin-dashboard/edit-category/<int:category_id>', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    category = Category.query.get_or_404(category_id)

    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))

    form = CategoryForm()
    if form.validate_on_submit():
        category.name = form.name.data
        db.session.commit()
        flash('Category updated successfully!', 'success')
        return redirect(url_for('categories'))

    form.name.data = category.name
    return render_template('edit_category.html', form=form, category=category)

@app.route('/admin-dashboard/delete-category/<int:category_id>', methods=['GET', 'POST'])
@login_required
def delete_category(category_id):
    category = Category.query.get_or_404(category_id)

    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))

    db.session.delete(category)
    db.session.commit()
    flash('Category deleted successfully!', 'success')

    return redirect(url_for('categories'))

@app.route('/admin-dashboard/create-product/<int:category_id>', methods=['GET','POST'])
@login_required
def create_product(category_id):
    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))
    
    form = ProductForm()

    if request.method == 'POST':
        category_id = category_id
        name = request.form.get('name')
        manufacture_date = datetime.strptime(request.form.get('manufacture_date'), '%Y-%m-%d').date()
        expiry_date = datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d').date()
        unit = request.form.get('unit')
        rate_per_unit = request.form.get('rate_per_unit')
        price = request.form.get('price')
        available_quantity = request.form.get('available_quantity')

        new_product = Product(
            category_id=category_id,
            name=name,
            manufacture_date=manufacture_date,
            expiry_date=expiry_date,
            rate_per_unit=rate_per_unit,
            price=price,
            available_quantity=available_quantity,
            unit=unit
        )

        db.session.add(new_product)
        db.session.commit()
        flash('New product created successfully!', 'success')
        return redirect(url_for('categories'))
    
    category = Category.query.get_or_404(category_id)
    
    return render_template('create_product.html',category_id=category_id, form=form)

@app.route('/admin-dashboard/edit-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)

    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))

    form = ProductForm()

    if request.method == 'POST':
        product.name = request.form.get('name')
        product.manufacture_date = datetime.strptime(request.form.get('manufacture_date'), '%Y-%m-%d').date()
        product.expiry_date = datetime.strptime(request.form.get('expiry_date'), '%Y-%m-%d').date()
        product.unit = request.form.get('unit')
        product.rate_per_unit = request.form.get('rate_per_unit')
        product.price = request.form.get('price')
        product.available_quantity = request.form.get('available_quantity')

        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('categories'))

    form.name.data = product.name
    form.manufacture_date.data = product.manufacture_date
    form.expiry_date.data = product.expiry_date
    form.unit.data = product.unit
    form.rate_per_unit.data = product.rate_per_unit
    form.price.data = product.price
    form.available_quantity.data = product.available_quantity

    return render_template('edit_product.html', product_id=product_id, form=form, product=product)

@app.route('/admin-dashboard/delete-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('user_dashboard'))

    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')

    return redirect(url_for('categories'))



class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)

class UserProduct(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    purchase_date = db.Column(db.DateTime, default=datetime.utcnow)  # Add purchase date
    
    user = db.relationship('Users', backref='user_products')

class BuyProductForm(FlaskForm):
    quantity = IntegerField('Quantity', validators=[InputRequired(), NumberRange(min=1)])
    submit = SubmitField('Buy')

@app.route('/add-to-cart/<int:product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    quantity = int(request.form.get('quantity', 1))

    user_cart = Cart.query.filter_by(user=current_user, product=product).first()

    if user_cart:
        user_cart.quantity += quantity
    else:
        user_cart = Cart(user=current_user, product=product, quantity=quantity)
        db.session.add(user_cart)

    db.session.commit()

    flash('Product added to cart successfully!', 'success')
    return redirect(request.referrer)


@app.route('/user-dashboard/cart', methods=['GET', 'POST'])
@login_required
def cart():
    user_carts = Cart.query.filter_by(user=current_user).all()
    total_price = sum(float(cart.product.rate_per_unit) * cart.quantity for cart in user_carts)
    return render_template('cart.html', user_carts=user_carts, total_price=total_price)


   

@app.route('/user-dashboard/buy-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def buy_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = BuyProductForm()

    if form.validate_on_submit():
        quantity = form.quantity.data
        if product.available_quantity is not None and quantity is not None:
            if quantity <= product.available_quantity:
                # Create a purchased item for the user
                purchased_item = UserProduct(user=current_user, product=product, quantity=quantity)
                db.session.add(purchased_item)
                
                # Update available quantity of the product
                product.available_quantity -= quantity
                
                # Add the product to the user's cart
                cart_item = Cart(user=current_user, product=product, quantity=quantity)
                db.session.add(cart_item)
                
                db.session.commit()
                flash('Product purchased successfully!', 'success')
                return redirect(url_for('cart'))
            else:
                flash('Insufficient stock. Please select a lower quantity.', 'danger')
        else:
            flash('Invalid quantity.', 'danger')

    return render_template('buy_product.html', product=product, form=form)

@app.route('/cart/remove-from-cart/<int:product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    product = Product.query.get_or_404(product_id)
    cart_item = Cart.query.filter_by(user=current_user, product=product).first()

    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Product removed from cart successfully!', 'success')
    else:
        flash('Product not found in your cart.', 'danger')

    return redirect(url_for('cart'))

@app.route('/user-dashboard/review-product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def review_product(product_id):
    product = Product.query.get_or_404(product_id)
    form = BuyProductForm()

    existing_cart_item = Cart.query.filter_by(user=current_user, product=product).first()

    if form.validate_on_submit():
        new_quantity = form.quantity.data

        if existing_cart_item:
            existing_cart_item.quantity = new_quantity
        else:
            new_cart_item = Cart(user=current_user, product=product, quantity=new_quantity)
            db.session.add(new_cart_item)

        db.session.commit()
        flash('Product quantity updated successfully!', 'success')
        return redirect(url_for('cart'))

    form.quantity.data = existing_cart_item.quantity if existing_cart_item else 1

    return render_template('review_product.html', product=product, form=form)



@app.route('/user-dashboard/user-profile')
@login_required
def user_profile():
    # Logic to fetch and display user profile
    return render_template('user_profile.html', current_user=current_user)

if __name__ == '__main__':
    with app.app_context(): 
        db.create_all()
        create_initial_admin()
    app.run(debug=True)
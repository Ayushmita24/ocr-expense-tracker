from flask import Flask, render_template, request, redirect, url_for,session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import pytesseract
from PIL import Image
import os
import re
from werkzeug.utils import secure_filename
from collections import defaultdict
from datetime import datetime
from functools import wraps
from flask import session, flash
from flask_session import Session  
from werkzeug.security import generate_password_hash, check_password_hash


#login and logout

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Initialize Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'  # Important: fix KeyError
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expense.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = '1234567890'
# Session config
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions on the filesystem
Session(app)  # Initialize session handling


# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Tesseract OCR path
pytesseract.pytesseract.tesseract_cmd = r'C:\Users\ayush\AppData\Local\Programs\Tesseract-OCR\tesseract.exe'

# Define User model (for login system)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
def __repr__(self):
    return f"<User {self.username}>"  
  
# Define Expense model
class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    date = db.Column(db.String(20))
    category = db.Column(db.String(50))  # New field
    amount = db.Column(db.String(20))
    text = db.Column(db.Text)

    def __repr__(self):
        return f"<Expense {self.name} - {self.amount}>"

# Create database (for dev use)
with app.app_context():
    db.create_all()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print("Session value:", session.get('logged_in'))  # Debug info in console
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Home route
@app.route('/')
@login_required
def index():
    return render_template('index.html')

# Upload receipt
@app.route('/upload', methods=['POST'])
def upload():
    if 'receipt' not in request.files:
        return 'No file uploaded', 400

    file = request.files['receipt']
    expense_name = request.form.get('expense_name', 'Unknown')
    expense_date = request.form.get('expense_date', 'Unknown')
    category = request.form.get('category', 'Other')

    if file.filename == '':
        return 'No file selected', 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # OCR process
    try:
        image = Image.open(filepath).convert('L')
        extracted_text = pytesseract.image_to_string(image, lang='eng')
    except Exception as e:
        return f"OCR Failed: {e}", 500

    # Extract amount
    lines = extracted_text.split('\n')
    amount = 0.0
    currency_symbol = ""

    # Cleaned lines
    cleaned_lines = [line.strip().lower() for line in lines if line.strip()]
    
    # 1. Try to find "Grand Total"
    for line in cleaned_lines:
        if "grand total" in line:
            match = re.search(r'(₹|rs\.?|inr|\$|€)?\s?(\d{1,6}(?:\.\d{2})?)', line)
            if match:
                currency_symbol = match.group(1) or ""
                amount = float(match.group(2))
                break
    
    # 2. If not found, search for "total" but skip "subtotal"
    if not amount:
        for line in cleaned_lines:
            if "total" in line and "subtotal" not in line:
                match = re.search(r'(₹|rs\.?|inr|\$|€)?\s?(\d{1,6}(?:\.\d{2})?)', line)
                if match:
                    currency_symbol = match.group(1) or ""
                    amount = float(match.group(2))
                    break
    
    # 3. Fallback to any valid amount in text, with a filter
    if not amount:
        matches = re.findall(r'(₹|rs\.?|inr|\$|€)?\s?(\d{1,6}(?:\.\d{2})?)', extracted_text.lower())
        candidates = []
        for sym, val in matches:
            val = float(val)
            if 10 <= val <= 5000:  # filter out unrealistic values
                candidates.append((sym, val))
        if candidates:
            # pick the smallest valid amount assuming OCR might overestimate
            currency_symbol, amount = min(candidates, key=lambda x: x[1])

    # Format currency
    if currency_symbol in ["rs.", "rs", "inr"]:
        currency_symbol = "₹"
    formatted_amount = f"{currency_symbol}{amount:,.2f}".replace("₹₹", "₹")

    # Save to DB
    new_expense = Expense(
        name=expense_name,
        date=expense_date,
        category=category,
        amount=formatted_amount,
        text=extracted_text
        )
    db.session.add(new_expense)
    db.session.commit()
    result = {
        'name': expense_name,
        'date': expense_date,
        'category': category,
        'amount': formatted_amount,
        'text': extracted_text
    }
    return render_template('result.html', result=result)

# View all saved expenses
@app.route('/expenses')
def view_expenses():
    search_name = request.args.get('name', '')
    search_date = request.args.get('date', '')

    query = Expense.query
    if search_name:
        query = query.filter(Expense.name.ilike(f'%{search_name}%'))
    if search_date:
        query = query.filter(Expense.date == search_date)

    expenses = query.order_by(Expense.id.desc()).all()
    return render_template('expenses.html', expenses=expenses, search_name=search_name, search_date=search_date)

# Dashboard with graphs
@app.route('/dashboard')
def dashboard():
    all_expenses = Expense.query.all()
    monthly_data = defaultdict(float)
    category_data = defaultdict(float)
    top_expenses = []

    for exp in all_expenses:
        try:
            amt = float(exp.amount.replace("₹", "").replace(",", ""))
        except:
            continue

        try:
            month = datetime.strptime(exp.date, "%Y-%m-%d").strftime("%b %Y")
        except:
            month = "Unknown"

        monthly_data[month] += amt
        category_data[exp.category] += amt
        top_expenses.append((exp.name, amt))

    top_expenses.sort(key=lambda x: x[1], reverse=True)
    top_expenses = top_expenses[:5]

    return render_template("dashboard.html",
        monthly_labels=list(monthly_data.keys()),
        monthly_values=list(monthly_data.values()),
        category_labels=list(category_data.keys()),
        category_values=list(category_data.values()),
        top_expenses=top_expenses
    )

# Download the csv or excel     
@app.route('/download_csv')
def download_csv():
    import csv
    from flask import make_response

    expenses = Expense.query.all()

    si = []
    si.append(['Name', 'Date', 'Category', 'Amount', 'Extracted Text'])
    for exp in expenses:
        si.append([exp.name, exp.date, exp.category, exp.amount, exp.text])

    response = make_response('\n'.join([','.join(map(str, row)) for row in si]))
    response.headers["Content-Disposition"] = "attachment; filename=expenses.csv"
    response.headers["Content-type"] = "text/csv"
    return response

# edit_expense 
@app.route('/edit/<int:expense_id>', methods=['GET', 'POST'])
def edit_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)

    if request.method == 'POST':
        expense.name = request.form['name']
        expense.date = request.form['date']
        expense.category = request.form['category']
        expense.amount = request.form['amount']
        expense.text = request.form['text']
        db.session.commit()
        return redirect(url_for('view_expenses'))

    return render_template('edit.html', expense=expense)

# delete_expense using POST method

@app.route('/delete/<int:expense_id>', methods=['POST'])
def delete_expense(expense_id):
    expense = Expense.query.get_or_404(expense_id)
    db.session.delete(expense)
    db.session.commit()
    return redirect(url_for('view_expenses'))

# login page here use GET and POST methods
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        action = request.form.get('action')

        # LOGIN FLOW
        if action == 'login':
            username = request.form.get('username')
            password = request.form.get('password')

            user = User.query.filter_by(username=username).first()
            print("🔍 Username:", username)
            print("🧠 User from DB:", user)

            if user and check_password_hash(user.password, password):
                session['logged_in'] = True
                session['username'] = user.username
                print("Session value:", session.get('logged_in'))
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error='Invalid credentials')

        # REGISTER FLOW
        elif action == 'register':
            reg_username = request.form.get('reg_username')
            reg_password = request.form.get('reg_password')

            existing_user = User.query.filter_by(username=reg_username).first()
            if existing_user:
                return render_template('login.html', register_error='Username already exists')

            hashed_password = generate_password_hash(reg_password)
            new_user = User(username=reg_username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return render_template('login.html', success='Registration successful! Please log in.')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    print("🔒 Logout route triggered")
    session.clear()

    user_exists = User.query.first() is not None
    print("User exists after logout:", user_exists)

    flash('Logged out successfully!', 'info')

    if not user_exists:
        return redirect(url_for('login'))  # Since register is handled in login.html
    return redirect(url_for('login'))

#navbar

@app.route('/navbar')
def navbar():
    return render_template('navbar.html')

#feature 

@app.route('/features')
def features():
    return render_template('feature.html')

# Run app
if __name__ == '__main__':
    if not os.path.exists('uploads'):
        os.makedirs('uploads')
    with app.app_context():
        db.create_all()
    app.run(debug=True)



from flask import Flask, render_template, request, redirect, url_for, session,flash
from flask_mysqldb import MySQL
import MySQLdb.cursors
import smtplib
from email.message import EmailMessage
from twilio.rest import Client
import bcrypt
import requests
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DecimalField, SelectField
from wtforms.validators import DataRequired, Email, Length, ValidationError, EqualTo, optional, NumberRange
import MySQLdb.cursors
import re
import pyotp
import qrcode
import os
import time
from datetime import datetime, timedelta
import rsa
import uuid
from user_agents import parse
from device_detector import DeviceDetector
from datetime import datetime
import calendar

import Transaction

app = Flask(__name__)
app.secret_key = 'your_secret_key'

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'mysql'
app.config['MYSQL_DB'] = 'pythonlogin'
app.config['MYSQL_PORT'] = 3306
app.config['charset'] = 'utf8mb4'
mysql = MySQL(app)

pubkey, privkey = rsa.newkeys(2048)

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_L,
    box_size=10,
    border=4,
)
qr.make(fit=True)
img = qr.make_image(fill_color="black", back_color="white")

img.save(os.path.join('static', 'qrcode.png'))

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

class TransactionForm(FlaskForm):
    recipient_username = StringField('Recipient Username', validators=[DataRequired()])
    amount = DecimalField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    submit = SubmitField('Make Transaction')

# Define questions and answers based on video
QUESTIONS = {
    'vid1': {
        'question': "What is one of the consequences of lacking financial literacy?",
        'correct_answer': "Taking on too much personal debt and having little to no savings",
        'options': ["Having too much disposable income",
                    "Being able to deal with unexpected emergencies easily",
                    "Taking on too much personal debt and having little to no savings",
                    "Achieving financial stability quickly"]
    },
    'vid2': {
        'question': "What is the main difference between a debit card and a credit card?",
        'correct_answer': "A debit card is linked to a bank account, while a credit card is a type of loan from a financial institution.",
        'options': ["A debit card is issued by a credit card company, while a credit card is linked to a bank account.",
                    "A debit card is linked to a bank account, while a credit card is a type of loan from a financial institution.",
                    "A debit card can be used to borrow money, while a credit card can be only used to make purchases.",
                    "A debit card has a higher credit limit than a credit card."]
    }
}


@app.route('/videos', methods=['GET', 'POST'])
def quiz():
    feedback = {}

    if request.method == 'POST':
        # Handle vid1 form submission
        if 'vid1_submit' in request.form:
            selected_option = request.form.get('vid1_option')
            correct_answer = QUESTIONS['vid1']['correct_answer']
            if selected_option:
                if selected_option == correct_answer:
                    feedback['vid1'] = "Correct!"
                else:
                    feedback['vid1'] = f"Wrong! The correct answer is {correct_answer}."
            else:
                feedback['vid1'] = "Please select a choice."

        # Handle vid2 form submission
        if 'vid2_submit' in request.form:
            selected_option = request.form.get('vid2_option')
            correct_answer = QUESTIONS['vid2']['correct_answer']
            if selected_option:
                if selected_option == correct_answer:
                    feedback['vid2'] = "Correct!"
                else:
                    feedback['vid2'] = f"Wrong! The correct answer is {correct_answer}."
            else:
                feedback['vid2'] = "Please select a choice."

    return render_template('videos.html', questions=QUESTIONS, feedback=feedback)
@app.route('/leaderboard')
def leaderboard():
    if 'loggedin' in session and session['loggedin'] and session.get('2fa', False):
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('home'))
    # Example data: Rankings with names and XP in descending order
    rankings = [
        {"rank": 1, "name": f"{user['username']}", "xp": 1500},
        {"rank": 2, "name": "Mohnish", "xp": 1400},
        {"rank": 3, "name": "Liam", "xp": 1300},
        {"rank": 4, "name": "John", "xp": 1200},  # Honorable Mention
        {"rank": 5, "name": "Alex", "xp": 1100}  # Honorable Mention
    ]
    return render_template('leaderboard.html', rankings=rankings)

def generate_otp():
    secret = pyotp.random_base32()
    otp = pyotp.TOTP(secret).now()
    session['otp_secret'] = secret
    return otp

@app.route('/verify_transaction_otp', methods=['GET', 'POST'])
def verify_transaction_otp():
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if 'otp' in session and entered_otp == session['otp']:

            transaction_data = session.pop('transaction_data')
            user_id = transaction_data['user_id']
            recipient_id = transaction_data['recipient_id']
            amount = transaction_data['amount']

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            cursor.execute('UPDATE accounts SET balance = balance - %s WHERE id = %s', (amount, user_id))
            cursor.execute('UPDATE accounts SET balance = balance + %s WHERE id = %s', (amount, recipient_id))
            cursor.execute('INSERT INTO transactions (user_id, recipient_id, amount) VALUES (%s, %s, %s)',
                           (user_id, recipient_id, amount))
            transaction_id = cursor.lastrowid
            mysql.connection.commit()


            log_transaction_status(cursor, user_id=user_id, transaction_id=transaction_id, status='Successful',
                                   details='')
            flash('Transaction successful', 'success')
            return redirect(url_for('transaction_history'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_otp.html')
def log_transaction_status(cursor, user_id, transaction_id, status, details):
    cursor.execute('INSERT INTO logs (user_id, transaction_id, status, details) VALUES (%s, %s, %s, %s)',
                   (user_id, transaction_id, status, details))
    mysql.connection.commit()

def get_public_ip_and_country():
    api_key = 'at_eGRfr4an62eB0hmnfQ9NYDkU8xtuT'
    try:

        response = requests.get(f'https://api.ipify.org?format=json', headers={'Authorization': f'Bearer {api_key}'})
        response.raise_for_status()
        ip_data = response.json()
        ip_address = ip_data.get('ip')

        if ip_address:

            geo_response = requests.get(f'https://ipinfo.io/{ip_address}/json')
            geo_response.raise_for_status()
            geo_data = geo_response.json()
            country = geo_data.get('country')
            return ip_address, country
        else:
            return None, None
    except requests.RequestException as e:
        print(f"Error fetching public IP or country: {e}")
        return None, None

def is_valid_phone_number_helper(phone_number):
    pattern = r'^\+\d{10,15}$'
    return re.match(pattern, phone_number)

def is_valid_phone_number(form, field):
    phone_number = field.data
    if not is_valid_phone_number_helper(phone_number):
        raise ValidationError('Invalid phone number. Please include the country code.')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={"id": "username"})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={"id": "password"})
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={"id": "confirm_password"})
    email = StringField('Email', validators=[DataRequired(), Email()], render_kw={"id": "email"})
    phone = StringField('Phone Number', validators=[DataRequired(), is_valid_phone_number], render_kw={"id": "phone"})
    submit = SubmitField('Register', render_kw={"id": "submit"})
class GoogleAuthForm(FlaskForm):
    auth_code = StringField('Authentication Code', validators=[DataRequired(), Length(6, 6)])
    submit = SubmitField('Verify')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone Number', validators=[is_valid_phone_number])
    password = PasswordField('New Password', validators=[optional(), Length(min=1)])
    confirm_password = PasswordField('Confirm Password', validators=[optional(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Update')

class LoginForm(FlaskForm):
    identifier = StringField('Identifier', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
def send_email(recipient_email, otp):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = 'bronsonscrtftr@gmail.com'
    sender_password = 'fysv wlnk xydh foln'

    msg = EmailMessage()
    msg['Subject'] = 'Your 2FA OTP Code'
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg.set_content(f'Your 2FA OTP code is: {otp}')
    print(otp)

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print('Email sent successfully.')
    except smtplib.SMTPException as e:
        print(f'Failed to send email: {e}')
    except Exception as e:
        print(f'Failed to send email: {e}')

login_attempts = {}

MAX_ATTEMPTS = 3
BLOCK_TIME = 60

def get_device_name(user_agent_string):
    user_agent = DeviceDetector(user_agent_string).parse()
    device_name = user_agent.os_name()
    device_type = user_agent.device_type()
    if device_type:
        return f'{device_name} {device_type}'
    else:
        return f'{device_name} Other'


@app.route('/', methods=['GET', 'POST'])
def login():
    MAX_ATTEMPTS = 3
    BLOCK_TIME = 60

    form = LoginForm()
    msg = ''
    recaptcha_site_key = RECAPTCHA_SITE_KEY
    ip_address, country = get_public_ip_and_country()


    if ip_address not in login_attempts:
        login_attempts[ip_address] = []


    current_time = time.time()
    login_attempts[ip_address] = [attempt for attempt in login_attempts[ip_address] if current_time - attempt < BLOCK_TIME]


    if len(login_attempts[ip_address]) >= MAX_ATTEMPTS:
        msg = 'Too many login attempts. Please try again later.'
        return render_template('index.html', msg=msg, form=form, recaptcha_site_key=recaptcha_site_key)


    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM blocked_ips WHERE ip_address = %s AND blocked_until > NOW()', (ip_address,))
    blocked_ip = cursor.fetchone()

    if blocked_ip:
        msg = 'Session revoked successfully. IP address temporarily blocked.'
        return render_template('index.html', msg=msg, form=form, recaptcha_site_key=recaptcha_site_key)


    if request.method == 'POST' and 'identifier' in request.form and 'password' in request.form:
        recaptcha_response = request.form['g-recaptcha-response']
        if not validate_recaptcha(recaptcha_response):
            msg = 'Please complete the reCAPTCHA'
            print("reCAPTCHA validation failed")
            return render_template('index.html', msg=msg, form=form, recaptcha_site_key=recaptcha_site_key)

        identifier = form.identifier.data
        password = form.password.data


        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        if re.match(r"[^@]+@[^@]+\.[^@]+", identifier):
            cursor.execute('SELECT * FROM accounts WHERE email = %s', (identifier,))
            session['login_method'] = 'email'
        elif is_valid_phone_number_helper(identifier):
            cursor.execute('SELECT * FROM accounts WHERE phone = %s', (identifier,))
            session['login_method'] = 'phone'
        else:
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (identifier,))
            session['login_method'] = 'username'

        account = cursor.fetchone()
        if account:
            stored_password = account['password']

            if bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):

                session['id'] = account['id']
                session['username'] = account['username']
                session['email'] = account['email']
                session['phone'] = account['phone']


                if session['login_method'] == 'username' and account.get('google_auth_enabled'):
                    session['loggedin'] = False
                    session['qr_token'] = pyotp.totp.TOTP(account['google_auth_secret']).now()
                    return redirect(url_for('verify_google_auth'))
                else:
                    session['loggedin'] = False
                    secret = pyotp.random_base32()
                    otp = pyotp.TOTP(secret).now()
                    session['otp_secret'] = secret
                    session['2fa'] = False

                    if session['login_method'] == 'email':
                        send_email(session['email'], otp)
                    elif session['login_method'] == 'phone':
                        send_sms(session['phone'], otp)


                    user_agent_string = request.headers.get('User-Agent')
                    ip_address, country = get_public_ip_and_country()
                    session_id = str(uuid.uuid4())

                    cursor.execute(
                        'SELECT id FROM sessions WHERE user_id = %s AND ip_address = %s AND user_agent = %s',
                        (account['id'], ip_address, user_agent_string)
                    )
                    existing_session = cursor.fetchone()

                    if existing_session:
                        cursor.execute(
                            'UPDATE sessions SET session_id = %s, created_at = CURRENT_TIMESTAMP, country = %s WHERE id = %s',
                            (session_id, country, existing_session['id'])
                        )
                    else:
                        cursor.execute(
                            'INSERT INTO sessions (user_id, session_id, ip_address, user_agent, device_name, country) VALUES (%s, %s, %s, %s, %s, %s)',
                            (account['id'], session_id, ip_address, user_agent_string, get_device_name(user_agent_string), country)
                        )
                    mysql.connection.commit()

                    return redirect(url_for('verify_otp'))
            else:

                login_attempts[ip_address].append(current_time)
                msg = 'Incorrect username/password!'
        else:
            msg = 'User does not exist'

    return render_template('index.html', form=form, msg=msg, recaptcha_site_key=recaptcha_site_key)
@app.route('/sessions', methods=['GET'])
def sessions():
    if 'loggedin' not in session or not session['loggedin']:
        return redirect(url_for('login'))

    if session.get('2fa') is False:
        return redirect(url_for('verify_otp_for_sessions'))

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM sessions WHERE user_id = %s', (session['id'],))
    sessions_data = cursor.fetchall()

    for session_data in sessions_data:
        user_agent_string = session_data['user_agent']
        user_agent = parse(user_agent_string)
        device_name = f'{user_agent.os.family} {user_agent.device.family}'
        session_data['device_name'] = device_name
        session_data['country'] = session_data.get('country', 'Unknown')

    return render_template('sessions.html', sessions=sessions_data)

@app.route('/logout')
def logout():
    if 'loggedin' in session:
        user_id = session.get('id')

        if user_id:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT email FROM accounts WHERE id = %s', (user_id,))
            user = cursor.fetchone()
            if user:
                user_email = user['email']
                send_email_logout(user_email, 'You have successfully logged out.')

        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('username', None)
        session.pop('email', None)
        session.pop('phone', None)
        session.clear()
    return redirect(url_for('login'))

def validate_username(username):
    if not re.match(r"^[A-Za-z0-9_]{3,20}$", username):
        return False
    return True


def validate_email(email):
    if not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email):
        return False
    return True

def validate_password(password):
    if len(password) < 10:
        return "Password must be at least 10 characters long"

    if re.search(r'(.)\1\1', password):
        return "Password must not have more than 2 identical characters in a row"

    upper = re.search(r'[A-Z]', password) is not None
    lower = re.search(r'[a-z]', password) is not None
    digit = re.search(r'\d', password) is not None
    special = re.search(r'[!@#$%^&*,.:;? ]', password) is not None

    if not upper:
        return "Password must contain at least one uppercase letter"
    if not lower:
        return "Password must contain at least one lowercase letter"
    if not digit:
        return "Password must contain at least one number"
    if not special:
        return "Password must contain at least one special character"

    if sum([upper, lower, digit, special]) < 3:
        return "Password must contain at least three of the following: uppercase letter, lowercase letter, number, special character"

    return None


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    msg = ''

    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data.lower()
            password = form.password.data
            confirm_password = form.confirm_password.data
            email = form.email.data
            phone = form.phone.data

            if not validate_username(username):
                msg = 'Invalid username!'
                return render_template('register.html', form=form, msg=msg)

            password_error = validate_password(password)
            if password_error:
                msg = f'Invalid password! {password_error}'
                return render_template('register.html', form=form, msg=msg)

            if password != confirm_password:
                msg = 'Passwords do not match!'
                return render_template('register.html', form=form, msg=msg)

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()
            if account:
                msg = 'Username already exists!'
                return render_template('register.html', form=form, msg=msg)

            cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
            account = cursor.fetchone()
            if account:
                msg = 'Email already exists!'
                return render_template('register.html', form=form, msg=msg)

            cursor.execute('SELECT * FROM accounts WHERE phone = %s', (phone,))
            account = cursor.fetchone()
            if account:
                msg = 'Phone number already exists!'
                return render_template('register.html', form=form, msg=msg)

            cursor.execute('INSERT INTO accounts (username, password, email, phone) VALUES (%s, %s, %s, %s)',
                           (username, hashed_password.decode('utf-8'), email, phone,))
            mysql.connection.commit()
            msg = 'You have successfully registered!'
            # create default budget
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            user = cursor.fetchone()
            cursor.execute('SELECT * FROM budget WHERE user_id = %s', (user['id'],))
            budget = cursor.fetchone()
            if budget:
                return redirect(url_for('login'))

            cursor.execute('INSERT INTO budget (user_id, allowance_frequency, allowance, wants_percent, needs_percent, savings_percent) VALUES (%s, %s, %s, %s, %s, %s)',
                           (user['id'], "Monthly", 0, 30, 50, 20,))
            mysql.connection.commit()
            return redirect(url_for('login'))

        else:
            msg = 'Please correct the errors in the form.'

    return render_template('register.html', form=form, msg=msg)


@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'loggedin' in session and session['loggedin'] and session.get('2fa', False):
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))

        cursor.execute('''SELECT *
                              FROM transactions 
                              WHERE user_id = %s
                              ORDER BY transaction_time DESC
                              LIMIT 10''', (user['id'],))
        transactions = cursor.fetchall()
        print(transactions)
        total_expense = 0
        for transaction in transactions:
            transaction["amount"] = float(transaction["amount"])
            total_expense += float(transaction["amount"])

        budget_obj = get_budget(user)
        return render_template('home.html', total_expense=total_expense, budget_obj =budget_obj,transactions=transactions,user=user)
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    if 'loggedin' in session and session['loggedin'] and session.get('2fa', False):
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        user = cursor.fetchone()
        form = ProfileForm()
        return render_template('profile.html', username=session['username'], account=account, form=form)
    return redirect(url_for('login'))


TWILIO_ACCOUNT_SID = 'AC0fdc92c3c70618c809be77932fc5f8ac'
TWILIO_AUTH_TOKEN = 'bb3169d9eccc359d741f004e24700ac4'
TWILIO_SERVICE_SID = 'VA3a81070240d9c90f5019823ef8eeb9c7'

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)



def send_sms(recipient_phone, otp):
    TWILIO_ACCOUNT_SID = 'AC0fdc92c3c70618c809be77932fc5f8ac'
    TWILIO_AUTH_TOKEN = 'bb3169d9eccc359d741f004e24700ac4'
    client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    try:
        message = client.messages.create(
            body=f'Your 2FA OTP code is: {otp}',
            from_=+13028040354,
            to=recipient_phone
        )
        print(f'SMS sent successfully. SID: {message.sid}')
    except Exception as e:
        print(f'Failed to send SMS: {e}')



def mask_data(data):
    return data[:0] + 'XXXX-XXXX'


RECAPTCHA_SECRET_KEY = '6LfsCgwqAAAAAAg0XIAyBr7-jH9ZbJpjQv_TI-eb'
RECAPTCHA_SITE_KEY = '6LfsCgwqAAAAAO-ql-57qn7mw9Kg1dTnBfIWe_IQ'


def validate_recaptcha(recaptcha_response):
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = response.json()
    print(f"reCAPTCHA result: {result}")
    return result.get('success')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp = request.form['otp']
        secret = session.get('otp_secret')
        print(otp)
        if pyotp.TOTP(secret).verify(otp, valid_window=4):
            session['loggedin'] = True
            session['2fa'] = True
            session.pop('otp_secret', None)
            return redirect(url_for('home'))
        else:
            flash('Invalid OTP. Please try again.')
    return render_template('verify_otp.html')

@app.route('/resend_otp')
def resend_otp():
    secret = session.get('otp_secret')
    if not secret:
        secret = pyotp.random_base32()
        session['otp_secret'] = secret
    otp = pyotp.TOTP(secret).now()

    print(f"Session email: {session.get('email')}")
    print(f"Session phone: {session.get('phone')}")

    login_method = session.get('login_method')
    if login_method == 'email' and 'email' in session:
        send_email(session['email'], otp)
        flash('A new OTP has been sent to your email.')
    elif login_method == 'phone' and 'phone' in session:
        send_sms(session['phone'], otp)
        flash('A new OTP has been sent to your phone.')
    else:
        flash('No contact information available to send OTP.')

    return redirect(url_for('verify_otp'))

@app.route('/toggle_google_auth', methods=['POST'])
def toggle_google_auth():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        if account:
            google_auth_enabled = request.form.get('google_auth_enabled', type=bool)
            if google_auth_enabled:
                secret = pyotp.random_base32()
                print(f"Generated Secret Key: {secret}")
                cursor.execute('UPDATE accounts SET google_auth_enabled = 1, google_auth_secret = %s WHERE id = %s',
                               (secret, session['id']))
                mysql.connection.commit()
            else:

                cursor.execute('UPDATE accounts SET google_auth_enabled = 0, google_auth_secret = NULL WHERE id = %s',
                               (session['id'],))
                mysql.connection.commit()

            session['google_auth_enabled'] = google_auth_enabled

            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()


            if google_auth_enabled:
                totp = pyotp.TOTP(secret)
                qr_code_url = totp.provisioning_uri(name=account['username'], issuer_name='YourApp')
                qr = qrcode.make(qr_code_url)
                qr_path = os.path.join('static', 'google_auth_qrcode.png')
                qr.save(qr_path)
                return render_template('enable_google_auth.html', qr_code_url=qr_path, account=account)


        return redirect(url_for('home'))

    return redirect(url_for('login'))

@app.route('/verify_google_auth', methods=['GET', 'POST'])
def verify_google_auth():
    form = GoogleAuthForm()
    if 'id' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        if account and account.get('google_auth_enabled'):
            if form.validate_on_submit():
                auth_code = form.auth_code.data


                secret = account['google_auth_secret']
                print(f"Secret Key: {secret}")
                totp = pyotp.TOTP(secret)


                current_code = totp.now()
                print(f"Current TOTP code: {current_code}")
                print(f"Entered code: {auth_code}")

                if totp.verify(auth_code, valid_window=1):
                    session['loggedin'] = True
                    session['username'] = account['username']
                    session['2fa'] = True
                    return redirect(url_for('home'))
                else:
                    msg = 'Invalid Google Authenticator code. Please try again.'
                    return render_template('verify_google_auth.html', form=form, msg=msg)

            return render_template('verify_google_auth.html', form=form)


        return redirect(url_for('home'))

    return redirect(url_for('home'))

@app.route('/verify_otp_for_update', methods=['GET', 'POST'])
def verify_otp_for_update():
    if request.method == 'POST':
        otp = request.form['otp']
        secret = session.get('otp_secret')
        if pyotp.TOTP(secret).verify(otp, valid_window=4):
            session['loggedin'] = True
            session.pop('otp_secret', None)
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.')
    return render_template('verify_otp.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

def send_email_logout(recipient_email, message):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    sender_email = 'bronsonscrtftr@gmail.com'
    sender_password = 'fysv wlnk xydh foln'

    msg = EmailMessage()
    msg['Subject'] = 'Logout'
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg.set_content(f'Bank: {message}')

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print('Email sent successfully.')
    except smtplib.SMTPException as e:
        print(f'Failed to send email: {e}')
    except Exception as e:
        print(f'Failed to send email: {e}')

# Frank

@app.route('/budgeter', methods=['GET', 'POST'])
def budgeter():
    if 'loggedin' in session and session['loggedin'] and session.get('2fa', False):
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))

        cursor.execute('''SELECT *
                              FROM transactions 
                              WHERE user_id = %s
                              ORDER BY transaction_time DESC
                              LIMIT 10''', (user['id'],))
        transactions = cursor.fetchall()
        print(transactions)
        budget_obj = get_budget(user)



        return render_template('needTable.html', budget_obj =budget_obj,transactions=transactions,user=user)
    return redirect(url_for('login'))

class EditAllowanceForm(FlaskForm):
    amount = StringField('Name')
    frequency = SelectField('Frequency',choices=[('Daily'),('Weekly'),('Monthly')])
    submit = SubmitField('Add to Wishlist')
@app.route('/budgeter/allowance/edit', methods=['GET', 'POST'])
def edit_allowance():
    form = EditAllowanceForm()
    if not form.validate_on_submit():
        print(form.errors)
    else:
        print("Inside")
        username = session['username']
        email = session['email']
        amount = float(form.amount.data)
        allowance = amount
        frequency = str(form.frequency.data)
        print(frequency)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            log_transaction_status(cursor, user_id=None, transaction_id=None, status='Unsuccessful',
                                   details='Invalid user')
            flash('User not found', 'danger')
            return redirect(url_for('home'))

        cursor.execute('SELECT * FROM budget WHERE user_id = %s', (user['id'],))
        budget = cursor.fetchone()
        if not budget:
            cursor.execute('INSERT INTO budget (user_id, allowance_frequency, allowance, wants_percent, needs_percent,needs_daily_limit, savings_percent) VALUES (%s, %s, %s, %s, %s, %s)',
                           (user['id'], allowance, 0, 50, 30,8, 20,))
            mysql.connection.commit()
            print("After Create")
        else:
            cursor.execute('UPDATE budget SET allowance_frequency = %s, allowance = %s, wants_percent = %s, needs_percent = %s, savings_percent = %s WHERE user_id = %s',
                               (frequency, allowance, user['id'],30,50,20))
            mysql.connection.commit()
            print("After Update ")

        # log_transaction_status(cursor, user_id=user['id'], transaction_id=transaction_id, status='Successful',
        #                        details='NA')
        flash('Transaction successful', 'success')
        return redirect(url_for('budgeter'))

    return render_template('edit_allowance.html', form=form)

def days_in_current_month():
    today = datetime.today()
    year = today.year
    month = today.month

    # Get number of days in the current month
    days_in_month = calendar.monthrange(year, month)[1]
    return days_in_month
def days_passed_month():
    today = datetime.today()

    # Days passed in the month
    days_passed = today.day

    return days_passed
def days_until_month_end():
    today = datetime.today()
    days_in_month = calendar.monthrange(today.year, today.month)[1]
    end_of_month = datetime(today.year, today.month, days_in_month)
    days_left = (end_of_month - today).days
    return days_left



def get_budget(user):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE id = %s', (user['id'],))
    user = cursor.fetchone()
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('home'))
    cursor.execute('''SELECT *
                      FROM budget 
                      WHERE user_id = %s''', (user['id'],))
    allowance_obj = cursor.fetchone()
    print(f'allowance_obj:{allowance_obj}')
    if not allowance_obj:
        return {"allowance":1,"needs":1,"wants":1,"savings":1}
    frequency = 1
    if allowance_obj["allowance_frequency"] == "Daily":
        frequency = days_in_current_month()
    elif allowance_obj["allowance_frequency"] == "Weekly":
        frequency = 4
    elif allowance_obj["allowance_frequency"] == "Monthly":
        pass
    allowance = float(allowance_obj["allowance"]) * frequency
    print(allowance)
    needs = allowance / 100 * float(allowance_obj["needs_percent"])

    wants = allowance / 100 * float(allowance_obj["wants_percent"])
    savings = allowance / 100 * float(allowance_obj["savings_percent"])
    days_left = days_until_month_end()
    days_passed = days_passed_month()
    days_total = days_in_current_month()

    wants_on_track = "on_track"
    needs_on_track = "on_track"
    savings_on_track = "on_track"

    if (needs / days_left) > float(allowance_obj["needs_daily_limit"]): # if its on track

        pass
    else:
        print("on track")
        needs_on_track = "over"
        minimum_needs = float(allowance_obj["needs_daily_limit"]) * days_left
        amt_needed = minimum_needs - needs
        print(f"the amount needed to transfer to needs is: {amt_needed}\n wants = {wants}")
        if wants > amt_needed: # if wants got enough to remove
            wants = wants - amt_needed
            needs = needs + amt_needed
            wants_on_track = "under"
        else:
            prompt_remove_savings = True


    cursor.execute('''SELECT *
                              FROM transactions 
                              WHERE user_id = %s
                              ORDER BY transaction_time DESC
                              LIMIT 10''', (user['id'],))
    transactions = cursor.fetchall()
    # print(transactions)
    transactions_today_list = []
    needs_today_expense = 0
    wants_today_expense = 0
    savings_today_expense = 0

    needs_total_expense = 0
    wants_total_expense = 0
    savings_total_expense = 0

    for transaction in transactions:
        # print(transaction["date"].date())
        print(transaction["type"])
        if transaction["date"].date() == datetime.today().date():
            transactions_today_list.append(transaction)
            if transaction["type"] == "Needs":
                needs_today_expense += float(transaction["amount"])
            elif transaction["type"] == "Wants":
                wants_today_expense += float(transaction["amount"])
            elif transaction["type"] == "Savings":
                savings_today_expense+=float(transaction["amount"])

        if transaction["type"] == "Needs":
            needs_total_expense += float(transaction["amount"])
        elif transaction["type"] == "Wants":
            wants_total_expense += float(transaction["amount"])
        elif transaction["type"] == "Savings":
            savings_total_expense+=float(transaction["amount"])
    print(f"wants totaltlasd{wants_total_expense}")

    return ({
        "savings_total_expense":savings_total_expense,
        "wants_total_expense":wants_total_expense,
        "needs_total_expense":needs_total_expense,
        "savings_today_expense":savings_today_expense,
        "wants_today_expense":wants_today_expense,
        "needs_today_expense":needs_today_expense,
        "days_total": days_total,
        "days_passed": days_passed,
        "days_left":days_left,
        "allowance":allowance,
        "needs":{"on_track":needs_on_track,"daily_limit":float(allowance_obj["needs_daily_limit"]),"remaining":needs,"percentage":float(allowance_obj["needs_percent"])},
        "wants":{"on_track":wants_on_track,"remaining":wants,"percentage":float(allowance_obj["wants_percent"])},
        "savings":{"on_track":savings_on_track,"remaining":savings,"percentage":float(allowance_obj["savings_percent"])}
    })

class DailyNeedsLimitForm(FlaskForm):
    amount = StringField('Name')
    submit = SubmitField('Add to Wishlist')
@app.route('/budgeter/needs/limit', methods=['GET', 'POST'])
def daily_needs_limit():
    form = DailyNeedsLimitForm()
    if not form.validate_on_submit():
        print(form.errors)
    else:
        print("Inside")
        username = session['username']
        email = session['email']
        amount = float(form.amount.data)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            log_transaction_status(cursor, user_id=None, transaction_id=None, status='Unsuccessful',
                                   details='Invalid user')
            flash('User not found', 'danger')
            return redirect(url_for('home'))

        cursor.execute('SELECT * FROM budget WHERE user_id = %s', (user['id'],))
        budget = cursor.fetchone()
        if not budget:
            cursor.execute('INSERT INTO budget (user_id, allowance_frequency, allowance, wants_percent, needs_percent,needs_daily_limit, savings_percent) VALUES (%s, %s, %s, %s, %s, %s)',
                           (user['id'], 1, 1, 50, 30,8, 20,))
            mysql.connection.commit()
            print("After Create")
        else:
            cursor.execute('UPDATE budget SET needs_daily_limit = %s WHERE user_id = %s',
                               (amount, user['id']))
            mysql.connection.commit()
            print("After Update")

        # log_transaction_status(cursor, user_id=user['id'], transaction_id=transaction_id, status='Successful',
        #                        details='NA')
        flash('Transaction successful', 'success')
        return redirect(url_for('budgeter'))

    return render_template('daily_needs_limit.html', form=form)

@app.route('/budgeter/needs', methods=['GET', 'POST'])
def budgeter_needs():
    if 'loggedin' in session and session['loggedin'] and session.get('2fa', False):
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))

        cursor.execute('''SELECT *
                              FROM transactions 
                              WHERE user_id = %s && type = %s
                              ORDER BY transaction_time DESC
                              LIMIT 10''', (user['id'],'Needs',))
        transactions = cursor.fetchall()
        print(transactions)

        print(f"user: {user['balance']}")
        budget_obj = get_budget(user)
        return render_template('needTable.html', budget_obj =budget_obj,transactions=transactions)
    return redirect(url_for('login'))

@app.route('/budgeter/wants', methods=['GET', 'POST'])
def budgeter_wants():
    if 'loggedin' in session and session['loggedin'] and session.get('2fa', False):
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))

        cursor.execute('''SELECT *
                              FROM transactions 
                              WHERE user_id = %s && type = %s
                              ORDER BY transaction_time DESC
                              LIMIT 10''', (user['id'],'Wants',))
        transactions = cursor.fetchall()
        print(transactions)
        budget_obj = get_budget(user)
        return render_template('wantTable.html', transactions=transactions,user=user, budget_obj =budget_obj)
    return redirect(url_for('login'))

@app.route('/budgeter/savings', methods=['GET', 'POST'])
def budgeter_savings():
    if 'loggedin' in session and session['loggedin'] and session.get('2fa', False):
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))

        cursor.execute('''SELECT *
                              FROM transactions 
                              WHERE user_id = %s && type = %s
                              ORDER BY transaction_time DESC
                              LIMIT 10''', (user['id'],'Savings',))
        transactions = cursor.fetchall()
        print(transactions)
        budget_obj = get_budget(user)
        print(budget_obj)
        return render_template('savingsTable.html', transactions=transactions,user=user, budget_obj =budget_obj)
    return redirect(url_for('login'))

@app.route('/wishlist', methods=['GET', 'POST'])
def wishlist():
    if 'loggedin' in session and session['loggedin'] and session.get('2fa', False):
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'danger')
            return redirect(url_for('home'))

        cursor.execute('''SELECT *
                              FROM wishlist 
                              WHERE user_id = %s
                              LIMIT 10''', (user['id'],))
        wishlist = cursor.fetchall()
        print(wishlist)
        for item in wishlist:
            item["price"] = float(item["price"])
        budget_obj = get_budget(user)
        return render_template('wishlist.html', budget_obj = budget_obj,wishlist=wishlist)
    return redirect(url_for('login'))


class AddWishlistForm(FlaskForm):
    name = StringField('Name')
    price = DecimalField('Price', validators=[DataRequired(), NumberRange(min=0.01)])
    category = SelectField('Category',choices=[('Dining'),('Leisure/Entertainment'),('Shopping'),('Others')])
    type = SelectField('Type',choices=[('Needs'),('Wants'),('Savings')])
    submit = SubmitField('Add to Wishlist')
@app.route('/add_wishlist', methods=['GET', 'POST'])
def add_wishlist():
    form = AddWishlistForm()
    if not form.validate_on_submit():
        print(form.errors)
    else:
        print("Inside")
        username = session['username']
        email = session['email']
        name = form.name.data
        price = float(form.price.data)
        category = form.category.data
        transaction_instance = Transaction.Transaction(name,price,category)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            log_transaction_status(cursor, user_id=None, transaction_id=None, status='Unsuccessful',
                                   details='Invalid user')
            flash('User not found', 'danger')
            return render_template('add_wishlist.html', form=form)

        cursor.execute('INSERT INTO wishlist (user_id, name , price, category) VALUES (%s, %s, %s, %s)',
                       (user['id'], name, price, category,))
        transaction_id = cursor.lastrowid
        mysql.connection.commit()
        print("After Update")

        # log_transaction_status(cursor, user_id=user['id'], transaction_id=transaction_id, status='Successful',
        #                        details='NA')
        flash('Transaction successful', 'success')
        return redirect(url_for('wishlist'))
    return render_template('add_wishlist.html', form=form)

class AddTransactionForm(FlaskForm):
    title = StringField('Category')
    amount = DecimalField('Amount', validators=[DataRequired(), NumberRange(min=0.01)])
    type = SelectField('Type',choices=[('Needs'),('Wants'),('Savings')])
    category = SelectField('Category',choices=[('Dining'),('Leisure/Entertainment'),('Shopping'),('Others')])
    submit = SubmitField('Add Transaction')

@app.route('/add_transaction', methods=['GET', 'POST'])
def add_transaction():
    form = AddTransactionForm()
    if not form.validate_on_submit():
        print(form.errors)
    else:
        print("Inside")
        username = session['username']
        email = session['email']
        title = form.title.data
        amount = float(form.amount.data)
        type = form.type.data
        category = form.category.data
        transaction_instance = Transaction.Transaction(title,amount,category)
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        user = cursor.fetchone()
        if not user:
            log_transaction_status(cursor, user_id=None, transaction_id=None, status='Unsuccessful',
                                   details='Invalid user')
            flash('User not found', 'danger')
            return render_template('add_transaction.html', form=form)

        if user['balance'] < amount:
            log_transaction_status(cursor, user_id=user['id'], transaction_id=None, status='Unsuccessful',
                                   details='Insufficient funds')
            flash('Insufficient balance', 'danger')
            return render_template('add_transaction.html', form=form)
        #
        # cursor.execute('UPDATE accounts SET balance = balance - %s WHERE id = %s', (amount, user['id'],))
        cursor.execute('INSERT INTO transactions (user_id, title , amount, category, type) VALUES (%s, %s, %s, %s, %s)',
                       (user['id'], title, amount, category, type,))
        transaction_id = cursor.lastrowid
        mysql.connection.commit()
        print("After Update")

        # log_transaction_status(cursor, user_id=user['id'], transaction_id=transaction_id, status='Successful',
        #                        details='NA')
        flash('Transaction successful', 'success')
        return redirect(url_for('budgeter'))
    return render_template('add_transaction.html', form=form)



if __name__ == '__main__':
    app.run(debug=True)
    # app.run(ssl_context=('localhost+1.pem', 'localhost+1-key.pem'), debug=True)


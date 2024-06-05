from flask import Flask, request, jsonify, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_mail import Mail, Message
from datetime import timedelta
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from werkzeug.utils import secure_filename
import os
from flask_migrate import Migrate


app = Flask(__name__)

# Configuration for MySQL database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/flask_db'

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'patthapriyank786@gmail.com'
app.config['MAIL_PASSWORD'] = 'tzrbvmbtoeovohpc'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
mail = Mail(app)

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    profile_pic = db.Column(db.String(150), nullable=True)

with app.app_context():
    db.create_all()

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']  # Ideally, you should hash the password
    profile_pic = None

    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            profile_pic = filename

    new_user = User(
        username=username,
        email=email,
        password=password,
        profile_pic=profile_pic
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(email=request.form['email']).first()
    if user and user.password == request.form['password']:  # Verify password properly in real use
        access_token = create_access_token(identity={'email': user.email})
        return jsonify(access_token=access_token)
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/getuser', methods=['GET'])
@jwt_required()
def getuser():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    profile_pic_url = url_for('uploaded_file', filename=user.profile_pic, _external=True) if user.profile_pic else None
    return jsonify(
        username=user.username,
        email=user.email,
        profile_pic=profile_pic_url
    )

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    if user:
        token = create_access_token(identity={'email': user.email}, expires_delta=timedelta(minutes=30))
        reset_link = f"http://localhost:5000/reset-password/{token}"
        msg = Message('Password Reset Request', sender='noreply@example.com', recipients=[user.email])
        msg.body = f'Your password reset link is {reset_link}'
        mail.send(msg)
        return jsonify({'message': f'Password reset link sent to {user.email}'}), 200
    return jsonify({'message': 'Email not found'}), 404

@app.route('/reset-password', methods=['POST'])
@jwt_required()
def reset_password():
    try:
        email = get_jwt_identity()
    except ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 400
    except InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 400

    password = request.form['password']  # Hash the new password in real use
    user = User.query.filter_by(email=email['email']).first()
    if user:
        user.password = password
        db.session.commit()
        return jsonify({'message': 'Password reset successful'}), 200
    return jsonify({'message': 'User not found'}), 404

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True)

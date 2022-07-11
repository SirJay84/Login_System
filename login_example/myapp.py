from flask import Flask,render_template,redirect,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField,PasswordField,BooleanField
from wtforms.validators import InputRequired,Email,Length
from flask_bcrypt import Bcrypt
from flask_login import LoginManager,login_required,login_user,logout_user,current_user,UserMixin
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI']= os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

flask_bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
  id = db.Column(db.Integer, primary_key=True)
  firstname = db.Column(db.String(50), nullable=False)
  lastname = db.Column(db.String(50), nullable=False)
  username = db.Column(db.String(50), unique=True, nullable=False)
  email = db.Column(db.String(50), unique=True, nullable=False)
  password = db.Column(db.String(80), nullable=False)

"""connection btwn flask login & actual data in database"""
@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id))
  
class LoginForm(FlaskForm):
  username = StringField('username', validators=[InputRequired(), Length(min=3,max=50)])
  # email = StringField('email',  validators=[InputRequired(), Email(message='Invalid Email Provided!')])
  password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
  remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
  firstname = StringField('firstname', validators=[InputRequired(), Length(min=3,max=50)])
  lastname = StringField('lastname', validators=[InputRequired(), Length(min=3,max=50)])
  username = StringField('username', validators=[InputRequired(), Length(min=3,max=50)])
  email = StringField('email', validators=[InputRequired(), Email(message='Invalid Email Provided'), Length(max=50)])
  password = PasswordField('password',validators=[InputRequired(),Length(min=8, max=80)])
  
@app.route('/')
@login_required
def index():
  return render_template('index.html', username=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(username=form.username.data).first()
    if user:
      if flask_bcrypt.check_password_hash(user.password, form.password.data):
        login_user(user, remember=form.remember.data)
        return redirect(url_for('index'))
      else:
        return '<h1>Invalid username or password!</h1>'
    # return '<h1>' +form.email.data +' ' +form.password.data + '</h1>'
  return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
  form = RegisterForm()
  if form.validate_on_submit():
    hashed_password = flask_bcrypt.generate_password_hash(form.password.data)
    new_user = User(
      firstname=form.firstname.data,
      lastname=form.lastname.data,
      username=form.username.data,
      email=form.email.data,
      password=hashed_password,
    )
    db.session.add(new_user)
    db.session.commit()
    # redirect to the login page
    return redirect(url_for('login'))
    # return '<h1>' +form.firstname.data +' ' +form.lastname.data +' ' +form.email.data +' ' +form.password.data +' ' +form.confirm_password.data + '</h1>'
  # load registration template
  return render_template('signup.html', form=form)

@app.route('/logout')
def logout():
  logout_user()
  # redirect to the login page
  return redirect(url_for('login'))
 
if __name__ == '__main__':
  app.run(debug=True)
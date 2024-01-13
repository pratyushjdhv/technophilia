from functools import wraps
from flask import Flask, render_template, request, redirect,flash,url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash,check_password_hash
import secrets 
from flask_login import LoginManager, login_required, current_user, UserMixin,login_user


'''class Config:
    SECRET_KEY = secrets.token_hex(4)  # Generate a 8-character (4 bytes) random key
    SQLALCHEMY_DATABASE_URI = "sqlite:///contestant.sqlite3
    this is to be used when app is published on a domain as itll generate new key for every session"'''

'''class Config: #creating class for configuration setting
    SECRET_KEY = 'tech_secret'
    SQLALCHEMY_DATABASE_URI = "sqlite:///contestant.sqlite3"'''

app = Flask(__name__)
app.secret_key = 'tech_secret'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///contestant.sqlite3"
#app.config.from_object(Config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class contestants(db.Model, UserMixin):
    name = db.Column(db.String(), nullable=False, unique=True)
    email = db.Column(db.String(), primary_key=True,unique=True)
    password = db.Column(db.String(), nullable=False)
    scores = db.Column(db.Integer(), nullable=True,default=0)
    is_admin = db.Column(db.Boolean(), default=False)

    def get_id(self):
        return str(self.email)

    def is_authenticated(self):
        return True
    
    @property
    def admin(self):
        return self.is_admin

@login_manager.user_loader
def load_user(user_id):
    return contestants.query.filter_by(email=user_id).first()

with app.app_context(): 
    db.create_all() #creates all the sql tables in sqlite file whever app starts

@app.route('/login',methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username') #gets username and password from user
        password = request.form.get('password')

        user=contestants.query.filter_by(name=username).first() #search for data of username
        if user and check_password_hash(user.password, password): #check if user is not---
            login_user(user)
            
            if user.is_admin:                                     #--none and check for password is same as password
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('home')) #redirect to be replaced by events page
        else:
            flash("Invalid username or password") 
            return redirect(url_for('login')) #redirect to 
    return render_template('login.html')

@app.route('/login/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        choice = request.form.get('redirect')

        if choice == 'list':
            return redirect(url_for('list'))
        elif choice == 'home':
            return redirect(url_for('home'))

    return render_template('admin-login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
        if request.method == 'POST':# Handle the form submission logic here
            try:        #checks for integrity failure
                username = request.form.get('username')
                email = request.form.get('email')
                password = request.form.get('password')

                if len(password) < 6:
                    flash("Password must be at least 6 characters long.")
                    return render_template('signup.html')
                
                existing_user = contestants.query.filter(contestants.name.ilike(username)).first() #to solve the issue ---
                if existing_user:                                                              #----with having similar username with different cases
                    flash("Username must be unique. Please choose a different username.")
                    return render_template('signup.html')
                
                hashed_password = generate_password_hash(password)

                #checking for admin access
                admins = ["harsh","piu","abc"]  # Add admin usernames here
                is_admin = username in admins

                new_contestant = contestants(name=username, email=email, password=hashed_password,is_admin=is_admin) #for creating a new user
                db.session.add(new_contestant)
                db.session.commit() 

                print(f"Is admin for {username}: {is_admin}")

                return redirect(url_for('login')) #after creting new user send them to login page
        
            except IntegrityError as e:
                db.session.rollback()                
                if 'UNIQUE constraint failed: contestants.name' in str(e): # Check if the error is related to a duplicate username
                    flash("Username must be unique. Please choose a different username.")
                elif 'UNIQUE constraint failed: contestants.email' in str(e): # Check if the error is related to a duplicate email
                    flash("Email must be unique. Please choose a different email.")
        return render_template('signup.html') #default is post but if some err then re render signup html

def admin_required(view_func):
    @wraps(view_func)
    def decorated_view(*args, **kwargs):
        # Check if the user is authenticated
        if not current_user.is_authenticated:
            flash("You need to log in to access this page.", 'warning')
            return redirect(url_for('login'))

        # Check if the user is an admin
        if not current_user.admin:
            flash("You don't have permission to access this page.", 'warning')
            return redirect(url_for('home'))

        return view_func(*args, **kwargs)

    return decorated_view


@app.route('/list',methods=['GET','POST'])
@login_required
@admin_required
def list():
    lis = contestants.query.all() #list all contestants
    if not lis:
        messages = "no enlistment available"
    else:
        messages = None
    return render_template('list.html', messages=messages, lis=lis)

@app.route('/list/<name>/update', methods=['GET', 'POST'])
def update(name):
    contestant = contestants.query.filter(contestants.name.ilike(name)).first() #get contestant of name
    if not contestant:
        #print(f"Contestant with name '{name}' not found.")
        return redirect(url_for('list'))
    
    new_score = contestant.scores
    if request.method == 'POST':
        new_score = int(request.form.get('scores')) #get new score
        contestant.scores = new_score  #update score which is default 0
        db.session.commit()

        return redirect(url_for('list'))
    
    return render_template('update.html', new_scores=new_score, contestant=contestant)


@app.route('/list/<name>/delete')
def delete(name):
    contestant = contestants.query.filter(contestants.name.ilike(name)).first() #get contestant of name
    db.session.delete(contestant)
    db.session.commit()
    
    return redirect(url_for('list'))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/events')
def events():
    return render_template('events.html')


if __name__ == "__main__":
    app.run(debug=True)
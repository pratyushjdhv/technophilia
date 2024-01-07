from flask import Flask, render_template, request, redirect,flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.secret_key = 'tech_secret'
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///contestant.sqlite3"

db = SQLAlchemy(app)


class contestants(db.Model):
    name = db.Column(db.String(), nullable=False, unique=True)
    email = db.Column(db.String(), primary_key=True,unique=True)
    password = db.Column(db.String(), nullable=False)
    scores = db.Column(db.Integer(), nullable=True,default=0)

with app.app_context():
    db.create_all()

@app.route('/')
def login():    
    return render_template('login.html')


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

                hashed_password = generate_password_hash(password)

                
                new_contestant = contestants(name=username, email=email, password=password) #for creating a new user
                db.session.add(new_contestant)
                db.session.commit()       
                return redirect('/list')
        
            except IntegrityError as e:
                db.session.rollback()                
                if 'UNIQUE constraint failed: contestants.name' in str(e): # Check if the error is related to a duplicate username
                    flash("Username must be unique. Please choose a different username.")
                elif 'UNIQUE constraint failed: contestants.email' in str(e): # Check if the error is related to a duplicate email
                    flash("Email must be unique. Please choose a different email.")
        return render_template('signup.html') #default is post but if some err then re render signup html

@app.route('/list',methods=['GET','POST'])
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
        return redirect('/list')
    
    new_score = contestant.scores
    if request.method == 'POST':
        new_score = int(request.form.get('scores')) #get new score
        contestant.scores = new_score  #update score which is default 0
        db.session.commit()

        return redirect('/list')
    
    #print(f"Contestant found: {contestant}")
    return render_template('update.html', new_scores=new_score, contestant=contestant)

    #return render_template('update.html', new_scores=new_score)

if __name__ == "__main__":
    app.run(debug=True)

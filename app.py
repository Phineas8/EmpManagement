from flask import Flask, request, render_template, redirect, url_for, flash, session
from sqlalchemy import create_engine, Column, Integer, String, TIMESTAMP, Sequence, MetaData, Table
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func
import bcrypt

# Initialize the Flask application
app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to a random secret key for sessions

# Define the database URL
DATABASE_URL = "mysql+mysqlconnector://ninad1:ninad123@localhost/empmanagement"

# Create a database engine
engine = create_engine(DATABASE_URL, echo=True)

# Create a metadata instance
metadata = MetaData()

# Define the Login table
login_table = Table('login', metadata,
    Column('id', Integer, Sequence('user_id_seq'), primary_key=True),
    Column('username', String(50), unique=True, nullable=False),
    Column('password', String(255), nullable=False),
    Column('created_at', TIMESTAMP, server_default=func.current_timestamp())
)

# Create the tables in the database
metadata.create_all(engine)

# Create a session factory
Session = sessionmaker(bind=engine)

@app.route('/')
def home():
    return render_template('Login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        session = Session()
        try:
            new_user = {
                'username': username,
                'password': hashed_password.decode('utf-8')
            }
            session.execute(login_table.insert().values(new_user))
            session.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            session.rollback()
            flash('Username already exists. Please choose another.', 'error')
            print(e)
        finally:
            session.close()
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        session = Session()
        user = session.execute(login_table.select().where(login_table.c.username == username)).fetchone()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session['username'] = username  # Store username in session
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password.', 'error')
        
        session.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)  # Remove username from session
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)

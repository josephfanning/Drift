# TODO - make sure these imports are properly implemented for the server
# TODO - make sure that the random flashes i haeve popped into else statements of routes are either working properly or are changed to just show 404 errors 
# import statements for various libraries from flask and other libs that have been used 
from flask import Flask, request, redirect, url_for, flash, session, render_template
from flask_sqlalchemy import SQLAlchemy # remember to download flask-sqlalchemy on server of deployment
from flask_bcrypt import Bcrypt # remmber to download on server!
from datetime import datetime # look into this for server 
import os

app = Flask(__name__)

# secret key used for session management
app.config["SECRET_KEY"] = "gb2576eetc445"

# database code for the create account and login page
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(os.path.dirname(__file__), "instance", "users.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

#initialiseas database
db = SQLAlchemy(app) 
# decleration used for database table security/encryption
bcrypt = Bcrypt(app)

# creates a class within databse called User which contains the user id, username, password,
# and a timestamp (created_at) attribute
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(8), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # uses the bcrypt library   
    def set_password(self, password):
        # generates a hashed version of the password using bcrypt, 
        # then stores it in the password attribute of user table within the database 
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        
    def check_password(self, password):
        # checks if the password matches the hashed password stored in the database
        # returns true or false
        return bcrypt.check_password_hash(self.password, password)

# creates post table within the database containing an id for posts, content(text of post), and user id
class Post(db.Model):
    postID = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='posts', lazy=True)

# table for freindships between users on the page
class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # constructor method that takes in user id and friend id as parameters
    def __init__(self, user_id, friend_id):
        self.user_id = user_id
        self.friend_id = friend_id

# creates all tables previously defined as well as database to hold them 
with app.app_context():
    db.create_all()

# creates a class for the database, each instance of this class will be a row in the database
@app.route('/')  # Define the route for the root URL
def home():
    return redirect(url_for('login')) # Render the login.html template

# route for signup.html which can be reached via the root URL
@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        # gets the username and password from the form
        username = request.form["username"]
        password = request.form["password"]
        # code to check no dupe usernames
        existing_user = User.query.filter_by(username=username).first()
        if existing_user is not None:
            # uses flash to report to the user any issues with the username, further below is another one for the password
            flash("Username already exists. Please choose a different username.")
            return render_template("signup.html")
        # code to check password length is more than 8 characters in length
        elif len(password) < 8:
            flash("Password must be at least 8 characters long.")
            return render_template("signup.html")
        else:
            # if username is unique, create a new user
            # validates data below 
            user = User(username=username)
            # uses set_password from the bcrypt library to encrypt the password
            user.set_password(password)
            # adds a user object to the database
            db.session.add(user)
            # saves and commits the changes to the database
            db.session.commit()
            # TODO should realistically add a page that states that the account creation was successful, can do this later
            return redirect(url_for("login"))
    return render_template("signup.html")

# route for logging in users
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        # queries the database for a user with the given username
        user = User.query.filter_by(username=username).first()
        # uses check_password from the bcrypt library to check if the password is correct compared to hashed version
        if user and user.check_password(password):
            session["user_id"] = user.id # used to monitor sessions activity
            return redirect(url_for("posts"))
        else:
            # shows an error if invalid login credentials
            flash("Invalid username or password. Please try again.")
    return render_template("login.html")

# route for creating a post
@app.route("/createpost", methods=["GET","POST"])
def createpost():
    if request.method == "POST":
        # requests the content (which is currently just text) from the form
        content = request.form["content"]
        # checks if the length of the post is more than one and less than 200 characters
        if len(content) < 1 or len(content) > 200:
            flash("Post must be between 1 and 200 characters.")
            return render_template("createpost.html")
        user_id = session.get("user_id") 
        # adds a post to the database consisting of the content and user id
        post = Post(content=content, user_id=user_id)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for("posts"))
    return render_template("createpost.html")      

# simple route for the posts page 
@app.route("/posts")
def posts():
    # simple query to the database that returns all posts (a post contains; content and user id)
    posts = Post.query.all()
    return render_template("posts.html", posts=posts)

# used to check if you click on your own post, if so, 
# takes you to your own account page instead of the account template page that should be used for other users
@app.route('/posts/<username>')
def user_posts(username):
    user = User.query.filter_by(username=username).first()
    # checks if the user exists within database
    if user:
        # checks if the found user is the same as the user logged in
        if user.id == session.get("user_id"):
            # sends them to their own account where they can view the posts instead of a different template 
            # used for viewing other users
            return redirect(url_for('account'))
        else:
            # if the user is not the same as the user logged in, sends them to otheruseraccounts.html, 
            # and queries the database for the selected users posts using user_id
            posts = Post.query.filter_by(user_id=user.id).all()
            return render_template('otheruseraccounts.html', user=user, posts=posts)
    else:
        flash('User not found')
        return redirect(url_for('index'))
    
# app route for the about page
@app.route("/about")
def about():
    return render_template("about.html")

# route for the account page
@app.route('/account')
def account():
    # queries the database for the user that is logged in
    user = User.query.filter_by(id=session['user_id']).first()
    # if the user is found, 
    # query the database for all of their posts and number of current friends and display them 
    if user:
        posts = Post.query.filter_by(user_id=user.id).all()
        friendships = Friendship.query.filter_by(user_id=user.id).all()
        num_friends = len(friendships)
        friends = [User.query.get(friendship.friend_id) for friendship in friendships]
        return render_template('account.html', user=user, posts=posts, num_friends=num_friends, friends=friends)

    else:
        # TODO make sure this is the correct way to display this error
        return "User not found", 404
        #return redirect(url_for('index'))

# route for the user to log out of their account within the account.html page 
@app.route("/logout", methods=["GET", "POST"]) # routing for the logout page. returns user to login page 
def logout():
    # if the user sends a POST request to logout then pop the session
    if request.method == "POST":
        session.pop("user_id", None)
        return redirect(url_for("login"))
    return render_template("logout.html")

# route for the user to delete their account within the account.html page 
@app.route('/delete_account', methods=['POST'])
def delete_account():
    user_id = session['user_id']
    user = User.query.get(user_id)
    if user:
        # Delete user's posts
        posts = Post.query.filter_by(user_id=user_id).all()
        for post in posts:
            db.session.delete(post)
        # Delete user account
        db.session.delete(user)
        db.session.commit()
        session.pop('user_id', None)
        return redirect(url_for('login'))
    else:
        return 'User not found', 404
    
@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get(post_id)
    if post:
        db.session.delete(post)
        db.session.commit()
        return redirect(url_for('account'))
    
# for showing other users account pages for otheruseraccounts.html
@app.route('/user/<username>')
def user_account(username):
    user = User.query.filter_by(username=username).first()
    if user:
        posts = Post.query.filter_by(user_id=user.id).all()
        friendships = Friendship.query.filter_by(user_id=user.id).all()
        num_friends = len(friendships)
        friends = [User.query.get(friendship.friend_id) for friendship in friendships]
        return render_template('otheruseraccounts.html', user=user, posts=posts, num_friends=num_friends, friends=friends)
    else:
        flash('User not found')
        return redirect(url_for('posts'))

# route for frienships using the friendship table within the database
@app.route('/add_friend/<int:friend_id>', methods=['POST'])
def add_friend(friend_id):
    user_id = session['user_id']
    # checks if there is an existing friendship using the friend_id and user_id
    existing_friendship = Friendship.query.filter_by(user_id=friend_id, friend_id=user_id).first()
    # if an existing friendship is true, then show a flash message
    if existing_friendship:
        flash('You are already friends!')
        return redirect(url_for('user_account', username=User.query.get(friend_id).username))
    else:
        # if there is no existing friendship, create a new friendship and add it to the Friendship table on the database
        friendship = Friendship(user_id=friend_id, friend_id=user_id)
        db.session.add(friendship)
        db.session.commit()
        flash('Friend added successfully!')
        return redirect(url_for('user_account', username=User.query.get(friend_id).username))

# shows friends using the friendship table within the database
# TODO get this to work in probs account page or just remove it all together 
@app.route('/friends')
def friends():
    user_id = session['user_id']
    friendships = Friendship.query.filter_by(user_id=user_id).all()
    friends = [User.query.get(friendship.friend_id) for friendship in friendships]
    return render_template('friends.html', friends=friends)


#with app.app_context():
#       db.drop_all()
#       db.create_all() 

# need an app route for /creataccount page
if __name__ == "__main__":
    app.run(debug=True)  # Run the app in debug mode

# used for resetting the database. only use if needing to add certain variables 
# or to erase the database
# keep in mind it needs to be above the app.run line



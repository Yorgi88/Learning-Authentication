from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from pathlib import PurePath
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
# python -m pip install -r requirements.txt to install the requirements
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

"""configure flask-login login's manager here"""
# login_manager = LoginManager()
# login_manager.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    # id = db.Column(db.Integer, primary_key=True)
    # email = db.Column(db.String(100), unique=True, nullable=False)
    # password = db.Column(db.String(100), nullable=False)
    # name = db.Column(db.String(1000), nullable=False)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))




"""create a user-loader callack here"""
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# return db.get_or_404(User, user_id)



 
with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    """Werkzeug library to hash user password."""
    if request.method == "POST":
        data = request.form
        name = data["name"]
        email = data["email"]
        password = data["password"]
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            #if user already exists
            flash("User already exists")
            return redirect(url_for('login'))
        hash_and_salted_password = generate_password_hash(
            password,
            method="pbkdf2:sha256",
            salt_length=8

        )
        new_user = User(
            name = name,
            email=email,
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        """So after the user registers, the user has access to the file 
        so after passing the auths the user can access the file"""

        # return render_template("secrets.html", name=request.form.get("name"))
        return redirect(url_for('secrets'))
    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.form
        email = data["email"]
        password = data["password"]

        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if not user or not check_password_hash(user.password, password):
            flash("incorrect email or password")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))

        # if not user:
        #     flash("email does not exist")
        #     return redirect(url_for('login'))
        # elif not check_password_hash(user.password, password):
        #     flash("incorrect password")
        #     return redirect(url_for('login'))
        # else:
        #     login_user(user)
        #     return redirect(url_for('secrets'))

        # user = User.query.filter_by(email=email).first()
        # if user and check_password_hash(user.password, password):
        #     login_user(user)
        #     return redirect(url_for('secrets'))
        # else:
        #     flash('Login Unsuccessful. Please check email and password', 'danger')

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    # now only authenticated users can access the secret file
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/download')
@login_required
def download():
    return send_from_directory("static", path="files/cheat_sheet.pdf")



"""Another way of doing it, lets try imprt pure path from pathlib"""




if __name__ == "__main__":
    app.run(debug=True)



"""Hashing are like fixed-size string assigned, the user register their login details and the details are passed 
through the hash function. Then converted to series of alphanumeric characters"""

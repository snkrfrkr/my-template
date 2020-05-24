from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

login_manager = LoginManager()

app = Flask(__name__)
app.config['SECRET_KEY'] = "fdndflkadlkadklmcdlkamclkmckdmadlkamkl"
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///User.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager.init_app(app)
db = SQLAlchemy(app)

login_manager.login_view = 'login'

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vorname = db.Column(db.String(128))
    nachname = db.Column(db.String(128))
    email = db.Column(db.String(128))
    password = db.Column(db.String(128))
    user_valid = db.Column(db.Integer)

class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

admin = Admin(app)
admin.add_view(MyModelView(Users, db.session))

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route("/", methods=['POST', 'GET'])
def index():
    return render_template("index.html")

@app.route("/signup", methods=['POST', 'GET'])
def signup():
    if request.method == "POST":
        tvorname = request.form['vorname']
        tnachname = request.form['nachname']
        temail = request.form['email']
        hpassword = generate_password_hash(request.form['password'], method='sha256')
        user_valid = 0
        new_user = Users(vorname=tvorname, nachname=tnachname, email=temail, password=hpassword, user_valid=user_valid)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('index'))
    return render_template("signup.html")

@app.route("/login", methods=['POST', 'GET'])
def login():
    if request.method == "POST":
        user = Users.query.filter_by(email=request.form['email']).first()
        user_state = bool(user.user_valid)
        print(f'User hat den Status {user_state}')
        if user:
            if check_password_hash(user.password, request.form['password']) and user_state == True:
                login_user(user, remember=False)
                return redirect(url_for('main'))
            else:
                return redirect(url_for('login'))

    return render_template("login.html")

@app.route("/logout", methods=['POST', 'GET'])
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/admin", methods=['POST', 'GET'])
@login_required
def admin():
    return redirect(url_for('admin'))

@app.route("/main", methods=['POST', 'GET'])
@login_required
def main():
    return render_template("test.html")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
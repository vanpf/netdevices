from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import re
from forms import LoginForm
from helpers import Bash, cidr_to_mask, get_devices, change_ip


app = Flask(__name__)


''' * * * * * * * * * * FOR AUTHENTICATION * * * * * * * * * * '''
db = SQLAlchemy(app)

app.config['SECRET_KEY'] = 'Flasky flasky flask'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

class User(db.Model, UserMixin):

    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self,  password):
        return check_password_hash(self.password_hash, password)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


''' * * * * * * * * * * CONTROLERS * * * * * * * * * * '''
@app.route('/')
@login_required
def index():
    return render_template('index.html', devices = get_devices())


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        user = User.query.filter_by(username=form.login.data).first()
        if user is not None and user.check_password(form.password.data):
            login_user(user)
            return redirect('/')
        flash('error')
    return render_template('login.html', form=form)


@app.route('/clear/<id>', methods=['GET', 'POST'])
def clear(id):

    try:
        id = int(id)
    except ValueError:
        return redirect('/')

    result = change_ip(id, False)

    if len(result) > 3:
        errors = result
        return render_template('errors.html', errors=errors)

    return redirect('/')


@app.route('/edit/<id>/<ip>/<mask>', methods=['GET', 'POST'])
def edit(id, ip, mask):

    try:
        id = int(id)
    except ValueError:
        return redirect('/')

    result = change_ip(id, False)

    if len(result) <= 3:
        result = change_ip(id, True, ip+'/'+mask)

    if len(result) > 3:
        errors = result
        return render_template('errors.html', errors=errors)

    return redirect('/')


@app.route('/validate', methods=['POST'])
def validator():

    valide = re.compile("[0-9]+[\.][0-9]+[\.][0-9]+[\.][0-9]+[\/]\d")
    if valide.search(request.form['ip']):
        return '/edit/'+request.form['id']+'/'+request.form['ip']

    return ''


if __name__ == '__main__':
    app.run(debug=True)

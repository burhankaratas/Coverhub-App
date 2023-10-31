from flask import Flask,render_template,flash,redirect,url_for,session,logging,request,g
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators, SubmitField
from passlib.hash import sha256_crypt 
from functools import wraps
import smtplib
import hashlib



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Bu sayfayı görüntüleme izniniz yok", "danger")
            return redirect(url_for("index"))
    return decorated_function



app = Flask(__name__)
app.secret_key= "gorevdefterisecretkey"





app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "coverHub"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"


 
mysql = MySQL(app)


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    loginForm = LoginForm(request.form)

    if request.method == "POST":
        usernameControlData = loginForm.username.data
        passwordControlData = loginForm.password.data

        cursor = mysql.connection.cursor()

        sorgu = "SELECT * FROM users WHERE username = %s"
        result = cursor.execute(sorgu, (usernameControlData,))

        if result > 0:
            data = cursor.fetchone()

            stored_password = data["password"]

            if sha256_crypt.verify(passwordControlData, stored_password):
                session["logged_in"] = True
                session["username"] = usernameControlData


                flash("Başarıyla giriş yaptınız.", "success")
                return redirect(url_for("home", username=session["username"],))
            else:
                flash("Hatalı şifre girdiniz.", "danger")
                return render_template("login.html", loginForm=loginForm)
        else:
            flash("Böyle bir kullanıcı bulunamadı.", "danger")
            return render_template("login.html", loginForm=loginForm)

    return render_template("login.html", loginForm=loginForm)








@app.route("/register", methods = ["POST", "GET"])
def register():
    registerForm = RegisterForm(request.form)

    if request.method == "GET":
        return render_template("register.html", registerForm = registerForm)
    
    elif request.method == "POST":
        emailData = registerForm.email.data
        usernameData = registerForm.username.data
        passwordData = registerForm.password.data
        passwordAgainData = registerForm.passwordAgain.data


        if passwordData == passwordAgainData:
            if registerForm.validate():
                hash_password = sha256_crypt.encrypt(passwordData)

                cursor = mysql.connection.cursor()        


                sorgu = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"

                cursor.execute(sorgu, (usernameData, emailData, hash_password))
                mysql.connection.commit()
                cursor.close()

                flash("Başarıyla Kaydoldunuz", "success")
                return redirect(url_for("login"))
            else:
                flash("Lütfen gerekli bilgileri doldurunuz.", "danger")
                return redirect(url_for("register"))
        
        else:
            flash("Şifreler Birbiri ile uyuşmuyor. Lütfen tekrar deneyiniz.", "danger")
            return redirect(url_for("register"))



@app.route("/home/<string:username>")
@login_required
def home(username):
    return render_template("home.html", username = username)


@app.route("/logout")
def logout():
    session.clear()
    flash("Başarıyla Çıkış Yaptınız.", "success")
    return redirect(url_for("login"))


class LoginForm(Form):
    username = StringField()
    password = PasswordField()


class RegisterForm(Form):
    email = StringField(validators=[validators.Email("Geçerli bir email adresi giriniz.")])
    username = StringField(validators=[validators.Length(min=5, max=25)])
    password = PasswordField(validators=[validators.length(min=6, max=25)])
    passwordAgain = PasswordField()

if __name__ == "__main__":
    app.run(debug= True)

from flask import Flask, render_template, redirect, url_for, session,request
import sqlite3
from flask import g

DATABASE = 'login.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def validate(username, password):
    g.db = get_db()
    user = query_db('SELECT * FROM Users WHERE username = ?',
                    [username], one=True)

    return False if user is None else True

def check_password(hashed_password, user_password):
    return True


app=Flask(__name__)

app.config['SECRET_KEY'] = "aw@4352gfdjfgdjn786437824"
@app.route("/",methods=["POST","GET"])
@app.route("/login",methods=["POST","GET"])
def login():
    error = None
    if request.method=='POST':
        username = request.form['username']
        password = request.form['password']
        validate_user = validate(username, password)
        if validate_user == False:
            error = 'Invalid Credentials Please Try Again'
            return render_template('login.html', error=error)
        else:
            session['username']=username
            session['password']=password
            return redirect(url_for('home'))
    return render_template('login.html', error=error)


@app.route("/home",methods=["POST","GET"])
def home():

    return render_template("home.html")

@app.route("/analysis",methods=["POST","GET"])
def analysis():
    import applib
    payload=load_analyzer.load_analyzer()
    hay=json.dumps(payload)
    return hay


@app.route("/net-analysis",methods=["POST","GET"])
def netaly():

    return render_template("analysis.html")


@app.route("/logout",methods=["POST","GET"])
def logout():
    session.pop("username",True)
    session.pop("password",True)
    return redirect(url_for("login"))




if __name__=="__main__":
    app.run(port="9001",debug=True)

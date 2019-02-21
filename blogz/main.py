from flask import Flask, request, redirect, render_template, session
import cgi
from app import app, db
from models import User, Blog
from hashutils import check_pw_hash

@app.before_request
def login_required():
    allowed_routes = ['index', 'blog', 'login', 'signup']
    if request.endpoint not in allowed_routes and 'username' not in session:
        return redirect('/login')

@app.route("/")
def index():
    users = User.query.all()
    user_id = request.args.get("user_id")
    if user_id:
        blogs = Blog.query.filter_by(owner_id=user_id).all()
        return render_template("selecteduser.html", users=users, blogs=blogs)
    return render_template("index.html", users=users)

@app.route("/blog")
def blog():
    blogs = Blog.query.all()
    blog_id = request.args.get("id")
    user_id = request.args.get("user_id")
    users = User.query.all()
    if user_id:
        blogs = Blog.query.filter_by(owner_id=user_id).all()
        return render_template("selectedbloger.html", blogs=blogs, users=users)
    if blog_id:
        blog = Blog.query.get(blog_id)
        return render_template("selectedblog.html", blog=blog, users=users)
    return render_template("blog.html", blogs=blogs, users=users)

@app.route("/newpost", methods=['POST', 'GET'])
def newpost():
    title_error = ""
    body_error = ""
    if request.method == "POST":
        title = request.form['title']
        body = request.form['body']    
        if title == "":
            title_error = "Please title your blog."
        if body == "":
            body_error = "Blog must have a body."
        if len(title) > 0 and len(body) > 0:
            owner = User.query.filter_by(username=session['username']).first()
            new_blog = Blog(title, body, owner)
            db.session.add(new_blog)
            db.session.commit()
            post_url = "/blog?id=" + str(new_blog.id)
            return redirect(post_url)
    return render_template("newblog.html", title_error=title_error, body_error=body_error)

@app.route("/login", methods=['POST', 'GET'])
def login():
    username_error = ""
    password_error = ""
    if request.method == 'POST':
        username = request.form['username']
        username = username.strip(" ")
        password = request.form['password']
        password = password.strip(" ")
        user = User.query.filter_by(username=username).first()
        if user and check_pw_hash(password, user.pw_hash):
            session['username'] = username
            return redirect("/newpost") 
        if not user:
            username_error = "Incorrect username."
        if user and not check_pw_hash(password, user.pw_hash):
            password_error = "Incorrect password."
    return render_template("login.html", username_error=username_error, password_error=password_error)

@app.route("/signup", methods=['POST', 'GET'])
def signup():
    username_error = ""
    password_error = ""
    verify_error = ""
    if request.method == 'POST':
        username = request.form['username']
        username = username.strip(" ")
        password = request.form['password']
        password = password.strip(" ")
        verify = request.form['verify']
        verify = verify.strip(" ")
        existing_user = User.query.filter_by(username=username).first()
        if not existing_user and len(username) >= 3 and len(password) >= 3 and password == verify:
            new_user = User(username, password)
            db.session.add(new_user)
            db.session.commit()
            session['username'] = username
            return redirect('/newpost')
        if existing_user:
            username_error = "Username already in use."
        if len(username) < 3:
            username_error = "Username must be more than 2 characters."
        if len(password) < 3:
            password_error = "Password must be more than 2 characters."
        if password != verify:
            verify_error = "Passwords don't match"
    return render_template("signup.html", username_error=username_error, password_error=password_error, verify_error=verify_error)

@app.route('/logout')
def logout():
    del session['username']
    return redirect('/blog')


if __name__ == '__main__':
    app.run()
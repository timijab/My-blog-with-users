from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from functools import wraps
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import InputRequired
from flask_login import LoginManager
from sqlalchemy.exc import IntegrityError
from flask import abort
from flask_ckeditor import CKEditorField

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# flask login
login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES
class BlogUser(UserMixin, db.Model):
    __tablename__ = "user_name"
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    #     we establish the relationship with the child here
    #  This will act like a list of blog post attached to each user
    #     the author refers to the aut
    posts = relationship("BlogPost", back_populates="author")
    #     relationship with the comment section parent giving the data
    comments = relationship("BlogComments", back_populates="comment_author")


db.create_all()


class BlogComments(db.Model):
    __tablename___ = 'comments_section'
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.String(250), nullable=False)
    # author id is storing the id of the author according to his id in the Bloguser database
    author_id = db.Column(db.Integer, db.ForeignKey('user_name.id'))
    # while this is giving the taking the child relationship and populating the useer with his comments
    comment_author = relationship("BlogUser", back_populates="comments")


db.create_all()


# in the relationship hierarchy this the child of the class BlogUser
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # the db.ForeignKey('something') relates the data in this table to the parent table
    # Create Foreign key, "user_name.id" username referring to the table
    author_id = db.Column(db.Integer, db.ForeignKey("user_name.id"))
    # we create child relationship
    author = relationship("BlogUser", back_populates="posts")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


db.create_all()


class UserRegistration(FlaskForm):
    username = StringField(label='Enter your name', validators=[InputRequired()])
    email = StringField(label='Email address', validators=[InputRequired()])
    password = PasswordField(label='Enter your desired password', validators=[InputRequired()])
    submit = SubmitField(label='register')



# login wrapper function
@login_manager.user_loader
def load_user(user_id):
    return BlogUser.query.get(int(user_id))


# current user is a function under the flask_login framework.


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = UserRegistration()
    if request.method == 'GET':
        return render_template('register.html', forms=form)
    elif request.method == 'POST':
        try:
            new_user = BlogUser(
                user=form.username.data,
                email=form.email.data,
                password=generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            flash('successfully added')
            return render_template('index.html', is_logged_in=True)
        except IntegrityError:
            flash('This email or username already exists')
            return redirect(url_for('login'))

name = ''
@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    post = BlogUser.query.all()
    if current_user.is_authenticated:
        for y in post:
            if int(y.id) == current_user.id:
                username = y.user
                global name
                name = username
                return render_template("index.html", all_posts=posts, new=post, name=username, is_logged_in=True)

    return render_template("index.html", all_posts=posts, new=post)



def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(current_user)
        if current_user.id != 1:
            return abort(403)
        else:
            pass
        return f(*args, **kwargs)

    return decorated_function


class LoginForm(FlaskForm):
    email = StringField(label='Enter your email', validators=[InputRequired()])
    password = PasswordField(label='enter your password')
    submit = SubmitField(label='let me in!')


@app.route('/login', methods=['POST', 'GET'])
def login():
    forms = LoginForm()
    if request.method == 'GET':
        return render_template("login.html", form=forms)
    # elif request.method == 'POST':
    elif forms.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user = BlogUser.query.filter_by(email=email).first()
        # to validate that form is submitted
        if user.email == email:
            checker = check_password_hash(pwhash=user.password, password=password)
            if checker is True:
                login_user(user)
                if int(user.id) == int(1):
                    is_admin = True

                else:
                    is_admin = False
                return render_template('index.html', is_logged_in=True, is_admin=is_admin)
            else:
                return redirect(url_for('login'))
        else:
            return redirect(url_for('login'))
    else:
        flash(message='Please go ahead and register')
        return redirect(url_for('login'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


class Comments(FlaskForm):
    comment_text = CKEditorField("Comment")
    submit = SubmitField(label="Submit comment")


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    form = Comments()
    if request.method == 'GET':
        requested_post = BlogPost.query.get(post_id)
        return render_template("post.html", post=requested_post, comment=form, name=name)
    elif request.method == 'POST':
        # new_comment = BlogComments(
        #     comment= form.comment_text.data,
        #     author_id=
        # )
        #
        # db.session.add(new_comment)
        # db.session.commit()
        print(current_user)
        return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['POST', 'GET'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method == 'GET':
        return render_template("make-post.html", form=form)
    elif request.method == "POST":
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)

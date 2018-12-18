import os
import requests
import json
from flask import Flask, render_template, session, redirect, request, url_for, flash
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FileField, PasswordField, BooleanField, SelectMultipleField, ValidationError
from wtforms.validators import Required, Length, Email, Regexp, EqualTo
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from newsapi import NewsApiClient
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate, MigrateCommand


# Application configurations
app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hardtoguessstring'
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get('DATABASE_URL') or "postgresql://localhost/nisakhanfinaldb"
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['HEROKU_ON'] = os.environ.get('HEROKU')
api_key = 'b6ad0853a6b743788e02e3cd26b93f3f'
newsapi = NewsApiClient(api_key='b6ad0853a6b743788e02e3cd26b93f3f')

manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)
migrate = Migrate(app, db)
manager.add_command('db', MigrateCommand)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

########################
######## Models ########
########################

## Association tables

tags = db.Table('tags', db.Column('searchTerms_id', db.Integer, db.ForeignKey('searchTerms.id')), db.Column('article_id', db.Integer, db.ForeignKey('articles.id')))
user_collection = db.Table('user_collection',db.Column('user_id', db.Integer, db.ForeignKey('articles.id')),db.Column('collection_id',db.Integer, db.ForeignKey('personalarticleCollection.id')))


## User-related Models

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, index=True)
    email = db.Column(db.String(64), unique=True, index=True)
    password_hash = db.Column(db.String(128))
    PersonalarticleCollection = db.relationship('PersonalarticleCollection', backref = "User")

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class article(db.Model):
    __tablename__ = 'articles'
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(128))
    pub = db.Column(db.String(256))
    URL = db.Column(db.String(256))
    description = db.Column(db.String())
    author = db.Column(db.String())
    def __repr__(self):
        return "{}: {}".format(self.title, self.pub, self.URL, self.description, self.author)

class PersonalarticleCollection(db.Model):
    __tablename__ = "personalarticleCollection"
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    articles = db.relationship('article', secondary=user_collection, backref=db.backref('personalarticleCollections', lazy = 'dynamic'), lazy = 'dynamic')

class SearchTerm(db.Model):
    __tablename__ = 'searchTerms'
    id = db.Column(db.Integer, primary_key=True)
    term = db.Column(db.String(32), unique = True)
    articles = db.relationship('article', secondary=tags, backref = db.backref('searchTerms', lazy='dynamic'), lazy = 'dynamic')
    def __repr__(self):
        return "{}".format(self.term)

class DeleteButtonForm(FlaskForm):
    submit = SubmitField("Delete")

########################
######## Forms #########
########################

class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Required(),Length(1,64),Email()])
    username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
    password2 = PasswordField("Confirm Password:",validators=[Required()])
    submit = SubmitField('Register User')

    def validate_email(self,field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered.')

    def validate_username(self,field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[Required(), Length(1,64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')

class articlesearchForm(FlaskForm):
    search = StringField("Enter a term to search articles", validators=[Required()])
    submit = SubmitField('Submit')

    def validate_search(self, field):
        search_here = field.data
        if search_here[0] == "#":
            raise ValidationError ("!!!! ERRORS IN FORM SUBMISSION - you can't start with hashtags!")
        if len(search_here.split(" ")) > 1:
            raise ValidationError ("Display name must be only 1 word")

class CollectionCreateForm(FlaskForm):
    name = StringField('Collection Name',validators=[Required()])
    article_picks = SelectMultipleField('articles to include')
    submit = SubmitField("Create Collection")

########################
### Helper functions ###
########################

def get_articles_from_newsapi(search_string):
    import requests
    baseurl = 'https://newsapi.org/v2/everything?q=' + search_string + '&' + 'apiKey=b6ad0853a6b743788e02e3cd26b93f3f'
    responsehere = json.loads(requests.get(baseurl).text)
    return(responsehere)

def get_article_by_id(id):
    newnewarticleid = article.query.filter_by(id=id).first()
    return newnewarticleid

def get_or_create_article(title, pub, url, description, author):
    articleherehere = article.query.filter_by(title = title).first()
    if articleherehere:
        return articleherehere
    else:
        xxx = article(title=title, pub=pub, URL = url, description=description, author=author)
        db.session.add(xxx)
        db.session.commit()
        return xxx

def get_or_create_search_term(term):
    searchingTerm = SearchTerm.query.filter_by(term = term).first()
    if searchingTerm:
        return searchingTerm
    else:
        searchingTerm = SearchTerm(term = term)
        articleList = get_articles_from_newsapi(term)
        for i in range(0, 10):
            newheadline = (articleList["articles"][i]["title"])
            newurl = (articleList["articles"][i]["url"])
            newpub = (articleList["articles"][i]["publishedAt"])
            newdescription = (articleList["articles"][i]["description"])
            newauthor = (articleList["articles"][i]["author"])
            xyx = get_or_create_article(newheadline, newpub, newurl, newdescription, newauthor)
            searchingTerm.articles.append(xyx)
    db.session.add(searchingTerm)
    db.session.commit()
    return searchingTerm

def get_or_create_collection(name, current_user, article_list=[]):
    collectionhere = PersonalarticleCollection.query.filter_by(name = name, user_id = current_user.id).first()
    if collectionhere:
        return collectionhere
    else:
        new_collectionhere = PersonalarticleCollection(name = name, user_id = current_user.id, articles = [])
        for i in article_list:
            new_collectionhere.articles.append(i)
        db.session.add(new_collectionhere)
        db.session.commit()
        return new_collectionhere


########################
#### View functions ####
########################

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/secret')
@login_required
def secret():
    return "Only authenticated users can do this! Try to log in or contact the site admin."

@app.route('/', methods=['GET', 'POST'])
def index():
    form = articlesearchForm()
    if form.validate_on_submit():
        searchingTerm = get_or_create_search_term(form.search.data)
        return redirect(url_for('search_results',search_term=searchingTerm))
    return render_template('index.html',form=form)

@app.route('/articles_searched/<search_term>')
def search_results(search_term):
    term = SearchTerm.query.filter_by(term=search_term).first()
    relevant_articles = term.articles.all()
    return render_template('searched_articles.html',articles=relevant_articles,term=term)

@app.route('/search_terms')
def search_terms():
    searchingTerm = SearchTerm.query.all()
    return render_template('search_terms.html', all_terms = searchingTerm)

@app.route('/all_articles')
def all_articles():
    articles = article.query.all()
    return render_template('all_articles.html',all_articles=articles)

@app.route('/create_collection',methods=["GET","POST"])
@login_required
def create_collection():
    form = CollectionCreateForm()
    articles = article.query.all()
    choices = [(g.id, g.title) for g in articles]
    form.article_picks.choices = choices
    if request.method == 'POST':
        articles = [get_article_by_id(int(id)) for id in form.article_picks.data]
        get_or_create_collection(name=form.name.data, current_user = current_user, article_list = articles)
        return redirect(url_for('collections'))
    return render_template('create_collection.html', form = form)


@app.route('/collections',methods=["GET","POST"])
@login_required
def collections():
    form = DeleteButtonForm()
    collectionshere = PersonalarticleCollection.query.filter_by(user_id = current_user.id)
    return render_template('collections.html', collections = collectionshere, form=form)

@app.route('/collection/<id_num>')
def single_collection(id_num):
    id_num = int(id_num)
    collection = PersonalarticleCollection.query.filter_by(id=id_num).first()
    articles = collection.articles.all()
    return render_template('collection.html',collection=collection, articles=articles)

@app.route('/delete/<searchTerms>',methods=["GET","POST"])
def delete(searchTerms):
    articleqq = PersonalarticleCollection.query.filter_by(name=searchTerms).first()
    db.session.delete(articleqq)
    db.session.commit()
    flash("Delete list {}".format(searchTerms))
    return redirect(url_for('collections'))


if __name__ == '__main__':
    db.create_all()
    manager.run()

# Dependencies
import os
import re
import random
import hashlib
import hmac
from string import letters
import webapp2
import jinja2
from google.appengine.ext import db

# Environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Security and Authentication
secret = 'GrownMenCanEnjoyLittlePonies'


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


# Parent Handler
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


# Models


# user parent
def users_key(group='default'):
    return db.Key.from_path('users', group)


# user model
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


# blog parent
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# blog model
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    authorId = db.IntegerProperty(required=True)
    authorName = db.StringProperty(required=True)

    def get_votes(self):
        votes = Vote.all()
        array = []
        for vote in votes:
            if(vote.post_id == self.key().id()):
                array.append(vote)
        return array

    def vote_score(self):
        score = 0
        votes = self.get_votes()
        for vote in votes:
            score += vote.value
        return score

    def get_comments(self):
        comments = Comment.all().order('created')
        array = []
        for comment in comments:
            if(comment.post_id == self.key().id()):
                array.append(comment)
        return array

    def render(self):
        id = str(self.key().id())
        votes = self.get_votes()
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p=self, id=id, count=self.vote_score(),
                          comments=self.get_comments())


# vote parent
def vote_key(name='default'):
    return db.Key.from_path('votes', name)


# vote model
class Vote(db.Model):
    value = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    voter_id = db.IntegerProperty(required=True)


# comment parent
def comment_key(name='default'):
    return db.Key.from_path('comments', name)


# Comment Model
class Comment(db.Model):
    ref_Id = db.IntegerProperty()
    post_id = db.IntegerProperty(required=True)
    commenter_id = db.IntegerProperty(required=True)
    commenter_name = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)


# Routes
class IndexRoute(BlogHandler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            return self.redirect('/signup')


class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts)


class PostPage(BlogHandler):
    def get(self, post_id):
        pkey = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(pkey)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        authorId = self.user.key().id()
        authorName = self.user.name

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content,
                     authorId=authorId, authorName=authorName, likes=0,
                     dislikes=0)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "Need a subject as well as content"
            self.render("newpost.html", subject=subject,
                        content=content, error=error)


# Renders a page to edit the Post if it belongs to the logged in user
class EditPost(BlogHandler):
    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        post_id = self.request.get('post_id')
        author_id = self.request.get('author_id')
        user_id = self.user.key().id()

        if(user_id == int(author_id)):
            error = ""
            if subject and content:
                self.render("editpost.html", subject=subject, content=content,
                            error=error, post_id=post_id, author_id=author_id)
            else:
                error = "Need a subject as well as content"
                self.render("editpost.html", subject=subject, content=content,
                            error=error, post_id=post_id, author_id=author_id)
        else:
            self.redirect('/blog/%s' % post_id)


# This is called by the EditPost page to overwrite the index in the database
class OverwritePost(BlogHandler):
    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')
        post_id = self.request.get('post_id')
        author_id = self.request.get('author_id')
        user_id = self.user.key().id()

        if(user_id == int(author_id)):
            error = ""
            if subject and content:
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)
                post.subject = subject
                post.content = content
                post.put()
                self.redirect("/blog/%s" % post_id)
            else:
                self.redirect("/blog/%s" % post_id)
        else:
            self.redirect('/blog/%s' % post_id)


class DeletePost(BlogHandler):
    def post(self):
        if not self.user:
            return self.redirect('/login')

        author_id = int(self.request.get('author_id'))
        uid = self.user.key().id()
        post_id = self.request.get('post_id')
        if(author_id == uid):
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            post.delete()
            self.redirect('/blog')
        else:
            self.redirect('/blog/%s' % post_id)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    def get(self):
        return self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # check if user exists
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')


class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error=msg)


class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class VoteHandler(BlogHandler):
    def post(self):
        if self.user:
            author_id = self.request.get('author_id')
            voter_id = self.user.key().id()
            post_id = self.request.get('post_id')
            score = int(self.request.get('score'))
            has_voted = False

            v = Vote(parent=vote_key(), value=score,
                     post_id=int(post_id), voter_id=int(voter_id))

            if(author_id != voter_id):
                key = db.Key.from_path('Post', int(post_id), parent=blog_key())
                post = db.get(key)

                votes = post.get_votes()
                has_voted = False
                if(votes):
                    for vote in votes:
                        if(vote.voter_id == self.user.key().id()):
                            has_voted = True

                    if has_voted:
                        self.redirect('/blog/%s' % post_id)
                    else:
                        v.put()
                        self.redirect('/blog/%s' % post_id)
                else:
                    v.put()
                    self.redirect('/blog/%s' % post_id)
            else:
                self.redirect('/blog/%s')
        else:
            return self.redirect('/login')


class CommentHandler(BlogHandler):
    def post(self):
        post_id = int(self.request.get('post_id'))
        if self.user:
            author_id = int(self.request.get('author_id'))
            commenter_id = self.user.key().id()
            commenter_name = self.user.name
            comment = self.request.get('comment')

            c = Comment(parent=comment_key(), author_id=author_id,
                        commenter_id=commenter_id,
                        commenter_name=commenter_name,
                        post_id=post_id, comment=comment)

            if(author_id and commenter_id):
                c.put()
                c.ref_Id = c.key().id()
                c.put()
                self.redirect('/blog/%s' % post_id)
            else:
                self.redirect('/blog/%s' % post_id)
        else:
            return self.redirect('/login')


class DeleteCommentHandler(BlogHandler):
    def post(self):
        if not self.user:
            return self.redirect('/login')

        comment_id = int(self.request.get('comment_id'))
        commenter_id = int(self.request.get('commenter_id'))
        post_id = self.request.get('post_id')
        user_id = self.user.key().id()

        if(commenter_id == user_id):
            key = db.Key.from_path('Comment', comment_id, parent=comment_key())
            comment = db.get(key)
            comment.delete()
            self.redirect('/blog')
        else:
            self.redirect('/blog/%s' % post_id)


class EditCommentHandler(BlogHandler):
    def post(self):
        if not self.user:
            return self.redirect('/login')

        new_comment = self.request.get('new_comment')
        comment_id = int(self.request.get('comment_id'))
        commenter_id = int(self.request.get('commenter_id'))
        post_id = self.request.get('post_id')
        user_id = self.user.key().id()

        if(user_id == commenter_id):
            key = db.Key.from_path('Comment', comment_id, parent=comment_key())
            comment = db.get(key)
            comment.comment = "Edited: \n" + new_comment
            comment.put()
            self.redirect("/blog/%s" % post_id)
        else:
            self.redirect('/blog/%s' % post_id)


app = webapp2.WSGIApplication([('/', IndexRoute),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/vote', VoteHandler),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost', EditPost),
                               ('/blog/delete', DeletePost),
                               ('/blog/savepost', OverwritePost),
                               ('/blog/comment', CommentHandler),
                               ('/blog/deletecomment', DeleteCommentHandler),
                               ('/blog/editcomment', EditCommentHandler),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout)
                               ],
                              debug=True)

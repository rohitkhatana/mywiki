#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import jinja2
import os
import re
from google.appengine.ext import db
import hashlib
import hmac

dire = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(autoescape=False,loader=jinja2.FileSystemLoader(dire))
class BaseHandler(webapp2.RequestHandler):
    def write(self,*a,**param):
        self.response.write(*a,**param)
        
    def render_str(self,template,**param):
        t = jinja_env.get_template(template)
        return t.render(**param)

    def render(self,template,**param):
        self.write(self.render_str(template,**param))

    def user_login(self):
        co_user_id = self.request.cookies.get("user_id")
        if co_user_id:
            if check_secure_val(co_user_id):
                key_id = Registration.get_by_id(int(check_secure_val(co_user_id)))
                if key_id:
                    name = key_id.username
                    return name
        else:
            return None

def render_str(self,template,**param):
        t = jinja_env.get_template(template)
        return t.render(**param)


    

###########################################################################################################################################################
def create_salt():
    s = ""
    lis=random.sample(string.letters,5)
    for i in lis:
        s =s+i
    return s

def make_pw_hash(us_name,pw,pass_salt):
    if pass_salt==None:
        pass_salt = create_salt();
    hashed = hashlib.sha256(us_name + pw + pass_salt).hexdigest()
    return '%s,%s' % (hashed,pass_salt)

def valid_pw(name,pw,hashed):
    salt = hashed.split(',')[1]
    if make_pw_hash(name,pw,salt) == hashed:
        return True
#<------------------------------ cookie hashing-------------------------------->
SECRET ="WIKICOOKIE"
def hash_str(s):
    return hmac.new(SECRET,s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
#############################################################################################################################################################
class WIKI(db.Model):
    page = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("wikiedit.html",p = self)

#table for registration
class Registration(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.EmailProperty()
###############################################################################################################################################################           
class MainHandler(BaseHandler):
    def get(self,path):
        name=self.user_login()
        url = self.request.url
        current_url = url.split('/')[3]
        self.response.headers.add_header('set-cookie','addr=%s;path=/' % current_url)
        self.write(self.request.url)
        self.render("wikifirst.html",name=name,url="")
    def post(self):
        pass
    
class EditPage(BaseHandler):
    def get(self,path):
        ed = self.request.cookies.get('edit')
        url = self.request.url
        current_url = url.split('/')[4]
        self.response.headers.add_header('set-cookie','addr=%s;path=/' % current_url)
        name=self.user_login()
        url = self.request.url
        current_url = url.split('/')[4]
        data = WIKI.all().filter("page = ",current_url).get()
        if data:
            self.render("edit.html",data=data,name=name)
        else:
            self.render("edit.html",name=name)
        

            
    def post(self):
        content = self.request.get('content')
        url = self.request.url
        current_url = url.split('/')[4]
        data = WIKI.all().filter("page = ",current_url).get()
        ######update query########################
        if data:
            setattr(data,'content',content)
            data.put()
            self.redirect('/' + current_url)
        else:
            if content:
                wp = WIKI(page=current_url,content=content)
                wp.put()
                self.redirect('/' + current_url)
            else:
                self.write(current_url)
                self.write(content)
                error = "some content should be there"
                self.render("wikiedit.html",error=error)


        
class WikiPage(BaseHandler):
    def get(self,path):
        name=self.user_login()
        url = self.request.url
        current_url = url.split('/')[3]
        self.response.headers.add_header('set-cookie','addr=%s;path=/' % current_url)    
        p = db.GqlQuery("select * from WIKI")
        flag=0
        for i in p:
            if i.page == current_url:
                flag=1
                content=i.content
        if flag:
            ur = "/_edit/" + current_url
            self.response.headers.add_header('set-cookie','edit=1;path=/')
            self.render('wikiedit.html',page=content,name=name,url=ur)
        elif not name:
            self.redirect('/login')
        else:
            self.redirect("/_edit/" + current_url)
    def post(self):
        content = self.request.get('content')
        url = self.request.url
        current_url = url.split('/')[3]
        if content:
            wp = WIKI(page=current_url,content=content)
            wp.put()
            self.redirect('/')
        else:
            self.write(current_url)
            self.write(content)
            error = "some content should be there"
            self.render("wikiedit.html",error=error)
#############################################################################################################################################################
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{6,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')  #[\S] means not any white space,newline,tab,catrige
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class SignupHandler(BaseHandler):
    def get(self):
        self.render('signup.html')
    def post(self):
        us_input=self.request.get('username')
        pass_input=self.request.get('password')
        ver_input=self.request.get('verify')
        email_input=self.request.get('email')
        error_flag=False
        params=dict(username=us_input,email=email_input)      #just a dict with these else there is no need of pass we can d=dict=()
        #checking if username is already exits 
        reg = db.GqlQuery("select * from Registration")
        for r in reg:
            if r.username == us_input:
                error_flag = True
                params['usname_error'] = "username already exists"
        
        if not valid_username(us_input):
            error_flag=True
            params['usname_error']="invalid user_name"
            
        if not valid_password(pass_input):
            error_flag=True
            params['pass_error']="invalid password"
        elif ver_input!=pass_input:
            params['ver_error']="your password didn't match"
            error_flag=True

        if not valid_email(email_input) or not email_input:
            error_flag=True
            params['mail_error']="it is'nt a valid e-mail address "
        if error_flag:
            self.render("signup.html",**params)
        else:
            pw = make_pw_hash(us_input,pass_input,'')
            R = Registration(username = us_input, password = pw, email = email_input)
            R.put()
            user_id = str(R.key().id())
            hashed_user_id = make_secure_val(user_id)
            self.response.headers.add_header('set-cookie','user_id = %s;path=/' % hashed_user_id)   #value of cookies always must be string type
            addr=self.request.cookies.get('addr')
            self.redirect('/' + addr)
            #self.redirect("/unit2/welcome?userid=" + str(R.key().id()))
            #self.redirect('/unit2/welcome?username=' + self.username)
        

class LoginHandler(BaseHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username=self.request.get('username')
        password=self.request.get('password')
        R = Registration.all().filter('username = ',username).get()
        if R:
            if valid_pw(username,password,R.password):
                user_id=R.key().id()
                hashed_user_id = make_secure_val(str(user_id))
                self.response.headers.add_header('set-cookie','user_id = %s;path=/' % hashed_user_id)
                #self.render('login.html',error=user_id)
                addr=self.request.cookies.get('addr')
                self.redirect('/' + addr)
                
        else:
            error="Username or Password is incorrect"
            self.render('login.html',error=error)

        
class LogOutHandler(BaseHandler):
    def get(self):
        addr=self.request.cookies.get('addr')
        self.response.headers.add_header('set-cookie','user_id =;path=/')
        self.redirect('/' + addr)
PAGE_RE = r'/(?:[a-zA-Z0-9_-]+)/*'
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/login', LoginHandler),
    ('/logout', LogOutHandler),
    ('/signup', SignupHandler),
    ('/_edit' + PAGE_RE, EditPage),
    (PAGE_RE, WikiPage)
], debug=True)

from flask import Flask, json, redirect, render_template,flash, request
from flask.globals import request, session
from flask.helpers import url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_sslify import SSLify
from sqlalchemy import text

from flask_login import login_required, logout_user, login_user, login_manager, LoginManager, current_user

from forms import *
from models import *

from flask_mail import Mail
import json
import os

import logging
from logging.handlers import RotatingFileHandler


# mydatabase connection
local_server=True
app=Flask(__name__)
app.secret_key=os.environ["SECRET_KEY"]
csrf = CSRFProtect(app) # Apply CSRF Protection globally
sslify = SSLify(app)

with open('config.json','r') as c:
    params=json.load(c)["params"]

# using the Self-signed certificate. setting the ssl context
if __name__ == '__main__':
    app.run(ssl_context=('cert.pem', 'key.pem'))

app.config.update(
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT='465',
    MAIL_USE_SSL=True,
    MAIL_USERNAME=params['gmail-user'],
    MAIL_PASSWORD=params['gmail-password']
)
mail = Mail(app)

# this is for getting the unique user access
login_manager=LoginManager(app)
login_manager.login_view='login'

# app.config['SQLALCHEMY_DATABASE_URI']='mysql://username:password@localhost/databsename'
app.config['SQLALCHEMY_DATABASE_URI']='mysql://root:@localhost/covid_new'
db=SQLAlchemy(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id)) or Hospitaluser.query.get(int(user_id))

# Create a logger object. Create a rotating file handler which will create the log file dynamically at the specified location and set the log format.
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
file_handler = RotatingFileHandler('/logs/application.log', maxBytes=10240, backupCount=5)
formatter = logging.Formatter('%(asctime)s [%(levelname)s] - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

if __name__ == "__main__":
    app.logger.addHandler(file_handler)


@app.route("/")
def home():
    try:
        return render_template("index.html")
    except Exception as e:
        logger.error(f"Error in home route: {str(e)}")
        # Redirect to 404 error handler
        return page_not_found(404)

@app.route("/trigers")
def trigers():
    query=Trig.query.all() 
    return render_template("trigers.html",query=query)


@app.route('/signup',methods=['POST','GET'])
def signup():
        form = SignupForm(request.form)
        if request.method=="POST" and form.validate():
            srfid=request.form.get('srf')
            email=request.form.get('email')
            dob=request.form.get('dob')
            # print(srfid,email,dob)
            encpassword=generate_password_hash(dob)
            user=User.query.filter_by(srfid=srfid).first()
            emailUser=User.query.filter_by(email=email).first()
            if user or emailUser:
                flash("Email or srfid is already taken","warning")
                logger.warning("Email or srfid is already taken for user %s", user)
                return render_template("usersignup.html")
            new_user=db.engine.execute(text
                                       ("INSERT INTO `user` (`srfid`,`email`,`dob`) VALUES (:srfid, :email, :encpassword)").params
                                       (srfid=srfid, email=email, encpassword=encpassword))
                    
            flash("SignUp Success. Please Login","success")
            logger.info("The SignUp for user %s is successful", new_user)
            return render_template("userlogin.html")

        return render_template("usersignup.html")


@app.route('/login',methods=['POST','GET'])
def login():
    form = LoginForm(request.form)
    if request.method=="POST" and form.validate():
        srfid=request.form.get('srf')
        dob=request.form.get('dob')
        user=User.query.filter_by(srfid=srfid).first()
        if user and check_password_hash(user.dob,dob):
            login_user(user)
            flash("Login Success","info")
            logger.info("Login successful for user %s", user)
            return render_template("index.html")
        else:
            flash("Invalid Credentials","danger")
            logger.error("Invalid credentials for user %s", user)
            return render_template("userlogin.html")


    return render_template("userlogin.html")

@app.route('/hospitallogin',methods=['POST','GET'])
def hospitallogin():
    form = HospitalLoginForm(request.form)
    if request.method=="POST" and form.validate():
        email=request.form.get('email')
        password=request.form.get('password')
        user=Hospitaluser.query.filter_by(email=email).first()
        if user and check_password_hash(user.password,password):
            login_user(user)
            flash("Login Success","info")
            logger.info("Login successful for user %s", user)
            return render_template("index.html")
        else:
            flash("Invalid Credentials","danger")
            logger.error("Invalid credentials for user %s", user)
            return render_template("hospitallogin.html")


    return render_template("hospitallogin.html")

@app.route('/admin',methods=['POST','GET'])
def admin():
    form = AdminForm(request.form)
    if request.method=="POST" and form.validate():
        username=request.form.get('username')
        password=request.form.get('password')
        if(username==params['user'] and password==params['password']):
            session['user']=username
            flash("login success","info")
            logger.info("Login successful for user %s", username)
            return render_template("addHosUser.html")
        else:
            flash("Invalid Credentials","danger")
            logger.error("Invalid credentials for user %s", username)

    return render_template("admin.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logout SuccessFul","warning")
    logger.info("Logout successful for user %s", current_user )
    return redirect(url_for('login'))



@app.route('/addHospitalUser',methods=['POST','GET'])
def hospitalUser():
    form = HospitalUserForm(request.form)
    if('user' in session and session['user']==params['user']):
      
        if request.method=="POST" and form.validate():
            hcode=request.form.get('hcode')
            email=request.form.get('email')
            password=request.form.get('password')        
            encpassword=generate_password_hash(password)  
            hcode=hcode.upper()      
            emailUser=Hospitaluser.query.filter_by(email=email).first()
            if  emailUser:
                flash("Email or srif is already taken","warning")
         
            db.engine.execute(text("INSERT INTO `hospitaluser` (`hcode`,`email`,`password`) VALUES (:hcode, :email, :encpassword)").params
                              (hcode=hcode, email=email, encpassword=encpassword))

            # my mail starts from here if you not need to send mail comment the below line
           
            mail.send_message('COVID CARE CENTER',sender=params['gmail-user'],recipients=[email],body=f"Welcome thanks for choosing us\nYour Login Credentials Are:\n Email Address: {email}\nPassword: {password}\n\nHospital Code {hcode}\n\n Do not share your password\n\n\nThank You..." )

            flash("Data Sent and Inserted Successfully","warning")
            logger.info("Data Sent and Inserted Successfully for user %s", current_user)
            return render_template("addHosUser.html")
    else:
        flash("Login and try Again","warning")
        logger.error("Data insertion was unsuccessful for user %s", current_user)
        return render_template("addHosUser.html")
    


# testing wheather db is connected or not  
@app.route("/test")
def test():
    try:
        a=Test.query.all()
        print(a)
        return f'MY DATABASE IS CONNECTED'
    except Exception as e:
        print(e)
        return f'MY DATABASE IS NOT CONNECTED {e}'

@app.route("/logoutadmin")
def logoutadmin():
    session.pop('user')
    flash("You are logout admin", "primary")
    logger.info("Logout admin for user %s", current_user)

    return redirect('/admin')


@app.route("/addhospitalinfo",methods=['POST','GET'])
def addhospitalinfo():
    form = HospitalInfoForm(request.form)
    email=current_user.email
    posts=Hospitaluser.query.filter_by(email=email).first()
    code=posts.hcode
    postsdata=Hospitaldata.query.filter_by(hcode=code).first()

    if request.method=="POST" and form.validate():
        hcode=request.form.get('hcode')
        hname=request.form.get('hname')
        nbed=request.form.get('normalbed')
        hbed=request.form.get('hicubeds')
        ibed=request.form.get('icubeds')
        vbed=request.form.get('ventbeds')
        hcode=hcode.upper()
        huser=Hospitaluser.query.filter_by(hcode=hcode).first()
        hduser=Hospitaldata.query.filter_by(hcode=hcode).first()
        if hduser:
            flash("Data is already Present you can update it..","primary")
            logger.info("Data is already Present you can update it.")
            return render_template("hospitaldata.html")
        if huser:            
            db.engine.execute(text("INSERT INTO `hospitaldata` (`hcode`,`hname`,`normalbed`,`hicubed`,`icubed`,`vbed`) VALUES (:hcode, :hname, :nbed, :hbed, :ibed, :vbed)").params
                              (hcode=hcode, hname=hname, nbed=nbed, hbed=hbed, ibed=ibed, vbed=vbed))
            flash("Data Is Added","primary")
            logger.info("Data is added to the database successfully for user %s", current_user)
        else:
            flash("Hospital Code not Exist","warning")
            logger.warning("Hospital Code not Exist")

    return render_template("hospitaldata.html",postsdata=postsdata)


@app.route("/hedit/<string:id>",methods=['POST','GET'])
@login_required
def hedit(id):
    form = EditForm(request.form)
    posts=Hospitaldata.query.filter_by(id=id).first()
  
    if request.method=="POST" and form.validate():
        hcode=request.form.get('hcode')
        hname=request.form.get('hname')
        nbed=request.form.get('normalbed')
        hbed=request.form.get('hicubeds')
        ibed=request.form.get('icubeds')
        vbed=request.form.get('ventbeds')
        hcode=hcode.upper()
        db.engine.execute(text("UPDATE `hospitaldata` SET `hcode` = :hcode, `hname` = :hname, `normalbed` = :nbed, `hicubed` = :hbed, `icubed` = :ibed, `vbed` = :vbed WHERE `hospitaldata`.`id` = :id").params
                          (hcode=hcode, hname=hname, nbed=nbed, hbed=hbed, ibed=ibed, vbed=vbed, id=id))
        flash("Slot Updated","info")
        logger.info("Slot Updated for user %s", current_user)
        return redirect("/addhospitalinfo")

    # posts=Hospitaldata.query.filter_by(id=id).first()
    return render_template("hedit.html",posts=posts)


@app.route("/hdelete/<string:id>",methods=['POST','GET'])
@login_required
def hdelete(id):
    form = DeleteForm(request.form)
    if request.method == 'POST' and form.validate():
        db.engine.execute(text("DELETE FROM `hospitaldata` WHERE `hospitaldata`.`id` = :id").params(id=id))
        flash("Date Deleted","danger")
        logger.info("Data Deleted for user %s", current_user)
        return redirect("/addhospitalinfo")
    
    return redirect("/addhospitalinfo")


@app.route("/pdetails",methods=['GET'])
@login_required
def pdetails():
    code=current_user.srfid
    print(code)
    data=Bookingpatient.query.filter_by(srfid=code).first()
   
    
    return render_template("detials.html",data=data)


@app.route("/slotbooking",methods=['POST','GET'])
@login_required
def slotbooking():
    form = SlotBookingForm(request.form)
    query=db.engine.execute(text("SELECT * FROM `hospitaldata` "))
    if request.method=="POST" and form.validate():
        srfid=request.form.get('srfid')
        bedtype=request.form.get('bedtype')
        hcode=request.form.get('hcode')
        spo2=request.form.get('spo2')
        pname=request.form.get('pname')
        pphone=request.form.get('pphone')
        paddress=request.form.get('paddress')  
        check2=Hospitaldata.query.filter_by(hcode=hcode).first()
        if not check2:
            flash("Hospital Code does not exist","warning")
            logger.warning("Hospital Code does not exist")

        code=hcode
        dbb=db.engine.execute(text("SELECT * FROM `hospitaldata` WHERE `hospitaldata`.`hcode`= :code").params(code=code))   
        bedtype=bedtype
        if bedtype=="NormalBed":       
            for d in dbb:
                seat=d.normalbed
                print(seat)
                ar=Hospitaldata.query.filter_by(hcode=code).first()
                ar.normalbed=seat-1
                db.session.commit()
                
        elif bedtype=="HICUBed":      
            for d in dbb:
                seat=d.hicubed
                print(seat)
                ar=Hospitaldata.query.filter_by(hcode=code).first()
                ar.hicubed=seat-1
                db.session.commit()

        elif bedtype=="ICUBed":     
            for d in dbb:
                seat=d.icubed
                print(seat)
                ar=Hospitaldata.query.filter_by(hcode=code).first()
                ar.icubed=seat-1
                db.session.commit()

        elif bedtype=="VENTILATORBed": 
            for d in dbb:
                seat=d.vbed
                ar=Hospitaldata.query.filter_by(hcode=code).first()
                ar.vbed=seat-1
                db.session.commit()
        else:
            pass

        check=Hospitaldata.query.filter_by(hcode=hcode).first()
        if(seat>0 and check):
            res=Bookingpatient(srfid=srfid,bedtype=bedtype,hcode=hcode,spo2=spo2,pname=pname,pphone=pphone,paddress=paddress)
            db.session.add(res)
            db.session.commit()
            flash("Slot is Booked kindly Visit Hospital for Further Procedure","success")
            logger.info("Slot is Booked for user %s", current_user)
        else:
            flash("Something Went Wrong","danger")
            logger.info("Something is wrong while booking the slot for user %s", current_user)
    
    return render_template("booking.html",query=query)

# Add CSRF error handling
@app.csrf_error(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e), 400

# Error handling for generic server errors
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Error handling for page not found (404) errors
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Error handling for other HTTP methods not allowed
@app.errorhandler(405)
def method_not_allowed(e):
    return render_template('405.html'), 405


app.run(debug=False)
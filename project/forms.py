from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField
from wtforms.validators import DataRequired, Email, Length, Regexp, NumberRange

class BaseForm(FlaskForm):
    srfid = IntegerField('SRFID', validators=[DataRequired(), NumberRange(min='0', max='10000', message='Invalid value')])
    dob = StringField('Date of Birth', validators=[DataRequired(), NumberRange(min='1900-01-01', max='today', message='Invalid date of birth')])
    hcode = StringField('Hospital Code', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), 
        Length(min=8, message='Password must be at least 8 characters'),
        Regexp(r'[A-Z]', message='Password must contain at least one uppercase letter'),
        Regexp(r'[a-z]', message='Password must contain at least one lowercase letter'),
        Regexp(r'[!@#$%^&*(),.?":{}|<>]', message='Password must contain at least one special character'),
        Regexp(r'\d', message='Password must contain at least one number')])

class AdminForm(BaseForm):
    username = StringField('Username', validators=[DataRequired()])

class SlotBookingForm(BaseForm):
    bedtype = StringField('Bed Type', validators=[DataRequired()])
    spo2 = StringField('Spo2', validators=[DataRequired(), NumberRange(min='0', max='100', message='Invalid value. Enter correct percentage of SpO2.')])
    pname = StringField('Patient Name', validators=[DataRequired()])
    pphone = StringField('Patient Phone', validators=[DataRequired(), Length(min='10', max='10', message='Add without country code +91 or 0')])
    paddress = StringField('Patient Address', validators=[DataRequired()])

class HospitalInfoForm(BaseForm):
    hname = StringField('Hospital Name', validators=[DataRequired()])
    normalbed = IntegerField('Normal Beds', validators=[DataRequired(), NumberRange(min='0', max='500', message='Invalid value.')])
    hicubeds = IntegerField('HiCu Beds', validators=[DataRequired(), NumberRange(min='0', max='500', message='Invalid value.')])
    icubeds = IntegerField('ICU Beds', validators=[DataRequired(), NumberRange(min='0', max='500', message='Invalid value.')])
    ventbeds = IntegerField('Vent Beds', validators=[DataRequired(), NumberRange(min='0', max='500', message='Invalid value.')])

# No additional fields for below endpoints, as they are common with BaseForm
class SignupForm(BaseForm):
    pass

class HospitalUserForm(BaseForm):
    pass  

class EditForm(BaseForm):
    pass  

class DeleteForm(BaseForm):
    pass  

class LoginForm(BaseForm):
    pass

class HospitalLoginForm(BaseForm):
    pass


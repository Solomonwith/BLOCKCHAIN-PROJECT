from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user,LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField,SubmitField,IntegerField, SelectField, FileField
from wtforms.validators import DataRequired, Email,InputRequired, Length, ValidationError 
from email_validator import validate_email, EmailNotValidError
from flask_bcrypt import Bcrypt
from ipfshttpclient import Client
from ipfshttpclient.exceptions import ConnectionError, ProtocolError
import base64
import hashlib
import json
from web3 import Web3
from web3.contract import Contract
                          

w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545')) # Change to your RPC provider
contract_address = '0x164c510e71F8De97bDCcc1908B436a98BC77aC15'
abi= 'abi.json'

with open('abi.json') as f:
    contract_abi = json.load(f)

# Create a contract instance
contract = w3.eth.contract(address=contract_address, abi=contract_abi)
account_address = '0x241AaB360798bC25D80d749E3AC63028907EFA7D'
private_key = '0x40d0c0dd80089f01aa82890d47a42813c38629da331428200f1c27cbec0177d0'


ipfs = Client()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.app_context().push()
app.config['SECRET_KEY'] = 'eyblockchainUI_ValidationKey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    firstName = db.Column(db.String(30), nullable=False)
    surname = db.Column(db.String(30), nullable=False)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(40), nullable=False, unique=True)
    jobTitle = db.Column(db.String(30), nullable=False, unique=True)
    organisationName = db.Column(db.String(100), nullable=False)
    userType = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(100), nullable=False)

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=30)],render_kw={'placeholder':'Username'})
    password = PasswordField(validators=[InputRequired(), Length(min=8)],render_kw={'placeholder':'Password'})
    submit = SubmitField('login')

class RegistrationForm(FlaskForm):
    firstName = StringField(validators=[InputRequired(), Length(min=4,max=30)],render_kw={'placeholder':'First Name'})
    surname = StringField(validators=[InputRequired(), Length(min=4,max=30)],render_kw={'placeholder':'Surname'})
    username = StringField(validators=[InputRequired(), Length(min=4,max=30)],render_kw={'placeholder':'Username'})
    email = StringField(validators=[DataRequired(), Email()],render_kw={'placeholder':'Email'})
    jobTitle = StringField(validators=[InputRequired(), Length(min=5,max=30)],render_kw={'placeholder':'Your Job Title'})
    organisationName = StringField(validators=[InputRequired(), Length(min=4,max=30)],render_kw={'placeholder':'Your Organisation'})
    userType = SelectField(choices=('requester','verifier'))
    password = PasswordField(validators=[InputRequired(), Length(min=8)],render_kw={'placeholder':'Password'})

    def validateUserName(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError('Username already exists. Please choose another one')

    def validateEmail(self, email):
        try:
            validate_email(email)
        except EmailNotValidError:
            #Invalid email format
            raise ValidationError('Invalid email address!')        
    submit = SubmitField('Register')


class DocumentVerificationForm(FlaskForm):
    clientName = StringField("Client - Audit Report for?",validators=[InputRequired()])
    documentId = IntegerField("Document ID as provided by Client",validators=[InputRequired()])
    auditReportFile = FileField("Select Audit Report(pdf)",validators=[InputRequired()])
    submit = SubmitField("Verify Authenticity")

class UpLoadAuditReportForm(FlaskForm):
    clientName = StringField("Client - Audit Report for?",validators=[InputRequired()])
    auditReportFile = FileField("Select Audit Report(pdf)",validators=[InputRequired()])
    upLoadedBy = StringField("Auditor's Full Name",validators=[InputRequired()])
    submit = SubmitField("Upload Audit Report")
    

def uploadAuditReport(filename):
    try:
        # Add file to IPFS
        res = ipfs.add(filename)
        file_hash = res['Hash']
        return file_hash
    except ConnectionError:
        print("Failed to connect to the IPFS API. Make sure the IPFS node or API endpoint is accessible.")

    except ProtocolError as e:
        print(f"An error occurred during IPFS interaction: {str(e)}")

    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")

    return None

@app.route('/download/<file_hash>')
def download_fileFromIPFS(file_hash):
    # Retrieve file from IPFS
    file = ipfs.get(file_hash)
    return file.read()


@app.route('/')
def index():
    #return render_template('index.html')
    return redirect(url_for('login'))

def getDocumentHash(documentId):
    result = contract.functions.getDocumentHash(documentId).call()
    return result

def getDocumentOwner(documentId):
    documentOwner = contract.functions.getDocumentOwner(documentId).call()
    return documentOwner

@app.route('/requesterDashboard', methods=['GET', 'POST'])
@login_required
def requesterDashboard():
    clientName = None
    documentId = None
    documentHash = None
    documentHashFromBlockChain = None
    documentOwner = None
    message = None
    form = DocumentVerificationForm()
    if form.validate_on_submit():
        clientName = form.clientName.data
        documentId = form.documentId.data
        #we use the same function below to get the document hash from IPFS
        #if it was already uploaded by an auditor the function will simply return the hash
        #otherwise if it wasn't uploaded the document will actually be uploaded and a hash will be returned.
        documentHash = uploadAuditReport(form.auditReportFile.data)
        documentHashFromBlockChain = getDocumentHash(int(documentId))
        documentOwner = getDocumentOwner(int(documentId))

    form.clientName.data = ''
    form.documentId.data = ''
    form.auditReportFile.data = ''    
    return render_template('requesterDashboard.html',current_user=current_user,
                           clientName=clientName,message=message,documentOwner=documentOwner,
                           documentHash=documentHash,documentId=documentId,documentHashFromBlockChain=documentHashFromBlockChain, form=form)

@app.route('/auditorDashboard', methods=['GET', 'POST'])
@login_required
def auditorDashboard():
    clientName = None
    auditReportFile = None
    upLoadedBy = None # should we record name of auditor who uploaded the report on the blockchain?
    fileHash = None
    tx_hash = None
    #stringFileHash = None
    form = UpLoadAuditReportForm()
    if form.validate_on_submit():
        clientName = form.clientName.data
        auditReportFile = form.auditReportFile.data
        fileHash = uploadAuditReport(auditReportFile)
        if fileHash is None:
            flash("Failed to upload file to IPFS")
        else:
            upLoadedBy = form.upLoadedBy.data # currently not being used whilst info is captured on Forms
            print(f"here is the hash from IPFS : {str(fileHash)}")
                #original call to blockchain function
                #tx_hash = contract.functions.uploadDocument(clientName,fileHash).transact()

            # Build the transaction parameters
            tx_hash = contract.functions.uploadDocument(clientName, fileHash).transact({
                'from': account_address,
                'gas': 6721975,  # Adjust the gas limit as needed
                'gasPrice': w3.eth.gas_price,
            })
                      
            # transaction_receipt = w3.eth.waitForTransactionReceipt(tx_hash)
            # w3.eth.waitForTransactionReceipt(tx_hash)
            # # Get the transaction status
            # status = transaction_receipt['status']
            if tx_hash:
                flash("Document uploaded to blockchain successfully!")
            else:
                flash("Failed to upload document to blockchain. Try again")            
    
    form.clientName.data = ''
    form.auditReportFile.data = ''
    form.upLoadedBy.data = ''
    
    return render_template('auditorDashboard.html',current_user=current_user,
                           clientName=clientName,upLoadedBy=upLoadedBy,
                           fileHash=fileHash,tx_hash=tx_hash,form=form)



@app.route('/login', methods=['GET', 'POST'])
def login():
    username = None
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Login Successful")
                if user.userType == 'requester':
                    return redirect(url_for('requesterDashboard'))
                else:
                #user.userType == 'verifier':
                    return redirect(url_for('auditorDashboard'))                    
            else:
                flash('Wrong password!', 'danger')
        else:
            flash('user not found!', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out, Thanks!!!")
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    firstName=None
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None:            
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(firstName=form.firstName.data,surname=form.surname.data,
                        username=form.username.data,email=form.email.data, jobTitle=form.jobTitle.data,
                        organisationName=form.organisationName.data, userType=form.userType.data,
                        password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash("User added successfully !!")
            return redirect(url_for('login'))
        else:
            flash("User email: {} , is already registered in database !!".format(form.email.data))
            return redirect(url_for('login'))
    return render_template('register.html', firstName=firstName,form=form)    
    
if __name__ == '__main__':
    app.run(debug=True)
    
    

"""Disclosed employee application usage + managed DLP policy inventory (pilot)."""
import os, re, secrets, datetime as dt, csv, io, hmac, hashlib, uuid
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, render_template, render_template_string, redirect, url_for, session, flash, Response, abort, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash
from dotenv import load_dotenv
load_dotenv()
app=Flask(__name__)
app.config.update(SECRET_KEY=os.environ.get('SECRET_KEY') or secrets.token_hex(32), SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL','postgresql+psycopg://monitor:monitor@localhost:5432/monitor'),SQLALCHEMY_TRACK_MODIFICATIONS=False,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE')=='1',MAX_CONTENT_LENGTH=4*1024*1024)
db=SQLAlchemy(app)
def utc():return dt.datetime.now(dt.timezone.utc)
class Device(db.Model):
 id=db.Column(db.Integer,primary_key=True);agent_id=db.Column(db.String(100),unique=True,nullable=False);name=db.Column(db.String(120));last_seen=db.Column(db.DateTime(timezone=True));enabled=db.Column(db.Boolean,default=True)
class Activity(db.Model):
 id=db.Column(db.Integer,primary_key=True);device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,index=True);app_name=db.Column(db.String(200),nullable=False);seconds=db.Column(db.Integer,nullable=False);idle_seconds=db.Column(db.Integer,default=0);recorded_at=db.Column(db.DateTime(timezone=True),default=utc,index=True)
class BlockRule(db.Model):
 id=db.Column(db.Integer,primary_key=True);device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False);domain=db.Column(db.String(253),nullable=False);created_at=db.Column(db.DateTime(timezone=True),default=utc);__table_args__=(db.UniqueConstraint('device_id','domain'),)
class DomainBlockEvent(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,index=True)
 domain=db.Column(db.String(253),nullable=False)
 rule_id=db.Column(db.Integer,nullable=True)
 observed_at=db.Column(db.DateTime(timezone=True),default=utc,index=True)
 source=db.Column(db.String(40),nullable=False,default='managed_browser')
class PolicyDeployment(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,unique=True)
 policy_hash=db.Column(db.String(64),nullable=False)
 applied_at=db.Column(db.DateTime(timezone=True),default=utc)
 status=db.Column(db.String(32),nullable=False,default='applied')
 detail=db.Column(db.String(200))
class WebsiteActivity(db.Model):
 id=db.Column(db.Integer,primary_key=True);device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,index=True);domain=db.Column(db.String(253),nullable=False);seconds=db.Column(db.Integer,nullable=False);recorded_at=db.Column(db.DateTime(timezone=True),default=utc,index=True)
class DlpEvent(db.Model):
 id=db.Column(db.Integer,primary_key=True);device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,index=True);rule=db.Column(db.String(80));file_name=db.Column(db.String(255));file_size=db.Column(db.BigInteger);observed_at=db.Column(db.DateTime(timezone=True),default=utc,index=True)
class TransferEvent(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 event_id=db.Column(db.String(64),unique=True,nullable=False,index=True)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=True,index=True)
 channel=db.Column(db.String(24),nullable=False,index=True)
 operation=db.Column(db.String(24),nullable=False)
 file_name=db.Column(db.String(255),nullable=False)
 extension=db.Column(db.String(24));mime_type=db.Column(db.String(120))
 file_size=db.Column(db.BigInteger);destination=db.Column(db.String(253))
 classification=db.Column(db.String(32),nullable=False,default='unclassified')
 decision=db.Column(db.String(16),nullable=False,default='allow')
 policy_name=db.Column(db.String(100));source=db.Column(db.String(64))
 observed_at=db.Column(db.DateTime(timezone=True),default=utc,index=True)
class TransferPolicy(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 name=db.Column(db.String(100),nullable=False,unique=True)
 channel=db.Column(db.String(24),nullable=False,default='any')
 extension=db.Column(db.String(24),nullable=False,default='*')
 destination_pattern=db.Column(db.String(253),nullable=False,default='*')
 classification=db.Column(db.String(32),nullable=False,default='any')
 action=db.Column(db.String(16),nullable=False,default='alert')
 enabled=db.Column(db.Boolean,nullable=False,default=True)
class DlpIncident(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 transfer_event_id=db.Column(db.Integer,db.ForeignKey('transfer_event.id'),unique=True,index=True)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),index=True)
 severity=db.Column(db.String(12),nullable=False,default='medium')
 status=db.Column(db.String(20),nullable=False,default='new')
 assignee=db.Column(db.String(100))
 resolution=db.Column(db.String(400))
 created_at=db.Column(db.DateTime(timezone=True),default=utc,index=True)
 updated_at=db.Column(db.DateTime(timezone=True),default=utc,onupdate=utc)
class DlpIncidentNote(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 incident_id=db.Column(db.Integer,db.ForeignKey('dlp_incident.id'),nullable=False,index=True)
 note=db.Column(db.String(2000),nullable=False)
 created_at=db.Column(db.DateTime(timezone=True),default=utc,index=True)

class CaptureRequest(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,index=True)
 kind=db.Column(db.String(20),nullable=False)
 status=db.Column(db.String(20),nullable=False,default='pending')
 requested_at=db.Column(db.DateTime(timezone=True),default=utc)
 completed_at=db.Column(db.DateTime(timezone=True))
 file_name=db.Column(db.String(100))
class EmployeeProfile(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,unique=True,index=True)
 display_name=db.Column(db.String(120))
 photo_file=db.Column(db.String(100))
class Audit(db.Model):
 id=db.Column(db.Integer,primary_key=True);action=db.Column(db.String(300));at=db.Column(db.DateTime(timezone=True),default=utc)
class KeywordRule(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 phrase=db.Column(db.String(120),nullable=False)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=True,index=True)
 enabled=db.Column(db.Boolean,default=True,nullable=False)

class KeywordAlert(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 event_id=db.Column(db.String(64),unique=True,nullable=False)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,index=True)
 rule_id=db.Column(db.Integer,db.ForeignKey('keyword_rule.id'),nullable=False)
 file_name=db.Column(db.String(255),nullable=False)
 source=db.Column(db.String(30),nullable=False,default='approved_file')
 observed_at=db.Column(db.DateTime(timezone=True),default=utc)


class WorkSession(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,index=True)
 token=db.Column(db.String(64),unique=True,nullable=False)
 started_at=db.Column(db.DateTime(timezone=True),default=utc,nullable=False)
 last_heartbeat=db.Column(db.DateTime(timezone=True),default=utc,nullable=False)
 ended_at=db.Column(db.DateTime(timezone=True))

class ScheduledScreenshot(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 session_id=db.Column(db.Integer,db.ForeignKey('work_session.id'),nullable=False,index=True)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,index=True)
 captured_at=db.Column(db.DateTime(timezone=True),default=utc,nullable=False)
 file_name=db.Column(db.String(100),nullable=False)

class ImmediateScreenshotRequest(db.Model):
 id=db.Column(db.Integer,primary_key=True)
 device_id=db.Column(db.Integer,db.ForeignKey('device.id'),nullable=False,index=True)
 session_id=db.Column(db.Integer,db.ForeignKey('work_session.id'),nullable=False,index=True)
 status=db.Column(db.String(20),nullable=False,default='pending')
 created_at=db.Column(db.DateTime(timezone=True),default=utc)
 completed_at=db.Column(db.DateTime(timezone=True))
 screenshot_id=db.Column(db.Integer,db.ForeignKey('scheduled_screenshot.id'))

with app.app_context():db.create_all()
@app.before_request
def csrf_guard():
 if request.method in ('POST','PUT','PATCH','DELETE') and not request.path.startswith('/api/'):
  if request.endpoint!='login' and not secrets.compare_digest(session.get('csrf',''),request.form.get('csrf','')):abort(400,'Invalid CSRF token')
@app.context_processor
def inject_csrf():return {'csrf_token':lambda:session.setdefault('csrf',secrets.token_urlsafe(32))}
def admin_required(fn):
 @wraps(fn)
 def inner(*a,**kw):
  if not session.get('admin'):return redirect(url_for('login'))
  return fn(*a,**kw)
 return inner
def agent_auth():return bool(os.environ.get('AGENT_API_KEY')) and secrets.compare_digest(request.headers.get('X-Agent-Key',''),os.environ['AGENT_API_KEY'])
@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  username=os.environ.get('ADMIN_USERNAME','admin');pw=os.environ.get('ADMIN_PASSWORD_HASH','')
  try:valid=bool(pw) and secrets.compare_digest(request.form.get('username',''),username) and check_password_hash(pw,request.form.get('password',''))
  except ValueError:valid=False
  if valid:
   session.clear();session['admin']=True;session['csrf']=secrets.token_urlsafe(32);db.session.add(Audit(action='Admin signed in'));db.session.commit();return redirect('/')
  flash('Invalid username or password')
 return render_template('login.html')
@app.post('/logout')
@admin_required
def logout():session.clear();return redirect('/login')
@app.get('/')
@admin_required
def dashboard():
 devices=Device.query.order_by(Device.agent_id).all();cutoff=utc()-dt.timedelta(minutes=3)
 stats={}
 for d in devices:
  rows=db.session.query(Activity.app_name,db.func.sum(Activity.seconds),db.func.sum(Activity.idle_seconds)).filter(Activity.device_id==d.id).group_by(Activity.app_name).order_by(db.func.sum(Activity.seconds).desc()).limit(8).all()
  stats[d.id]=[{'app':x[0],'seconds':int(x[1] or 0),'idle':int(x[2] or 0)} for x in rows]
 return render_template('dashboard.html',devices=devices,stats=stats,cutoff=cutoff,rules=BlockRule.query.order_by(BlockRule.id.desc()).all(),audits=Audit.query.order_by(Audit.id.desc()).limit(20).all(),keyword_rules_count=KeywordRule.query.filter_by(enabled=True).count(),keyword_alerts_count=KeywordAlert.query.count(),recent_keyword_alerts=KeywordAlert.query.order_by(KeywordAlert.id.desc()).limit(5).all())
@app.get('/devices/<int:device_id>')
@admin_required
def detail(device_id):
 d=db.get_or_404(Device,device_id)
 rows=Activity.query.filter_by(device_id=d.id).order_by(Activity.id.desc()).limit(300).all()
 app_totals=db.session.query(Activity.app_name,db.func.sum(Activity.seconds),db.func.sum(Activity.idle_seconds)).filter_by(device_id=d.id).group_by(Activity.app_name).order_by(db.func.sum(Activity.seconds).desc()).all()
 web_totals=db.session.query(WebsiteActivity.domain,db.func.sum(WebsiteActivity.seconds)).filter_by(device_id=d.id).group_by(WebsiteActivity.domain).order_by(db.func.sum(WebsiteActivity.seconds).desc()).limit(50).all()
 events=DlpEvent.query.filter_by(device_id=d.id).order_by(DlpEvent.id.desc()).limit(100).all()
 
 websites=WebsiteActivity.query.filter_by(device_id=d.id).order_by(WebsiteActivity.id.desc()).limit(150).all()
 transfers=TransferEvent.query.filter_by(device_id=d.id).order_by(TransferEvent.id.desc()).limit(150).all()
 timeline=sorted(
   ([{'at':x.recorded_at,'kind':'Application','description':x.app_name,'details':str(round(x.seconds/60,2))+' min'} for x in rows]+
    [{'at':x.recorded_at,'kind':'Website','description':x.domain,'details':str(round(x.seconds/60,2))+' min'} for x in websites]+
    [{'at':x.observed_at,'kind':'DLP alert','description':x.file_name,'details':x.rule or ''} for x in events]+
    [{'at':x.observed_at,'kind':'Transfer '+x.decision,'description':x.file_name,'details':x.channel+' / '+x.operation} for x in transfers]),
   key=lambda x:x['at'].isoformat() if x['at'] else '',reverse=True)[:350]
 profile=EmployeeProfile.query.filter_by(device_id=d.id).first()
 captures=CaptureRequest.query.filter_by(device_id=d.id).order_by(CaptureRequest.id.desc()).limit(50).all()
 work_screenshots=ScheduledScreenshot.query.filter_by(device_id=d.id).order_by(ScheduledScreenshot.captured_at.desc()).limit(50).all()
 return render_template('detail.html',device=d,profile=profile,captures=captures,work_screenshots=work_screenshots,rows=rows,app_totals=app_totals,web_totals=web_totals,events=events,timeline=timeline)
# Images are private, served only to logged-in administrators.
CAPTURE_DIR=Path(os.getenv('CAPTURE_STORAGE_DIR',str(Path(__file__).resolve().parent/'private_captures')))
CAPTURE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)

PROFILE_DIR=Path(os.getenv('PROFILE_STORAGE_DIR',str(Path(__file__).resolve().parent/'private_profiles')))
PROFILE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)

@app.post('/devices/<int:device_id>/profile')
@admin_required
def update_employee_profile(device_id):
 d=db.get_or_404(Device,device_id)
 name=request.form.get('display_name','').strip()[:120]
 profile=EmployeeProfile.query.filter_by(device_id=d.id).first()
 if not profile:
  profile=EmployeeProfile(device_id=d.id)
  db.session.add(profile)
 if name:profile.display_name=name
 photo=request.files.get('photo')
 if photo and photo.filename:
  data=photo.read(2*1024*1024+1)
  if not 0<len(data)<=2*1024*1024:abort(413,'Photo must be smaller than 2 MB')
  try:
   from PIL import Image,ImageOps,UnidentifiedImageError
   with Image.open(io.BytesIO(data)) as im:
    im.load()
    if im.width*im.height>16000000:abort(413,'Image dimensions too large')
    im=ImageOps.fit(im.convert('RGB'),(400,400))
    output=io.BytesIO();im.save(output,'JPEG',quality=85)
  except (UnidentifiedImageError,OSError,ValueError):abort(400,'Invalid image')
  new_name=uuid.uuid4().hex+'.jpg'
  (PROFILE_DIR/new_name).write_bytes(output.getvalue())
  old=profile.photo_file;profile.photo_file=new_name
  if old:(PROFILE_DIR/old).unlink(missing_ok=True)
 db.session.add(Audit(action=f'Admin updated employee profile for {d.agent_id}'))
 db.session.commit()
 flash('Employee profile updated')
 return redirect(url_for('detail',device_id=d.id))

@app.get('/devices/<int:device_id>/photo')
@admin_required
def employee_photo(device_id):
 db.get_or_404(Device,device_id)
 profile=EmployeeProfile.query.filter_by(device_id=device_id).first()
 if not profile or not profile.photo_file:abort(404)
 return send_file(PROFILE_DIR/profile.photo_file,mimetype='image/jpeg',conditional=False)

@app.post('/devices/<int:device_id>/capture')
@admin_required
def request_capture(device_id):
 d=db.get_or_404(Device,device_id)
 kind=request.form.get('kind')
 if kind not in ('screen','camera'):abort(400)
 if not d.enabled:abort(409,'Device disabled')
 # Legacy screenshot forms must never enqueue employee-approval screenshot requests.
 # Route them through the active, employee-started tracking session instead.
 if kind=='screen':
  return queue_immediate_screenshot(d)

 # Expire stale requests so they cannot block new requests indefinitely.
 for old in CaptureRequest.query.filter_by(device_id=d.id,status='pending').all():
  when=old.requested_at
  if when and when.tzinfo is None:when=when.replace(tzinfo=dt.timezone.utc)
  if when and utc()-when>dt.timedelta(minutes=10):old.status='expired';old.completed_at=utc()
 db.session.flush()
 if CaptureRequest.query.filter_by(device_id=d.id,status='pending').first():
  flash('A capture request is already pending for this device.')
 else:
  c=CaptureRequest(device_id=d.id,kind=kind)
  db.session.add(c);db.session.add(Audit(action=f'Admin requested employee-approved {kind} capture for {d.agent_id}'));db.session.commit()
  flash('Request queued. The employee must approve it locally.')
 return redirect(url_for('detail',device_id=d.id))

@app.get('/api/v1/capture/pending/<agent_id>')
def pending_capture(agent_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
 if not d:return jsonify(error='device not enrolled'),404
 c=CaptureRequest.query.filter_by(device_id=d.id,status='pending').order_by(CaptureRequest.id).first()
 if c and c.requested_at:
  requested=c.requested_at
  if requested.tzinfo is None:requested=requested.replace(tzinfo=dt.timezone.utc)
  if utc()-requested>dt.timedelta(minutes=10):
   c.status='expired';c.completed_at=utc();db.session.commit();c=None
 return jsonify(request={'id':c.id,'kind':c.kind} if c else None)

@app.post('/api/v1/capture/<int:capture_id>/decision')
def capture_decision(capture_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 c=db.get_or_404(CaptureRequest,capture_id)
 if c.status!='pending':return jsonify(error='already processed'),409
 d=db.session.get(Device,c.device_id)
 body=request.get_json(silent=True) or {}
 if body.get('agent_id')!=d.agent_id or body.get('status') not in ('denied','unavailable'):return jsonify(error='invalid decision'),400
 c.status=body['status'];c.completed_at=utc()
 db.session.add(Audit(action=f'Employee {c.status} {c.kind} capture for {d.agent_id}'));db.session.commit()
 return jsonify(ok=True)

@app.post('/api/v1/capture/<int:capture_id>/upload')
def upload_capture(capture_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 c=db.get_or_404(CaptureRequest,capture_id)
 d=db.session.get(Device,c.device_id)
 if c.status!='pending' or request.form.get('agent_id')!=d.agent_id:return jsonify(error='invalid request'),409
 f=request.files.get('image')
 if not f:return jsonify(error='image required'),400
 data=f.read(3*1024*1024+1)
 if not 0<len(data)<=3*1024*1024:return jsonify(error='image too large'),413
 # Decode and normalize to strip metadata and reject malformed images.
 try:
  from PIL import Image,UnidentifiedImageError
  with Image.open(io.BytesIO(data)) as im:
   im.load()
   if im.width>7680 or im.height>4320 or im.width*im.height>16000000:raise ValueError('oversized dimensions')
   out=io.BytesIO();im.convert('RGB').save(out,format='JPEG',quality=80,optimize=True)
 except (ValueError,OSError,UnidentifiedImageError):return jsonify(error='invalid image'),400
 filename=f'{uuid.uuid4().hex}.jpg'
 path=CAPTURE_DIR/filename
 with path.open('xb') as stream:stream.write(out.getvalue())
 c.file_name=filename;c.status='approved';c.completed_at=utc()
 db.session.add(Audit(action=f'Employee approved {c.kind} capture for {d.agent_id}'));db.session.commit()
 return jsonify(ok=True)


# Admin-triggered screenshots are permitted only in a fresh employee-started session.
def current_active_session(device_id):
 w=WorkSession.query.filter_by(device_id=device_id,ended_at=None).order_by(WorkSession.id.desc()).first()
 if not w:return None
 last=w.last_heartbeat
 if last.tzinfo is None:last=last.replace(tzinfo=dt.timezone.utc)
 return w if utc()-last<=dt.timedelta(seconds=90) else None

def queue_immediate_screenshot(d):
 w=current_active_session(d.id) if d.enabled else None
 if not w:
  flash('Cannot take screenshot: employee work tracking is not active. Ask the employee to start tracking from the MonitorGuard tray icon.')
  return redirect(url_for('detail',device_id=d.id))
 pending=ImmediateScreenshotRequest.query.filter_by(device_id=d.id,status='pending').first()
 if pending:
  flash('A Take Screenshot command is already queued for this device.')
 else:
  db.session.add(ImmediateScreenshotRequest(device_id=d.id,session_id=w.id))
  db.session.add(Audit(action=f'Admin queued immediate screenshot for {d.agent_id} during active work session'))
  db.session.commit()
  flash('Take Screenshot command queued. The agent will upload it shortly. View work-session screenshot history.')
 return redirect(url_for('detail',device_id=d.id))

@app.post('/devices/<int:device_id>/take-screenshot')
@admin_required
def take_screenshot(device_id):
 return queue_immediate_screenshot(db.get_or_404(Device,device_id))

@app.get('/api/v1/work-session/<agent_id>/immediate-pending')
def immediate_pending(agent_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
 if not d:return jsonify(error='device not enrolled'),404
 w=current_active_session(d.id)
 if not w:return jsonify(request=None)
 for old in ImmediateScreenshotRequest.query.filter_by(device_id=d.id,status='pending').all():
  created=old.created_at
  if created.tzinfo is None:created=created.replace(tzinfo=dt.timezone.utc)
  if old.session_id!=w.id or utc()-created>dt.timedelta(minutes=2):old.status='expired';old.completed_at=utc()
 db.session.commit()
 cmd=ImmediateScreenshotRequest.query.filter_by(device_id=d.id,session_id=w.id,status='pending').order_by(ImmediateScreenshotRequest.id).first()
 return jsonify(request={'id':cmd.id} if cmd else None)

@app.post('/api/v1/work-session/<agent_id>/immediate/<int:command_id>/upload')
def immediate_upload(agent_id,command_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
 if not d:return jsonify(error='device not enrolled'),404
 w=current_active_session(d.id)
 cmd=db.session.get(ImmediateScreenshotRequest,command_id)
 if not w or not cmd or cmd.device_id!=d.id or cmd.session_id!=w.id or cmd.status!='pending':
  return jsonify(error='no active capture command'),409
 if request.form.get('session_token')!=w.token:return jsonify(error='invalid session'),403
 f=request.files.get('image')
 if not f:return jsonify(error='image required'),400
 data=f.read(3*1024*1024+1)
 if not 0<len(data)<=3*1024*1024:return jsonify(error='image too large'),413
 try:
  from PIL import Image,UnidentifiedImageError
  with Image.open(io.BytesIO(data)) as im:
   im.load()
   if im.width>7680 or im.height>4320 or im.width*im.height>16000000:raise ValueError('oversized dimensions')
   out=io.BytesIO();im.convert('RGB').save(out,format='JPEG',quality=75,optimize=True)
 except (ValueError,OSError,UnidentifiedImageError):return jsonify(error='invalid image'),400
 filename=uuid.uuid4().hex+'.jpg'
 with (CAPTURE_DIR/filename).open('xb') as stream:stream.write(out.getvalue())
 shot=ScheduledScreenshot(device_id=d.id,session_id=w.id,file_name=filename)
 db.session.add(shot);db.session.flush()
 cmd.screenshot_id=shot.id;cmd.status='completed';cmd.completed_at=utc()
 db.session.add(Audit(action=f'Immediate screenshot completed for {agent_id}, command {cmd.id}'))
 db.session.commit()
 return jsonify(ok=True,screenshot_id=shot.id)

# Scheduled screenshots are distinct from employee-approved manual capture requests.
# Sessions can only be started locally in the employee's tray menu.
@app.post('/api/v1/work-session/<agent_id>/start')
def work_session_start(agent_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
 if not d:return jsonify(error='device not enrolled'),404
 for old in WorkSession.query.filter_by(device_id=d.id,ended_at=None).all():old.ended_at=utc()
 token=secrets.token_hex(32)
 w=WorkSession(device_id=d.id,token=token)
 db.session.add(w);db.session.add(Audit(action=f'Employee started screenshot-enabled work session on {agent_id}'))
 db.session.commit()
 return jsonify(session_token=token)

@app.post('/api/v1/work-session/<agent_id>/heartbeat')
def work_session_heartbeat(agent_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
 if not d:return jsonify(error='device not enrolled'),404
 body=request.get_json(silent=True) or {}
 w=WorkSession.query.filter_by(device_id=d.id,token=body.get('session_token'),ended_at=None).first()
 if not w:return jsonify(error='session inactive'),409
 w.last_heartbeat=utc();db.session.commit()
 return jsonify(ok=True)

@app.post('/api/v1/work-session/<agent_id>/stop')
def work_session_stop(agent_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
 if not d:return jsonify(error='device not enrolled'),404
 body=request.get_json(silent=True) or {}
 w=WorkSession.query.filter_by(device_id=d.id,token=body.get('session_token'),ended_at=None).first()
 if not w:return jsonify(error='session inactive'),409
 w.ended_at=utc();db.session.add(Audit(action=f'Employee stopped work session on {agent_id}'));db.session.commit()
 return jsonify(ok=True)

@app.post('/api/v1/work-session/<agent_id>/screenshot')
def work_session_screenshot(agent_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
 if not d:return jsonify(error='device not enrolled'),404
 token=request.form.get('session_token','')
 w=WorkSession.query.filter_by(device_id=d.id,token=token,ended_at=None).first()
 if not w:return jsonify(error='session inactive'),409
 last=w.last_heartbeat
 if last.tzinfo is None:last=last.replace(tzinfo=dt.timezone.utc)
 if utc()-last>dt.timedelta(seconds=90):return jsonify(error='session heartbeat expired'),409
 latest=ScheduledScreenshot.query.filter_by(session_id=w.id).order_by(ScheduledScreenshot.captured_at.desc()).first()
 if latest:
  captured=latest.captured_at
  if captured.tzinfo is None:captured=captured.replace(tzinfo=dt.timezone.utc)
  if utc()-captured<dt.timedelta(seconds=270):return jsonify(error='capture interval not elapsed'),429
 f=request.files.get('image')
 if not f:return jsonify(error='image required'),400
 data=f.read(3*1024*1024+1)
 if not 0<len(data)<=3*1024*1024:return jsonify(error='image too large'),413
 try:
  from PIL import Image,UnidentifiedImageError
  with Image.open(io.BytesIO(data)) as im:
   im.load()
   if im.width>7680 or im.height>4320 or im.width*im.height>16000000:raise ValueError('oversized dimensions')
   out=io.BytesIO();im.convert('RGB').save(out,format='JPEG',quality=75,optimize=True)
 except (ValueError,OSError,UnidentifiedImageError):return jsonify(error='invalid image'),400
 filename=uuid.uuid4().hex+'.jpg'
 with (CAPTURE_DIR/filename).open('xb') as stream:stream.write(out.getvalue())
 db.session.add(ScheduledScreenshot(device_id=d.id,session_id=w.id,file_name=filename))
 db.session.commit()
 return jsonify(ok=True)

@app.get('/devices/<int:device_id>/scheduled-screenshots')
@admin_required
def scheduled_screenshots(device_id):
 d=db.get_or_404(Device,device_id)
 items=ScheduledScreenshot.query.filter_by(device_id=d.id).order_by(ScheduledScreenshot.id.desc()).limit(100).all()
 return render_template_string("""<h2>Scheduled screenshots — {{device.agent_id}}</h2><p>Most recent 100 captures. <a href="{{url_for('detail',device_id=device.id)}}">Back to device</a></p><ul>{% for item in items %}<li>{{item.captured_at}} — <a href="{{url_for('scheduled_screenshot_image',screenshot_id=item.id)}}">View screenshot</a></li>{% else %}<li>No scheduled screenshots</li>{% endfor %}</ul>""",device=d,items=items)


@app.get('/scheduled-screenshots/<int:screenshot_id>/image')
@admin_required
def scheduled_screenshot_image(screenshot_id):
    item = db.get_or_404(ScheduledScreenshot, screenshot_id)

    image_path = CAPTURE_DIR / item.file_name

    if not image_path.is_file():
        app.logger.warning(
            "Deleted scheduled screenshot: id=%s, file=%s",
            item.id, item.file_name
        )
        abort(404, description="Screenshot file was deleted")

    db.session.add(
        Audit(action=f'Admin viewed scheduled screenshot {item.id}')
    )
    db.session.commit()

    return send_file(
        image_path,
        mimetype='image/jpeg',
        conditional=False
    )

@app.get('/captures/<int:capture_id>/image')
@admin_required
def capture_image(capture_id):
    c = db.get_or_404(CaptureRequest, capture_id)

    if c.status != 'approved' or not c.file_name:
        abort(404, description="Screenshot unavailable")

    image_path = CAPTURE_DIR / c.file_name

    if not image_path.is_file():
        app.logger.warning(
            "Deleted screenshot: capture_id=%s, file=%s",
            c.id, c.file_name
        )
        abort(404, description="Screenshot file was deleted")

    db.session.add(
        Audit(action=f'Admin viewed capture {c.id}')
    )
    db.session.commit()

    return send_file(
        image_path,
        mimetype='image/jpeg',
        as_attachment=False,
        download_name='capture.jpg',
        conditional=False
    )

@app.get('/devices/<int:device_id>/export.csv')
@admin_required
def export(device_id):
 d=db.get_or_404(Device,device_id);buf=io.StringIO();w=csv.writer(buf);w.writerow(['timestamp_utc','application','seconds','idle_seconds'])
 for a in Activity.query.filter_by(device_id=d.id).order_by(Activity.id.desc()).limit(10000):w.writerow([a.recorded_at.isoformat(),a.app_name,a.seconds,a.idle_seconds])
 db.session.add(Audit(action=f'CSV exported for {d.agent_id}'));db.session.commit();return Response(buf.getvalue(),mimetype='text/csv',headers={'Content-Disposition':f'attachment; filename="device-{d.id}-activity.csv"'})
@app.post('/devices/<int:device_id>/toggle')
@admin_required
def toggle(device_id):
 d=db.get_or_404(Device,device_id);d.enabled=not d.enabled;db.session.add(Audit(action=f'Device {d.agent_id} enabled={d.enabled}'));db.session.commit();return redirect('/')
@app.post('/api/v1/report')
def report():
 if not agent_auth():return jsonify(error='unauthorized'),401
 body=request.get_json(silent=True) or {};aid=body.get('agent_id');entries=body.get('activities',[])
 if not isinstance(aid,str) or not 1<=len(aid)<=100 or not isinstance(entries,list) or len(entries)>500:return jsonify(error='invalid payload'),400
 cleaned=[]
 websites=body.get('websites',[]);file_events=body.get('dlp_events',[]);transfers=body.get('transfers',[])
 if not isinstance(websites,list) or len(websites)>300 or not isinstance(file_events,list) or len(file_events)>100:return jsonify(error='invalid batch'),400
 if not isinstance(transfers,list) or len(transfers)>100:return jsonify(error='invalid transfers'),400
 try:transfer_clean=[clean_transfer(x) for x in transfers]
 except (ValueError,TypeError):return jsonify(error='invalid transfer'),400
 web_clean=[];file_clean=[]
 for item in websites:
  if not isinstance(item,dict):return jsonify(error='invalid website'),400
  domain=str(item.get('domain','')).lower().strip('.');seconds=item.get('seconds')
  if not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]',domain) or not isinstance(seconds,int) or not 1<=seconds<=86400:return jsonify(error='invalid website'),400
  web_clean.append((domain,seconds))
 for item in file_events:
  if not isinstance(item,dict) or not isinstance(item.get('rule'),str) or not isinstance(item.get('file_name'),str):return jsonify(error='invalid file event'),400
  file_clean.append((item['rule'][:80],item['file_name'][:255],max(0,min(int(item.get('file_size',0)),10**15))))
 for e in entries:
  if not isinstance(e,dict) or not isinstance(e.get('app'),str):return jsonify(error='invalid activity'),400
  try:name=e['app'][:200];seconds=int(e['seconds']);idle=int(e.get('idle_seconds',0))
  except (ValueError,TypeError,KeyError):return jsonify(error='invalid activity'),400
  if not name or not 0<=seconds<=86400 or not 0<=idle<=seconds:return jsonify(error='invalid duration'),400
  cleaned.append((name,seconds,idle))
 d=Device.query.filter_by(agent_id=aid).first()
 if d is None:d=Device(agent_id=aid,name=str(body.get('name') or aid)[:120]);db.session.add(d);db.session.flush()
 if not d.enabled:return jsonify(error='device disabled'),403
 d.last_seen=utc()
 for name,seconds,idle in cleaned:db.session.add(Activity(device_id=d.id,app_name=name,seconds=seconds,idle_seconds=idle))
 for domain,seconds in web_clean:db.session.add(WebsiteActivity(device_id=d.id,domain=domain,seconds=seconds))
 for rule,filename,size in file_clean:db.session.add(DlpEvent(device_id=d.id,rule=rule,file_name=filename,file_size=size))
 for item in transfer_clean:record_transfer(item,d.id)
 db.session.commit();return jsonify(ok=True)
def clean_transfer(item):
 if not isinstance(item,dict):raise ValueError('invalid event')
 channel=item.get('channel','');operation=item.get('operation','upload')
 if channel not in ('browser','usb','email','cloud') or operation not in ('upload','copy','send','sync','selection_blocked'):raise ValueError('invalid channel/operation')
 name=item.get('file_name','')
 if not isinstance(name,str) or not 1<=len(name)<=255 or '/' in name or "\\" in name:raise ValueError('invalid file name')
 destination=str(item.get('destination') or '')[:253].lower()
 if destination and not re.fullmatch(r'[a-z0-9][a-z0-9.:-]{0,252}',destination):raise ValueError('invalid destination')
 size=item.get('file_size')
 if size is not None and (not isinstance(size,int) or not 0<=size<=10**15):raise ValueError('invalid file size')
 ext=('.'+name.rsplit('.',1)[-1].lower()) if '.' in name else ''
 mime=str(item.get('mime_type') or '')[:120]
 eid=str(item.get('event_id') or '')
 if not re.fullmatch(r'[A-Za-z0-9_-]{12,64}',eid):raise ValueError('invalid event id')
 return dict(event_id=eid,channel=channel,operation=operation,file_name=name,extension=ext,mime_type=mime,file_size=size,destination=destination,source=str(item.get('source') or channel)[:64])
def classify_file(data):
 name=data['file_name'].lower()
 if re.search(r'(payroll|salary|credential|password|customer|confidential|private[_ -]?key)',name):return 'sensitive'
 return 'unclassified'
def match_transfer_policy(data,classification):
 for p in TransferPolicy.query.filter_by(enabled=True).order_by(TransferPolicy.id).all():
  if p.channel not in ('any',data['channel']):continue
  if p.extension not in ('*',data['extension']):continue
  if p.classification not in ('any',classification):continue
  if p.destination_pattern!='*' and not (data['destination']==p.destination_pattern or data['destination'].endswith('.'+p.destination_pattern)):continue
  return p
 return None
def record_transfer(data,device_id=None):
 if db.session.query(TransferEvent.id).filter_by(event_id=data['event_id']).first():return False
 classification=classify_file(data);policy=match_transfer_policy(data,classification)
 # Observe/alert only. No false claims of blocking already-completed transfers.
 decision=('blocked' if data['operation']=='selection_blocked' else ('alert' if policy and policy.action in ('alert','block') else 'allow'))
 event=TransferEvent(device_id=device_id,classification=classification,decision=decision,policy_name=policy.name if policy else None,**data)
 db.session.add(event)
 if decision in ('blocked','alert'):
  db.session.flush()
  severity='high' if decision=='blocked' or classification=='sensitive' else 'medium'
  db.session.add(DlpIncident(transfer_event_id=event.id,device_id=device_id,severity=severity,status='new'))
 return True
@app.post('/api/v1/integrations/<channel>')
def integration_ingest(channel):
 if channel not in ('email','cloud'):return jsonify(error='unsupported channel'),404
 secret=os.environ.get('INTEGRATION_WEBHOOK_SECRET','')
 if len(secret)<24:return jsonify(error='integration not configured'),503
 raw=request.get_data();provided=request.headers.get('X-MonitorGuard-Signature','')
 expected=hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest()
 if not hmac.compare_digest(provided,expected):return jsonify(error='unauthorized'),401
 body=request.get_json(silent=True)
 if not isinstance(body,dict) or not isinstance(body.get('events'),list) or len(body['events'])>100:return jsonify(error='invalid batch'),400
 agent_id=body.get('agent_id');device=Device.query.filter_by(agent_id=agent_id).first() if isinstance(agent_id,str) else None
 if device and not device.enabled:return jsonify(error='device disabled'),403
 try:
  cleaned=[clean_transfer(dict(x,channel=channel)) for x in body['events']]
 except (ValueError,TypeError):return jsonify(error='invalid event'),400
 added=sum(record_transfer(x,device.id if device else None) for x in cleaned)
 db.session.commit();return jsonify(ok=True,created=added)
@app.get('/transfers')
@admin_required
def transfers():
 channel=request.args.get('channel','');decision=request.args.get('decision','');device_id=request.args.get('device_id',type=int)
 q=TransferEvent.query
 if channel in ('browser','usb','email','cloud'):q=q.filter_by(channel=channel)
 if decision in ('allow','alert','blocked'):q=q.filter_by(decision=decision)
 if device_id:q=q.filter_by(device_id=device_id)
 rows=q.order_by(TransferEvent.id.desc()).limit(300).all()
 return render_template('transfers.html',rows=rows,devices=Device.query.order_by(Device.agent_id).all(),policies=TransferPolicy.query.order_by(TransferPolicy.id).all())
@app.post('/transfers/policies')
@admin_required
def add_transfer_policy():
 name=request.form.get('name','').strip()[:100];channel=request.form.get('channel','any');action=request.form.get('action','alert');ext=request.form.get('extension','*').lower().strip();dest=request.form.get('destination_pattern','*').lower().strip();classification=request.form.get('classification','any')
 if not name or channel not in ('any','browser','usb','email','cloud') or action not in ('alert','allow','block') or classification not in ('any','sensitive','unclassified') or not re.fullmatch(r'\*|\.[a-z0-9]{1,20}',ext) or not re.fullmatch(r'\*|[a-z0-9][a-z0-9.-]{0,252}',dest):abort(400)
 if TransferPolicy.query.filter_by(name=name).first():flash('Policy name already exists');return redirect('/transfers')
 db.session.add(TransferPolicy(name=name,channel=channel,action=action,extension=ext,destination_pattern=dest,classification=classification));db.session.add(Audit(action=f'Transfer policy added: {name}'));db.session.commit();return redirect('/transfers')
@app.post('/transfers/policies/<int:policy_id>/delete')
@admin_required
def delete_transfer_policy(policy_id):
 policy=db.get_or_404(TransferPolicy,policy_id);db.session.add(Audit(action=f'Transfer policy deleted: {policy.name}'));db.session.delete(policy);db.session.commit();return redirect('/transfers')
@app.post('/rules')
@admin_required
def add_rule():
 d=db.session.get(Device,request.form.get('device_id',type=int));domain=request.form.get('domain','').strip().lower().rstrip('.')
 if not d or not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain):flash('Invalid device or domain');return redirect('/')
 if not BlockRule.query.filter_by(device_id=d.id,domain=domain).first():db.session.add(BlockRule(device_id=d.id,domain=domain));db.session.add(Audit(action=f'Domain policy published: {d.agent_id} / {domain}'));db.session.commit()
 flash('Policy saved. Managed browser extension applies it on its next policy refresh.');return redirect('/')
@app.post('/rules/<int:rule_id>/delete')
@admin_required
def remove_rule(rule_id):
 r=db.get_or_404(BlockRule,rule_id);db.session.add(Audit(action=f'Domain policy removed: {r.device_id} / {r.domain}'));db.session.delete(r);db.session.commit();return redirect('/')
@app.get('/devices')
@admin_required
def devices_page():return redirect('/#devices')
@app.get('/activity')
@admin_required
def activity_page():return redirect('/#devices')
@app.get('/domain-policies')
@admin_required
def domain_policies_page():return redirect('/#domain-policies')
@app.get('/audit-log')
@admin_required
def audit_log_page():return redirect('/#audit-log')

@app.get('/health')
def health():return jsonify(status='ok')


@app.get('/api/v1/policy/<agent_id>')
def policy(agent_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id).first()
 if not d or not d.enabled:return jsonify(error='device not enrolled'),404
 return jsonify(domains=[r.domain for r in BlockRule.query.filter_by(device_id=d.id).all()])


@app.get('/api/v1/browser-policy/<agent_id>')
def browser_policy(agent_id):
    """Policy snapshot for a managed, opt-in extension; default is no blocking."""
    if not agent_auth():return jsonify(error='unauthorized'),401
    device=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
    if not device:return jsonify(error='device not enrolled'),404
    rules=TransferPolicy.query.filter_by(enabled=True,action='block').order_by(TransferPolicy.id).all()
    domain_rules=BlockRule.query.filter_by(device_id=device.id).order_by(BlockRule.id).all()
    domains=[{'id':r.id,'domain':r.domain} for r in domain_rules]
    version=hashlib.sha256(jsonify(domains=domains).get_data()).hexdigest()
    return jsonify(version=version,domains=domains,rules=[{'name':r.name,'extension':r.extension,'destination_pattern':r.destination_pattern,'classification':r.classification} for r in rules if r.channel in ('any','browser')])

@app.post('/api/v1/browser-policy/<agent_id>/ack')
def browser_policy_ack(agent_id):
    if not agent_auth():return jsonify(error='unauthorized'),401
    device=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
    if not device:return jsonify(error='device not enrolled'),404
    data=request.get_json(silent=True) or {}
    version=str(data.get('version',''))
    status=str(data.get('status',''))
    if not re.fullmatch(r'[a-f0-9]{64}',version) or status not in ('applied','failed','unsupported'):abort(400)
    detail=str(data.get('detail',''))[:200]
    row=PolicyDeployment.query.filter_by(device_id=device.id).first()
    if not row:row=PolicyDeployment(device_id=device.id,policy_hash=version);db.session.add(row)
    row.policy_hash=version;row.status=status;row.detail=detail;row.applied_at=utc()
    db.session.commit()
    return jsonify(ok=True)

@app.post('/api/v1/domain-block/<agent_id>')
def report_domain_block(agent_id):
    if not agent_auth():return jsonify(error='unauthorized'),401
    device=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
    if not device:return jsonify(error='device not enrolled'),404
    data=request.get_json(silent=True) or {}
    domain=str(data.get('domain','')).lower().rstrip('.')
    if not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain):abort(400)
    rule=next((r for r in BlockRule.query.filter_by(device_id=device.id).all() if domain==r.domain or domain.endswith('.'+r.domain)),None)
    if not rule:return jsonify(error='no matching policy'),409
    db.session.add(DomainBlockEvent(device_id=device.id,domain=domain,rule_id=rule.id))
    db.session.commit()
    return jsonify(ok=True)

@app.get('/domain-block-events')
@admin_required
def domain_block_events():
    events=DomainBlockEvent.query.order_by(DomainBlockEvent.id.desc()).limit(200).all()
    deployments={x.device_id:x for x in PolicyDeployment.query.all()}
    return render_template('domain_blocks.html',events=events,devices={x.id:x for x in Device.query.all()},deployments=deployments)




@app.get('/incidents')
@admin_required
def incidents():
 status=request.args.get('status','')
 severity=request.args.get('severity','')
 q=DlpIncident.query
 if status in ('new','investigating','resolved','closed'):q=q.filter_by(status=status)
 if severity in ('low','medium','high'):q=q.filter_by(severity=severity)
 rows=q.order_by(DlpIncident.id.desc()).limit(250).all()
 transfers={x.id:x for x in TransferEvent.query.filter(TransferEvent.id.in_([i.transfer_event_id for i in rows])).all()} if rows else {}
 notes={i.id:DlpIncidentNote.query.filter_by(incident_id=i.id).order_by(DlpIncidentNote.id.desc()).limit(10).all() for i in rows}
 return render_template('incidents.html',rows=rows,transfers=transfers,notes=notes)

@app.post('/incidents/<int:incident_id>/update')
@admin_required
def update_incident(incident_id):
 incident=db.get_or_404(DlpIncident,incident_id)
 status=request.form.get('status','')
 if status not in ('new','investigating','resolved','closed'):abort(400)
 assignee=request.form.get('assignee','').strip()
 if len(assignee)>100:abort(400)
 note=request.form.get('note','').strip()
 if len(note)>2000:abort(400)
 incident.status=status;incident.assignee=assignee
 if note:db.session.add(DlpIncidentNote(incident_id=incident.id,note=note))
 db.session.add(Audit(action=f'Incident {incident.id} changed to {status}'))
 db.session.commit()
 return redirect(url_for('incidents'))

# Keyword DLP: alert-only; no keystroke collection or document contents uploaded.
@app.get('/api/v1/keyword-policy/<agent_id>')
def keyword_policy(agent_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
 if not d:return jsonify(rules=[])
 rules=KeywordRule.query.filter_by(enabled=True).filter(db.or_(KeywordRule.device_id==None,KeywordRule.device_id==d.id)).order_by(KeywordRule.id).all()
 return jsonify(rules=[{'id':r.id,'phrase':r.phrase} for r in rules])

@app.post('/api/v1/keyword-alerts/<agent_id>')
def keyword_alerts(agent_id):
 if not agent_auth():return jsonify(error='unauthorized'),401
 d=Device.query.filter_by(agent_id=agent_id,enabled=True).first()
 if not d:return jsonify(error='unknown or disabled device'),403
 body=request.get_json(silent=True) or {}
 events=body.get('events',[])
 if not isinstance(events,list) or len(events)>50:return jsonify(error='invalid events'),400
 rules={r.id:r for r in KeywordRule.query.filter_by(enabled=True).filter(db.or_(KeywordRule.device_id==None,KeywordRule.device_id==d.id)).all()}
 for e in events:
  if not isinstance(e,dict):return jsonify(error='invalid event'),400
  eid=e.get('event_id');rid=e.get('rule_id');filename=e.get('file_name')
  if not isinstance(eid,str) or not re.fullmatch(r'[0-9a-f]{32}',eid) or not isinstance(rid,int) or rid not in rules or not isinstance(filename,str) or not 1<=len(filename)<=255:return jsonify(error='invalid event'),400
  if KeywordAlert.query.filter_by(event_id=eid).first():continue
  db.session.add(KeywordAlert(event_id=eid,device_id=d.id,rule_id=rid,file_name=filename))
 db.session.commit()
 return jsonify(ok=True)

@app.get('/keyword-dlp')
@admin_required
def keyword_dlp_page():
 rules=KeywordRule.query.order_by(KeywordRule.id.desc()).all()
 alerts=KeywordAlert.query.order_by(KeywordAlert.id.desc()).limit(200).all()
 devices=Device.query.order_by(Device.agent_id).all()
 device_names={d.id:(d.name or d.agent_id) for d in devices}
 rule_names={r.id:r.phrase for r in rules}
 return render_template('keyword_dlp.html',rules=rules,alerts=alerts,devices=devices,device_names=device_names,rule_names=rule_names)


@app.post('/keyword-dlp/rules')
@admin_required
def add_keyword_rule():
 phrase=request.form.get('phrase','').strip()
 raw=request.form.get('device_id','')
 if not 2<=len(phrase)<=120 or '\n' in phrase or '\r' in phrase:abort(400)
 if raw and not raw.isdecimal():abort(400)
 device_id=int(raw) if raw else None
 if device_id is not None and not db.session.get(Device,device_id):abort(400)
 db.session.add(KeywordRule(phrase=phrase,device_id=device_id))
 db.session.add(Audit(action='Keyword DLP rule created'))
 db.session.commit();return redirect('/keyword-dlp')

@app.post('/keyword-dlp/rules/<int:rule_id>/delete')
@admin_required
def delete_keyword_rule(rule_id):
 r=db.get_or_404(KeywordRule,rule_id)
 r.enabled=False
 db.session.add(Audit(action=f'Keyword DLP rule {rule_id} disabled'))
 db.session.commit();return redirect('/keyword-dlp')

if __name__=="__main__":app.run(host=os.environ.get("SERVER_HOST","127.0.0.1"),port=int(os.environ.get("SERVER_PORT",5000)),debug=False)

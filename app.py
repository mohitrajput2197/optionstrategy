import os
import io
import json
import threading
import yfinance as yf
from dotenv import load_dotenv
from datetime import datetime, timedelta
from flask import Flask, render_template, request, send_file, session, redirect, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin,AdminIndexView
from flask_admin.contrib.sqla import ModelView
from wtforms.fields import PasswordField
from flask_babel import Babel

load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "a-default-safe-key-for-development")
INVITATION_CODE = os.environ.get("INVITATION_CODE", "BIJNOR24")

basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'users.db')
# app.py mein yeh badlav karein

database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    # Heroku's URL ko SQLAlchemy ke liye theek karna
    database_url = database_url.replace("postgres://", "postgresql://", 1)

# Agar Heroku par hai, to PostgreSQL use karega, warna local computer par SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///' + os.path.join(basedir, 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['BABEL_DEFAULT_LOCALE'] = 'en'
babel = Babel(app)
db = SQLAlchemy(app)

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    last_analysis_result = db.Column(db.Text)

class SavedStrategy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    strategy_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('strategies', lazy=True, cascade="all, delete-orphan"))
    script = db.Column(db.String(50)); expiry = db.Column(db.String(50)); firstStrikeCE = db.Column(db.Integer)
    firstStrikePE = db.Column(db.Integer); strikeStep = db.Column(db.Integer); totStrikes = db.Column(db.Integer)
    buySellPattern = db.Column(db.String(50)); mode = db.Column(db.String(10)); ratios_gaps_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class TradeJournal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('journal_entries', lazy=True, cascade="all, delete-orphan"))
    strategy_details_json = db.Column(db.Text, nullable=False)
    entry_date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text); final_pnl = db.Column(db.Float)

# --- Admin Panel ---
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return session.get('logged_in') and session.get('is_admin')
    def inaccessible_callback(self, name, **kwargs):
        flash('You do not have permission to access the Admin Panel.', 'error')
        return redirect('/login')

class SecureModelView(ModelView):
    column_list = ['username', 'is_admin']
    form_columns = ['username', 'password', 'is_admin']
    form_overrides = { 'password': PasswordField }
    def on_model_change(self, form, model, is_created):
        if form.password.data: model.password = generate_password_hash(form.password.data)
    def is_accessible(self): return session.get('logged_in') and session.get('is_admin')
    def inaccessible_callback(self, name, **kwargs): return redirect('/login')

admin = Admin(app, name='Control Panel', template_mode='bootstrap3', index_view=MyAdminIndexView())
admin.add_view(SecureModelView(User, db.session))
admin.add_view(ModelView(SavedStrategy, db.session))
admin.add_view(ModelView(TradeJournal, db.session))

with app.app_context():
    db.create_all()

@app.template_filter('fromjson')
def fromjson_filter(value):
    return json.loads(value)

# --- Main Routes ---
@app.route('/')
def index():
    if not session.get("logged_in"): return redirect('/login')
    return render_template('dashboard.html', username=session.get("username"), is_admin=session.get('is_admin', False))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get("username")).first()
        if user and check_password_hash(user.password, request.form.get("password")):
            session["logged_in"]=True; session["username"]=user.username; session["is_admin"]=user.is_admin
            return redirect('/')
        else: flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if request.form.get('invitation_code') != INVITATION_CODE:
            flash('Invalid Invitation Code.', 'error'); return redirect('/register')
        if User.query.filter_by(username=request.form.get('username')).first():
            flash('That username is already taken.', 'error'); return redirect('/register')
        new_user = User(username=request.form.get('username'), password=generate_password_hash(request.form.get('password')), is_admin=False)
        db.session.add(new_user); db.session.commit()
        flash('Registration successful! You can now log in.', 'success'); return redirect('/login')
    return render_template('register.html')

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); flash('You have been successfully logged out.', 'success'); return redirect("/login")

# --- Feature Routes ---
@app.route('/history')
def history():
    if not session.get("logged_in"): return redirect('/login')
    user = User.query.filter_by(username=session['username']).first()
    user_strategies = SavedStrategy.query.filter_by(user_id=user.id).order_by(SavedStrategy.created_at.desc()).all()
    return render_template('history.html', strategies=user_strategies, username=session.get("username"))

@app.route('/save_strategy', methods=['POST'])
def save_strategy():
    if not session.get("logged_in"): return jsonify({"status": "error"}), 401
    data = request.json; user = User.query.filter_by(username=session['username']).first()
    new_strategy = SavedStrategy(strategy_name=data.get('strategy_name','Unnamed'), user_id=user.id, script=data.get('script'),
                                expiry=data.get('expiry'), firstStrikeCE=data.get('firstStrikeCE'), firstStrikePE=data.get('firstStrikePE'),
                                strikeStep=data.get('strikeStep'), totStrikes=data.get('totStrikes'), buySellPattern=data.get('buySellPattern'),
                                mode=data.get('mode'), ratios_gaps_json=json.dumps(data.get('ratios_gaps')))
    db.session.add(new_strategy); db.session.commit()
    return jsonify({"status": "success", "message": f"Strategy '{new_strategy.strategy_name}' saved!"})

@app.route('/load_strategy/<int:strategy_id>')
def load_strategy(strategy_id):
    if not session.get("logged_in"): return jsonify({}), 401
    strategy = SavedStrategy.query.get_or_404(strategy_id)
    user = User.query.filter_by(username=session['username']).first()
    if strategy.user_id != user.id: return jsonify({"status": "error"}), 403
    return jsonify({'script': strategy.script, 'expiry': strategy.expiry, 'firstStrikeCE': strategy.firstStrikeCE, 'firstStrikePE': strategy.firstStrikePE,
                    'strikeStep': strategy.strikeStep, 'totStrikes': strategy.totStrikes, 'buySellPattern': strategy.buySellPattern,
                    'mode': strategy.mode, 'ratios_gaps': json.loads(strategy.ratios_gaps_json)})

@app.route('/delete_strategy', methods=['POST'])
def delete_strategy():
    if not session.get("logged_in"): return jsonify({}), 401
    strategy = SavedStrategy.query.get_or_404(request.json.get('id'))
    user = User.query.filter_by(username=session['username']).first()
    if strategy.user_id != user.id: return jsonify({"status": "error"}), 403
    db.session.delete(strategy); db.session.commit()
    return jsonify({"status": "success", "message": "Strategy deleted."})

@app.route('/journal')
def journal():
    if not session.get("logged_in"): return redirect('/login')
    user = User.query.filter_by(username=session['username']).first()
    try:
        time_limit = datetime.utcnow() - timedelta(hours=24)
        entries_to_delete = TradeJournal.query.filter(TradeJournal.user_id == user.id, TradeJournal.entry_date < time_limit).all()
        if entries_to_delete:
            for entry in entries_to_delete: db.session.delete(entry)
            db.session.commit()
    except Exception as e: print(f"Error during auto-deletion: {e}"); db.session.rollback()
    entries = TradeJournal.query.filter_by(user_id=user.id).order_by(TradeJournal.entry_date.desc()).all()
    return render_template('journal.html', entries=entries, username=session.get("username"))

@app.route('/update_journal_entry', methods=['POST'])
def update_journal_entry():
    if not session.get("logged_in"): return jsonify({"status": "error"}), 401
    data = request.json; entry = TradeJournal.query.get_or_404(data.get('id'))
    user = User.query.filter_by(username=session['username']).first()
    if entry.user_id != user.id: return jsonify({"status": "error"}), 403
    entry.notes = data.get('notes')
    try: entry.final_pnl = float(data.get('pnl')) if data.get('pnl') else None
    except (ValueError, TypeError): entry.final_pnl = None
    db.session.commit(); return jsonify({"status": "success"})

@app.route('/journal/delete', methods=['POST'])
def delete_journal_entry():
    if not session.get("logged_in"): return jsonify({"status": "error"}), 401
    entry = TradeJournal.query.get_or_404(request.json.get('id'))
    user = User.query.filter_by(username=session['username']).first()
    if entry.user_id != user.id: return jsonify({"status": "error"}), 403
    db.session.delete(entry); db.session.commit()
    return jsonify({"status": "success", "message": "Journal entry deleted."})

@app.route('/market_insight')
def market_insight():
    if not session.get("logged_in"): return jsonify({"insight": "Not authorized."})
    vix_price = 15.0
    try:
        vix_ticker = yf.Ticker('^INDIAVIX')
        info = vix_ticker.info
        if info and info.get('regularMarketPrice'): vix_price = info['regularMarketPrice']
    except Exception as e: print(f"Error fetching VIX from yfinance: {e}")
    insight = f"Market volatility is neutral (VIX at {vix_price:.2f}). Exercise caution."
    if vix_price > 20: insight = f"High volatility detected (VIX at {vix_price:.2f}). Consider strategies that sell premium."
    elif vix_price < 12: insight = f"Low volatility detected (VIX at {vix_price:.2f}). Consider strategies that buy premium."
    return jsonify({"insight": insight})

@app.route('/ticker_data')
def ticker_data():
    if not session.get("logged_in"): return jsonify({"error": "Not authorized"}), 401
    symbol_map = {'NIFTY 50': '^NSEI', 'NIFTY Bank': '^NSEBANK', 'SENSEX': '^BSESN'}
    ticker_results = []
    for display_name, api_symbol in symbol_map.items():
        try:
            ticker = yf.Ticker(api_symbol); info = ticker.info
            price = info.get('regularMarketPrice'); prev_close = info.get('previousClose')
            if price and prev_close:
                change = price - prev_close; percent_change = (change / prev_close) * 100
                ticker_results.append({'symbol': display_name, 'value': price, 'change': change, 'percent': percent_change})
        except Exception as e: print(f"Error fetching {api_symbol} from yfinance: {e}")
    return jsonify({"data": ticker_results})

# --- YOUR ORIGINAL MAIN LOGIC: THE GENERATE FUNCTION ---
@app.route('/generate', methods=['POST'])
def generate():
    if not session.get("logged_in"):
        return redirect("/login")

    form_data_for_journal = {key: request.form.getlist(key) for key in request.form.keys()}
    def get_int_from_form(field_name, default_value):
        value = request.form.get(field_name, str(default_value))
        if value and value.isdigit(): return int(value)
        return default_value
    ratios_list = request.form.getlist('ratios'); gaps_list_str = request.form.getlist('gaps'); parsed_pairs = []
    for r, g_str in zip(ratios_list, gaps_list_str):
        if r.strip():
            g_vals = [int(g.strip()) for g in g_str.split(',') if g.strip().isdigit()]
            if g_vals: parsed_pairs.append((r.strip(), g_vals))
    if not parsed_pairs: flash("Please enter at least one valid Ratio/Gap pair.", "error"); return redirect('/')
    script = request.form.get('script', 'NIFTY').upper(); expiry_raw = request.form.get('expiry', '')
    firstStrikeCE = get_int_from_form('firstStrikeCE', 24100); firstStrikePE = get_int_from_form('firstStrikePE', 25400)
    strikeStep = get_int_from_form('strikeStep', 50); totStrikes = get_int_from_form('totStrikes', 10)
    buySellPattern = request.form.get('buySellPattern', 'S.B.S').upper()
    fileName = request.form.get('fileName') or f"{script}-strategy.csv"; mode = request.form.get('mode', '8184')
    csv_script = 'BSX' if script == 'SENSEX' else script
    lot_per_script = 75
    if script == "BANKNIFTY": lot_per_script = 35
    elif script == "SENSEX": lot_per_script = 20
    elif script == "MIDCAP": lot_per_script = 140
    elif script == "FINNIFTY": lot_per_script = 65
    def formatExpiry(dateStr):
        if not dateStr: return ""
        try: d = datetime.strptime(dateStr, '%Y-%m-%d')
        except Exception: return ""
        months = ["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"]
        return f"{d.day:02d}-{months[d.month-1]}-{d.year}"
    def getStgCode(ratioStr, mode):
        count = len(ratioStr.split('.'));
        if mode == "IOC": return 210
        if count == 2: return 10201
        if count == 3: return 10301
        if count == 4: return 10401
        return 10301
    expiry = formatExpiry(expiry_raw)
    headerLine = "#PID,cost,bcmp,scmp,flp,stgcode,script,lotsize,itype,expiry,otype,stkprice,ratio,buysell,pnAdd,pnMulti,bsoq,bqty,bprice,sprice,sqty,ssoq,btrQty,strQty,gap,ticksize,orderDepth,priceDepth,thshqty,allowedBiddth,allowedSlippage,tradeGear,shortflag,isBidding,marketOrderRetries,marketOrLimitOrder,isBestbid,unhedgedActionType,TERActionType,BidWaitingType,param2,param3,param4,param5,param6,param7,param01,param02,param03,param04,param05,param06,param07,param08,param09,param10,param11,param12,param13,param14,param15,param16,param17,param18,param19,param20,param21,param22,param23,param24,param25,param26,param27,param28,param29,param30,param31,param32,param33,param34,param35,param36,param3-7,param38,param39,param40,param301,param302,param303,param304,param305,param306,param307,param308,param309,param310,param311,param312,param313,param314,param315,param316,param317,param318,param319,param320,param321,param322,param323,param324,param325,param326,param327,param328,param329,param330,param331,param332,param333,param334,param335,param336,param337,param338,param339,param340"
    headers = headerLine.split(","); rows = [headerLine]; pid = 1; baseParts = buySellPattern.split('.'); baseCount = len(baseParts)
    for ratio, gapValues in parsed_pairs:
        legCount = len(ratio.split('.')); stgCode = getStgCode(ratio, mode); current_lotSize = "|".join([str(lot_per_script)] * legCount) if mode == "7155" else str(lot_per_script)
        for gap in gapValues:
            buySellStr = '.'.join([baseParts[i % baseCount] for i in range(legCount)])
            for i in range(totStrikes):
                prices = [firstStrikeCE + i * strikeStep + j * gap for j in range(legCount)]; row = ['0'] * len(headers); row[0] = str(pid); pid += 1; row[5] = str(stgCode); row[6] = csv_script; row[7] = current_lotSize; row[8] = '-'.join(['OPTIDX'] * legCount); row[9] = '|'.join([expiry] * legCount); row[10] = '|'.join(['CE'] * legCount); row[11] = '|'.join(map(str, prices)); row[12] = ratio; row[13] = buySellStr; row[24] = str(gap)
                row[15] = '1'; row[18] = '0'; row[19] = '0'; row[25] = '10'; row[26] = '2'; row[27] = '2'; row[29] = '5'; row[30] = '50' if mode == "IOC" else '200'; row[31] = '2'; row[32] = '1'; row[33] = 'FALSE' if mode == "IOC" else 'TRUE'; row[34] = '5'; row[37] = '2'; row[38] = '1'; row[39] = '500'; row[46] = '60'; row[47] = '50' if mode == "IOC" else '800'; row[50] = '100'; row[51] = '200'; row[52] = '2575'; row[53] = '60'; row[54] = '100'; row[55] = '200'; row[56] = '100'; row[57] = '100'; row[58] = '10'; row[60] = '1'; row[64] = '1999'; row[66] = '30'; row[68] = '10'; row[86] = '101'; row[28] = '80' if mode == "IOC" else '0'
                rows.append(','.join(row))
            for i in range(totStrikes):
                prices = [firstStrikePE - i * strikeStep - j * gap for j in range(legCount)]; row = ['0'] * len(headers); row[0] = str(pid); pid += 1; row[5] = str(stgCode); row[6] = csv_script; row[7] = current_lotSize; row[8] = '-'.join(['OPTIDX'] * legCount); row[9] = '|'.join([expiry] * legCount); row[10] = '|'.join(['PE'] * legCount); row[11] = '|'.join(map(str, prices)); row[12] = ratio; row[13] = buySellStr; row[24] = str(gap)
                row[15] = '1'; row[18] = '0'; row[19] = '0'; row[25] = '10'; row[26] = '2'; row[27] = '2'; row[29] = '5'; row[30] = '50' if mode == "IOC" else '200'; row[31] = '2'; row[32] = '1'; row[33] = 'FALSE' if mode == "IOC" else 'TRUE'; row[34] = '5'; row[37] = '2'; row[38] = '1'; row[39] = '500'; row[46] = '60'; row[47] = '50' if mode == "IOC" else '800'; row[50] = '100'; row[51] = '200'; row[52] = '2575'; row[53] = '60'; row[54] = '100'; row[55] = '200'; row[56] = '100'; row[57] = '100'; row[58] = '10'; row[60] = '1'; row[64] = '1999'; row[66] = '30'; row[68] = '10'; row[86] = '101'; row[28] = '80' if mode == "IOC" else '0'
                rows.append(','.join(row))

    try:
        user = User.query.filter_by(username=session['username']).first()
        if user:
            journal_entry = TradeJournal(user_id=user.id, strategy_details_json=json.dumps(form_data_for_journal))
            db.session.add(journal_entry)
            db.session.commit()
    except Exception as e:
        print(f"Could not create journal entry: {e}")

    csv_content = '\n'.join(rows)
    output = io.StringIO(csv_content); output.seek(0)
    return send_file(io.BytesIO(output.read().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name=fileName)

# --- Run the Application ---
if __name__ == '__main__':
    app.run(debug=True)
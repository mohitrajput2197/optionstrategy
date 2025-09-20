
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
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from wtforms.fields import PasswordField
from flask_babel import Babel

# --- Configuration ---
load_dotenv()
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "a-default-secret-key-for-development")
INVITATION_CODE = os.environ.get("INVITATION_CODE", "BIJNOR24")

# --- Database Configuration (Works on Heroku and Local) ---
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
     # Heroku's URL ko SQLAlchemy ke liye theek karna
    database_url = database_url.replace("postgres://", "postgresql://", 1)
basedir = os.path.abspath(os.path.dirname(__file__))
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
    def is_accessible(self): return session.get('logged_in') and session.get('is_admin')
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

# (All other routes for login, register, history, etc. are here and unchanged)
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
    if not session.get("logged_in"): return redirect("/login")
        
    def get_int_from_form(field_name, default_value):
        value = request.form.get(field_name, str(default_value)); return int(value) if value and value.isdigit() else default_value
    def get_str_from_form(field_name, default_value):
        value = request.form.get(field_name); return value if value and value.strip() else str(default_value)

    # --- Standard form fields ---
    ratios_list = request.form.getlist('ratios')
    gaps_list_str = request.form.getlist('gaps')
    use_individual_gaps_list = request.form.getlist('use_individual_gaps')
    
    parsed_pairs = []
    for i, (ratio_str, gap_str) in enumerate(zip(ratios_list, gaps_list_str)):
        use_individual = (i < len(use_individual_gaps_list) and use_individual_gaps_list[i] == 'on')
        parsed_pairs.append({'ratio': ratio_str, 'gaps': gap_str, 'individual': use_individual})

    script=request.form.get('script','NIFTY').upper(); expiry_raw=request.form.get('expiry','')
    firstStrikeCE=get_int_from_form('firstStrikeCE',24100); firstStrikePE=get_int_from_form('firstStrikePE',25400)
    strikeStep=get_int_from_form('strikeStep',50)
    totStrikes = get_int_from_form('totStrikes', 10)
    buySellPattern=request.form.get('buySellPattern','S.B.S').upper()
    fileName=request.form.get('fileName')or f"{script}-strategy.csv";mode=request.form.get('mode','8184')
    
    # --- Advanced Parameters Logic ---
    use_advanced_csv = request.form.get('use_advanced_csv') == 'on'
    adv_bsoq = get_str_from_form('bsoq', '0') if use_advanced_csv else '0'
    adv_bqty = get_str_from_form('bqty', '0') if use_advanced_csv else '0'
    adv_bprice = get_str_from_form('bprice', '0') if use_advanced_csv else '0'
    adv_sprice = get_str_from_form('sprice', '0') if use_advanced_csv else '0'
    adv_sqty = get_str_from_form('sqty', '0') if use_advanced_csv else '0'
    adv_ssoq = get_str_from_form('ssoq', '0') if use_advanced_csv else '0'
    
    # --- Your original CSV logic ---
    csv_script = 'BSX' if script == 'SENSEX' else script
    lot_per_script = 75
    if script == "BANKNIFTY": lot_per_script = 35
    elif script == "SENSEX": lot_per_script = 20
    elif script == "MIDCAP": lot_per_script = 140
    elif script == "FINNIFTY": lot_per_script = 65
    def formatExpiry(dateStr):
        if not dateStr:return ""
        try:d=datetime.strptime(dateStr,'%Y-%m-%d'); months=["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"]; return f"{d.day:02d}-{months[d.month-1]}-{d.year}"
        except Exception:return ""
    def getStgCode(ratioStr,mode):
        count=len(ratioStr.split('.'));
        if mode=="IOC":return 210
        if count==2:return 10201
        if count==3:return 10301
        if count==4:return 10401
        return 10301
    expiry=formatExpiry(expiry_raw)
    headerLine = "#PID,cost,bcmp,scmp,flp,stgcode,script,lotsize,itype,expiry,otype,stkprice,ratio,buysell,pnAdd,pnMulti,bsoq,bqty,bprice,sprice,sqty,ssoq,btrQty,strQty,gap,ticksize,orderDepth,priceDepth,thshqty,allowedBiddth,allowedSlippage,tradeGear,shortflag,isBidding,marketOrderRetries,marketOrLimitOrder,isBestbid,unhedgedActionType,TERActionType,BidWaitingType,param2,param3,param4,param5,param6,param7,param01,param02,param03,param04,param05,param06,param07,param08,param09,param10,param11,param12,param13,param14,param15,param16,param17,param18,param19,param20,param21,param22,param23,param24,param25,param26,param27,param28,param29,param30,param31,param32,param33,param34,param35,param36,param3-7,param38,param39,param40,param301,param302,param303,param304,param305,param306,param307,param308,param309,param310,param311,param312,param313,param314,param315,param316,param317,param318,param319,param320,param321,param322,param323,param324,param325,param326,param327,param328,param329,param330,param331,param332,param333,param334,param335,param336,param337,param338,param339,param340"
    headers = headerLine.split(","); rows = [headerLine]; pid = 1; baseParts = buySellPattern.split('.'); baseCount = len(baseParts)
    
    for pair in parsed_pairs:
        ratio_str = pair['ratio']; gap_str = pair['gaps']; use_individual = pair['individual']
        if not ratio_str.strip() or not gap_str.strip(): continue

        all_gaps_to_iterate = [int(g.strip()) for g in gap_str.split(',') if g.strip().isdigit()]
        if not all_gaps_to_iterate: continue

        legCount = len(ratio_str.split('.')); stgCode = getStgCode(ratio_str, mode); current_lotSize = "|".join([str(lot_per_script)] * legCount) if mode == "7155" else str(lot_per_script)
        buySellStr = '.'.join([baseParts[i % baseCount] for i in range(legCount)])
        
        for gap in all_gaps_to_iterate:
            for i in range(totStrikes):
                if use_individual: # This logic now only applies to how strikes are calculated, not the loop
                    leg_gaps = all_gaps_to_iterate
                    current_ce_strike = firstStrikeCE + (i * strikeStep)
                    ce_prices = [current_ce_strike]
                    for j in range(legCount - 1):
                        gap_to_add = leg_gaps[j] if j < len(leg_gaps) else leg_gaps[-1]
                        current_ce_strike += gap_to_add; ce_prices.append(current_ce_strike)
                else: # Old logic uses the single current gap for all legs
                    ce_prices = [firstStrikeCE + i * strikeStep + j * gap for j in range(legCount)]
                
                row_ce = ['0'] * len(headers); row_ce[0] = str(pid); pid += 1; row_ce[5]=str(stgCode); row_ce[6]=csv_script; row_ce[7]=current_lotSize; row_ce[8]='-'.join(['OPTIDX']*legCount); row_ce[9]='|'.join([expiry]*legCount); row_ce[10]='|'.join(['CE']*legCount); row_ce[11]='|'.join(map(str, ce_prices)); row_ce[12]=ratio_str; row_ce[13]=buySellStr; row_ce[24]=str(gap)
                row_ce[16]=adv_bsoq; row_ce[17]=adv_bqty; row_ce[18]=adv_bprice; row_ce[19]=adv_sprice; row_ce[20]=adv_sqty; row_ce[21]=adv_ssoq
                row_ce[15]='1'; row_ce[25]='10'; row_ce[26]='2'; row_ce[27]='2'; row_ce[29]='5'; row_ce[30]='50' if mode=="IOC" else '200'; row_ce[31]='2'; row_ce[32]='1'; row_ce[33]='FALSE' if mode=="IOC" else 'TRUE'; row_ce[34]='5'; row_ce[37]='2'; row_ce[38]='1'; row_ce[39]='500'; row_ce[46]='60'; row_ce[47]='50' if mode=="IOC" else '800'; row_ce[50]='100'; row_ce[51]='200'; row_ce[52]='2575'; row_ce[53]='60'; row_ce[54]='100'; row_ce[55]='200'; row_ce[56]='100'; row_ce[57]='100'; row_ce[58]='10'; row_ce[60]='1'; row_ce[64]='1999'; row_ce[66]='30'; row_ce[68]='10'; row_ce[86]='101'; row_ce[28]='80' if mode=="IOC" else '0'
                rows.append(','.join(row_ce))

            for i in range(totStrikes):
                if use_individual:
                    leg_gaps = all_gaps_to_iterate
                    current_pe_strike = firstStrikePE - (i * strikeStep)
                    pe_prices = [current_pe_strike]
                    for j in range(legCount - 1):
                        gap_to_subtract = leg_gaps[j] if j < len(leg_gaps) else leg_gaps[-1]
                        current_pe_strike -= gap_to_subtract; pe_prices.append(current_pe_strike)
                else:
                    pe_prices = [firstStrikePE - i * strikeStep - j * gap for j in range(legCount)]

                row_pe = ['0'] * len(headers); row_pe[0] = str(pid); pid += 1; row_pe[5]=str(stgCode); row_pe[6]=csv_script; row_pe[7]=current_lotSize; row_pe[8]='-'.join(['OPTIDX']*legCount); row_pe[9]='|'.join([expiry]*legCount); row_pe[10]='|'.join(['PE']*legCount); row_pe[11]='|'.join(map(str, pe_prices)); row_pe[12]=ratio_str; row_pe[13]=buySellStr; row_pe[24]=str(gap)
                row_pe[16]=adv_bsoq; row_pe[17]=adv_bqty; row_pe[18]=adv_bprice; row_pe[19]=adv_sprice; row_pe[20]=adv_sqty; row_pe[21]=adv_ssoq
                row_pe[15]='1'; row_pe[25]='10'; row_pe[26]='2'; row_pe[27]='2'; row_pe[29]='5'; row_pe[30]='50' if mode=="IOC" else '200'; row_pe[31]='2'; row_pe[32]='1'; row_pe[33]='FALSE' if mode=="IOC" else 'TRUE'; row_pe[34]='5'; row_pe[37]='2'; row_pe[38]='1'; row_pe[39]='500'; row_pe[46]='60'; row_pe[47]='50' if mode=="IOC" else '800'; row_pe[50]='100'; row_pe[51]='200'; row_pe[52]='2575'; row_pe[53]='60'; row_pe[54]='100'; row_pe[55]='200'; row_pe[56]='100'; row_pe[57]='100'; row_pe[58]='10'; row_pe[60]='1'; row_pe[64]='1999'; row_pe[66]='30'; row_pe[68]='10'; row_pe[86]='101'; row_pe[28]='80' if mode=="IOC" else '0'
                rows.append(','.join(row_pe))
            
            # If using individual gaps, we only want to process the list of gaps once
            if use_individual:
                break 
            
            

    csv_content = '\n'.join(rows)
    output = io.StringIO(csv_content); output.seek(0)
    return send_file(io.BytesIO(output.read().encode('utf-8')), mimetype='text/csv', as_attachment=True, download_name=fileName)

if __name__ == '__main__':
    app.run(debug=True)

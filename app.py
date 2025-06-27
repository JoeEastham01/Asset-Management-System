from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from dateutil.relativedelta import relativedelta
import sqlite3
from datetime import datetime
from datetime import date
import re


# Flask app setup
app = Flask(__name__)
app.secret_key = 'supersecretkey2f'

# Password encryption
bcrypt = Bcrypt(app)



# Connects to the applications SQLite database
def get_db_connection():
    conn = sqlite3.connect('database/RailAssetManagement.db')
    conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row
    return conn



GRADE_MONTHS = {
    'A': 36, 'B': 30, 'C': 24, 'D': 18, 'E': 12, 'F': 6
}

ASSET_OFFSET_MONTHS = {
    'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6
}

def calculate_compliance_date(grade, exam_date_str, offset=None):
    try:
        exam_date = datetime.strptime(exam_date_str, '%Y-%m-%d')
        months = GRADE_MONTHS.get(grade.upper())
        if months:
            compliance_date = exam_date + relativedelta(months=months)
            if offset:
                compliance_date = compliance_date - relativedelta(months=offset)
            return compliance_date.date()
    except Exception as e:
        print(f"Error: {e}")
    return None



def reset_autoincrement(conn, table, id_column):
    cursor = conn.cursor()

    get_max_id = f'SELECT MAX({id_column}) FROM {table}'
    cursor.execute(get_max_id)
    max_id = cursor.fetchone()[0]
    if max_id is None:
        max_id = 0

    cursor.execute(
        "UPDATE sqlite_sequence SET seq = ? WHERE name = ?",
        (max_id, table)
    )
    conn.commit()




#-------------------------------------------------------------------------------------------------------




# Route for the application home page, launch page
@app.route('/')
def home():
    return render_template('home.html')
        


# Login function verifies credentials, and redirects to the appropriate dashboard
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        # Check if user exists and password matches hashed password in DB
        if user and bcrypt.check_password_hash(user['password'], password): 
            session['user_id'] = user['user_id']
            session['email'] = user['email']

            # Redirect admins and regular users to their respective dashboards
            if user['admin'] == True:
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

'''
More detailed error feedback to indicate if the password or email is icorrect,
is avoided to prevent giving clues to attackers about valid accounts.
'''


#-------------------------------------------------------------------------------------------------------


def validate_credentials_format(email, password):
    special_characters = r'[!@#$%^&*(),.?\":{}|<>]'
    Valid = True

    # email validation to check for '@' and accepted domains
    if '@' not in email:
        Valid = False
    if '.com' not in email:
        if '.co.uk' not in email:
            Valid = False
    if Valid == False:
        flash('Please enter a valid email address')
        
    # Password length and special character validation
    if len(password) < 5:
        Valid = False
        flash('Please enter a password at least 5 charactors long')
    elif not re.search(special_characters, password):
        Valid = False
        flash('Password must contain at least one special character [!@#$%^&*(),.?\":{}|<>]')   

    return Valid


# User registration route handling both displaying the form and processing form submission
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        Valid = validate_credentials_format(email, password)
    
        if Valid == True:
            try:
                conn = get_db_connection()
                reset_autoincrement(conn, 'users', 'user_id')
                conn.execute('INSERT INTO users (email, password, admin) VALUES (?, ?, ?)', (email, hashed_pw, 0))
                conn.commit()
                conn.close()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email already registered')

    # Render registration form if GET request or validation failed
    return render_template('register.html') 

'''
Further validation could be included such as sending an email and generating a code
to confirm a valid address and then activate the account.
'''


# Admin user registration
@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        # Get admin flag from form, default to 0 (non-admin)
        admin = int(request.form.get('admin', 0))

        Valid = validate_credentials_format(email, password)

        if Valid == True:
            try:
                conn = get_db_connection()
                reset_autoincrement(conn, 'users', 'user_id')
                conn.execute('INSERT INTO users (email, password, admin) VALUES (?, ?, ?)', (email, hashed_pw, admin))
                conn.commit()
                conn.close()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email already registered')

    # Render admin registration form if GET or on failure        
    return render_template('admin_register.html')



#-------------------------------------------------------------------------------------------------------


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session['email'])



@app.route('/admin_dashboard')
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html', email=session['email'])



#-------------------------------------------------------------------------------------------------------


@app.route('/asset_data')
def asset_data():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    assets = conn.execute('SELECT * FROM assets').fetchall()
    exams = conn.execute('SELECT exam_id FROM exams').fetchall()
    conn.close()
    is_admin = admin_status()   
    
    return render_template('asset_data.html', exams=exams, assets=assets, is_admin=is_admin)   



def update_asset(asset_id, exam_id, asset_type, grade, comments):
    conn = get_db_connection()
    conn.execute('''
        UPDATE assets
        SET exam_id = ?,
            type = ?,
            grade = ?,
            comments = ?
        WHERE asset_id = ?
    ''', (exam_id, asset_type, grade, comments, asset_id))
    conn.commit()
    conn.close()


@app.route('/update_assets', methods=['POST'])
def update_assets():
    conn = get_db_connection()
    assets = conn.execute('SELECT * FROM assets').fetchall()
    exams = conn.execute('SELECT * FROM exams').fetchall()
    for asset in assets:
        asset_id = asset['asset_id']
        asset_exam_id = request.form.get(f'exam_id_{asset_id}')
        asset_type = request.form.get(f'type_{asset_id}')
        grade = request.form.get(f'grade_{asset_id}')
        comments = request.form.get(f'comments_{asset_id}')
        update_asset(asset_id, asset_exam_id, asset_type, grade, comments)
            
    for exam in exams:
        try:
            exam_id = exam['exam_id']
            exam_grade = exam['grade']
            exam_date = exam['date']
            conn = get_db_connection()
            row = conn.execute('SELECT MAX(grade) AS worst_grade FROM assets WHERE exam_id = ?', (exam_id,)).fetchone()
            worst = row['worst_grade'] if row and row['worst_grade'] else None
            offset = ASSET_OFFSET_MONTHS.get(worst.upper(), 0) if worst else 0
            compliance_date = calculate_compliance_date(exam_grade, exam_date, offset)
            conn = get_db_connection()
            conn.execute('''
                UPDATE exams
                SET compliance_date = ?
                WHERE exam_id = ?
            ''', (compliance_date, exam_id))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f'{e} - error updating complaince date from assets')
            
    return redirect('/asset_data')



@app.route('/add_asset', methods=['POST'])
def add_asset():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    exam_id = request.form['exam_id']
    asset_type = request.form['type']
    grade = request.form['grade']
    comments = request.form['comments']

    conn = get_db_connection()
    reset_autoincrement(conn, 'assets', 'asset_id')
        
    conn.execute('INSERT INTO assets (exam_id, type, grade, comments) VALUES (?, ?, ?, ?)', (exam_id, asset_type, grade, comments))
    conn.commit()
    conn.close()
    return redirect(url_for('asset_data'))
 


@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
def delete_asset(asset_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM assets WHERE asset_id = ?', (asset_id,))
    conn.commit()
    conn.close()
    flash(f'Asset {asset_id} deleted successfully.')
    return redirect('/asset_data')  



#-------------------------------------------------------------------------------------------------------


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'User {user_id} deleted successfully.')
    return redirect('/user_data')  


def admin_status():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()

    # Get current user's admin status
    admin_status = conn.execute('SELECT admin FROM users WHERE user_id = ?', (session['user_id'],)).fetchone()
    conn.close()
    if admin_status['admin'] == 1:
        is_admin = True
    else:
        is_admin = False
        
    return is_admin


@app.route('/user_data')
def user_data():   
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    is_admin = admin_status()
    
    return render_template('user_data.html', email=session['email'], users=users, is_admin=is_admin)



def update_user(user_id, user_email, user_admin):
    conn = get_db_connection()
    conn.execute('''
        UPDATE users
        SET user_id = ?,
            email = ?,
            admin = ?
        WHERE user_id = ?
    ''', (user_id, user_email, user_admin, user_id))
    conn.commit()
    conn.close()



@app.route('/update_users', methods=['POST'])
def update_users():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()

    for user in users:  
        user_id = user['user_id']
        user_email = request.form.get(f'email_{user_id}')
        user_admin = request.form.get(f'admin_{user_id}')
          
        # Then update the DB using SQL or your ORM
        update_user(user_id, user_email, user_admin)
    return redirect('/user_data')





#-------------------------------------------------------------------------------------------------------


@app.route('/exam_data')
def exam_data():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    exams = conn.execute('SELECT * FROM exams').fetchall()

    raw_exams = conn.execute('''
        SELECT 
            exams.*,
            (SELECT COUNT(*) FROM assets WHERE assets.exam_id = exams.exam_id) AS asset_count
        FROM exams
    ''').fetchall()

    today = date.today()
    exams = []

    for row in raw_exams:
        exam = dict(row)  # Convert to mutable dictionary
        compliance_date = exam['compliance_date']
        if isinstance(compliance_date, str):
            compliance_date = date.fromisoformat(compliance_date)
        
        exam['is_compliant'] = today <= compliance_date
        exams.append(exam)

    # All route IDs
    all_routes = conn.execute('SELECT * FROM routes').fetchall()

    # Route IDs already assigned to exams
    used_ids = {exam['route_id'] for exam in exams}

    # Available route IDs only
    available_routes = [route for route in all_routes if route['route_id'] not in used_ids]

    # Build per-exam allowed route lists (own + unused)
    allowed_routes = {}
    for exam in exams:
        this_id = exam['exam_id']
        this_route = exam['route_id']
        used_except_self = used_ids - {this_route}

        allowed = [
            r for r in all_routes
            if r['route_id'] not in used_except_self
        ]
        allowed_routes[this_id] = allowed


    users = conn.execute('SELECT user_id, email FROM users').fetchall()
    routes = conn.execute('SELECT route_id, ELR FROM routes').fetchall()
    is_admin = admin_status()
    current_date = date.today().isoformat()
    return render_template('exam_data.html', email=session['email'], exams=exams, users=users, routes=routes, allowed_routes=allowed_routes, available_routes=available_routes, is_admin=is_admin, current_date=current_date)   



def update_exam(exam_id, user_id, route_id, grade, date, compliance_date):
    conn = get_db_connection()
    conn.execute('''
        UPDATE exams
        SET user_id = ?,
            route_id = ?,
            grade = ?,
            date = ?,
            compliance_date = ?
        WHERE exam_id = ?
    ''', (user_id, route_id, grade, date, compliance_date, exam_id))
    conn.commit()
    conn.close()



@app.route('/update_exams', methods=['POST'])
def update_exams():
    conn = get_db_connection()
    exams = conn.execute('SELECT * FROM exams').fetchall()

    for exam in exams:  
        exam_id = exam['exam_id']
        user_id = request.form.get(f'user_id_{exam_id}')
        route_id = request.form.get(f'route_id_{exam_id}')
        grade = request.form.get(f'grade_{exam_id}')
        date = request.form.get(f'date_{exam_id}')

        # Look up worst asset grade for this exam
        conn = get_db_connection()
        row = conn.execute(
            'SELECT MAX(grade) AS worst_grade FROM assets WHERE exam_id = ?', (exam_id,)
        ).fetchone()
        conn.close()
        worst = row['worst_grade'] if row and row['worst_grade'] else None
        offset = ASSET_OFFSET_MONTHS.get(worst.upper(), 0) if worst else 0
        
        try:
            compliance_date = calculate_compliance_date(grade, date, offset)
        except Exception as e:
            print(f'[update_exams] Error parsing dates or calculating compliance date for exam ID {exam_id}: {e}')
            compliance_date = date #None
            
        # Then update the DB using SQL
        update_exam(exam_id, user_id, route_id, grade, date, compliance_date)

    return redirect('/exam_data')  


@app.route('/add_exam', methods=['POST'])
def add_exam():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = int(request.form.get('user_id'))
    route = request.form['route']
    grade = request.form['grade']
    current_date = date.today().isoformat()
    compliance_date = calculate_compliance_date(grade, current_date)

    conn = get_db_connection()
    reset_autoincrement(conn, 'exams', 'exam_id')
    
    conn.execute('INSERT INTO exams (user_id, route_id, grade, date, compliance_date) VALUES (?, ?, ?, ?, ?)', (user_id, route, grade, current_date, compliance_date))
    conn.commit()
    conn.close()

    return redirect(url_for('exam_data'))



@app.route('/delete_exam/<int:exam_id>', methods=['POST'])
def delete_exam(exam_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM exams WHERE exam_id = ?', (exam_id,))
    conn.commit()
    conn.close()
    flash(f'User {exam_id} deleted successfully.')
    return redirect('/exam_data')






#-------------------------------------------------------------------------------------------------------


@app.route('/route_data')
def route_data():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    routes = conn.execute('SELECT * FROM routes').fetchall()
    conn.close()
    is_admin = admin_status()
    
    return render_template('route_data.html', routes=routes, is_admin=is_admin) 



@app.route('/delete_route/<int:route_id>', methods=['POST'])
def delete_route(route_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM routes WHERE route_id = ?', (route_id,))
    conn.commit()
    conn.close()
    flash(f'Route {route_id} deleted successfully.')
    return redirect('/route_data') 



def update_route(route_id, route_elr, route_start_mileage, route_end_mileage):
    conn = get_db_connection()
    conn.execute('''
        UPDATE routes
        SET elr = ?,
            start_mileage = ?,
            end_mileage = ?
        WHERE route_id = ?
    ''', (route_elr, route_start_mileage, route_end_mileage, route_id))
    conn.commit()
    conn.close()



@app.route('/update_routes', methods=['POST'])
def update_routes():
    conn = get_db_connection()
    routes = conn.execute('SELECT * FROM routes').fetchall()
    conn.close()

    for route in routes:  
        route_id = route['route_id']
        route_elr = request.form.get(f'elr_{route_id}')
        route_start_mileage = request.form.get(f'start_mileage_{route_id}')
        route_end_mileage = request.form.get(f'end_mileage_{route_id}')
          
        update_route(route_id, route_elr, route_start_mileage, route_end_mileage)
    return redirect('/route_data')




@app.route('/add_route', methods=['POST'])
def add_route():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    route_elr = request.form['elr']
    start_mileage = request.form['start_mileage']
    end_mileage = request.form['end_mileage']

    conn = get_db_connection()
    reset_autoincrement(conn, 'routes', 'route_id')
    
    conn.execute('INSERT INTO routes (elr, start_mileage, end_mileage) VALUES (?, ?, ?)', (route_elr, start_mileage, end_mileage))
    conn.commit()
    conn.close()

    return redirect(url_for('route_data'))




#-------------------------------------------------------------------------------------------------------



@app.route('/back')
def back():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT admin FROM users WHERE user_id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if user and user['admin'] == 1:
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('dashboard'))



#-------------------------------------------------------------------------------------------------------


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))




if __name__ == '__main__':
    app.run(debug=True)
















    

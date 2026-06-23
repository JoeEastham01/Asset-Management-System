from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from dateutil.relativedelta import relativedelta
import sqlite3
from datetime import datetime
from datetime import date
import re
import json


# Flask app setup
app = Flask(__name__)
app.secret_key = 'supersecretkey2f'  # SECURITY: Change this in production

# Password encryption
bcrypt = Bcrypt(app)


# Connects to the applications SQLite database
def get_db_connection():
    """Establish connection to SQLite database with foreign key constraints enabled"""
    conn = sqlite3.connect('database/RailAssetManagement.db')
    conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row
    return conn


# Grade to months mapping for compliance calculations
GRADE_MONTHS = {
    'A': 36, 'B': 30, 'C': 24, 'D': 18, 'E': 12, 'F': 6
}

# Asset offset months for adjusting compliance dates based on asset conditions
ASSET_OFFSET_MONTHS = {
    'A': 1, 'B': 2, 'C': 3, 'D': 4, 'E': 5, 'F': 6
}


def calculate_compliance_date(grade, exam_date_str, offset=None):
    """
    Calculate compliance date based on exam grade and optional asset offset
    
    Args:
        grade (str): Exam grade (A-F)
        exam_date_str (str): Exam date in YYYY-MM-DD format
        offset (int, optional): Months to subtract from compliance date
        
    Returns:
        date: Calculated compliance date or None if calculation fails
    """
    try:
        exam_date = datetime.strptime(exam_date_str, '%Y-%m-%d')
        months = GRADE_MONTHS.get(grade.upper())
        if months:
            compliance_date = exam_date + relativedelta(months=months)
            if offset:
                compliance_date = compliance_date - relativedelta(months=offset)
            return compliance_date.date()
    except Exception as e:
        print(f"Error calculating compliance date: {e}")
    return None


def reset_autoincrement(conn, table, id_column):
    """Reset table autoincrement sequence to match the highest existing ID"""
    cursor = conn.cursor()

    # Get the maximum ID from the table
    get_max_id = f'SELECT MAX({id_column}) FROM {table}'
    cursor.execute(get_max_id)
    max_id = cursor.fetchone()[0]
    if max_id is None:
        max_id = 0

    # Update the autoincrement sequence
    cursor.execute(
        "UPDATE sqlite_sequence SET seq = ? WHERE name = ?",
        (max_id, table)
    )
    conn.commit()


#-------------------------------------------------------------------------------------------------------
# AUTHENTICATION ROUTES
#-------------------------------------------------------------------------------------------------------


@app.route('/')
def home():
    """Application home page"""
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login function verifies credentials and redirects to appropriate dashboard"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        flash('') 

        # Check if user exists and password matches hashed password in DB
        if user and bcrypt.check_password_hash(user['password'], password): 
            session['user_id'] = user['user_id']
            session['email'] = user['email']
            session['name'] = user['name']

            # Redirect admins and regular users to their respective dashboards
            if user['admin'] == 1:  # FIX: Use == 1 instead of == True for consistency
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
    return render_template('login.html')

"""
More detailed error feedback to indicate if the password or email is incorrect,
is avoided to prevent giving clues to attackers about valid accounts.
"""


def validate_credentials_format(email, password, name):
    """
    Validate email and password format
    
    Args:
        name (str): name to validate
        email (str): Email address to validate
        password (str): Password to validate
        
    Returns:
        bool: True if both email and password are valid format
    """
    special_characters = r'[!@#$%^&*(),.?\":{}|<>]'
    is_valid = True  # FIX: Use more descriptive variable name

    # Email validation to check for '@' and accepted domains
    if '@' not in email:
        is_valid = False
        flash('Please enter a valid email address')
    elif '.com' not in email and '.co.uk' not in email:  # FIX: Combine conditions
        is_valid = False
        flash('Please enter a valid email address')
        
    if name.strip() == '':
        is_valid = False
        flash('Please enter name')
        
    # Password length and special character validation
    if len(password) < 5:
        is_valid = False
        flash('Please enter a password at least 5 characters long')  # FIX: Spelling
    elif not re.search(special_characters, password):
        is_valid = False
        flash('Password must contain at least one special character [!@#$%^&*(),.?\":{}|<>]')   

    return is_valid


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route for regular users"""
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        is_valid = validate_credentials_format(email, password, name)  # FIX: Use consistent variable name
    
        if is_valid:  # FIX: Remove unnecessary == True comparison
            try:
                conn = get_db_connection()
                reset_autoincrement(conn, 'users', 'user_id')
                conn.execute('INSERT INTO users (email, password, admin, name) VALUES (?, ?, ?, ?)', 
                           (email, hashed_pw, 0, name))
                conn.commit()
                conn.close()
                flash('Registration successful! Please log in.')  # ADD: Success message
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email already registered')

    return render_template('register.html') 

"""
Further validation could be included such as sending an email and generating a code
to confirm a valid address and then activate the account.
"""


@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    """Admin user registration route"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        name = request.form['name']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        # Get admin flag from form, default to 0 (non-admin)
        admin = int(request.form.get('admin', 0))

        is_valid = validate_credentials_format(email, password, name)  # FIX: Use consistent variable name

        if is_valid:  # FIX: Remove unnecessary == True comparison
            try:
                conn = get_db_connection()
                reset_autoincrement(conn, 'users', 'user_id')
                conn.execute('INSERT INTO users (email, password, admin, name) VALUES (?, ?, ?, ?)', 
                           (email, hashed_pw, admin, name))
                conn.commit()
                conn.close()
                flash('Admin registration successful! Please log in.')  # ADD: Success message
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Email already registered')

    return render_template('admin_register.html')


#-------------------------------------------------------------------------------------------------------
# DASHBOARD ROUTES
#-------------------------------------------------------------------------------------------------------


@app.route('/dashboard')
def dashboard():
    """Regular user dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session['email'], name=session['name'])


@app.route('/admin_dashboard')
def admin_dashboard():
    """Admin user dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html', email=session['email'], name=session['name'])


#-------------------------------------------------------------------------------------------------------
# ASSET MANAGEMENT ROUTES
#-------------------------------------------------------------------------------------------------------


def admin_status():
    """
    Check if current user is an admin
    
    Returns:
        bool: True if current user is admin, False otherwise
    """
    conn = get_db_connection()
    # FIX: Remove unused variable
    admin_result = conn.execute('SELECT admin FROM users WHERE user_id = ?', 
                               (session['user_id'],)).fetchone()
    conn.close()
    
    return admin_result and admin_result['admin'] == 1


@app.route('/asset_data')
def asset_data():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    search_query = request.args.get('search', '').strip()
    selected_elr = request.args.get('elr', 'AGY').strip() # Default to AGY elr to speed up the page loading speed

    conn = get_db_connection()

    # Fetch all ELRs for dropdown
    all_elrs = conn.execute("SELECT DISTINCT elr FROM routes ORDER BY elr").fetchall()

    # Fetch exams for dropdowns
    exams = conn.execute("SELECT exam_id FROM exams").fetchall()

    # Base query with joins so ELR is available
    base_query = """
        SELECT assets.*, routes.elr AS ELR
        FROM assets
        JOIN exams ON assets.exam_id = exams.exam_id
        JOIN routes ON exams.route_id = routes.route_id
        WHERE 1 = 1
    """

    params = []

    # Filter by asset_id search
    if search_query:
        base_query += " AND CAST(assets.asset_id AS TEXT) = ?"
        params.append(search_query.strip())

    # Filter by ELR dropdown
    if selected_elr:
        base_query += " AND routes.elr = ?"
        params.append(selected_elr)

    # Execute final query
    assets = conn.execute(base_query, params).fetchall()

    conn.close()
    is_admin = admin_status()

    return render_template(
        'asset_data.html',
        exams=exams,
        assets=assets,
        all_elrs=all_elrs,
        selected_elr=selected_elr,
        search_query=search_query,
        is_admin=is_admin
    )




def update_asset(asset_id, exam_id, asset_type, grade, comments):
    """Update asset record in database"""
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
    """Update all asset records and recalculate compliance dates"""
    conn = get_db_connection()
    assets = conn.execute('SELECT * FROM assets').fetchall()
    exams = conn.execute('SELECT * FROM exams').fetchall()
    conn.close()  # FIX: Close connection after fetching data
    
    # Update each asset
    for asset in assets:
        asset_id = asset['asset_id']
        asset_exam_id = request.form.get(f'exam_id_{asset_id}')
        asset_type = request.form.get(f'type_{asset_id}')
        grade = request.form.get(f'grade_{asset_id}')
        comments = request.form.get(f'comments_{asset_id}')
        if not asset_exam_id:
            continue # Handel where asset missing exam_id
        
        update_asset(asset_id, asset_exam_id, asset_type, grade, comments)
    
    # Recalculate compliance dates for all exams
    for exam in exams:
        try:
            exam_id = exam['exam_id']
            exam_grade = exam['grade']
            exam_date = exam['date']
            
            conn = get_db_connection()
            row = conn.execute('SELECT MAX(grade) AS worst_grade FROM assets WHERE exam_id = ?', 
                             (exam_id,)).fetchone()
            conn.close()  # FIX: Close connection after query
            
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
            print(f'{e} - error updating compliance date from assets')  # FIX: Spelling
            
    flash('Assets updated successfully!')  # ADD: Success message
    return redirect('/asset_data')


@app.route('/add_asset', methods=['POST'])
def add_asset():
    """Add a new asset to the database"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    exam_id = request.form['exam_id']
    asset_type = request.form['type']
    grade = request.form['grade']
    comments = request.form['comments']

    conn = get_db_connection()
    reset_autoincrement(conn, 'assets', 'asset_id') 
    conn.execute('INSERT INTO assets (exam_id, type, grade, comments) VALUES (?, ?, ?, ?)', 
                (exam_id, asset_type, grade, comments))
    conn.commit()
    conn.close()
    
    flash('Asset added successfully!')  # ADD: Success message
    return redirect(url_for('asset_data'))


@app.route('/delete_asset/<int:asset_id>', methods=['POST'])
def delete_asset(asset_id):
    """Delete asset record"""
    if 'user_id' not in session:  # ADD: Authentication check
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM assets WHERE asset_id = ?', (asset_id,))
    conn.commit()
    conn.close()
    flash(f'Asset {asset_id} deleted successfully.')
    return redirect('/asset_data')

"""
With foreign key constraints on the database, deleting an exam record will delete all associated assets,
and deleting a route will delete the associated exam. Cascade delete.
"""


#-------------------------------------------------------------------------------------------------------
# USER MANAGEMENT ROUTES
#-------------------------------------------------------------------------------------------------------


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    """Delete user record"""
    if 'user_id' not in session:  # ADD: Authentication check
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash(f'User {user_id} deleted successfully.')
    return redirect('/user_data')  


@app.route('/user_data')
def user_data():
    """User data management page"""
    if 'user_id' not in session:  # ADD: Authentication check
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    is_admin = admin_status()
    
    return render_template('user_data.html', email=session['email'], users=users, is_admin=is_admin)


def update_user(user_id, user_email, user_admin):
    """Update user record in database"""
    conn = get_db_connection()
    conn.execute('''
        UPDATE users
        SET email = ?,
            admin = ?
        WHERE user_id = ?
    ''', (user_email, user_admin, user_id))  # FIX: Remove redundant user_id assignment
    conn.commit()
    conn.close()


@app.route('/update_users', methods=['POST'])
def update_users():
    """Update all user records"""
    if 'user_id' not in session:  # ADD: Authentication check
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()

    for user in users:  
        user_id = user['user_id']
        user_email = request.form.get(f'email_{user_id}')
        user_admin = request.form.get(f'admin_{user_id}')
        user_admin = 1 if user_admin == 'on' else 0  # FIX: Handle checkbox values properly
          
        update_user(user_id, user_email, user_admin)
    
    flash('Users updated successfully!')  # ADD: Success message
    return redirect('/user_data')


#-------------------------------------------------------------------------------------------------------
# EXAM MANAGEMENT ROUTES
#-------------------------------------------------------------------------------------------------------


@app.route('/exam_data')
def exam_data():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()

    search = request.args.get('search', '').strip()
    selected_elr = request.args.get('elr', 'AGY').strip() # Default to AGY elr to speed up the page loading speed

    exams = []
    allowed_routes = {}
    available_routes = []

    # Load ELRs for dropdown
    all_elrs = conn.execute('''
        SELECT DISTINCT elr
        FROM routes
        WHERE elr IS NOT NULL AND elr != ''
        ORDER BY elr
    ''').fetchall()

    # Build route filter (ONLY ELR now)
    route_query = '''
        SELECT route_id
        FROM routes
        WHERE 1=1
    '''
    params = []

    if selected_elr:
        route_query += ' AND elr = ?'
        params.append(selected_elr)

    route_matches = conn.execute(route_query, params).fetchall()
    route_ids = [r['route_id'] for r in route_matches]

    # Build exam query
    if route_ids:
        # Added direct column references for real route track properties
        exam_query = f'''
            SELECT
                exams.*,
                routes.bid,
                routes.description AS route_desc,
                routes.route_type AS route_kind,
                routes.speedband AS route_speed,
                (SELECT COUNT(*)
                 FROM assets
                 WHERE assets.exam_id = exams.exam_id) AS asset_count
            FROM exams
            INNER JOIN routes ON exams.route_id = routes.route_id
            WHERE exams.route_id IN ({','.join(['?'] * len(route_ids))})
        '''

        exam_params = route_ids

        # SEARCH NOW ONLY TARGETS exam_id
        if search:
            exam_query += ' AND CAST(exams.exam_id AS TEXT) = ?'
            exam_params.append(search)

        exam_query += ' LIMIT 100'

        raw_exams = conn.execute(exam_query, exam_params).fetchall()

        today = date.today()

        for row in raw_exams:
            exam = dict(row)

            compliance_date = exam['compliance_date']
            if isinstance(compliance_date, str):
                compliance_date = date.fromisoformat(compliance_date)

            exam['is_compliant'] = (
                compliance_date is not None and today <= compliance_date
            )

            exams.append(exam)

        # route + permissions logic
        all_routes = conn.execute('SELECT * FROM routes').fetchall()
        used_ids = {exam['route_id'] for exam in exams}

        available_routes = [
            r for r in all_routes
            if r['route_id'] not in used_ids
        ]

        allowed_routes = {}

        for exam in exams:
            this_id = exam['exam_id']
            this_route = exam['route_id']

            used_except_self = used_ids - {this_route}

            allowed_routes[this_id] = [
                r for r in all_routes
                if r['route_id'] not in used_except_self
            ]

    # Always available
    users = conn.execute('SELECT user_id, email FROM users').fetchall()
    routes = conn.execute('SELECT route_id, elr FROM routes').fetchall()

    conn.close()

    is_admin = admin_status()
    current_date = date.today().isoformat()

    return render_template(
        'exam_data.html',
        email=session['email'],
        exams=exams,
        users=users,
        routes=routes,
        all_elrs=all_elrs,
        selected_elr=selected_elr,
        allowed_routes=allowed_routes,
        available_routes=available_routes,
        is_admin=is_admin,
        current_date=current_date
    )



def update_exam(exam_id, user_id, route_id, grade, date, compliance_date):
    """Update exam record in database"""
    conn = get_db_connection()
    conn.execute('''
        UPDATE exams
        SET user_id = ?,
            route_id = ?,
            grade = ?,
            exam_date = ?,
            compliance_date = ?
        WHERE exam_id = ?
    ''', (user_id, route_id, grade, date, compliance_date, exam_id))
    conn.commit()
    conn.close()


@app.route('/update_exams', methods=['POST'])
def update_exams():
    """Update all exam records and recalculate compliance dates"""
    if 'user_id' not in session:  # ADD: Authentication check
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    exams = conn.execute('SELECT * FROM exams').fetchall()
    conn.close()  # FIX: Close connection after fetching data

    for exam in exams:  
        exam_id = exam['exam_id']
        user_id = request.form.get(f'user_id_{exam_id}')
        route_id = request.form.get(f'route_id_{exam_id}')
        grade = request.form.get(f'grade_{exam_id}')
        exam_date = request.form.get(f'date_{exam_id}')
        if route_id is None:
            continue

        # Look up worst asset grade for this exam
        conn = get_db_connection()
        row = conn.execute(
            'SELECT MAX(grade) AS worst_grade FROM assets WHERE exam_id = ?', (exam_id,)
        ).fetchone()
        conn.close()
        
        worst = row['worst_grade'] if row and row['worst_grade'] else None
        offset = ASSET_OFFSET_MONTHS.get(worst.upper(), 0) if worst else 0
        
        try:
            compliance_date = calculate_compliance_date(grade, exam_date, offset)
        except Exception as e:
            print(f'[update_exams] Error calculating compliance date for exam ID {exam_id}: {e}')
            compliance_date = None  # FIX: Set to None instead of date string
            
        today = date.today()
         
        if compliance_date:
            status = 'Compliant' if today <= compliance_date else 'Non-Compliant'
        else:
            status = 'Non-Compliant'
            
        if not route_id:
            print(f"Missing route_id for exam {exam_id}")
            print(request.form)
            continue            
                     
        update_exam(exam_id, user_id, route_id, grade, exam_date, compliance_date)        

    flash('Exams updated successfully!')  # ADD: Success message
    return redirect('/exam_data')  


@app.route('/add_exam', methods=['POST'])
def add_exam():
    """Add a new exam record"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = int(request.form.get('user_id'))
    route = request.form['route']
    grade = request.form['grade']
    current_date = date.today().isoformat()
    compliance_date = calculate_compliance_date(grade, current_date)

    conn = get_db_connection()
    reset_autoincrement(conn, 'exams', 'exam_id')
    conn.execute('INSERT INTO exams (user_id, route_id, grade, exam_date, compliance_date) VALUES (?, ?, ?, ?, ?)', 
                (user_id, route, grade, current_date, compliance_date))
    conn.commit()
    conn.close()

    flash('Exam added successfully!')  # ADD: Success message
    return redirect(url_for('exam_data'))


@app.route('/delete_exam/<int:exam_id>', methods=['POST'])
def delete_exam(exam_id):
    """Delete exam record"""
    if 'user_id' not in session:  # ADD: Authentication check
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM exams WHERE exam_id = ?', (exam_id,))
    conn.commit()
    conn.close()
    flash(f'Exam {exam_id} deleted successfully.')  # FIX: Change "User" to "Exam"
    return redirect('/exam_data')
    



@app.route('/track_section_record')
def track_section_record():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    # 1. Pull metadata from URL arguments
    bid = request.args.get('bid', 'Unknown Track')
    description = request.args.get('description', 'Unknown Track')
    route_type = request.args.get('route_type', 'Unknown')
    speedband = request.args.get('speedband', 'Unknown')
    route_id = request.args.get('ogr_fid', None) # Read the database identifier

    # 2. Query the DB using the track identifier if available
    exam_record = None
    if route_id:
        conn = get_db_connection()
        exam_record = conn.execute('SELECT * FROM exams WHERE route_id = ?', (route_id,)).fetchone()
        conn.close()

    # 3. Fallback safely using valid sqlite3.Row bracket notation
    if exam_record:
        try:
            examiner = exam_record['examiner']
        except (IndexError, KeyError):
            examiner = exam_record['user_id'] if 'user_id' in exam_record.keys() else "Assigned Staff"

        try:
            exam_date = exam_record['exam_date']
        except (IndexError, KeyError):
            exam_date = exam_record['date'] if 'date' in exam_record.keys() else "N/A"

        compliance_date = exam_record['compliance_date']
        grade = exam_record['grade']
    else:
        examiner = "No Active Record"
        exam_date = "N/A"
        compliance_date = "N/A"
        grade = "N/A"

    # 4. Optional: Update session variables if your app tracking needs them
    session['examiner'] = examiner
    session['exam_date'] = exam_date
    session['compliance_date'] = compliance_date
    session['grade'] = grade
    
    return render_template(
        'track_section_record.html', 
        bid=bid, 
        description=description, 
        route_type=route_type, 
        speedband=speedband,
        examiner=examiner, 
        exam_date=exam_date, 
        compliance_date=compliance_date, 
        grade=grade
    )

    

#-------------------------------------------------------------------------------------------------------
# ROUTE MANAGEMENT ROUTES
#-------------------------------------------------------------------------------------------------------


@app.route('/route_data')
def route_data():
    """Route data overview page with search and ELR filter capabilities"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get parameters from the URL
    search_query = request.args.get('search', '').strip()
    selected_elr = request.args.get('elr', 'AGY').strip()
    
    conn = get_db_connection()
    
    # 1. Fetch all unique ELRs to populate the dropdown menu dynamically
    all_elrs = conn.execute('SELECT DISTINCT elr FROM routes WHERE elr IS NOT NULL AND elr != "" ORDER BY elr').fetchall()
    
    # 2. Build dynamic SQL query based on filters
    query = "SELECT * FROM routes WHERE 1=1"
    params = []
    
    if search_query:
        query += " AND route_id LIKE ?"
        params.append(f"%{search_query}%")
        
    if selected_elr:
        query += " AND elr = ?"
        params.append(selected_elr)
        
    routes = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    
    is_admin = admin_status()
    
    # Pass everything down to the template
    return render_template(
        'route_data.html', 
        routes=routes, 
        is_admin=is_admin, 
        search_query=search_query,
        all_elrs=all_elrs,
        selected_elr=selected_elr
    )


@app.route('/delete_route/<int:route_id>', methods=['POST'])
def delete_route(route_id):
    """Delete route record"""
    if 'user_id' not in session:  # ADD: Authentication check
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    conn.execute('DELETE FROM routes WHERE route_id = ?', (route_id,))
    conn.commit()
    conn.close()
    
    delete_route_from_geojson(route_id) # testing
    
    flash(f'Route {route_id} deleted successfully.')
    return redirect('/route_data') 


def update_route(route_id, route_elr, route_start_mileage, route_end_mileage):
    """Update route record in database"""
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
    """Update all route records"""
    if 'user_id' not in session:  # ADD: Authentication check
        return redirect(url_for('login'))
        
    conn = get_db_connection()
    routes = conn.execute('SELECT * FROM routes').fetchall()
    conn.close()

    for route in routes:  
        route_id = route['route_id']
        route_elr = request.form.get(f'elr_{route_id}')
        route_start_mileage = request.form.get(f'start_mileage_{route_id}')
        route_end_mileage = request.form.get(f'end_mileage_{route_id}')
          
        update_route(route_id, route_elr, route_start_mileage, route_end_mileage)
    
    flash('Routes updated successfully!')  # ADD: Success message
    return redirect('/route_data')


@app.route('/add_route', methods=['POST'])
def add_route():
    """Add new route record"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    route_elr = request.form['elr']
    start_mileage = request.form['start_mileage']
    end_mileage = request.form['end_mileage']

    conn = get_db_connection()
    reset_autoincrement(conn, 'routes', 'route_id')
    conn.execute('INSERT INTO routes (elr, start_mileage, end_mileage) VALUES (?, ?, ?)', 
                (route_elr, start_mileage, end_mileage))
    conn.commit()
    conn.close()

    flash('Route added successfully!')  # ADD: Success message
    return redirect(url_for('route_data'))
    
    
def delete_route_from_geojson(route_id):
    file_path = 'north_east_small.geojson'

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)

        # Filter out the route
        filtered_features = [
            feature for feature in data['features']
            if feature['properties'].get('route_id') != route_id
        ]

        data['features'] = filtered_features

        # Save back to file
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)

    except Exception as e:
        print(f"Error updating GeoJSON: {e}")    
    


#-------------------------------------------------------------------------------------------------------
# UTILITY ROUTES
#-------------------------------------------------------------------------------------------------------


@app.route('/back')
def back():
    """Navigate back to appropriate dashboard based on user role"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT admin FROM users WHERE user_id = ?', (session['user_id'],)).fetchone()
    conn.close()

    if user and user['admin'] == 1:
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    """Clear user session and redirect to home"""
    session.clear()
    flash('You have been logged out successfully.')  # ADD: Logout message
    return redirect(url_for('home'))


# Run the application
if __name__ == '__main__':
    app.run(debug=True)

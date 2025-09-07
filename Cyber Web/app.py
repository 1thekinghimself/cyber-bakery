import os
import json
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'cyberweb-secret-key-2023'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Enhanced session configuration
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600
)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database functions
def init_databases():
    databases = ['products', 'sections', 'click_logs', 'payment_receipts', 'access_codes', 'admins', 'wallets', 'site_settings']
    for db in databases:
        if not os.path.exists(f'{db}.json'):
            with open(f'{db}.json', 'w') as f:
                if db == 'site_settings':
                    json.dump({}, f)
                else:
                    json.dump([], f)

    # Default site settings
    site_settings = load_data('site_settings')
    if not site_settings or site_settings == {}:
        site_settings = {
            "site_name": "CYBER WEB",
            "site_description": "Digital products for the cyberpunk enthusiast"
        }
        save_data('site_settings', site_settings)

    # Default wallets
    wallets = load_data('wallets')
    if not wallets:
        wallets = [
            {"id": 1, "name": "Bitcoin", "address": "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", "active": True},
            {"id": 2, "name": "Ethereum", "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "active": True},
            {"id": 3, "name": "Litecoin", "address": "LTpYZG15YJ9XhVLMQkK2kS5yFcM2U4cEoN", "active": True},
            {"id": 4, "name": "Monero", "address": "48jiWwqY5x2J2yC3RnJmT2sL3jJ5J2J2J2J2J2J2J2J2J2J2J2J2J2J2J2J2", "active": True}
        ]
        save_data('wallets', wallets)

    # Default products
    products = load_data('products')
    if not products:
        products = [
            {"id": 1, "name": "Layer Codecake", "description": "A multi-layered code solution for your cyber needs", "image": "codecake.jpg", "price": "$1000-50000", "requires_access": False},
            {"id": 2, "name": "The Ledger", "description": "Secure transaction tracking system", "image": "ledger.jpg", "price": "$2000", "requires_access": True},
            {"id": 3, "name": "Dough Factory", "description": "Generate digital assets with our factory", "image": "dough.jpg", "price": "$3500", "requires_access": True},
            {"id": 4, "name": "Cookie Jar", "description": "Store your digital cookies securely", "image": "cookiejar.jpg", "price": "$1500", "requires_access": True},
            {"id": 5, "name": "Breadwinner", "description": "Maximize your crypto earnings", "image": "breadwinner.jpg", "price": "$5000", "requires_access": True}
        ]
        save_data('products', products)

    # Default sections
    sections = load_data('sections')
    if not sections:
        sections = [
            {"id": 1, "product_id": 1, "name": "Codecake 2.0", "price_range": "$1000-5000"},
            {"id": 2, "product_id": 1, "name": "Codecake 3.0", "price_range": "$5000-10000"},
            {"id": 3, "product_id": 1, "name": "Codecake X", "price_range": "$10000-50000"}
        ]
        save_data('sections', sections)

    # Default access codes
    access_codes = load_data('access_codes')
    if not access_codes:
        access_codes = [
            {"id": 1, "product_id": 2, "code": "LEDGER2023", "description": "Access code for The Ledger"},
            {"id": 2, "product_id": 3, "code": "DOUGHFACTORY", "description": "Access code for Dough Factory"},
            {"id": 3, "product_id": 4, "code": "COOKIEJAR", "description": "Access code for Cookie Jar"},
            {"id": 4, "product_id": 5, "code": "BREADWINNER", "description": "Access code for Breadwinner"}
        ]
        save_data('access_codes', access_codes)

    # Default admin accounts
    admins = load_data('admins')
    if not admins:
        admins = [
            {"id": str(uuid.uuid4()), "username": "cyberadmin", "password": hash_password("cyber12345")},
            {"id": str(uuid.uuid4()), "username": "introvert", "password": hash_password("skii12345")}
        ]
        save_data('admins', admins)

def load_data(filename):
    try:
        with open(f'{filename}.json', 'r') as f:
            data = json.load(f)
            if filename == 'site_settings':
                if isinstance(data, list) and len(data) > 0:
                    return data[0]
                elif isinstance(data, dict):
                    return data
                return {"site_name": "CYBER WEB", "site_description": "Digital products for the cyberpunk enthusiast"}
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        if filename == 'site_settings':
            return {"site_name": "CYBER WEB", "site_description": "Digital products for the cyberpunk enthusiast"}
        return []

def save_data(filename, data):
    with open(f'{filename}.json', 'w') as f:
        if filename == 'site_settings' and isinstance(data, dict):
            json.dump(data, f, indent=4)
        else:
            json.dump(data, f, indent=4)

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(hashed_password, user_password):
    try:
        return bcrypt.checkpw(user_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except:
        return False

def log_click(product_id):
    click_logs = load_data('click_logs')
    click_logs.append({
        "id": str(uuid.uuid4()),
        "product_id": product_id,
        "ip_address": request.remote_addr,
        "timestamp": datetime.now().isoformat()
    })
    save_data('click_logs', click_logs)

def check_access_code(product_id, code):
    access_codes = load_data('access_codes')
    for access_code in access_codes:
        if access_code['product_id'] == product_id and access_code['code'] == code:
            return True
    return False

# Initialize databases
init_databases()

# Debug routes
@app.route('/debug/session')
def debug_session():
    return jsonify({
        'admin_id': session.get('admin_id'),
        'admin_username': session.get('admin_username'),
        'session_keys': list(session.keys())
    })

@app.route('/debug/admins')
def debug_admins():
    admins = load_data('admins')
    safe_admins = [{'id': a['id'], 'username': a['username']} for a in admins]
    return jsonify(safe_admins)

@app.route('/debug/test-auth')
def debug_test_auth():
    test_username = "cyberadmin"
    test_password = "cyber12345"
    
    admins = load_data('admins')
    admin = next((a for a in admins if a['username'] == test_username), None)
    
    if admin:
        password_match = check_password(admin['password'], test_password)
        return jsonify({
            'admin_found': True,
            'password_match': password_match,
            'hashed_password': admin['password'][:20] + '...' if admin['password'] else None
        })
    else:
        return jsonify({'admin_found': False})

# Main routes
@app.route('/')
def index():
    try:
        products = load_data('products')
        site_settings = load_data('site_settings')
        return render_template('index.html', products=products, site_settings=site_settings)
    except Exception as e:
        return f"Error loading page: {str(e)}", 500

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    try:
        site_settings = load_data('site_settings')
        
        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            if not username or not password:
                return render_template('login.html', error='Username and password are required', site_settings=site_settings)
            
            admins = load_data('admins')
            admin = next((a for a in admins if a['username'] == username), None)
            
            if admin and check_password(admin['password'], password):
                session['admin_id'] = admin['id']
                session['admin_username'] = admin['username']
                session.permanent = True
                return redirect(url_for('admin'))
            else:
                return render_template('login.html', error='Invalid credentials', site_settings=site_settings)
        
        return render_template('login.html', site_settings=site_settings)
    except Exception as e:
        site_settings = load_data('site_settings')
        return render_template('login.html', error=f'Server error during login: {str(e)}', site_settings=site_settings)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin')
def admin():
    try:
        if 'admin_id' not in session:
            return redirect(url_for('admin_login'))

        products = load_data('products')
        sections = load_data('sections')
        click_logs = load_data('click_logs')
        receipts = load_data('payment_receipts')
        access_codes = load_data('access_codes')
        wallets = load_data('wallets')
        site_settings = load_data('site_settings')

        # Enhance data for display
        enhanced_logs = []
        for log in click_logs:
            product = next((p for p in products if p['id'] == log['product_id']), None)
            enhanced_logs.append({
                **log,
                "product_name": product['name'] if product else "Unknown"
            })

        enhanced_receipts = []
        for receipt in receipts:
            section = next((s for s in sections if s['id'] == receipt['section_id']), None)
            product = next((p for p in products if p['id'] == section['product_id']), None) if section else None
            
            enhanced_receipts.append({
                **receipt,
                "section_name": section['name'] if section else "Unknown",
                "product_name": product['name'] if product else "Unknown"
            })

        return render_template('admin.html',
                              products=products, 
                              sections=sections, 
                              click_logs=enhanced_logs, 
                              receipts=enhanced_receipts,
                              access_codes=access_codes,
                              wallets=wallets,
                              site_settings=site_settings)
    except Exception as e:
        site_settings = load_data('site_settings')
        return render_template('error.html', error_message=f"Admin panel error: {str(e)}", site_settings=site_settings)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    try:
        log_click(product_id)
        products = load_data('products')
        product = next((p for p in products if p['id'] == product_id), None)
        site_settings = load_data('site_settings')

        if not product:
            return "Product not found", 404

        access_codes = load_data('access_codes')
        requires_access = any(ac['product_id'] == product_id for ac in access_codes)

        if requires_access and not session.get(f'access_granted_{product_id}'):
            return render_template('access_required.html', product=product, site_settings=site_settings)

        if product_id == 1:
            sections = load_data('sections')
            product_sections = [s for s in sections if s['product_id'] == product_id]
            return render_template('product_detail.html', product=product, sections=product_sections, site_settings=site_settings)

        if product_id == 2:
            return render_template('product_ledger.html', product=product, site_settings=site_settings)

        return render_template('product_detail.html', product=product, site_settings=site_settings)
    except Exception as e:
        return f"Product detail error: {str(e)}", 500

@app.route('/verify_access', methods=['POST'])
def verify_access():
    try:
        product_id = int(request.form.get('product_id', 0))
        access_code = request.form.get('access_code', '')
        
        if check_access_code(product_id, access_code):
            session[f'access_granted_{product_id}'] = True
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Invalid access code'})
    except:
        return jsonify({'success': False, 'error': 'Invalid request'})

@app.route('/payment/<int:section_id>')
def payment(section_id):
    try:
        sections = load_data('sections')
        section = next((s for s in sections if s['id'] == section_id), None)
        
        if not section:
            return "Section not found", 404
        
        products = load_data('products')
        product = next((p for p in products if p['id'] == section['product_id']), None)
        wallets = [w for w in load_data('wallets') if w.get('active', True)]
        site_settings = load_data('site_settings')
        
        return render_template('payment.html', section=section, product=product, wallets=wallets, site_settings=site_settings)
    except Exception as e:
        return f"Payment error: {str(e)}", 500

@app.route('/upload_receipt', methods=['POST'])
def upload_receipt():
    try:
        if 'receipt' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'})
        
        file = request.files['receipt']
        section_id = request.form.get('section_id', '')
        customer_email = request.form.get('customer_email', 'anonymous')
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if file:
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(filepath)
            
            receipts = load_data('payment_receipts')
            receipts.append({
                "id": str(uuid.uuid4()),
                "customer_email": customer_email,
                "section_id": int(section_id),
                "file_path": unique_filename,
                "ip_address": request.remote_addr,
                "timestamp": datetime.now().isoformat()
            })
            save_data('payment_receipts', receipts)
            
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Receipt management routes
@app.route('/admin/view_receipt/<receipt_id>')
def view_receipt(receipt_id):
    if 'admin_id' not in session:
        return redirect(url_for('admin_login'))
    
    try:
        receipts = load_data('payment_receipts')
        receipt = next((r for r in receipts if r['id'] == receipt_id), None)
        
        if not receipt:
            return "Receipt not found", 404
        
        return send_from_directory(app.config['UPLOAD_FOLDER'], receipt['file_path'])
    except Exception as e:
        return f"Error viewing receipt: {str(e)}", 500

@app.route('/admin/delete_receipt/<receipt_id>', methods=['POST'])
def delete_receipt(receipt_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        receipts = load_data('payment_receipts')
        receipt = next((r for r in receipts if r['id'] == receipt_id), None)
        
        if receipt:
            # Delete the file from uploads folder
            if receipt.get('file_path'):
                try:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], receipt['file_path'])
                    if os.path.exists(file_path):
                        os.remove(file_path)
                except:
                    pass
            
            # Remove from database
            receipts = [r for r in receipts if r['id'] != receipt_id]
            save_data('payment_receipts', receipts)
            
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Receipt not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Admin CRUD operations
@app.route('/admin/add_product', methods=['POST'])
def add_product():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        name = request.form.get('name', '')
        description = request.form.get('description', '')
        image = request.form.get('image', '')
        price = request.form.get('price', '')
        requires_access = request.form.get('requires_access') == 'on'
        
        products = load_data('products')
        new_id = max(p['id'] for p in products) + 1 if products else 1
        
        products.append({
            "id": new_id,
            "name": name,
            "description": description,
            "image": image,
            "price": price,
            "requires_access": requires_access
        })
        
        save_data('products', products)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        products = [p for p in load_data('products') if p['id'] != product_id]
        save_data('products', products)
        
        sections = [s for s in load_data('sections') if s['product_id'] != product_id]
        save_data('sections', sections)
        
        access_codes = [ac for ac in load_data('access_codes') if ac['product_id'] != product_id]
        save_data('access_codes', access_codes)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/add_section', methods=['POST'])
def add_section():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        product_id = int(request.form.get('product_id', 0))
        name = request.form.get('name', '')
        price_range = request.form.get('price_range', '')
        
        sections = load_data('sections')
        new_id = max(s['id'] for s in sections) + 1 if sections else 1
        
        sections.append({
            "id": new_id,
            "product_id": product_id,
            "name": name,
            "price_range": price_range
        })
        
        save_data('sections', sections)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/delete_section/<int:section_id>', methods=['POST'])
def delete_section(section_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        sections = [s for s in load_data('sections') if s['id'] != section_id]
        save_data('sections', sections)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/add_access_code', methods=['POST'])
def add_access_code():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        product_id = int(request.form.get('product_id', 0))
        code = request.form.get('code', '')
        description = request.form.get('description', '')
        
        access_codes = load_data('access_codes')
        new_id = max(ac['id'] for ac in access_codes) + 1 if access_codes else 1
        
        access_codes.append({
            "id": new_id,
            "product_id": product_id,
            "code": code,
            "description": description
        })
        
        save_data('access_codes', access_codes)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/delete_access_code/<int:code_id>', methods=['POST'])
def delete_access_code(code_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        access_codes = [ac for ac in load_data('access_codes') if ac['id'] != code_id]
        save_data('access_codes', access_codes)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/add_wallet', methods=['POST'])
def add_wallet():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        name = request.form.get('name', '')
        address = request.form.get('address', '')
        
        wallets = load_data('wallets')
        new_id = max(w['id'] for w in wallets) + 1 if wallets else 1
        
        wallets.append({
            "id": new_id,
            "name": name,
            "address": address,
            "active": True
        })
        
        save_data('wallets', wallets)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/delete_wallet/<int:wallet_id>', methods=['POST'])
def delete_wallet(wallet_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        wallets = [w for w in load_data('wallets') if w['id'] != wallet_id]
        save_data('wallets', wallets)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/toggle_wallet/<int:wallet_id>', methods=['POST'])
def toggle_wallet(wallet_id):
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        wallets = load_data('wallets')
        for wallet in wallets:
            if wallet['id'] == wallet_id:
                wallet['active'] = not wallet.get('active', True)
                break
        save_data('wallets', wallets)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/admin/update_settings', methods=['POST'])
def update_settings():
    if 'admin_id' not in session:
        return jsonify({'success': False, 'error': 'Access denied'})
    
    try:
        site_settings = {
            "site_name": request.form.get('site_name'),
            "site_description": request.form.get('site_description')
        }
        save_data('site_settings', site_settings)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
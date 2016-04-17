# -*- coding: utf-8 -*-

"""
Hades IOC Scanner
2015 Molnár Marell
"""

import os
import datetime
import bcrypt
from sqlite3 import dbapi2 as sqlite3
from simplecrypt import encrypt, decrypt
from flask import Flask, request, session, g, redirect, url_for, abort, render_template, flash, send_from_directory
from werkzeug import secure_filename

from stixparser import parse

app = Flask(__name__)
    
"""bcrypt.hashpw('password',bcrypt.gensalt())"""
app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'hades.db'),
    DEBUG=True,
    SECRET_KEY='fbviefrvinefrvneinveirnvpienmvienmrvpoimrepoivnme',
    USERNAME='admin',
    PASSWORDHASH="$2a$12$27ZnMTay3iKfkMVN6kNzJ.g0ShNZgXn1RfLLyndWWPB1wtXgayWeq",
    PASSWORD="",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    ALLOWED_EXTENSIONS = set(['stix', 'ioc', 'xml']),
    UPLOAD_FOLDER = 'iocfiles',
    SCAN_FOLDER = 'scanfiles'
))
app.config.from_envvar('HADES_SETTINGS', silent=True)

def connect_db():
    """Csatlakozás az adatbázishoz."""
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv

def get_db():
    """Adatbázis kapcsolat lekérése a request kezdetekor."""
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

def init_db():
    """Adatbázis létrehozása eljárás."""
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

@app.cli.command('initdb')
def initdb_command():
    """Adatbázist létrehozó parancs."""
    init_db()
    print('Adatbázis létrehozva.')

@app.teardown_appcontext
def close_db(error):
    """Lezárja az adatbáziskapcsolatot a request végén."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def main():
    """Gyökér útvonal."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    else:
        return redirect(url_for('scans'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != app.config['USERNAME']:
            error = 'Érvénytelen felhasználónév vagy jelszó'
        elif bcrypt.hashpw(request.form['password'], app.config['PASSWORDHASH']) != app.config['PASSWORDHASH']:
            error = 'Érvénytelen felhasználónév vagy jelszó'
        else:
            session['logged_in'] = True
            app.config['PASSWORD'] = request.form['password']
            flash('Sikeres belépés')
            return redirect(url_for('scans'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('login'))

@app.route('/scans')
def scans():
    """Lefuttatott keresések listázása."""
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    cur = db.execute('select id, name, date, lastrun from scans order by date')
    scans = cur.fetchall()
    return render_template('list_scans.html', scans=scans)

@app.route('/showscan')
def showscan():
    if not session.get('logged_in'):
        abort(401)
    id = request.args.get('id')
    db = get_db()
    cur = db.execute('select name, date, lastrun, report from scans where id=?', id)
    scan = cur.fetchone()
    cur_hosts = db.execute('select hostid, name from scanshosts JOIN hosts ON hosts.id=scanshosts.hostid where scanshosts.scanid=? order by hostid', id)
    cur_iocs = db.execute('select iocid, name from scansiocs JOIN iocs ON iocs.id=scansiocs.iocid where scansiocs.scanid=? order by iocid', id)
    iocs = cur_iocs.fetchall()
    hosts = cur_hosts.fetchall()
    return render_template('showscan.html', scan=scan, hosts=hosts, iocs=iocs)

@app.route('/createscan')
def createscan():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    cur_hosts = db.execute('select id, name from hosts order by id')
    cur_iocs = db.execute('select id, name from iocs order by id')
    iocs = cur_iocs.fetchall()
    hosts = cur_hosts.fetchall()
    return render_template('createscan.html', hosts=hosts, iocs=iocs)

@app.route('/addscan', methods=['POST'])
def addscan():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    db.execute('insert into scans values (NULL,?,?,NULL,NULL)',
               [request.form['title'], str(datetime.datetime.now())])
    db.commit()
    cur = db.execute('SELECT max(id) FROM scans')
    id = cur.fetchone()[0]
    for iocid in request.values.getlist('selectediocs'):
        db.execute('insert into scansiocs values (NULL,?,?)',
               [id, iocid])
    for hostid in request.values.getlist('selectedhosts'):
        db.execute('insert into scanshosts values (NULL,?,?)',
               [id, hostid])
    db.commit()
    return redirect(url_for('scans'))

@app.route('/hosts')
def hosts():
    """Rendelkezésre álló munkaállomások listája."""
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    cur = db.execute('select id, name, address from hosts order by name')
    hosts = cur.fetchall()
    return render_template('list_hosts.html', hosts=hosts)

@app.route('/showhost')
def showhost():
    if not session.get('logged_in'):
        abort(401)
    id = request.args.get('id')
    db = get_db()
    cur = db.execute('select password from hosts where id=?', id)
    host = cur.fetchone()
    password = decrypt(app.config['PASSWORD'], host[0].decode("hex"))
    cur = db.execute('select id, name, address, port, type, username, "?" from hosts where id=?', id)
    host = cur.fetchone()
    return render_template('showhost.html', host=host, password=password)

@app.route('/createhost')
def createhost():
    if not session.get('logged_in'):
        abort(401)
    return render_template('createhost.html')

@app.route('/addhost', methods=['POST'])
def addhost():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    db.execute('insert into hosts values (NULL,?,?,?,?,?,?)',
               [request.form['name'], request.form['address'], request.form['port'], request.form['type'], request.form['username'], ''.join(x.encode('hex') for x in encrypt(app.config['PASSWORD'], request.form['password']))])
    db.commit()
    return redirect(url_for('hosts'))

@app.route('/iocs')
def iocs():
    """Rendelkezésre álló ioc állományok listája."""
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    cur = db.execute('select id, name, date from iocs order by date')
    iocs = cur.fetchall()
    return render_template('list_iocs.html', iocs=iocs)

@app.route('/showioc')
def showioc():
    if not session.get('logged_in'):
        abort(401)
    id = request.args.get('id')
    db = get_db()
    print id
    cur = db.execute('select name, date, file from iocs where id=?', (id,))
    ioc = cur.fetchone()
    report = open(os.path.join(app.config['SCAN_FOLDER'], ioc[0], "report.log"), 'r').readlines()
    scanfile = open(os.path.join(app.config['SCAN_FOLDER'], ioc[0], "scan.json"), 'r').readlines()
    """Html-e konvertálás..."""
    scanfile.remove(scanfile[0])
    scanfile.remove(scanfile[0])
    scanreadable = []
    for x in scanfile:
        if not "observable_composition" in x and not "observables" in x:
            line = x.replace("{", "").replace("}","").replace("[", "").replace("]", "").replace("\n", "").replace(",","").replace('\"', " ")
            if line.strip():
                scanreadable.append(line.replace("\t","-").replace("    ","----")[24:])
    return render_template('showioc.html', ioc=ioc, report=report, scanreadable = scanreadable, id=id)

@app.route('/exportioc')
def exportioc():
    if not session.get('logged_in'):
        abort(401)
    id = request.args.get('id')
    db = get_db()
    cur = db.execute('select name, date, file from iocs where id=?', (id,))
    ioc = cur.fetchone()
    return send_from_directory(directory=os.path.join(app.config['SCAN_FOLDER'], ioc[0]), filename="scan.json")

@app.route('/createioc')
def createioc():
    if not session.get('logged_in'):
        abort(401)
    return render_template('createioc.html')

@app.route('/addioc', methods=['POST'])
def addioc():
    if not session.get('logged_in'):
        abort(401)
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
	name = secure_filename(request.form['name'])
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    db = get_db()
    db.execute('insert into iocs values (NULL,?,?,?)',
               [name, str(datetime.datetime.now()), os.path.join(app.config['UPLOAD_FOLDER'], filename)])
    db.commit()
    parse(os.path.join(app.config['SCAN_FOLDER'], name), os.path.join(app.config['UPLOAD_FOLDER'], filename))
    return redirect(url_for('iocs'))

#if __name__ == '__main__':
#    app.run()


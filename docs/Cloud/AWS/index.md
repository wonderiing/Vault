# AWS

Esta seccion funciona como una cheat sheet de un curso de AWS. La idea es tener apuntes rapidos, ejemplos y recordatorios practicos sobre los servicios principales, configuraciones comunes y conceptos base de cloud computing.

## Que es AWS

Amazon Web Services es una plataforma de servicios en la nube que permite crear, desplegar y administrar infraestructura sin depender directamente de servidores fisicos propios. AWS ofrece servicios para computo, almacenamiento, redes, bases de datos, seguridad, monitoreo, automatizacion y despliegue de aplicaciones.

## Conceptos Generales

- **Region**: ubicacion geografica donde AWS agrupa centros de datos.
- **Availability Zone**: centro de datos o grupo de centros de datos dentro de una region.
- **Escalabilidad**: capacidad de aumentar o reducir recursos segun la demanda.
- **Alta disponibilidad**: diseno para mantener servicios funcionando aunque falle una parte de la infraestructura.
- **IAM**: servicio para administrar usuarios, roles, permisos y politicas.
- **Modelo de responsabilidad compartida**: AWS protege la infraestructura cloud, mientras el usuario protege sus datos, permisos, configuraciones y aplicaciones.

## Servicios Cubiertos

- EC2 para servidores virtuales.
- S3 para almacenamiento de objetos.
- RDS para bases de datos administradas.
- IAM para identidad y permisos.
- Lambda para ejecucion serverless.
- VPC para redes privadas en AWS.
- CloudFormation para infraestructura como codigo.
- CloudShell para operar AWS desde una terminal en el navegador.
- OIDC con GitHub Actions para despliegues CI/CD sin guardar credenciales estaticas.

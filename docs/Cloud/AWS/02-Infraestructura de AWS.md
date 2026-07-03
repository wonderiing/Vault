### Regiones y Availibity Zones

AWS cuenta con una infraestructura global repartida por distintas regiones como:

- us-east
- ap-south

Cada region tiene distintas Availability Zones.

- Las availability zones son básicamente distintos centros de datos en la misma region aislados físicamente unos de otros para evitar catástrofes y habilitar la replicación de tu información en distintos centros de datos. 
- Las AZ suelen estar denominadas como us-east-1a, us-east-1b y así.
- Cada region tiene un mínimo de 3 AZ y un máximo de 6.

Los servicios de AWS se dividen en 2 categorías:

### Tipos de Servicios

Servicios Globales:

- IAM: para control de accesos
- WAF: Firewall para apps Web
- CloudFront: CDN para la distribución de contenido
- Route 53: Servicio DNS

Servicios Regionales:

La mayoría de servicios de AWS son regionales, algunos ejemplos son:

- EC2
- S3
- Elastic Beanstalk
- RDS
- Lambda
- etc.
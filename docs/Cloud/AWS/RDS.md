## **Motores de la base de datos:**
![](assets/Pasted%20image%2020250308150208.png)
## **Filtros y Versiones:**

Multi AZ DB cluster se refiere a tener una replica de tu base de datos primaria por si algo le llegara a pasar a esta poder utilizar la replica, todo esto dentro de la misma region. Esta opcion obviamente vuelve mas caro el servicio de RDS
![](assets/Pasted%20image%2020250308150235.png)
## **Plantilla:**

Con la capa gratuita no puedes hacer un Cluster AZ pero es gratis

![](assets/Pasted%20image%2020250308150515.png)
## **Ajustes y Credenciales:**
Las credenciales para conectarte a la DB como root
![](assets/Pasted%20image%2020250308150720.png)

## **Tipo de Instancia:**
Se refiere a los recursos que tiene la base de datos
![](assets/Pasted%20image%2020250308150832.png)
## **Almacenamiento de la base de datos:**

Esto puede ser modificado despues de la creacion
![](assets/Pasted%20image%2020250308150905.png)
## **Conectividad**:
La base de datos puede estar conectada directamente a una Instancia EC2 solo seria cuestion de eleguir la opcion de Connect to an EC2 y eleguir la instancia

En este caso no conectamos a un EC2
![](assets/Pasted%20image%2020250308151027.png)


Acesso Publico  es para que cualquiera se pueda conectar, puedes ponerlo en NO si solo necesitas que tu base de datos este conectado a algun servicio dentro del propio de AWS y te ahorras problemas con la seguirdad

Availability Zone es donde se alojara tu base de datos, no preference indica que te da igual 
![](assets/Pasted%20image%2020250308151308.png)

## **Resumen de la RDS:**
Aqui tenemos informacion general de la base de datos como el endpoint para poder conectarnos
![](assets/Pasted%20image%2020250308160009.png)

## **Conexion:**
Primero configuraremos las inbound rules de el grupo de seguridad:

Lo normal es poner solo tu ip pero en este caso puse anywhere
![](assets/Pasted%20image%2020250308155425.png)

Y ahora ya podemos conectarnos 
![](assets/Pasted%20image%2020250308155839.png)

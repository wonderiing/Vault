Un clúster de ECS no es mas que un espacio lógico que agrupa distintos recursos de computo como EC2 o Fargate los cuales nos sirven para ejecutar nuestros propios contenedores. No es una maquina sino mas bien es el "contenedor" que organiza todos los recursos.

- `Tasks`: Las tareas en ECS son un grupo de contenedores, es similar a un POD de Kubernetes
- `Services`: Los servicios son un conjunto de tareas.
- `Fargate`: Fargate es un servicio de computo Serverless es decir nosotros no nos encargamos de los recursos ni de configurarlo como EC2, simplemente lo creamos. Fargate no funciona por si solo, tiene que ir de la mano con ECS o EKS 
- Costo: No se cobra por creación de Clústeres, se cobra por la infraestructura que usa ese clúster por ejemplo: Fargate cobra por los recursos que se utilicen mientras tu tarea esta corriendo


![](assets/Pasted%20image%2020260707141046.webp)

## Clúster ECS

Crear clúster de ECS:

`ECS -> Clusteres -> Crear Cluster`

![](assets/Pasted%20image%2020260707134528.webp)

Es buena practica colocar las siguientes tags:

![](assets/Pasted%20image%2020260707134724.webp)

## Security Groups

Crearemos varios security groups para controlar el acceso a nuestro recursos

### Security Group ECS

- `EC2 -> Security Groups`
- La regla de entrada habilita el puerto 8080, pero podemos elegir el que use nuestra app.
- Este security group ira attacheado a las tareas (contenedores) del ECS

![](assets/Pasted%20image%2020260707135231.webp)

### Security Group Loada Balancer

Segundo security Group para el load balancer:

- Este security group será asignado al Load Balancer, que permite la entrada de trafico por el puerto `80`

![](assets/Pasted%20image%2020260707135412.webp)


## Target Groups

Un target group no es mas que un conjunto de instancias, direcciones ips, balanceadores o funciones lambda. Este grupo nos ayuda a registrar las distintas IPs de Fargate que vamos a tener para que el balanceador de carga distribuya la carga.

- Colocamos el Puerto 8080 por que es donde van a correr nuestras apps en el clúster de ECS

![](assets/Pasted%20image%2020260707135651.webp)

En targets no agregaremos ninguno por que Fargate los agregara al registrar las tareas (contenedores) en clúster.

![](assets/Pasted%20image%2020260707135835.webp)

## Balanceador de Carga

Ahora crearemos el balanceador de carga.

`EC2 -> Balanceador de Carga`

El ALB cobra por dos cosas:

- Load Balancer cobra fijo por hora
- Un LCU mide las dimensiones en las que el ALB procesa tu tráfico, promediadas por hora. Son 4 dimensiones. La clave: solo pagas por la dimensión más alta. [Amazon Web Services](https://aws.amazon.com/es/elasticloadbalancing/pricing/)


Usaremos un Application load balancer.

![](assets/Pasted%20image%2020260707140007.webp)

La Config será la siguiente:

- Misma vpc que el clúster de ECS y mismas subredes.

![](assets/Pasted%20image%2020260707140145.webp)

Asignaremos el Security Group que creamos anteriormente:

- Crearemos un listener en el puerto `80`, este nos sirve para que el balanceador de carga escuche el trafico por ese puerto y lo redirija al target group que creamos anteriormente.

![](assets/Pasted%20image%2020260707140227.webp)

Podemos probar el balanceador de carga tirandole un CURL

- El resultado esperado es un 503, lo que quiere decir que el balanceador de carga si esta recibiendo trafico, pero no esta pudiendo redirigir el trafico a ningún target (es por que no hemos registrado nada aun.)

```
> curl alb-app-863210803.us-east-2.elb.amazonaws.com                                                                    
curl : 503 Service Temporarily Unavailable
```

## Tasks

Ahora vamos a registrar una Tarea (contenedor)

`ECS -> Crear una nueva Definicion de Tarea`

- En mi caso seleccionare Fargate y los recursos mínimos.
- También podemos colocarle un Rol IAM a los contenedores.

![](assets/Pasted%20image%2020260707141419.webp)

Después viene el registro de Contenedores, recordemos que una tarea puede tener mas de 1 contenedor.

- Aquí podremos elegir nuestro contenedor de algún registry (docker hub, github registry, etc.), en mi caso usare un sample de Google

![](assets/Pasted%20image%2020260707141714.webp)

Si es necesario también podemos asignar variables de entorno:

![](assets/Pasted%20image%2020260707141831.webp)

Como ajustes adicionales existen los siguientes:

- Logs de CloudWatch (Por defecto esta activado, yo desactive los logs en esta ocasión)
- Almacenamiento de la tarea (21 GB por defecto)
- Ajustes del contenedor como Health Check, Etiquetas Docker, EntryPoint de Docker etc.

## Servicios

- Recordemos que un servicio es el conjunto de varias tareas, en este caso vamos a crear un servicio con 3 replicas de nuestra tarea y lo asignaremos al clúster que tenemos.

![](assets/Pasted%20image%2020260707142330.webp)


En clúster deberemos elegir el clúster que creamos 

![](assets/Pasted%20image%2020260707142615.webp)


### Configuración

La Estrategia de proveedor de capacidad nos deja asignar un base y peso

- Base es la cantidad mínima de tareas que queremos que se ejecute en ese proveedor
- Peso es la prioridad de tareas que va a tener cada proveedor, es decir si tenemos 2 proveedores un EC2 y un Fargate los dos con 50% entonces las tareas se distribuirán de manera uniforme.

![](assets/Pasted%20image%2020260707142941.webp)

En el apartado de replicas nosotros podemos elegir cuantas tareas queremos desplegar.

![](assets/Pasted%20image%2020260707143200.webp)

### Redes:

- Aquí tenemos que elegir la misma VPC y mismas subredes que usamos en el clúster.
- También elegiremos el security group que creamos para el clúster (habilita el trafico de entrada al puerto 8080).
- Utilizaremos la opción de IP Publica para asignarle una a cada tarea y podernos conectar a cada una.

![](assets/Pasted%20image%2020260707143311.webp)

### Balanceador de Carga

Aquí simplemente utilizaremos el balanceador de carga, el target group y el listener que ya hemos creado anteriormente:

![](assets/Pasted%20image%2020260707143552.webp)


![](assets/Pasted%20image%2020260707143603.webp)

### Escalado automático (Opcional):

- Aquí podemos agregar cuantas replicas mínimas y máximas queremos para el escalado.
- Se puede escalar por memoria, cpu o por cantidad de reqs que recibe el balanceador

![](assets/Pasted%20image%2020260707143709.webp)

### Overview

- Al crearlo podemos ver el servicio recién creado y el numero de tareas que se están ejecutando. Al darle click al nombre del servicio veremos mas info de cada una de las tareas.

![](assets/Pasted%20image%2020260707144011.webp)

Ahora si podemos probar el clúster:

- El hostname va cambiando por lo que podemos comprender que el balanceador y las tareas estan funcionando correctamente.

```

> curl alb-app-863210803.us-east-2.elb.amazonaws.com
Hello, world!
Version: 1.0.0
Hostname: ip-172-31-30-68.us-east-2.compute.internal


> curl alb-app-863210803.us-east-2.elb.amazonaws.com
Hello, world!
Version: 1.0.0
Hostname: ip-172-31-35-182.us-east-2.compute.internal


> curl alb-app-863210803.us-east-2.elb.amazonaws.com
Hello, world!
Version: 1.0.0
Hostname: ip-172-31-4-41.us-east-2.compute.internal

```

Podemos ir viendo y conectándonos a cada uno de las tareas por su IP Publica:

![](assets/Pasted%20image%2020260707144318.webp)

Las tareas (contenedores) corren en el puerto 8080, y todas las task están registradas en el target group a app-tg que esta configurado en el puerto 8080

```
> curl -s 18.225.234.233:8080
Hello, world!
Version: 1.0.0
Hostname: ip-172-31-4-41.us-east-2.compute.internal

```
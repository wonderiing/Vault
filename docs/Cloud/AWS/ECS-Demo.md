Esta nota explica cómo desplegar una API de NestJS en AWS usando ECS con Fargate. La API correrá en contenedores, usará una base de datos Postgres en RDS, será expuesta con un Application Load Balancer y la imagen Docker estará guardada en GitHub Container Registry. [Repositorio](https://github.com/wonderiing/aero-api), [Package público](https://github.com/wonderiing/aero-api/pkgs/container/aero-api)

El package de ejemplo es público, así que ECS puede descargar la imagen sin credenciales privadas. Los pasos de subir imagen a GHCR y guardar credenciales en Secrets Manager solo son necesarios si vas a usar tu propia imagen o si el package está privado.

El flujo general será este:

- Crear la base de datos en RDS.
- Crear los Security Groups necesarios.
- Crear un Target Group para registrar las tareas de ECS.
- Crear un Application Load Balancer para exponer la API.
- Usar la imagen pública de GitHub Container Registry o subir tu propia imagen.
- Guardar las credenciales del registry en Secrets Manager solo si la imagen es privada.
- Crear una Task Definition en ECS.
- Crear un cluster y un servicio para mantener la API corriendo.

## 1. Crear la base de datos en RDS

Primero tenemos que crear la base de datos en:

```txt
RDS -> Crear Base de Datos
```

Mi API usa Postgres, así que elegiré ese motor.

![](assets/Pasted%20image%2020260721181529.webp)

Más abajo podemos ver las configuraciones de seguridad y conexión:

- Elegimos la versión del motor Postgres.
- Configuramos el usuario y contraseña master.
- Estas credenciales las usaremos luego como variables de entorno en ECS.

![](assets/Pasted%20image%2020260721181613.webp)

### Almacenamiento

Aquí elegimos los recursos de la base de datos, como almacenamiento y tipo de instancia.

![](assets/Pasted%20image%2020260721181637.webp)

### Red

En la parte de red usaré estos ajustes:

!!! info "Security Group"
    Un Security Group funciona como un firewall de AWS. Define qué tráfico puede entrar o salir de un recurso. Para este despliegue conviene separar reglas: el ALB recibe tráfico público por `80` o `443`, ECS recibe tráfico solo desde el ALB por `3000`, y RDS recibe tráfico solo desde ECS por `5432`.

- VPC por defecto de AWS.
- Acceso público deshabilitado.
- Security Group permitiendo entrada al puerto `5432`.
- La DB solo debería recibir tráfico desde recursos dentro de la VPC, por ejemplo las tasks de ECS.

![](assets/Pasted%20image%2020260721181717.webp)

## 2. Crear Target Group, ALB y Security Groups

El ALB será el punto de entrada público hacia la API. Los usuarios no le pegarán directamente a una task de ECS, sino al balanceador.

El Target Group agrupa las IPs de las tasks que están corriendo. Esto es importante porque en Fargate las tasks pueden cambiar de IP cuando se reinician o cuando hacemos un nuevo deploy.

Los Security Groups funcionan como reglas de firewall:

- El ALB debería aceptar tráfico desde internet por `80` y/o `443`.
- Las tasks de ECS deberían aceptar tráfico desde el ALB por el puerto de la API.
- RDS debería aceptar tráfico desde ECS por `5432`.

### Target Group

!!! info "Target Group"
    El Target Group es el grupo de destinos al que el ALB enviará tráfico. En este caso, los destinos serán las IPs de las tasks de Fargate. Esto es importante porque las tasks pueden cambiar de IP cuando se reinician o cuando hacemos un nuevo deploy.

Lo crearemos en:

```txt
EC2 -> Grupos de Destino
```

Configuración principal:

- Tipo: `Direcciones IP`.
- Protocolo y puerto: el puerto donde corre el contenedor. En mi caso la API corre en `3000`.

![](assets/Pasted%20image%2020260721182006.webp)

Cuando AWS pida registrar destinos, lo dejamos en blanco. Fargate se encargará de registrar las tasks automáticamente cuando creemos el servicio.

![](assets/Pasted%20image%2020260721182205.webp)
![](assets/Pasted%20image%2020260721182216.webp)

### Application Load Balancer

!!! info "Application Load Balancer"
    El ALB es la entrada pública hacia la API. Los usuarios hacen peticiones al DNS del Load Balancer, no directamente a las tasks. Luego el ALB reparte el tráfico hacia las tasks disponibles dentro del Target Group.

El balanceador lo crearemos en:

```txt
EC2 -> Balanceadores de Carga
```

Será de tipo `Application Load Balancer`.

![](assets/Pasted%20image%2020260721182348.webp)

Le colocamos el nombre que queramos y usamos `IPv4`.

![](assets/Pasted%20image%2020260721182426.webp)

En red, el ALB debe estar en la misma VPC que ECS y RDS.

![](assets/Pasted%20image%2020260721182447.webp)

En seguridad, creé un Security Group permitiendo tráfico de entrada por los puertos `80` y `443`, que son los puertos donde escuchará el ALB.

![](assets/Pasted%20image%2020260721182618.webp)

Así se ve el Security Group:

![](assets/Pasted%20image%2020260721182601.webp)

### Listeners

Los listeners son los puertos donde el ALB escucha peticiones. En este caso el tráfico que llegue por `80` o `443` será redirigido al Target Group que creamos antes.

![](assets/Pasted%20image%2020260721182739.webp)

## 3. Subir la imagen a GitHub Container Registry

Antes de crear la Task Definition necesitamos tener una imagen Docker subida a un registry. En este caso usaré GitHub Container Registry, también conocido como `ghcr.io`.

Si usas el package público de ejemplo, puedes saltarte este paso y usar directamente la URI de la imagen en ECS:

```txt
ghcr.io/wonderiing/aero-api:latest
```

Solo necesitas construir y subir tu propia imagen si quieres desplegar una versión propia del proyecto.

Para eso la app necesita un `Dockerfile`. Este archivo define cómo construir la imagen: versión de Node, instalación de dependencias, build del proyecto y comando para arrancar el contenedor.

Ejemplo general del flujo:

```bash
docker build -t ghcr.io/usuario/aero-api:latest .
```

Luego iniciamos sesión en GitHub Container Registry:

```bash
docker login ghcr.io
```

Y subimos la imagen:

```bash
docker push ghcr.io/usuario/aero-api:latest
```

La URI `ghcr.io/usuario/aero-api:latest` será la que colocaremos después en ECS.

## 4. Guardar credenciales en Secrets Manager

!!! info "Secrets Manager"
    Secrets Manager sirve para guardar información sensible como tokens, passwords o credenciales. En este ejemplo solo sería necesario para GHCR si la imagen es privada. Si usamos el package público, ECS no necesita un secreto para descargar la imagen.

Este paso es opcional. Si usas el package público de ejemplo, no necesitas crear un secreto para GHCR porque ECS puede descargar la imagen sin autenticarse.

Si la imagen está privada, ECS necesita credenciales para descargarla desde GitHub Container Registry. Para eso usaremos Secrets Manager.

En mi caso creé un Classic Token en GitHub con permisos para leer paquetes:

```txt
Settings -> Developer Settings -> Personal Access Tokens -> Tokens Classic
```

![](assets/Pasted%20image%2020260721183525.webp)

Cuando tengamos el token, creamos un nuevo secreto en AWS Secrets Manager. Este secreto debe guardar las credenciales que ECS usará para autenticarse contra el registry, normalmente usuario de GitHub y token.

Después del primer paso AWS pedirá más configuraciones, pero se pueden dejar en default si no necesitas algo especial.

![](assets/Pasted%20image%2020260721183109.webp)

Después de crear el secreto, al rol de ejecución de ECS hay que asignarle el permiso `AWSSecretsManagerClientReadOnlyAccess`.

Esto permite que ECS lea el secreto y pueda autenticarse para pullear la imagen privada.

![](assets/Pasted%20image%2020260721183259.webp)

## 5. Crear la Task Definition

!!! info "Task Definition"
    La Task Definition es la plantilla del contenedor. Ahí se define qué imagen Docker se usará, qué puerto expone, qué variables de entorno necesita, cuánta CPU y memoria tendrá, y si enviará logs a CloudWatch. No ejecuta nada por sí sola; solo describe cómo debe ejecutarse.

La Task Definition es la plantilla de ejecución del contenedor. Aquí indicamos qué imagen usar, qué puerto expone, qué variables de entorno necesita, qué recursos tendrá y si queremos activar logs.

Vamos a:

```txt
ECS -> Definición de Tareas
```

Creamos una nueva definición de tarea. En mi caso usaré Fargate.

![](assets/Pasted%20image%2020260721183804.webp)

Más abajo aparece el rol de ejecución de tarea. Este rol debe tener permisos para leer el secreto de Secrets Manager.

![](assets/Pasted%20image%2020260721184027.webp)

### Contenedor

Aquí configuramos el contenedor que correrá dentro de la task:

- URI de la imagen en GitHub Container Registry.
- ARN del secreto con las credenciales del registry, solo si la imagen es privada.
- Puerto del contenedor. Mi API corre en `3000`.

![](assets/Pasted%20image%2020260721184141.webp)

Más abajo podemos agregar las variables de entorno que necesita la API para conectarse a RDS.

Las credenciales las podemos sacar desde:

```txt
RDS -> dev (nombre de la DB) -> Conectividad y Seguridad
```

![](assets/Pasted%20image%2020260721185005.webp)

Variables importantes:

- Host: usar el punto de enlace de RDS.
- `POSTGRES_PASSWORD`: contraseña master que colocaste al crear la DB.
- También deberías colocar el usuario, nombre de la base de datos, puerto y cualquier otra variable que use tu API.

![](assets/Pasted%20image%2020260721185048.webp)

También podemos activar logs para revisar errores o comportamiento del contenedor desde CloudWatch.

![](assets/Pasted%20image%2020260721185146.webp)

Al crear la tarea podemos pasar a crear el servicio.

![](assets/Pasted%20image%2020260721185228.webp)

## 6. Crear el cluster de ECS

!!! info "ECS"
    Amazon Elastic Container Service es el servicio de AWS que nos permite ejecutar contenedores. En vez de levantar manualmente una máquina, instalar Docker y correr el contenedor nosotros, ECS se encarga de iniciar, detener y monitorear esos contenedores dentro de AWS.

!!! info "Fargate"
    Fargate es una forma de usar ECS sin administrar servidores EC2. Nosotros solo indicamos cuánta CPU y memoria necesita el contenedor, y AWS se encarga de crear la infraestructura necesaria para ejecutarlo.

El cluster es el lugar lógico donde ECS ejecutará nuestros servicios y tasks. Como usaremos Fargate, no necesitamos administrar instancias EC2 manualmente.

Creamos el cluster en:

```txt
ECS -> Crear Cluster
```

![](assets/Pasted%20image%2020260721185345.webp)

## 7. Crear el servicio de ECS

!!! info "Service"
    El Service mantiene vivas las tasks. Si una task falla o se detiene, ECS crea otra para reemplazarla. También permite definir cuántas réplicas queremos y conectar esas tasks con un Load Balancer para recibir tráfico externo.

!!! info "Task"
    Una Task es una ejecución real de una Task Definition. Si la Task Definition es como el molde, la Task es el contenedor corriendo de verdad. Por ejemplo, si el servicio tiene 2 réplicas, ECS levantará 2 tasks usando la misma definición.

El servicio mantiene corriendo las tasks. Por ejemplo, si configuramos `2` réplicas, ECS intentará mantener siempre dos tasks activas. Si una se cae, ECS levanta otra usando la misma Task Definition.

También conectaremos el servicio con el Load Balancer para que el tráfico externo llegue a los contenedores.

![](assets/Pasted%20image%2020260721185903.webp)

Elegimos el cluster donde se ejecutará y el proveedor. En mi caso usaré `FARGATE`.

![](assets/Pasted%20image%2020260721180714.webp)

### Réplicas

Aquí indicamos cuántas tasks queremos corriendo. En mi caso usaré `2`.

![](assets/Pasted%20image%2020260721190011.webp)

### Balanceador de carga

En este apartado conectamos el servicio con el ALB y el Target Group que creamos antes.

![](assets/Pasted%20image%2020260721190040.webp)

Seleccionamos los recursos que ya habíamos creado:

![](assets/Pasted%20image%2020260721190049.webp)

## 8. Revisar el despliegue

En el overview podemos ver si el servicio se creó correctamente.

![](assets/Pasted%20image%2020260721190126.webp)

También podemos revisar que las tasks estén corriendo.

![](assets/Pasted%20image%2020260721190237.webp)

Finalmente probamos la API usando el DNS del Load Balancer.

![](assets/Pasted%20image%2020260721181943.webp)

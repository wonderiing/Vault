IAM - Identity Access Managment es un servicio global encargado de la gestión y administración de accesos a los recursos de AWS mediante grupos y políticas:

- Los usuarios pueden pertenecer a 1 o mas grupos.
- Los grupos no contienen grupos.
- Las políticas definen los permisos de los usuarios.
- A los usuarios y grupos se les pueden asignar políticas en formato de JSON o visual.
- AWS aplica el principio de mínimo privilegio, que consiste en solo dar los permisos necesarios a los usuarios.

Mejores Practicas:

- No utilizar la cuenta root excepto para la configuración de la cuenta AWS
- Usuario físico = Usuario AWS
- Utilizar MFA
- Crear Politicas de contraseña fuertes
- Asignar usuarios a grupos y permisos a grupos
- Crear y utilizar roles/permisos a servicios de AWS
- Utilizar claves de acceso para CLI Y SDK
- No compartir usuarios IAM ni claves de acceso

## Creación de Usuarios.

Podemos crear un usuario IAM siguiendo la siguiente ruta:

`IAM -> Usuarios IAM -> Crear Usuario`

![](assets/Pasted%20image%2020260630115147.png)

Después podemos adjuntarle políticas al usuario directamente o asignarlo a un grupo. En este caso yo cree un nuevo grupo llamado admin y asigne la política de `AdministratorAcess` que da un acceso completo a AWS

![](assets/Pasted%20image%2020260630115400.png)

Por ultimo, crearemos la persona y se nos mostrara un resumen del usuario creado al cual podremos enviarle la invitación de acceso por correo o darle sus credenciales:

![](assets/Pasted%20image%2020260630115544.png)

## Acceso a usuarios IAM

Para acceder al panel de AWS como un usuario IAM es necesario dirigirnos a `IAM -> Panel` y del lado derecho veremos información de la cuenta AWS:

- Le daremos a Crear alias de cuenta.

![](assets/Pasted%20image%2020260630115839.png)

Cuando creemos el alias se mostrara algo así:

- Esta URL es la que necesitaran nuestros usuarios IAM, para poder acceder al panel de AWS (si tienen permisos.)
- Solo es necesario crear el Alias una vez, una vez creado podremos utilizarlo para todas las cuentas IAM.

![](assets/Pasted%20image%2020260630115928.png)

Al utilizar esa URL accederemos directamente al panel de login de AWS IAM, donde los usuarios podrán ingresar sus credenciales y acceder al panel.

- La primera vez que ingresen normalmente pedirá un cambio de password.

![](assets/Pasted%20image%2020260630120401.png)

## Cuentas Simultaneas en AWS.

Podemos tener mas de una cuenta iniciada en la consola de AWS, para no tener que cerrar sesión y volver a iniciar cada que querramos cambiar de cuenta. Esto lo podemos hacer desde el panel arriba a la derecha en nuestro nombre de la consola:

- Activamos la compatibilidad con varias sesiones.

![](assets/Pasted%20image%2020260630120916.png)

Al activarlo podemos volver a darle a nuestro nombre y veremos un nuevo botón llamado Agregar sesión:

![](assets/Pasted%20image%2020260630121023.png)

Al darle click nos llevara al login y podremos ingresar nuestras credenciales y al volver al panel ahora podemos ver las distintas sesiones que tenemos activas. Al darle click a cada una nos llevara a su respectiva consola de AWS

![](assets/Pasted%20image%2020260630121159.png)

## Políticas IAM

Una política define los permisos que los usuarios tienen.

- **Identity-based policies:** se attachean a un usuario, grupo o rol. No llevan `Principal` en el statement, ya que el "quién" queda definido por la identidad a la que se attachea la política (si se attachea a un grupo, aplica a todos sus miembros).
- **Resource-based policies:** se attachean directamente a un recurso (ej. un bucket de S3). Estas sí llevan `Principal`, porque es el recurso el que define explícitamente quién tiene permiso de acceder a él.

![](assets/Pasted%20image%2020260630122751.png)

Ejemplo de política y su estructura:

- `Version`: Es la versión del lenguaje en la que esta escrita la política y casi siempre es el mismo "2012-10-17"
- `Id`: Es un identificador único de la política (Este campo es opcional)
- `Statement`: Es una o mas declaración individuales (Campo obligatorio).

Los `Statements` están estructurados de la siguiente manera:

- `Sid`: Es un identificador para la declaración (opcional).
- `Effect`: Si la sentencia permite o deniega el acceso.
- `Principal`: Es la cuenta/usuario/rol al que se le aplica esta política.
- `Action`: Las acciones que permite o deniega la política.
- `Resource`: Lista de los recursos a los que se les aplican las acciones.

```json
{
    "Version": "2012-10-17",
    "Id": "S3-Account-Permissions",
    "Statement": [
        {
            "Sid": "1",
            "Effect": "Allow",
            "Principal": {
                "AWS": ["arn:aws:iam::123456789012:root"]
            },
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": ["arn:aws:s3:::mybucket/*"]
        }
    ]
}
```

*Nota: esta política en particular es una resourced based policy mas en concreto una bucket policy*

#### Creando Politicas.

Podemos crear políticas en `IAM -> Politicas -> Crear Politicas`

- Las políticas que creemos después las podemos attachear a grupos o usuarios.

Hay 2 tipos de creación de políticas la primera es visual:

- Aquí básicamente podemos ir eligiendo a través de menús, el recurso, las acciones, los arns de la politica.

![](assets/Pasted%20image%2020260630124043.png)


La segunda es a través de JSON y sigue la estructura que mencionamos anteriormente:

- Aquí la IA nos puede ayudar mucho a crear políticas.

![](assets/Pasted%20image%2020260630123419.png)

## Politicas de Contraseñas y MFA

Una política de contraseñas no son mas que una serie de reglas que el usuario IAM tiene que seguir al crear su contraseña. Ej:

- Contraseña de mínimo 10 caracteres.
- Incluir un símbolo
- Requerir que las contraseñas sean cambiadas cada "n" tiempo.
- Impedir la reutilización de contraseña.

Podemos crear una política de contraseña desde `IAM -> Configuracion de Cuenta -> Editar Politica de Contraseña`. 

Hay 2 opciones para las políticas de contraseña.


- Personalizado (Tu pones las reglas. Ej: Longitud, Símbolos, Caducidad)

![](assets/Pasted%20image%2020260701222117.png)

- Reglas Predeterminadas:

![](assets/Pasted%20image%2020260701222022.png)

**MFA - Multi Factor Authentication**

El MFA es una segunda/tercera capa de seguridad independiente de tu contraseña. Ej:

- Envió de email por correo para verificar que eres tu.
- SMS a tu dispositivo.
- Generación de códigos OTP virtuales a través de apps como Google Authentication
- **Hardware TOTP Token:** dispositivo físico tipo llavero provisto por Thales (antes Gemalto), genera un código de 6 dígitos; debe comprarse a través de los enlaces oficiales de AWS para garantizar compatibilidad.
- **FIDO2/U2F Security Key:** llave de seguridad física como YubiKey (Yubico) u otras certificadas FIDO; resistente a phishing y no requiere compra exclusiva en AWS.

AWS solo permite OTPs virtuales y dispositivos físicos.

Para añadir un MFA podemos darle click a nuestro nombre de cuenta arriba a la derecha y elegir la opción de `Credenciales de Seguridad`

![](assets/Pasted%20image%2020260701222435.png)


Podemos darle a `Asignar dispositivo MFA` y continuar con el proceso:

![](assets/Pasted%20image%2020260701222530.png)

## AWS CLI y SDK

Existen 3 formas distintas para utilizar AWS:

- Consola de AWS: La interfaz visual que hemos estado usando.
- AWS CLI: Herramienta de linea de comandos de AWS
- AWS SDK: Kit de desarrollo de AWS que permite la integración de sus servicios (S3, DynamoDB, etc.) con las aplicaciones de los desarrolladores.

Para autenticarte con el CLI o con el SDK es necesario tener llaves de acceso las cuales consisten de piezas:

- ID Clave de Acceso: Es el ID del usuario
- Clave Acceso secreta: La "contraseña" del usuario

### Config de AWS CLI

Para la instalación de la CLI podemos ir a [Docs](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) 

Para utilizar el CLI primero tenemos que crear una clave de acceso:

```
IAM -> Usuarios de IAM -> (Eliges el usuario) -> Credenciales de Seguridad
```

![](assets/Pasted%20image%2020260701224219.png)

Al darle a crear claves de acceso podemos ver las distintas opciones que hay, en este caso vamos a crear una clave de accesso para la CLI:


![](assets/Pasted%20image%2020260701224357.png)

Al crearla vamos a poder ver las credenciales:

![](assets/Pasted%20image%2020260701224436.png)

Y desde la CLI podemos configurarlo:

```
> aws configure                                                                                                         
Tip: You can deliver temporary credentials to the AWS CLI using your AWS Console session by running the command 'aws login'.

AWS Access Key ID [None]: AKIA5DINKLAQHTZY5DFW
AWS Secret Access Key [None]: <CLAVE ACCESO SECRETA>
Default region name [None]: us-east-1
Default output format [None]:
```

La podemos probar:

```
> aws iam list-users                                                                                                    {
    "Users": [
        {
            "Path": "/",
            "UserName": "wndr",
            "UserId": "AIDA5DINKLAQHCKJMURRT",
            "Arn": "arn:aws:iam::900360460320:user/wndr",
            "CreateDate": "2026-06-30T18:00:41+00:00",
            "PasswordLastUsed": "2026-06-30T18:10:44+00:00"
        }
    ]
}
```

## Roles IAM a Servicios

Podemos asignar roles a servicios para que hagan cosas a nuestro nombre. Ej: Asignar algún rol a Lambda para hacer un backup de un DB y subir a un bucket.

Para crear asignar un rol debemos ir a `IAM -> Roles -> Crear Rol`

- Tipo de Entidad de Confianza: Servicio de AWS
- Caso de uso: Servicio de AWS al que le asignaremos el rol.


![](assets/Pasted%20image%2020260701230403.png)

Después le podemos agregar las políticas que querramos:

![](assets/Pasted%20image%2020260701230600.png)

Por ultimo deberemos asignar un nombre y descripción al rol:

![](assets/Pasted%20image%2020260701230719.png)

## Herramientas de IAM

**IAM Credential Report** (nivel de cuenta): Informe que enumera todos los usuarios de tu cuenta y el estado de sus credenciales.

- Para descargar el informe debemos ir a `IAM -> Informe de Credenciales` ahí nos toparemos con un botón que nos descargar el informe en formato `.csv`

![](assets/Pasted%20image%2020260701231550.png)

**IAM Access Advisor** (nivel usuario): Muestra los permisos concedidos a un usuario y cuando se accedió a esos servicios por ultima vez.

- Para ver la info de un usuario nos vamos a `IAM -> Usuarios -> Ultimo Acceso`

![](assets/Pasted%20image%2020260701231754.png)

Te cobran por el tiempo de computacion una lambda solo se ejecuta cuando la llaman

**La lambda es una funcion serverless**

## **Configuracion:**

El runtime lo puedes cambiar por algun otro lenguaje
![](assets/Pasted%20image%2020250308205320.webp)
## **Codigo de la lambda:**
Este codigo sera lo que ejecute nuestra lambda en este caso solo suma 1  + 1
![](assets/Pasted%20image%2020250308210059.webp)
## **Respuesta:**

Para probar la lambda deberemos crear un Test y despues ya podremos testearlo
Cada que hagamos un cambio en el codigo de la lambda deberemos de darle a Deplor

Aparte  de darnos el resultado del codigo nos da mas informacion como el tiempo de ejecucion de la lambda, esto es importante ya que lambda te cobra por tiempo de computacion, entre mas ligera sea la lambda mas barato sera
![](assets/Pasted%20image%2020250308210203.webp)
## **Monitorizacion**
Aqui podemos ver metricas como cuantas veces falla la api o el success rate tambien en la parte inferior podemos ver los Logs
## ![](assets/Pasted%20image%2020250308210505.webp)**Desencadenadores**
La lambda puede ser ejecutada mediante un desencadenador es decir
Cada que suceda un evento que tu configures la lambda se ejecutara estos son algunos triggers:
![](assets/Pasted%20image%2020250308210707.webp)
## **URL de la Lambda**
En la parte de Configuracion de la lambda podemos crearle una url publica para que se ejecute nuestra lambda:

Esta url puede ser autentificada con IAM o no, en este caso esta sin autentificar

Cada que visitemos esta URL en nuestro navegador o algun cliente para realizar solicitudes la lambda se ejecutra
![](assets/Pasted%20image%2020250308211140.webp)
Ejecutandose
![](assets/Pasted%20image%2020250308211209.webp)
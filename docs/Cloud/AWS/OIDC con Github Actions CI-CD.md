
Primero necesitamos crear un Proveedor de Identidad para que GitHub pueda llamar a AWS desde el Workflow y asi poder desplegar nuestro codigo:

![](assets/Pasted%20image%2020260418164018.png)

Después vamos a necesitar crear un Rol para GitHub actions

- Este rol se va a permitir a github actions poder enviar comandos a través de SSM para poder desplegar el codigo

![](assets/Pasted%20image%2020260418164250.png)

Permiso para el rol:

![](assets/Pasted%20image%2020260418164500.png)


- Entonces, este rol solo lo puede asumir mi repositorio desde un token emitido por el provedor de identidad que cree anteriormente

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Principal": {
                "Federated": "arn:aws:iam::535002880672:oidc-provider/token.actions.githubusercontent.com"
            },
            "Condition": {
                "StringEquals": {
                    "token.actions.githubusercontent.com:aud": [
                        "sts.amazonaws.com"
                    ]
                },
                "StringLike": {
                    "token.actions.githubusercontent.com:sub": [
                        "repo:wonderiing/aero-api:*",
                        "repo:wonderiing/aero-api:*"
                    ]
                }
            }
        }
    ]
}
```

Por ultimo deberemos agregarle permisos al rol para poder enviar comandos a traves de SSM a cualquier recurso.

```json
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": [
				"ssm:SendCommand",
				"ssm:GetCommandInvocation",
				"ssm:ListCommandInvocations"
			],
			"Resource": "*"
		}
	]
}
```

![](assets/Pasted%20image%2020260418174613.png)


Luego deberemos crear una instancia EC2 y crear un Rol IAM

- El rol EC2 le permite a tu instancia **registrarse y mantenerse conectada a SSM** para poder recibir comandos.

![](assets/Pasted%20image%2020260418175152.png)

Con el permiso:

![](assets/Pasted%20image%2020260418175204.png)


Y desde las configuraciones de la instancia modificaremos el rol para poner el que creamos:

![](assets/Pasted%20image%2020260418183252.png)



## Conectando a instancia EC2:


Ahora me tengo que conectar a la instancia de EC2.

- Aqui clonaremos el proyecto e instalaremos todas sus dependencias necesarias.
- Adicionalmente crearemos un script que usara github actions para automatizar el despliegue del proyecto:

```bash
[ec2-user@ip-10-0-3-74 aero-api]$ nano /home/ec2-user/deploy.sh
[ec2-user@ip-10-0-3-74 aero-api]$ cat /home/ec2-user/deploy.sh
#!/bin/bash
source /home/ec2-user/.nvm/nvm.sh
cd /home/ec2-user/app/aero-api
git pull origin main
npm ci
npm run build
pm2 restart aero-api
```

- También necesitamos levantar el cliente SSM para poder recibir comandos:

```bash
sudo systemctl enable amazon-ssm-agent sudo systemctl start amazon-ssm-agent
```

Y por ultimo necesitamos crear un proceso de PM2 para dejar vivo el proceso:

- PM2 mantiene vivo el proceso, si crashea lo vuelve a levantar, si la EC2 se reinicia vuelve a levantar el proyecto y guarda los logs:

```bash
[ec2-user@ip-10-0-3-74 aero-api]$ ls
README.md  dist  docker-compose.yml  eslint.config.mjs  nest-cli.json  node_modules  package-lock.json  package.json  pnpm-lock.yaml  src  test  tsconfig.build.json  tsconfig.json
[ec2-user@ip-10-0-3-74 aero-api]$ cd /home/ec2-user/app/aero-api
[ec2-user@ip-10-0-3-74 aero-api]$ npm run build

> aero@0.0.1 build
> nest build

[ec2-user@ip-10-0-3-74 aero-api]$ pm2 start dist/main.js --name aero-api
[PM2] Starting /home/ec2-user/app/aero-api/dist/main.js in fork_mode (1 instance)
[PM2] Done.
┌────┬─────────────┬─────────────┬─────────┬─────────┬──────────┬────────┬──────┬───────────┬──────────┬──────────┬──────────┬──────────┐
│ id │ name        │ namespace   │ version │ mode    │ pid      │ uptime │ ↺    │ status    │ cpu      │ mem      │ user     │ watching │
├────┼─────────────┼─────────────┼─────────┼─────────┼──────────┼────────┼──────┼───────────┼──────────┼──────────┼──────────┼──────────┤
│ 0  │ aero-api    │ default     │ 0.0.1   │ fork    │ 33176    │ 0s     │ 0    │ online    │ 0%       │ 25.9mb   │ ec2-user │ disabled │
└────┴─────────────┴─────────────┴─────────┴─────────┴──────────┴────────┴──────┴───────────┴──────────┴──────────┴──────────┴──────────┘
[ec2-user@ip-10-0-3-74 aero-api]$ pm2 save
[PM2] Saving current process list...
[PM2] Successfully saved in /home/ec2-user/.pm2/dump.pm2
```

Por ultimo, en nuestro proyecto deberemos crear una carpeta `.github/workflows` y crear un nuevo Workflow que va a ser el flujo de despliegue:

```yaml
name: Deploy to EC2

  

on:
  push:
    branches: [main]


permissions:
  id-token: write
  contents: read


jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
      - name: Configure AWS credentials via OIDC
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::535002880672:role/github-actions
          aws-region: us-east-1
      - name: Deploy via SSM
        run: |
          COMMAND_ID=$(aws ssm send-command \
            --instance-ids "${{ vars.EC2_INSTANCE_ID }}" \
            --document-name "AWS-RunShellScript" \
            --parameters 'commands=["sudo -u ec2-user bash /home/ec2-user/deploy.sh"]' \
            --query "Command.CommandId" \
            --output text)

  
          aws ssm wait command-executed \
            --command-id "$COMMAND_ID" \
            --instance-id "${{ vars.EC2_INSTANCE_ID }}" || true
  

          aws ssm get-command-invocation \
            --command-id "$COMMAND_ID" \
            --instance-id "${{ vars.EC2_INSTANCE_ID }}" \
            --query "StandardErrorContent" \
            --output text

          STATUS=$(aws ssm get-command-invocation \
            --command-id "$COMMAND_ID" \
            --instance-id "${{ vars.EC2_INSTANCE_ID }}" \
            --query "Status" --output text)

          echo "Deploy status: $STATUS"
          [ "$STATUS" = "Success" ] || exit 1

      - name: Notify on failure
        if: failure()
        run: echo "::error::Deploy failed — revisar logs de SSM"
```

Ahora desde los ajustes del repositorio en github deberemos configurar nuestros secretos y variables:

- En este caso el Workflow utiliza como variables el ID de la instancia y la region:

![](assets/Pasted%20image%2020260418183611.png)

## Problemas comunes:

- La region utilizando letras como a o b
- Paths del proyecto mal escrita
- Si la instancia no tiene muchos recursos el workflow puede mostrar fallido, pero en los cambios si que se subieron y el proyecto se actualizo, debo de checar eso manualmente.
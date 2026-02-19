## Machine Browsed (Active) [Medium]

lets start with an nmap scan: 
```
    ❯ nmap -T4 -F -sV 10.129.3.5
    Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-19 23:24 +0100
    Nmap scan report for 10.129.3.5
    Host is up (0.57s latency).
    Not shown: 98 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    nginx 1.24.0 (Ubuntu)
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 14.44 seconds

```

alright, so a web interface and an ssh port;

lets check on the web interface:\
![alt text](image.png)\
from here we can identify 2 intresting pages : \
/samples.html \
![alt text](image-1.png)\
and /upload.php\
![alt text](image-2.png)\
lets take a look at them one by one and analyze their behaviour:
for /sample.html u basically dowanload extensions, lets check upload.php\
![alt text](image-3.png)\
what it apparently does is try the extension zip file, so we prolly can inject something in that extension file that could grant us shell or anything useful
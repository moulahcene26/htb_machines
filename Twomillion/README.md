## Machine TwoMillion [EASY]

Im doing it adventure mode so no hints no guidance
nmap scan:
```
❯ nmap -sV -T4 10.129.9.112
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-02 22:41 +0100
Nmap scan report for 10.129.9.112
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.72 seconds
```

alr so http + ssh;\
let's check:
![alt text](image.png)\
let's check one by one\
so there's ``` http://2million.htb/invite ``` with this :\
![alt text](image-1.png)\
alr lets try a login:\
so i dont have any creds and i can't create an account (no signup page)\

after a long time of being stuck, i tried a directory scan and got register:\
![alt text](image-2.png)\
but it still asks for an invite code\
after viewing the source code i find this js file ```inviteapi.min.js``` and this is its code :
```
eval(function(p, a, c, k, e, d) {
    e = function(c) {
        return c.toString(36)
    }
    ;
    if (!''.replace(/^/, String)) {
        while (c--) {
            d[c.toString(a)] = k[c] || c.toString(a)
        }
        k = [function(e) {
            return d[e]
        }
        ];
        e = function() {
            return '\\w+'
        }
        ;
        c = 1
    }
    ;while (c--) {
        if (k[c]) {
            p = p.replace(new RegExp('\\b' + e(c) + '\\b','g'), k[c])
        }
    }
    return p
}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}', 24, 24, 'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'), 0, {}))

```
so let's see if we can do something with this code:\
idk what this does, but there's like names of functions, like ` verifyInviteCode ` and ` makeInviteCode ` let's try them in the console :\
![alt text](image-3.png)\
it does give me the autocomplete, let's see if it gives me an invite code:\
![alt text](image-4.png)\
looks like rot 13 text, it translates to this:\
` In order to generate the invite code, make a POST request to /api/v1/invite/generate `\
alr lets try it:\
i get this : 
```
{"0":200,"success":1,"data":{"code":"TTk5QUMtVzRFSVotQUEwUkktS1JVODE=","format":"encoded"}}
```
its a b64 that decoded to ` M99AC-W4EIZ-AA0RI-KRU81 `,
lets use it to register:\
done, now we login:\
![alt text](image-5.png)\
oh this is big, really, let's see\
so all of these are fake buttons except for ``` access , changelog, rules ```\
let's check them out: \
nothing really interesting in rules, lets check changelog, so there's a lot of logs, there's ones marked as bugs, let's read them there might be something as a hint that we could use prolly:\
there's this one that seems ineteresting : \
```
[*] Security Bug [reported by makelarisjr]: Shoutbox API information disclosure.
A bug in the shoutbox API could allow an individual to acquire information about other members.
```
we try to get info about admin, let's keep it in mind and let's check the access page:\
![alt text](image-6.png)\
we got some stuff going on. the buttons download openvpn download configs, im already connected to the htb vpn so it doesn make sense to connect to these, they're prolly invalid too, let's see if there's anything else we could use:\
so ```/api/v1/user/vpn/regenerate``` is where it downloads, so let's look at the documentation of the api first:\
(```/api/v1```) \
we get this:\
![alt text](image-7.png)\
this is promising : ` /api/v1/admin/settings/update `\
i get this back ( when i give it nothing):\
`{"status":"danger","message":"Invalid content type."}`
so we need to get the format of how the request should be :\
so we make the content application/json:\
it asks for email now:\
lets try to give it the email :\
and i get this:
```
"status":"danger","message":"Missing parameter: is_admin"
```
so lets make is_admin=1 and get admin prolly:\
returned this:
```
{"id":13,"username":"testUser","is_admin":1}
```
we prolly got admin, lets refresh and see:\
nothing different on the website, let's see if we can do post to admin's vpn and stuff like that:\
i get this:
```
{"status":"danger","message":"Missing parameter: username"}
```
let's keep doing it until we get all the fields:\
and yes, we get it:\
```
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
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
2iX/ag==
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=UK, ST=London, L=London, O=HackTheBox, OU=VPN, CN=2million/emailAddress=info@hackthebox.eu
        Validity
            Not Before: Mar  3 02:14:13 2026 GMT
            Not After : Mar  3 02:14:13 2027 GMT
        Subject: C=GB, ST=London, L=London, O=testUser, CN=testUser
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:bc:d6:8c:d9:61:2c:8b:09:f7:96:1c:b0:1f:2c:
                    43:a2:27:32:dd:a9:2e:48:9d:3e:c8:7f:6c:57:41:
                    28:07:65:a7:3c:a6:89:39:8c:2c:c8:76:7d:85:c1:
                    a6:9e:26:c2:d7:41:07:4a:47:9b:0f:c7:9c:fa:56:
                    cb:9f:5a:d2:42:4b:bc:ef:12:62:b4:83:25:b1:ca:
                    35:a7:63:47:b6:6e:f6:94:18:20:e5:61:48:e4:b1:
                    50:c2:71:b4:94:d6:19:fd:1e:3e:03:92:4b:00:db:
                    4a:04:ad:1e:eb:f7:a0:1d:41:34:3f:71:f6:b7:3c:
                    4f:9d:0d:9f:ab:1e:0a:e1:63:ab:28:9b:a7:49:66:
                    25:9e:6e:ef:e8:55:0f:46:e3:17:e4:b5:bb:3a:d6:
                    ae:9c:0c:71:33:09:16:a2:df:c5:cc:06:0f:28:1a:
                    0e:51:98:97:0d:b2:2c:d8:5e:22:b0:f6:53:df:b1:
                    cd:8b:6c:ac:3d:ce:51:eb:9b:22:00:f7:4c:fc:20:
                    40:57:9a:47:d3:06:bc:1b:87:42:63:9f:70:38:06:
                    e4:3e:a7:91:ee:a4:8e:19:15:b6:0d:57:98:83:dc:
                    3b:ad:50:3d:76:59:2e:90:b3:6f:34:d0:c4:03:81:
                    0f:c8:f3:cd:a0:81:71:a2:ff:62:da:f6:ac:9f:ab:
                    91:93
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                1F:45:19:8B:82:D4:64:F9:2C:5F:2B:11:EF:3E:FE:AB:A5:5C:E6:E8
            X509v3 Authority Key Identifier: 
                7A:62:DD:1D:B6:FE:4A:C8:E3:F8:9F:FA:AC:F4:15:0C:96:BA:2E:91
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Key Usage: 
                Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign
            Netscape Comment: 
                OpenSSL Generated Certificate
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        44:bc:66:9a:b7:f2:fe:08:f5:90:c8:af:d5:4c:71:91:e6:dd:
        11:9f:93:da:d1:c4:d8:ff:6e:8d:af:6f:2e:84:8d:52:51:bc:
        db:b2:9b:84:fa:9f:ac:73:c8:e0:11:5f:4b:0f:ef:e2:f3:71:
        80:75:0f:4a:6e:55:b6:1e:9b:7c:2a:35:e1:45:91:6f:c6:be:
        c8:f1:ee:90:31:54:a9:33:ef:2f:ef:e2:03:01:d5:a4:a9:93:
        23:b1:5d:ed:c5:b1:8d:ec:55:5d:5a:54:7a:76:13:8e:e3:b5:
        97:eb:2d:4c:c0:ce:93:75:2e:1c:c6:c8:88:34:30:c8:8d:08:
        5c:2c:6c:e1:f5:66:0e:4c:8e:75:46:37:11:f1:ae:bd:95:c3:
        a4:f4:1f:b3:81:f0:a3:c9:3a:e4:cd:2a:2a:eb:cb:cb:ba:27:
        f7:a7:18:17:f7:be:0e:de:4b:3b:7d:36:78:e5:3d:6c:02:25:
        0b:d3:40:4d:40:a5:73:ca:2a:f2:f8:14:7f:bc:5d:1d:97:e7:
        a1:f6:17:ed:dc:3f:b5:53:a5:39:7b:f0:3f:ae:d9:0c:d9:21:
        ec:72:ad:a4:27:a7:23:98:90:2c:1c:f1:83:47:9c:94:1b:e2:
        3a:fe:aa:23:16:8e:01:5f:92:0b:58:3f:58:a3:6b:d0:f0:e3:
        43:9e:ba:1d:ec:c7:37:d0:69:c3:d0:60:91:e7:3c:26:f7:97:
        43:2e:ec:f2:d4:19:56:9a:8a:14:38:1c:d1:ed:6e:89:dc:a2:
        4c:58:88:c7:ed:57:aa:72:59:88:f2:ae:47:23:19:10:1d:94:
        57:bc:30:25:b3:47:a0:b9:69:b1:f2:62:cf:00:f6:ea:c7:5d:
        06:fa:68:9a:b9:f5:ff:9c:ff:6e:64:bd:c5:0e:bc:31:54:aa:
        de:75:09:fb:e7:fd:8f:1a:30:ea:75:1a:eb:55:4b:86:58:b1:
        56:e3:f2:99:31:77:b1:e4:45:e2:90:9b:5a:52:2f:01:56:15:
        9f:b9:0a:9c:ff:49:74:bb:59:80:7d:d5:4f:7b:44:42:70:da:
        5f:fd:67:e6:37:8d:fa:4b:e3:89:93:1a:69:ed:68:71:39:27:
        19:0f:eb:a7:e5:34:ce:cf:11:e6:51:18:6d:65:fa:86:b8:4e:
        b5:18:40:11:ce:83:01:08:fa:db:66:f0:eb:23:18:85:90:9e:
        cb:e4:37:91:7d:30:24:0d:ac:18:3c:e4:31:6a:8f:b9:41:f3:
        69:43:f6:9d:f1:51:c3:7c:34:b6:34:95:c6:80:88:3c:9f:01:
        dd:bf:e1:1f:70:bc:dc:fe:27:46:7c:d5:03:0e:98:cd:4c:ff:
        67:69:b0:74:b8:ba:06:cc
-----BEGIN CERTIFICATE-----
MIIE4zCCAsugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVUsx
DzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMRMwEQYDVQQKDApIYWNr
VGhlQm94MQwwCgYDVQQLDANWUE4xETAPBgNVBAMMCDJtaWxsaW9uMSEwHwYJKoZI
hvcNAQkBFhJpbmZvQGhhY2t0aGVib3guZXUwHhcNMjYwMzAzMDIxNDEzWhcNMjcw
MzAzMDIxNDEzWjBVMQswCQYDVQQGEwJHQjEPMA0GA1UECAwGTG9uZG9uMQ8wDQYD
VQQHDAZMb25kb24xETAPBgNVBAoMCHRlc3RVc2VyMREwDwYDVQQDDAh0ZXN0VXNl
cjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALzWjNlhLIsJ95YcsB8s
Q6InMt2pLkidPsh/bFdBKAdlpzymiTmMLMh2fYXBpp4mwtdBB0pHmw/HnPpWy59a
0kJLvO8SYrSDJbHKNadjR7Zu9pQYIOVhSOSxUMJxtJTWGf0ePgOSSwDbSgStHuv3
oB1BND9x9rc8T50Nn6seCuFjqyibp0lmJZ5u7+hVD0bjF+S1uzrWrpwMcTMJFqLf
xcwGDygaDlGYlw2yLNheIrD2U9+xzYtsrD3OUeubIgD3TPwgQFeaR9MGvBuHQmOf
cDgG5D6nke6kjhkVtg1XmIPcO61QPXZZLpCzbzTQxAOBD8jzzaCBcaL/Ytr2rJ+r
kZMCAwEAAaOBiTCBhjAdBgNVHQ4EFgQUH0UZi4LUZPksXysR7z7+q6Vc5ugwHwYD
VR0jBBgwFoAUemLdHbb+Ssjj+J/6rPQVDJa6LpEwCQYDVR0TBAIwADALBgNVHQ8E
BAMCAf4wLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmlj
YXRlMA0GCSqGSIb3DQEBCwUAA4ICAQBEvGaat/L+CPWQyK/VTHGR5t0Rn5Pa0cTY
/26Nr28uhI1SUbzbspuE+p+sc8jgEV9LD+/i83GAdQ9KblW2Hpt8KjXhRZFvxr7I
8e6QMVSpM+8v7+IDAdWkqZMjsV3txbGN7FVdWlR6dhOO47WX6y1MwM6TdS4cxsiI
NDDIjQhcLGzh9WYOTI51RjcR8a69lcOk9B+zgfCjyTrkzSoq68vLuif3pxgX974O
3ks7fTZ45T1sAiUL00BNQKVzyiry+BR/vF0dl+eh9hft3D+1U6U5e/A/rtkM2SHs
cq2kJ6cjmJAsHPGDR5yUG+I6/qojFo4BX5ILWD9Yo2vQ8ONDnrod7Mc30GnD0GCR
5zwm95dDLuzy1BlWmooUOBzR7W6J3KJMWIjH7VeqclmI8q5HIxkQHZRXvDAls0eg
uWmx8mLPAPbqx10G+miaufX/nP9uZL3FDrwxVKredQn75/2PGjDqdRrrVUuGWLFW
4/KZMXex5EXikJtaUi8BVhWfuQqc/0l0u1mAfdVPe0RCcNpf/WfmN436S+OJkxpp
7WhxOScZD+un5TTOzxHmURhtZfqGuE61GEARzoMBCPrbZvDrIxiFkJ7L5DeRfTAk
DawYPOQxao+5QfNpQ/ad8VHDfDS2NJXGgIg8nwHdv+EfcLzc/idGfNUDDpjNTP9n
abB0uLoGzA==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC81ozZYSyLCfeW
HLAfLEOiJzLdqS5InT7If2xXQSgHZac8pok5jCzIdn2FwaaeJsLXQQdKR5sPx5z6
VsufWtJCS7zvEmK0gyWxyjWnY0e2bvaUGCDlYUjksVDCcbSU1hn9Hj4DkksA20oE
rR7r96AdQTQ/cfa3PE+dDZ+rHgrhY6som6dJZiWebu/oVQ9G4xfktbs61q6cDHEz
CRai38XMBg8oGg5RmJcNsizYXiKw9lPfsc2LbKw9zlHrmyIA90z8IEBXmkfTBrwb
h0Jjn3A4BuQ+p5HupI4ZFbYNV5iD3DutUD12WS6Qs2800MQDgQ/I882ggXGi/2La
9qyfq5GTAgMBAAECggEAAyuMfiwhP4BLIlj+8YPTt6NcbKSZCbaiEpZl1Wn0zkYv
MleoknyMIx1iHatSxorno6dy0OHQDf0pR6z9vbVPnE9OYt3cv4nU4yqXqTGDra6O
zMB1WB4NYQSp0p0IDaUxsH8gEv1GU90nXY0hqY8+cxJ6JxDptfySm/qNK9k7drpa
WvrcHQk/SVUoQOa8qMw8GxQyGYNhVCTnq3XQeLpVpOXd3baHJXj31dYoOqX3gtvF
Y/2fJLYXmBSSsONEen9fDzbND0Ad23E3RYIKuVuYxeXiYJee2sxJgaYzVyp0JK2h
08j7XaaL2ZbD45JlKEf9g28rGQALjmPeUWS1YCJJyQKBgQD9to3BOv/AJGvQZ10X
/ATJ36HtZ8sRlKjJlVwxq87z+OSLCHXEtZIM6v/S9JASJrnCLuOD+QhZHCIMtMss
LzxylWnCvgFRIUUq9MBfsr7MzZnc0rIwOqegXQE47+RANJdd4lrKCArpwJxmlklo
JaaqypW94aQVzIT7b4Muloe6nQKBgQC+ikvpJuM6BAffgHV8Q4pICWG2QFeZOv2w
X3t86/0MRIQLFeq7EQoZDK+60z0cfn16DwpV34q9YcMUhbPEQ/d0TW3gMyzVSlV7
S/roCvHrbtVk2aWPThXlDA1e94Y2reJqhERXr/F/R0SHWqiCeXwoiU7QLvBnC4ZK
1OXXSKXt7wKBgQCPZI3ZmC7TucH1l3XWCGnsbqhmNTNgTFTZGcFxkVj2KsWAjteA
xd41ztunrvF+UMTMKxQLksRVGMFlzQjHgCr519heaGT2JYeiL5JKhAuyVMGRPMPY
3k2/JNF8DJlEcHTcawJFDSad1m6OzIHQivcXsEfReaXzbBP8x5msywcLQQKBgEaM
2nKnzXbLy0Z8QAQU1fy6TI244TaBWzGVCRpGHtoN/H5GTTWap4yC4AZi9Lu6Mieh
rggBz1M0AZF1uAwxxkwv50Eecbk/3sraZTrJ4q1zylufIuge14iJn+HL8MwKMk2S
T+PP57Fi6ALeFIrLBKfVv3LiDm15HO5USg4efiHNAoGBAM+M19hSd5kMfPqkpBvl
rlzmZBozyZM/lCEC6cWiOOqUNTuQ8PUA1HMvMKyZ8J8MY5wiYcqIMIchdkwQ+RF1
yfWzS7AYkp/2SARxi8PBcHZB55nHB3+JRU/zd41gyM+6/qg9bzN1ssKs/LsMnl8G
1LpErc/AoH9AkIqKV98Yzj4W
-----END PRIVATE KEY-----
</key>
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
45df64cdd950c711636abdb1f78c058c
358730b4f3bcb119b03e43c46a856444
05e96eaed55755e3eef41cd21538d041
079c0fc8312517d851195139eceb458b
f8ff28ba7d46ef9ce65f13e0e259e5e3
068a47535cd80980483a64d16b7d10ca
574bb34c7ad1490ca61d1f45e5987e26
7952930b85327879cc0333bb96999abe
2d30e4b592890149836d0f1eacd2cb8c
a67776f332ec962bc22051deb9a94a78
2b51bafe2da61c3dc68bbdd39fa35633
e511535e57174665a2495df74f186a83
479944660ba924c91dd9b00f61bc09f5
2fe7039aa114309111580bc5c910b4ac
c9efb55a3f0853e4b6244e3939972ff6
bfd36c19a809981c06a91882b6800549
-----END OpenVPN Static key V1-----
</tls-auth>

```
but this looks like an output of a command rather than file content:\
let's try command injection:\
![alt text](image-8.png)\
yep that's it:\
let's get user flag:\
before that i found a .env with this:
```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```
let's keep it in mind, anyways:\
these are the users:
```
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
www-data:x:33:33:www-data:/var/www:/bin/bash
pollinate:x:105:1::/var/cache/pollinate:/bin/false
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
admin:x:1000:1000::/home/admin:/bin/bash
memcache:x:115:121:Memcached,,,:/nonexistent:/bin/false
_laurel:x:998:998::/var/log/laurel:/bin/false
```
so its probably admin that we login to:\
and yep he used that password, and we got user!\
![alt text](image-9.png
let's do priv esc:\
when we got in the ssh, there was some writing at first : ` You have mail.`\
let's see what they mean:\
so with this : ` grep -r "@2million.htb" / 2>/dev/null  ` i find this email:\
```
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather

```
let's google the cve:\

right :\
![alt text](image-10.png)\
CVE-2023-0386\
we can use setuid, and give ourselves root:\
i found this website where i can follow instructions : https://www.vicarius.io/vsociety/posts/cve-2023-0386-a-linux-kernel-bug-in-overlayfs \
lets follow it\
and we got root:\
![alt text](image-11.png)\
SOLVED:\
![alt text](image-12.png)


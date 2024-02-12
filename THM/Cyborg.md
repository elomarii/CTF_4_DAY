# Cyborg
A box involving encrypted archives, source code analysis and more.

We are given the IP address of the machine which will be refered to as $IP in the following.

Lets start our `nmap` scan:
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
>> insert image

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

We were able to find two directories. Whene navigating to the admin portal, we find a downloadable Borg backup of the website called.
The archive is encrypted and needs a passphrase for decrypion.

Let's check the etc directory. This contains a configuration file of a Squid proxy and a passwd file.
The passwd file contains a hash of the `music_archive` user.
```
music_archive:$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.
```

We successfully crack the password using `hashcat` and the `rockyou` wordlist. The password is `squidward`.

```
$ hashcat -m 1600 -a 0 hash /usr/share/wordlists/rockyou.txt 

<snip>

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 7 secs

$apr1$BpZ.Q.1m$F0qqPwHSOG50URuOVQTTn.:squidward

<snip>

```



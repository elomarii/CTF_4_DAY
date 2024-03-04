# Nax
Identify the critical security flaw in the most powerful and trusted network monitoring software on the market, that allows an user authenticated execute remote code execution.

---
### Resolution

Nmap verison and default scripts scan:
```
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 62:1d:d9:88:01:77:0a:52:bb:59:f9:da:c1:a6:e3:cd (RSA)
|   256 af:67:7d:24:e5:95:f4:44:72:d1:0c:39:8d:cc:21:15 (ECDSA)
|_  256 20:28:15:ef:13:c8:9f:b8:a7:0f:50:e6:2f:3b:1e:57 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: ubuntu.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN
| ssl-cert: Subject: commonName=ubuntu
| Not valid before: 2020-03-23T23:42:04
|_Not valid after:  2030-03-21T23:42:04
|_ssl-date: TLS randomness does not represent time
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
389/tcp open  ldap     OpenLDAP 2.2.X - 2.3.X
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=192.168.85.153/organizationName=Nagios Enterprises/stateOrProvinceName=Minnesota/countryName=US
| Not valid before: 2020-03-24T00:14:58
|_Not valid after:  2030-03-22T00:14:58
|_http-title: Site doesn't have a title (text/html).
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: Host:  ubuntu.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Both web apps have the same content. Visiting the website we find a suspecious welcoming expression:
```
<...snip...>
                  Welcome to elements.
					Ag - Hg - Ta - Sb - Po - Pd - Hg - Pt - Lr
```
The symbols refer to periodic elements, based on the atomic number we end up with the following list `[47, 80, 73, 51, 84, 46, 80, 78, 103]`. If we interpret the numbers as ascii characters we get `/PI3T.PNg`. Is this the hidden file? yep it is.

We download that image to inspect it more. We can use `exiftool` to read the image's metadata:
```
$ exiftool PI3T.PNg 

<...snip...>
Palette                         : (Binary data 768 bytes, use -b option to extract)
Transparency                    : (Binary data 256 bytes, use -b option to extract)
Artist                          : Piet Mondrian
Copyright                       : Piet Mondrian, tryhackme 2020
Image Size                      : 990x990
Megapixels                      : 0.980
```

There we have our author name as the artist.

For the next step, a username is required. A username of what service? we can fuzz the web application for more directories. Spoil alert: the room is about Nagios so we expect it to be in the results.
```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://<machine_ip>/FUZZ"               

<...snip...>
javascript              [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 41ms]
nagios                  [Status: 401, Size: 460, Words: 42, Lines: 15, Duration: 44ms]
```

Alternativly, the source code of the home page indicates a path `/nagiosxi/`
![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/57bcd0ba-e59a-403b-b095-71d762a053a8)

Navigating to `http://<machin_ip>/nagiosxi/`, we find a login page for the Nagios XI dashboard.\
The intuition based on the previous questions is to derive a username from the artist name "Pieter Cornelis Mondriaan". However this was a trap and has nothing to do with the next quesitons.\
If we take a look at what default usernames Nagios uses for its products, we find a list of potential answers, including the one we're looking for; the default Nagios admin username `nagiosadmin`.

Next, we try brute force our way to the dashboard using hydra:





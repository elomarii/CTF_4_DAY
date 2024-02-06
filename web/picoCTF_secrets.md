## Challenge
#### Description
We have several pages hidden. Can you find the one with the flag?

#### Hints
1- folders folders folders

## Resolution
From the description and the given hint, the first idea is to fuzz for other folders of the application and then maybe some files in these folders can lead to the flag.
Lets do it!!

We can use ffuf and the directory-list-2.3-medium.txt wordlist for this purpose.

```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u "http://saturn.picoctf.net:65455/FUZZ"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://saturn.picoctf.net:65455/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
secret                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 106ms]
                        [Status: 200, Size: 1023, Words: 201, Lines: 37, Duration: 115ms]

```

We were able to discover the secret folder, wonder what can we find inside. Let's fuzz again for entries using the common.txt wordlist.
```
$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt:FUZZ -u "http://saturn.picoctf.net:65455/secret/FUZZ" 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://saturn.picoctf.net:65455/secret/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

assets                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 108ms]
hidden                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 110ms]
index.html              [Status: 200, Size: 468, Words: 55, Lines: 13, Duration: 109ms]

```

This time we found two folders (plus index.html file), assets and hidden. The latter looks interesting so we'll look for its content.

By navigating to `http://saturn.picoctf.net:65455/secret/hidden/`, we find a login page. We can try login, maybe injecting some code, but unsuccessful. Let's inspect the source code of the page. We find that a js script is referenced `<link href="superhidden/login.css" rel="stylesheet" />`, and thus a folder named superhidden exists in the current path.

By navigating to `http://saturn.picoctf.net:65455/secret/hidden/superhidden`, we can find the flag by inspecting the source code of the page.

Result: picoCTF{succ3ss_@h3n1c@10n_39849bcf}






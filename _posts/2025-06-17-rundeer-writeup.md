---
title: "BTLO Rundeer Writeup"
date: 2025-06-17
---
Once the VM is running, there is a README.txt on the desktop; it contains the path to Volatility 3, which Python version to use for it, and the hostname of the compromised machine "frostbyte." With that we start!
# Q1) Using Volatility, find the file that led to Initial Access to the workstation. (Format: Filename.extension)
First I moved to the Artifacts directory that contained the memory dump in RAW format. Here I ran a series of commands with Volatility and output them to .txt files for further processing with other tools. The commands I ran were:

> [!NOTE]
> <details>
> <summary>Commands</summary>
> `python3.8 /path/to/volatility/vol.py -f FROSTBYTE.raw windows.cmdline > frostbyte_cmdline.txt` <br>
> Repeat and change both the windows module and the file name to the following: pslist, pstree, netscan, filescan, dlllist
> </details>

I started with the cmdline output to see what stood out. I ran the command 


`cat frostbyte_windows.cmdline.txt | awk '{print $2} | sort -fu`


to see what processes were running. From that list my initial interest was in WINWORD.EXE and powershell.exe. My next command was 


`grep -i winword.exe frostbyte_windows.cmdline.txt`


Immediately what caught my eye was the path in that output.

> [!NOTE]
> <details>
> <summary>Path</summary>
>C:\Users\Reindeer\Desktop\PendingInvoice.docm
> </details>

The file name brought to mind email scams so I typed in the name of the file and answered this first question correctly. To verify the answer I correlated information between the pstree and pslist outputs. WINWORD.EXE opened the file at 17:11:40 and spawned a powershell instance at 17:13:44. This first powershell then spawned a 2nd PS instance at 17:13:46. This 2nd instance executed the base64 encoded command in Q3.  

> [!NOTE]
> <details>
> <summary>Answer</summary>
> PendingInvoice.docm
> </details>

# Q2) Provide the name of the compromised user account. (Format: User)
The path in Q1 showed who the compromised user was.

> [!NOTE]
> <details>
> <summary> Answer </summary>
> Reindeer
> </details>

# Q3) A reverse shell activity took place, find the IP and associated port. (Format: IP, Port)
I started looking for the IP and port info in the windows.netscan output first. However there was no info there so I switched to the windows.cmdline output.


To take a look at the longer (and possibly malicious) commands I ran a 'sort' by line length


`cat cmdline.txt | awk '{print length, $0}' | sort -ns`


The longest lines at the bottom of the sort displayed a powershell command in base64. So I ran the command


`echo "[base64 from previous command]" | base64 -d` 


to get the decoded command. Here were the IP and port needed for the question.

> [!NOTE]
> <details>
> <summary> Answer </summary>
> 139.177.207.94, 8080
> </details>

# Q4) Analyze the given malware file and provide the category to which it best belongs. (Format: Category)
I started my analysis of conhost.exe in the Artifacts folder with Cutter RE. I ran `strings` on it with the same 'sort' command I ran on Q3.


`strings conhost.exe | awk '{print length, $0} | sort -ns' > conhost_strings.txt`


A few items stood out: "Error generating encryption key;" "Starting encryption process;" and "Encrypted: %s\n." All these were in both the `strings` output and Cutter RE's strings tab. With those strings there was only one malware category that came to mind.

> [!NOTE]
> <details>
> <summary> Answer </summary>
> ransomware
> </details>

# Q5) A component of the Windows workstation is being used for key creation in malware. Which API call is responsible for fetching it? (Format: API)
Getting this answer took a long time because I didn't understand 2 key pieces of information in the question: how wide a definition "component" could be and what form an API could take. 


To show you how confused I was I'll put a screenshot of my raw notes below. Only after reading an explanation on the difference between an API and a DLL on [stackoverflow](https://stackoverflow.com/questions/4365731/difference-between-api-and-dll) did I realize I had passed over the answer multiple times.

![rundeer raw notes indicating confusion | 600 ](https://github.com/ElOtroMano/pins_to_keys/blob/main/assets/images/rundeer_raw_notes.png)


As for how wide the definition of a component is I had conflated the idea of a workstation part used for encryption with that of it being a complicated part of the system. 


To locate the answer I scrolled through the imports in CutterRE. It made sense that this was THE computer component used for the encryption process. Verification came after I had done further analysis for Q6 and Q8.
> [!NOTE]
> <details>
> <summary> Answer </summary>
> GetComputerNameA
> </details>

# Q6) What extension is the malware adding to the files it is affecting? (Format: EXTENSION (without dot))
This one I got simply because I got lucky. I wasn't sure how to start searching for this answer so I started by browsing the disassembly tab in Cutter RE. From the "main" function I scrolled up a little to see what was happening before the this function started. Reviewing those lines revealed the answer.


However after coming back to the question to find a more reasoned path to the answer, I followed the decompiled code. The main function shows its encryption process; the strings in Q4 are easily visible here. In that section of code there is a subroutine between the "start" and "completion" strings of the encryption that, when decompiled, shows how it adds the answer string to the file. 
> [!NOTE]
> <details>
> <summary> Answer </summary>
> FROSTED
> </details>


A tip for using Cutter as a newbie: run the analysis with Advanced options to "Name function by context" and "Type and Argument Matching Analysis." This led to clearer (for me) decompiler instructions. 

# Q7) There was a key text file affected by malware. Find and dump it. Provide its MD5 hash. (Format: MD5 hash)
I returned to a review of the filescan output from Q1. Since I was looking for affected files and Q6 revealed the file extension, I ran


`grep -i frosted filescan.txt`


This brought up 2 files with that extension and their virtual memory addresses but I'm interested only in the one below:

`0xdf0a7ed9d690 \Users\Reindeer\Desktop\S3cr3t\README.txt.FROSTED`


To extract that file I needed to run an additional volatility command: 

> [!NOTE]
> <details>
> <summary> Command </summary>
> `python3.8 vol.py -f ~/Desktop/Artifacts/FROSTBYTE.raw windows.dumpfiles --virtaddr 0xdf0a7ed9d690 > ~/Desktop/Artifacts/README.txt.FROSTED`
> </details>


I then got its MD5 hash with the command 


`md5sum README.txt.FROSTED.dat`


> [!NOTE]
> <details>
> <summary> Answer </summary>
> c0917374705dabb04853940b04f651e9
> </details>

# Q8) You are tasked to decrypt the file. Analyze the malware and get the decryption key. (Format: decryption key, lowercase & ASCII)
From Q5 we know that a component of the encryption process is the API GetComputerNameA so that was my entry point for analysis. Since we are given the hostname "frostbyte" in the introduction to the investigation, we know the encryption uses that name as part of the encryption process.


![rundeer XOR |600](https://github.com/ElOtroMano/pins_to_keys/blob/main/assets/images/rundeer_XOR.png)


It took me some time to realize what an XOR process looked like when decompiled. After some research I realized that I was thinking of the mathematical symbol for exponents (look at your calculator); that symbol in this context meant XOR.

> [!NOTE]
> <details>
> <summary> XOR key </summary>
> 0x23


With that key I used Cyberchef to run the XOR function on the hostname "frostbyte" and provided the answer per the question's formatting: lowercase, ASCII. This detail is important for what happened in Q9.

> [!NOTE]
> <details>
> <summary> Answer </summary>
> eqlpwazwf

# 9) Decrypt the text file. Read the content. Who sent the information to the user, provide the name. (As per the content inside the text file) (Format: Name)
So with the decryption key I use Cyberchef again to decrypt the README from Q7 using the key from the last question. However I noticed that using the hostname in lower case led to an upper case decryption key. That upper case decryption key led to an incomplete decryption of the file with most of the letters in upper case. Using the decryption key in lower case as per Q8 results in a complete decryption with the answer.

> [!NOTE]
> <details>
> <summary> Answer </summary>
> Agent1337
> </details>

A huge thank you to @Mirthzna on Discord and their write up at https://mirthz.xyz/blog/rundeer-writeup/ for helping to guide my thinking.

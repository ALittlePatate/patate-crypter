# patate-crypter
I am not responsible for any damage caused by this program. It was made as a learning experiment to gather more knowledge about anti virus.<br>
The project structure is **very** messy because i wasn't planning on releasing it, sorry i guess.<br>
I will not provide any support for running the program, it is only made for people interested in cyber security to learn more about how AV work.
patate crypter officially supports 32bit and 64bit DLLs and PEs.<br>
Note that the final payload does not use any Windows API, indirect syscalls are used instead.<br>

# Limitations
There is an issue where the reallocations would fail for specific payloads, TOFIX.<br>
There is code in the `metadata.py` file to generate random BMP images in the metadata of the PE but it makes the entropy go way to high (from 6.4 to 7.4) (see [link](https://practicalsecurityanalytics.com/file-entropy/)).

# Detection rate
There is currently 0/40 detections for a crypted meterperter :
- [original meterpreter](https://www.kleenscan.com/scan_result/6ea55d54a947393082f524215c28185ef90a7ec9cb9c50f25c555715b61b0e3e)
- [crypted 32 bit](https://www.kleenscan.com/scan_result/0b867e81b96a21679161b2437fcf60233663fc6e95f0fd8e62fbdb3a8aad218c)
- [crypted 64 bit](https://www.kleenscan.com/scan_result/50eeb46c0ec822a1889cb8f195001ed56639d5aca0a8ef0557eca65f7c76e03d)

# How does it work ?
The crypter (compile time) works by :
- storing the raw bytes of the payload into a buffer (XOR encrypted)
- adding junk code/control flow flattening to the decryption stub
- copying a Windows file signature on the generated PE (using [SigThief](https://github.com/secretsquirrel/SigThief))

Then the stub (at runtime) :
- if a VM is detected, proceeds to compute 20k digits of pi before exiting
- decrypts the sections of the payload one by one and encrypts them back after copying them into the memory (bypasses ESET AV emulation)
- rebases the payload to its new base address
- calls (Dll)main

Here are screenshots of the same function before and after the obfuscation pass :<br>
Without obfuscation : <br>
![no_obfuscation](Screenshots/no_obfuscation.png)<br>
With obfuscation (only showing a few nodes, the original graph was more than 40K nodes) : <br>
![obfuscated](Screenshots/obfuscated.png)<br>

# How to run
```
cd Builder
python gui.py
```

# Credits
- [Alcatraz](https://github.com/weak1337/Alcatraz)
- [SigThief](https://github.com/secretsquirrel/SigThief)
- [What is file entropy](https://practicalsecurityanalytics.com/file-entropy/)
- [Direct syscalls vs indirect syscalls](https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls)
- some random gui on [xss](xss.is) who released a big article explaining the basics of cryptors. //TODO, find link
- [vx-underground's Blackmass Volume 2 (A Peek Into Antivirus Memory Scanning)](https://samples.vx-underground.org/Papers/Other/VXUG%20Zines/2022-11-13%20-%20Black%20Mass%20Halloween%202022.pdf)
- [pi spigot algorithm](https://craftofcoding.wordpress.com/tag/spigot-algorithm/)
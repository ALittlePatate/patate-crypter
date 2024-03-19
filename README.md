# patate-crypter
I am not responsible for any damage caused by this program. It was made as a learning experiment to gather more knowledge about anti virus.<br>
The project structure is **very** messy because i wasn't planning on releasing it, sorry i guess.<br>
I will not provide any support for running the program, it is only made for people interested in cyber security to learn more about how AV work.

# Limitations
patate crypter officially supports 32bit DLLs and PEs. It might be possible to add x64 bit support without too much issues, but i never tried, maybe one day.<br>
There is an issue where the reallocations would fail for specific payloads, TOFIX.<br>
There is code in the `metadata.py` file to generate random BMP images in the metadata of the PE but it makes the entropy go way to high (from 6.4 to 7.4) (see [link](https://practicalsecurityanalytics.com/file-entropy/)).

# Detection rate
There is currently 0/40 detections for a crypted meterperter :
- [original meterpreter](https://www.kleenscan.com/scan_result/6ea55d54a947393082f524215c28185ef90a7ec9cb9c50f25c555715b61b0e3e)
- [crypted](https://www.kleenscan.com/scan_result/697277eeddc7cf01ffc81430e3c549488e3a96970edb9ec8d96860d9135eac54)

# How does it work ?
The crypter (compile time) works by :
- storing the raw bytes of the payload into a buffer (XOR encrypted)
- adding junk code/control flow flattening to the decryption stub
- copying a Windows file signature on the generated PE (using [SigThief](https://github.com/secretsquirrel/SigThief))

Then the stub (at runtime) :
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

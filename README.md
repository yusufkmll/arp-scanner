# ARP scanner

This program sends ARP requests to all of the IP adresses specified in "config.txt" file in <a target="_blank" href="https://whatismyipaddress.com/cidr">CIDR</a> format.

๐พ To install this program 
```bash
$ sudo make install
```

๐  To configure IP adresses
```
$ sudo make config
```

๐โโ๏ธ To run the program
```
$ sudo arpscanner "ifname"
```
๐งน To delete the program
```
$ sudo make clean
```

โ ๏ธ  : <span style="color: yellow;">This program has no format control in file reading operation yet. Be careful to write IP adresses in appropriate format.</span>

๐ : This program will not change source IP address if the interface is "wlo1"

โ : <span style="color: lime;">Format control will be added in future releases</span>


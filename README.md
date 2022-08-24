# ARP scanner

This program sends ARP requests to all of the IP adresses specified in "config.txt" file in <a href="https://whatismyipaddress.com/cidr">CIDR</a> format.

💾 To install this program 
```bash
$ sudo make install
```

🛠 To configure IP adresses
```
$ sudo make config
```

🏃‍♂️ To run the program
```
$ sudo arpscanner "ifname"
```
🧹 To delete the program
```
$ sudo make clean
```

⚠️  : <span style="color: yellow;">This program has no format control in file reading operation yet. Be careful to write IP adresses in appropriate format.</span>

📝 : This program will not change source IP address if the interface is "wlo1"

✅ : <span style="color: lime;">Format control will be added in future releases</span>


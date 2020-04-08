# WifikeyDecryptor
decrypt all of the wifi key interface Profile in Windows

All the passwords of the wireless networks you are connected, stored in the interfaced folder in X:\ProgramData\Microsoft\Wlansvc\Profiles.
All the information discussed hence forth will apply only to Vista and higher operating systems only.
As we know already, each wireless settings are stored in XML file. Here is the actual contents of one such file,
```
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
<name>wifiname</name>
<SSIDConfig>
<SSID>
<hex>536563757269747958706C6F646564</hex>
<name>SecurityXploded</name>
</SSID>
<nonBroadcast>false</nonBroadcast>
</SSIDConfig>
<connectionType>ESS</connectionType>
<connectionMode>auto</connectionMode>
<autoSwitch>false</autoSwitch>
<MSM>
<security>
<authEncryption>
<authentication>WPAPSK</authentication>
<encryption>AES</encryption>
<useOneX>false</useOneX>
</authEncryption>
<sharedKey>
<keyType>passPhrase</keyType>
<protected>true</protected>
<keyMaterial>password</keyMaterial>
</sharedKey>
</security>
</MSM>
</WLANProfile>
```
Each Wireless profile mainly stores information about WiFi name, security settings such as authentication, encryption and the encrypted password. Here each wireless device is represented by its interface GUID {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} and all the wireless settings for this device are stored in XML file with random GUID name.
```
C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}\{Random-GUID}.xml
```
The tools that decrypt the wireless key Only get the values key inside the current interface and perform their operations on it.
But every time you try to remove the interface or use another wireless network card and... A new interface folder is created in the interfaces folder.

![alt text](https://filestore.community.support.microsoft.com/api/images/260de800-6f70-447c-8d7c-961a14ec8399)
this tool first obtains the encrypted keys in all interfaces that have been created in the past, and then decrypts them.

Run Program as administrator for Decrypt Key and show them :)

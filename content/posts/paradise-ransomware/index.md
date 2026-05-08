+++
date = '2026-05-05T16:09:41+03:00'
title = 'Paradise Ransomware'
+++
# Executive summary
The analyzed sample named "paradise.exe" is a 32-bit windows excutable that encrypts everything on the host.The sample establish presistence via windows startup folder and disable windows defender by editing registry.

# File Identification
* **Filename :** paradise.exe  
* **File Size :** 334 KB  
* **Architecture :** PE32 (x86)  
* **Compiler Stamp :** 2019-12-08 19:42:38  
* **MD5 :** 9ac8c2482e25dab49befb711172924f7  
* **SHA-256 :** c12b75f4b1bfcf41c45666f9a3801b735653c7ea61d14c3b700e60c035f55b32  
* **SHA-1 :** dbc38594cd2e6ab7ae0f2ab7dfdb023d73e6c1c9
* **BASE :** 0x0400000


# Static Analysis
### PE & Sections
The sample has 5 sections  
|Section|Size|
|-------|----|
|.text  |15000|
|.data  |2000 |
|.rsrc  |8000 |
|.py    |10000|
|.py    |15000|  

### Imports & Strings
All imports are destroyed, No interesting strings either so it idicactes the malware is packed.


# Dynamic Analysis
When running the malware it asks for administration access,if we gave it the access it encrypts every thing in our pc and rename them and adds .tor as extenstion.  
![alt text](image-3.png)
The malware makes a file called 
"---==%$$$OPEN_ME_UP$$$==---.txt" in every folder.  
if we opened "---==%$$$OPEN_ME_UP$$$==---.txt" it opens multiple windows of notepad and all displaying the same text    

"WHAT HAPPENED!
Your important files produced on this computer have been encrypted due a security problem.
If you want to restore then write to the online chat.
 
 
Contact!
Online chat: http://prt-recovery.support/chat/25-decryptor
Your operator: decryptor
Your personal ID: uudl5W
 
Enter your ID and e-mail in the chat that you would immediately answered.
 
 
Attention!
Do not rename encrypted files.
Do not try to decrypt your data using third party software, it may cause permanent data loss.
Do not attempt to use the antivirus or uninstall the program.
This will lead to your data loss and unrecoverable.
Decoders of other users is not suitable to decrypt your files - encryption key is unique."  


![alt text](image-1.png)  
the personal ID changes everytime you run the malware.  
The malware drops a file in the startup path "C:\Users\Malware\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" it has a random name in my case it's "qkHQv9K52orENSR8a2q.exe" with the same size probably a copy of the malware.  
![alt text](image-2.png)
The malware delete itself from the host and relies on the copy in the startup folder,everytime we reboot the host the copy asks for administration access.

# Reverse Engineering & Code Analysis
When we open the code in ida we find nothing much as the malware is packed,there is a tale jump at the end of the start function at address **0x04040CC**
![alt text](image-4.png)
After we debug in x32dbg we find that the malware allocates memory in a remote location and copies the subroutine at address 0x04040CE
to that remote location as a secound stage unpacker.  
This subroutine rewrite the .txt in the original malware sample and that's the real code.
after rewriting the the .text the code jumps to the sample again at address 0x04031E0
when we hit address 0x04031E0 the first subroutine call is loading libraries and storing apis in memory
![alt text](image-5.png)
![alt text](image-6.png)
* **1-** is for getting the apis  
* **2-** is for storing it in memory

then the malware calls a subroutine sub_401C10 it loads resource from memory turns out this resource is the public key of RSA 2048-bit
![alt text](image-7.png)
![alt text](image-8.png)
in Big-Endian it's  
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1b5lZMEyJhN1nRSUgKdy
SR8ahvSt5TdB3J2HqU/9SoFiiQVKM9NsUP+EwL7yiN/zzps1chU2n6yWLbluNIWY
NbwT+fekGUbf4COkvJzRVxQmREuJjpcjg2IZV1dpka7+fPcYbQ1uTbRG1LobNBPa
KMZVK6UEzO0twt9K1fv2crvnPiuGBbjKwL4fl6R3DvpPK3V+M3mhMnnqoTGWGo+w
kBl7FhZXwD8aiTzlv71p8c7xV3YV9zfzP7ANDPXq+5JtYOUwrLPWKrtgUaGjdKGU
potpRoz5weuPL1S9Y19EZgT5GZZsePCl+quvX4xdradqGKtmeeM3yDwQJbm0hTzu
LQIDAQAB
-----END PUBLIC KEY---  
After this subroutine the malware gets the default language and compare it to the following languages  
|Hex Code|Decimal|Language|Locale Name|
|--------|-------|--------|-----------|
|43Fh    |1087   |Kazakh  |kk-KZ      |
|419h    |1049   |Russian |ru-RU      |
|423h    |1059   |Belarusian| be-BY   |
|422h    |1058   |Ukrainian |uk-UA    |
|444h    |1092   |Tatar     |tt-RU    |
![alt text](image-9.png)
if any of these languages it enters sub_402860 which deletes the malware and exits the process
![alt text](image-10.png)
![alt text](image-11.png)
If not it enters sub_402E60
## sub_402E60
It is the core of the malware first thing in this subroutine that it calls another function sub_4028F0 
### sub_4028F0
in this function first it checks for the process privilage ![alt text](image-12.png)  
if it has no administration privilage it run it asks to run itself as administration ![alt text](image-13.png)  


after sub_4028F0 we go back to sub_402E60 it's intializing RSA using **CryptAcquireContextW**, then the function calls 
sub_401780.
### sub_401780
The function starts by asking the OS for Crypto keys using **CryptGenKey** ![alt text](image-17.png).
Then at **0x04017EE** the malware exports the public key using **CryptExportKey** and by passing **6** as **dwBlobType** ![alt text](image-18.png)
by inspecting ESI where the key is exported we can get the RSA length and it's 1024-bit RSA ![alt text](image-20.png)
and then it calls **CryptExportKey** with **7** as **dwBlobType** to export the private key ![alt text](image-19.png)  


So the malware uses RSA 1024-bit to encrypt files and then it encrypts the private key with the hardcoded RSA 2048-bit.  
We can get the private key of the RSA 1024-bit but it's unique for every host so if we got the key we can decrypt only one host.  
To decrypt all hosts we should get the private key of RSA 2048-bit and it's only with the author not in the binary.  


Then the malware imports first the public and private key of RSA 1024-bit into **CSP**.  
![alt text](image-21.png)
The first call is to import the public and private key of the RSA 1024-bit,The secound call is to import the public master key of the RSA 2048-bit.  
Then the malware uses **CryptEncrypt** to encrypts the private key of RSA 1024-bit using the public key of RSA 2048-bit.  

Next the malware disable windows defender real-time scanning and core services by editing registry **"SOFTWARE\Policies\Microsoft\Windows Defender"** and set it to **"DisableAntiSpyware"**
![alt text](image-14.png)

Then the malware deletes any snapshot or shadow copy the host has by excuting this **"\\sysnative\\vssadmin.exe delete shadows /all /quiet"**
![alt text](image-15.png)


![alt text](image-16.png)
After that we have 4 major subroutine
### 1- sub_402B20
![alt text](image-22.png)
The malware starts by getting the path to **C:\Users\User\AppData\Roaming** by **SHGetFolderPathW** and the add **\taridd** to it and then check if it exists, if it exists the malware just reads it and store it if not the malware calls **sub_4029C0** which generates random 6 characters and then write the file and six characters to it.

### 2- sub_402D00
The secound one is to store the message on the .txt file we talked about earlier and to make your id for contact operator.  


### 3- sub_402BE0
![alt text](image-23.png)
The malware first get the path to itself then get the path to the startup folder then it calls **sub_401040** and **sub_402A60** to generate a random name then it copy itself to the startup folder using **CopyFileW**.  

### 4- sub_401EF0
The malware first see the process using **Process32NextW** and compare it with a list of processes 
|mysql|IBM|bes10|black|sql|store.exe|vee|postg|sage|
|-----|---|-----|-----|---|---------|---|-----|----|

if it is one of the process listed the process will be terminated using **TerminateProcess**.  
And it checks for the services under the same name if it found one it will call **ControlService** with **SERVICE_CONTROL_STOP** as **dwControl**.![alt text](image-30.png)


Then the malware call **SHGetFolderPathW** to get the path to the **Desktop** then it calls **sub_402720**
### sub_402720
The malware here gets all drives and get the type of it![alt text](image-24.png)
if **EAX** is **4** **DRIVE_REMOTE** or **2** **DRIVE_REMOVABLE** or **3** **DRIVE_FIXED** the malware will work on it,it ignores any other type of memory.  
The malware then make thread that has **StartAddress** which is the encryption function at address **0x0402470** then it increaments **EDI**,![alt text](image-25.png)  
The maximum number of threads per time is **4** if there are 4 threads the malware will wait using  **WaitForMultipleObjects**.  


### StartAddress at address 0x0402470
The Malware first upload 5 strings into an array **Windows,$Recycle.bin,System Volume Information,Program Files,Program Files (x86)** then it takes the thread parameter which will be the drive the thread is working on and append **\*** to it using **wnsprintfW** then the malware calls **FindFirstFileW** to get the first file of the drive.  
The malware then go into do while loop each time it compares the file found by **FindNextFileW** with the five strings we found earlier, if it's one of the 5 strings it skips the encryption so the malware doesn't encrypt the core system.  
![alt text](image-26.png)
Then the malware compares if it there is any sub-folder or not to prevent infinite-loop , if it found any sub-folders it calls itself again with the new constructed path and the parent caller goes to **FindNextFileW**.  
If the malware found a file it checks it's attribute and checks if the file is already encrypted using it's own unique extension or the file is **---==%$$$OPEN_ME_UP$$$==---.txt** or **taridd** if it's one of those it skips the encryption,if not it calls **sub_402190** which is the core encryption.![alt text](image-27.png)  

### sub_402190
The function starts by checking if the file is already encrypted using extention,then it opens the file with READ\WRITE access.
Then it calls **sub_401150** to generate custom symmetric key and then the malware encrypt that key using the **RSA 1024-bit** key by **CryptEncrypt**.
Then the malware reads the first 10KB of the file using **ReadFile**  and calls **sub_401680** to apply the encryption.  
Then it calls **WriteFile** to write the first 10KB of the file ![alt text](image-28.png).  
Then it writes it's configurations , RSA key and mark to the end of the file and then it renames the file with it's extension ![alt text](image-29.png).  
 
After **sub_402190** finishes the malware go back to **StartAddress** to call **sub_4023C0** which write **---==%$$$OPEN_ME_UP$$$==---.txt** to the folder.


Then the malware calls **sub_401A80** and pass a URL **https://iplogger.org/1AsWy7**.
### sub_401A80
This function first calls **sub_4018C0** and pass the URL to it to split the url into **iplogger.org** and **1AsWy7** then  it calls **InternetOpenW** and then calls **InternetConnectW** with **lpszServerName** as **iplogger.org** then it opens **GET** request and send it to **1AsWy7** this makes the attacker stores data about the infected machines.

# IoCs
|Type    |Indicator|Description|
|--------|---------|-----------|
|Hash MD5|9ac8c2482e25dab49befb711172924f7|Original File Hash|
|File path|C:\Users\User\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\\ |Drop a copy of itself in the startup folder under a random name|
|Registry|SOFTWARE\Policies\Microsoft\Windows Defender|Disable Windows defender|
|File dropped|---==%$$$OPEN_ME_UP$$$==---.txt|Drops this file after encryption as instructions for contacting the author|
|Strings|Windows,$Recycle.bin,System Volume Information,Program Files,Program Files (x86)|Malware avoid to encrypts these|
|URL|https://iplogger.org/1AsWy7|Attacker uses this to know the infected machines|
|Request type| GET | Attacker make a GET request|
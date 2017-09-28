## About PEInfo

PEInfo is a utility to query bulk file information for researching.
Before using this utility, please fill your API key in PEInfo.ini or disable VirusTotal/Detux feature. (API key of these websites is free after registering an account)

### Main features:
- BasicHash: MD5, SHA1, SHA256
- ImpHash: Import table hash
- PEID: Compiler and packer recognition by [userdb.txt] (https://github.com/winest/FixUserDb)
- CompileTime: Compile time extraction
- PDB: PDB symbol path extraction
- ExportFunc: Exported function list
- VirusTotal: Selected anti-virus engines detection name on VirusTotal
- Detux: Get sandbox report on Detux



## Examples

### Run in Windows explorer:
- Double click "_AddExeToMenu.bat" with Administrator privilege
- Right click on any file or directory in explorer, and select "PE Info"
- Check Output folder to get the result

### Run in command line:
- PEInfo.exe -f "Samples\FileList.txt" "C:\Windows\System32\calc.exe;a03fe2d6566d7e9c167216acb55d3f6c"
- python3 PEInfo.py "C:\Windows\System32\calc.exe;a03fe2d6566d7e9c167216acb55d3f6c"
- python3 PEInfo.py -f "Samples\FileList.txt"



## Author
[ChienWei Hung] (https://www.linkedin.com/profile/view?id=351402223)

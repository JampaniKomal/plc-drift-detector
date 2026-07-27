import os
import time
import difflib
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from engine.parser import L5XParser
from engine.logger import SIEMLogger

class PLCMonitorHandler(FileSystemEventHandler):
    def __init__(self, baseline_file: str, parser: L5XParser, logger: SIEMLogger):
        self.baseline_file = baseline_file
        self.parser = parser
        self.logger = logger
        
        print(f"[*] Initializing OT-Guard Baseline from {baseline_file}...")
        sys.stdout.flush()
        
        self.baseline_signature = self.parser.sign_baseline(self.baseline_file)
        self.baseline_content = self.parser.normalize_xml(self.baseline_file)
        
        print(f"[*] Baseline locked. Signature: {self.baseline_signature}")
        sys.stdout.flush()

    def on_modified(self, event):
        if event.is_directory:
            return
            
        # Ignore changes to the baseline file itself in this demo
        if os.path.basename(event.src_path) == os.path.basename(self.baseline_file):
            return
            
        if not event.src_path.endswith('.xml'):
            return
            
        print(f"[*] File change detected: {event.src_path}")
        sys.stdout.flush()
        
        time.sleep(0.5) # Wait for file write to complete
        
        try:
            drifted, current_content, _ = self.parser.check_drift(event.src_path, self.baseline_signature)
            if drifted:
                # Generate diff text
                diff = difflib.unified_diff(
                    self.baseline_content.splitlines(),
                    current_content.splitlines(),
                    fromfile='baseline.xml',
                    tofile='active.xml',
                    lineterm=''
                )
                diff_text = '\n'.join(list(diff))
                self.logger.log_drift(event.src_path, diff_text)
                
                # Update baseline content to avoid repetitive alerting for the same drift
                self.baseline_content = current_content
                self.baseline_signature = self.parser.sign_baseline(event.src_path)
                
        except Exception as e:
            print(f"[ERROR] Failed to process {event.src_path}: {e}")
            sys.stdout.flush()

def main():
    watch_dir = os.environ.get("WATCH_DIR", "./plc_config")
    baseline_file = os.environ.get("BASELINE_FILE", os.path.join(watch_dir, "baseline.xml"))
    log_dir = os.environ.get("LOG_DIR", "./logs")
    
    # Ensure active.xml matches baseline.xml on startup
    active_file = os.path.join(watch_dir, "active.xml")
    if os.path.exists(baseline_file):
        with open(baseline_file, 'r') as bf:
            with open(active_file, 'w') as af:
                af.write(bf.read())
    else:
        print(f"[!] Baseline file not found at {baseline_file}")
        sys.exit(1)
        
    parser = L5XParser()
    logger = SIEMLogger(log_dir=log_dir)
    
    event_handler = PLCMonitorHandler(baseline_file, parser, logger)
    observer = Observer()
    observer.schedule(event_handler, watch_dir, recursive=False)
    
    print(f"[*] Starting OT-Guard Drift Engine on {watch_dir}...")
    sys.stdout.flush()
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()

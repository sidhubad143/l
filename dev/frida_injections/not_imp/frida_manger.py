#!/usr/bin/env python3
import subprocess
import time
import socket

FRIDA_HOST = "192.168.0.0"
FRIDA_PORT = 27042
PROCESS_NAME = "Gadget"
JS_SCRIPTS = ["index.js", "new.js", "restart_after_register.js"]
FRIDA_CLI = "frida"  # Make sure frida CLI is in your PATH

def is_port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except Exception:
        return False

def run_frida_cli():
    cmd = [FRIDA_CLI, "-H", f"{FRIDA_HOST}:{FRIDA_PORT}", "-n", PROCESS_NAME]
    for script in JS_SCRIPTS:
        cmd += ["-l", script]

    print(f"[*] Running: {' '.join(cmd)}")
    # Run the command and wait for it to exit (blocking)
    proc = subprocess.Popen(cmd)
    proc.wait()
    print(f"[*] frida CLI exited with code {proc.returncode}")

def main():
    print("[*] Waiting for Gadget to start and Frida server to listen...")
    while True:
        if is_port_open(FRIDA_HOST, FRIDA_PORT):
            print("[*] Frida server is listening! Starting frida CLI...")
            run_frida_cli()
            print("[*] frida CLI stopped. Waiting for Gadget to restart...")
        else:
            print("[*] Frida server not reachable yet, waiting 3 seconds...")
            time.sleep(1)

if __name__ == "__main__":
    main()

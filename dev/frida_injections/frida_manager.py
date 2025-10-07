#!/usr/bin/env python3

# Protective Source License v1.0 (PSL-1.0)
# Copyright (c) 2025 Kaif
# Unauthorized removal of credits or use for abusive/illegal purposes
# will terminate all rights granted under this license.

"""
frida_launcher.py

Interactive Frida launcher:
- supports TCP (remote frida-server) and USB (-U)
- lists devices via `frida-ls-devices` (if available)
- uses default scripts but asks if you want to append more each session
- restarts the frida CLI when it exits and waits for the device/server
"""

import subprocess
import time
import socket
import os
import shutil
import sys

# --- CONFIG ---
DEFAULT_TCP_HOST = "127.0.0.1"
DEFAULT_TCP_PORT = 27042
PROCESS_NAME = "Gadget"
DEFAULT_JS_SCRIPTS = ["index.js", "new.js", "restart_after_register.js"]
FRIDA_CLI = "frida"             # make sure frida CLI is in PATH
FRIDA_LS_DEVICES = "frida-ls-devices"  # optional helper to list devices
WAIT_BETWEEN_CHECKS = 1.0      # seconds
# ----------------

def is_port_open(host, port, timeout=1.0):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except Exception:
        return False

def file_exists_list(scripts):
    missing = [p for p in scripts if not os.path.isfile(p)]
    return missing

def run_subprocess_and_wait(cmd):
    print("[*] Running:", " ".join(cmd))
    try:
        proc = subprocess.Popen(cmd)
        proc.wait()
        print(f"[*] frida CLI exited with code {proc.returncode}")
    except KeyboardInterrupt:
        print("\n[*] KeyboardInterrupt: terminating frida launcher.")
        try:
            proc.terminate()
        except Exception:
            pass
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error launching frida: {e}")

def list_usb_devices():
    """Try to run frida-ls-devices and return parsed lines (if available)."""
    if not shutil.which(FRIDA_LS_DEVICES):
        return None
    try:
        out = subprocess.check_output([FRIDA_LS_DEVICES], stderr=subprocess.STDOUT, text=True, timeout=5)
    except Exception:
        return None

    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    # keep only meaningful lines (device id / summary)
    return lines

def ask_connection_choice():
    """Interactive prompt to choose connection mode and parameters."""
    options = []
    # Present some choices:
    print("Choose connection method:")
    print("  1) USB (auto)")
    print("  2) USB (pick device from frida-ls-devices if available)")
    print(f"  3) TCP (default: {DEFAULT_TCP_HOST}:{DEFAULT_TCP_PORT})")
    print("  4) Enter custom TCP host:port")
    print("  5) Use previously saved TCP host")
    choice = input("Select [1-4] (default 1): ").strip() or "1"

    if choice == "1":
        return ("usb", None, None)
    if choice == "2":
        devices = list_usb_devices()
        if not devices:
            print("[!] frida-ls-devices not available or returned nothing. Falling back to USB auto (-U).")
            return ("usb", None, None)
        print("\nAvailable devices (frida-ls-devices):")
        for i, ln in enumerate(devices, start=1):
            print(f"  {i}) {ln}")
        idx = input(f"Pick device [1-{len(devices)}] or press Enter to use auto USB: ").strip()
        if idx.isdigit() and 1 <= int(idx) <= len(devices):
            chosen = devices[int(idx)-1]
            # Try to extract device id token (first token)
            dev_id = chosen.split()[0]
            print(f"[*] Using device id: {dev_id}")
            return ("usb", dev_id, None)
        else:
            print("[*] Using generic USB (-U).")
            return ("usb", None, None)
    if choice == "3":
        return ("tcp", DEFAULT_TCP_HOST, DEFAULT_TCP_PORT)
    if choice == "4":
        hostport = input("Enter host:port (example 192.168.1.2:27042): ").strip()
        if ":" not in hostport:
            print("[!] invalid format, falling back to default TCP.")
            return ("tcp", DEFAULT_TCP_HOST, DEFAULT_TCP_PORT)
        host, port = hostport.split(":", 1)
        return ("tcp", host.strip(), int(port.strip()))
    # default fallback
    print("[*] Defaulting to USB.")
    return ("usb", None, None)

def ask_extra_scripts(defaults):
    """Ask user if they want to add extra scripts. Return final list."""
    print("\nDefault scripts to inject:", defaults)
    extra = input("Add extra script paths? (comma-separated) or press Enter to keep defaults: ").strip()
    if not extra:
        chosen = list(defaults)
    else:
        extras = [s.strip() for s in extra.split(",") if s.strip()]
        chosen = list(defaults) + extras
    missing = file_exists_list(chosen)
    if missing:
        print("[!] Warning: the following script files were not found and will be skipped:")
        for m in missing:
            print("   -", m)
        chosen = [p for p in chosen if p not in missing]
    if not chosen:
        print("[!] No scripts found to inject. Exiting.")
        sys.exit(1)
    print("[*] Final script list:", chosen)
    return chosen

def build_frida_cmd(conn_type, process_name, scripts, device_id=None, host=None, port=None):
    """Return a list representing the frida CLI command to run."""
    cmd = [FRIDA_CLI]
    if conn_type == "usb":
        # use -U, optionally -D <device-id>
        if device_id:
            # -D device-id selects a specific device (works if frida supports it)
            cmd += ["-D", device_id]
        else:
            cmd += ["-U"]
    elif conn_type == "tcp":
        if not host or not port:
            raise ValueError("tcp host and port required")
        cmd += ["-H", f"{host}:{port}"]
    else:
        raise ValueError("unknown connection type")

    # attach by process name
    cmd += ["-n", process_name]

    # add scripts
    for s in scripts:
        cmd += ["-l", s]

    return cmd

def main_loop():
    print("=== Frida Launcher ===")
    print("Defaults: process =", PROCESS_NAME)
    conn_type, conn_arg1, conn_arg2 = ask_connection_choice()
    # for USB: conn_arg1 = device_id or None
    # for TCP: conn_arg1 = host, conn_arg2 = port
    scripts = ask_extra_scripts(DEFAULT_JS_SCRIPTS)

    # persistent run loop: wait for device/server and start frida CLI; when frida exits, rerun
    while True:
        if conn_type == "tcp":
            host = conn_arg1
            port = conn_arg2
            print(f"[*] Waiting for TCP frida-server at {host}:{port} ...")
            while not is_port_open(host, port, timeout=1.0):
                print(f"  [-] {host}:{port} not reachable yet. retrying in {WAIT_BETWEEN_CHECKS}s")
                time.sleep(WAIT_BETWEEN_CHECKS)
            print(f"[*] {host}:{port} reachable. launching frida...")
            cmd = build_frida_cmd("tcp", PROCESS_NAME, scripts, host=host, port=port)

        else:  # usb
            device_id = conn_arg1
            # if device_id is None, we still proceed with -U which should use the available USB device
            if device_id:
                print(f"[*] Waiting for USB device '{device_id}' to appear (frida will use that device id)...")
                # naive wait: poll frida-ls-devices until the device id appears
                devices = list_usb_devices()
                found = False
                if devices:
                    found = any(device_id in ln for ln in devices)
                while not found:
                    print(f"  [-] device '{device_id}' not present yet. retrying in {WAIT_BETWEEN_CHECKS}s")
                    time.sleep(WAIT_BETWEEN_CHECKS)
                    devices = list_usb_devices()
                    if devices:
                        found = any(device_id in ln for ln in devices)
                print("[*] device present. launching frida...")
            else:
                print("[*] Waiting for any USB device (frida -U) ...")
                # no reliable generic check other than trying frida -U and letting frida fail; give a small sleep to allow device to settle
                # Optionally you could poll `frida-ls-devices` to confirm any device is present.
                if list_usb_devices():
                    print("[*] USB device(s) detected by frida-ls-devices.")
                else:
                    print("[*] frida-ls-devices not available or returned nothing; attempting to launch frida -U.")
                # short sleep
                time.sleep(0.5)

            cmd = build_frida_cmd("usb", PROCESS_NAME, scripts, device_id=device_id)

        # run frida and wait
        run_subprocess_and_wait(cmd)

        # after frida exits, ask user whether to keep same connection and scripts or change
        print("\n[*] frida process exited.")
        choice = input("Press Enter to relaunch with same settings, or type (c)hange to pick a different connection/scripts, or (q)uit: ").strip().lower()
        if choice == "q":
            print("[*] Quitting.")
            break
        if choice == "c" or choice == "change":
            conn_type, conn_arg1, conn_arg2 = ask_connection_choice()
            scripts = ask_extra_scripts(DEFAULT_JS_SCRIPTS)
        else:
            print("[*] Relaunching with same settings...")

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user. Exiting.")
        sys.exit(0)

#!/usr/bin/env python3
"""
Discovery tool - no longer functional after SEND_DESTINATION removal.
Agents now actively register themselves with the controller.
This tool is kept for reference only.
"""
import usp_controller
import time
import sys

def main():
    print("[!] This tool is deprecated.")
    print("[!] SEND_DESTINATION has been removed from configuration.")
    print("[!] Agents now actively register with the controller via reply_to in their messages.")
    print("[!] Check devices.json to see registered agents.")
    return 1

if __name__ == "__main__":
    sys.exit(main())

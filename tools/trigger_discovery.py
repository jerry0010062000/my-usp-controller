#!/usr/bin/env python3
import usp_controller
import time
import sys

def main():
    print("Sending Discovery Probe...")
    
    stomp = usp_controller.STOMPConnection(
        usp_controller.BROKER_HOST, 
        usp_controller.BROKER_PORT, 
        usp_controller.USERNAME, 
        usp_controller.PASSWORD
    )
    
    if not stomp.connect():
        print("Failed to connect")
        return 1

    # Probe 1: Plain Text with Reply-To
    # Some agents might reply with an error saying "unsupported content-type"
    print("Sending Probe 1: Text PING")
    stomp.send_message(
        usp_controller.SEND_DESTINATION, 
        b"PING_DISCOVERY", 
        content_type="text/plain", 
        reply_to=usp_controller.REPLY_TO_QUEUE
    )
    
    time.sleep(1)

    # Probe 2: Malformed USP Message
    # Agents should reply with an error ("Failed to parse")
    print("Sending Probe 2: Malformed USP")
    stomp.send_message(
        usp_controller.SEND_DESTINATION, 
        b"\x0a\x00\x10\x00", # Random bytes looking vaguely like protobuf
        content_type="application/vnd.bbf.usp.msg", 
        reply_to=usp_controller.REPLY_TO_QUEUE
    )

    stomp.disconnect()
    print("Probes sent.")

if __name__ == "__main__":
    sys.exit(main())

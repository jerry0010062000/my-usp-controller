#!/usr/bin/env python3
import usp_controller
import time
import sys

def main():
    print("Starting USP Controller in Daemon Mode...")
    
    # Create STOMP connection using settings from usp_controller
    stomp_conn = usp_controller.STOMPConnection(
        usp_controller.BROKER_HOST, 
        usp_controller.BROKER_PORT, 
        usp_controller.USERNAME, 
        usp_controller.PASSWORD
    )
    
    # Connect to broker
    if not stomp_conn.connect():
        print("[!] Failed to connect to broker")
        return 1
    
    # Subscribe to required topics
    stomp_conn.subscribe(usp_controller.RECEIVE_TOPIC)
    stomp_conn.subscribe(usp_controller.REPLY_TO_QUEUE)
    
    # Try to subscribe to ActiveMQ Advisory topics to find other connections
    stomp_conn.subscribe("ActiveMQ.Advisory.Connection.>")
    stomp_conn.subscribe("ActiveMQ.Advisory.Producer.Queue.>")
    
    print(f"[*] Daemon running. Listening on {usp_controller.RECEIVE_TOPIC}, {usp_controller.REPLY_TO_QUEUE} and Advisory topics")
    
    try:
        # Keep the main thread alive while the receiver thread works in the background
        while True:
            time.sleep(10)
            # Periodic status check can be added here
    except KeyboardInterrupt:
        print("\n[*] Shutting down daemon...")
    finally:
        stomp_conn.disconnect()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())


import socket
import time
import threading
import random
import argparse

def attack_thread(target_ip, port, intensity):
    """Blasts the target with TCP connections and payloads to trigger the IDS."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((target_ip, port))
        
        # Dynamically get our own IP to use as C2
        try:
            s_ip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_ip.connect(("8.8.8.8", 80))
            my_ip = s_ip.getsockname()[0]
            s_ip.close()
        except:
            my_ip = "192.168.1.100"

        # Simulate attack payloads
        payloads = [
            b"SCAN --port 22,80,443\n",
            b"AUTH --user admin --pass wordlist.txt --brute\n",
            b"EXEC payload_stage2.bin --target NODE-04\n",
            b"PIVOT --discover-peers --network 10.0.0.0/24\n",
            b"GET /api/sensor/dump\n",
            f"SEND /c2/beacon {my_ip}:4444 --data sensor_dump.gz\n".encode(),
            b"CONNECT 185.15.22.4:8080 --tunnel\n",
            # New SQL Injection Patterns
            b"GET /search?id=1' OR '1'='1' --\n",
            b"GET /admin?user=admin' UNION SELECT password FROM users--\n",
            # Huge packet size (Potential Jumbo Probe)
            b"DATA " + (b"A" * 2000) + b"\n",
            # Tiny packet header
            b"X\n"
        ]
        
        # We include the honey token to trigger the mesh quarantine
        honey_payload = b"AUTH --token ZS_TOKEN_7f3a9c2d8e4b1a6f --escalate\n"
        
        # Blast traffic
        for _ in range(int(30 * intensity)):
            cmd = random.choice(payloads)
            s.sendall(cmd)
            # Randomized IAT (Inter-Arrival Time) to trigger AI sequence analysis
            time.sleep(random.uniform(0.001, 0.1) if random.random() > 0.1 else random.uniform(2.0, 5.0))
            
        s.sendall(honey_payload)
        
        # Receive any responses from the honeypot
        try:
            while True:
                resp = s.recv(4096)
                if not resp: break
                print(f"[+] Received {len(resp)} bytes from target")
        except socket.timeout:
            pass
            
        s.close()
    except Exception as e:
        print(f"[-] Connection failed: {e}")

def ddos_flood_thread(target_ip, port, duration):
    """Simulates a high-rate packet flood (DDoS PPS violation)."""
    end_time = time.time() + duration
    while time.time() < end_time:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, port))
            for _ in range(100):
                s.send(b"FLOOD\n")
            s.close()
        except:
            pass

def main():
    parser = argparse.ArgumentParser(description="ShieldNet Live Attacker Simulation")
    parser.add_argument("--target", required=True, help="IP address of the IDPS Proxy")
    parser.add_argument("--port", type=int, default=9002, help="Proxy port (default: 9002)")
    parser.add_argument("--threads", type=int, default=12, help="Number of concurrent attack streams")
    parser.add_argument("--ddos", action="store_true", help="Include high-rate DDoS flood component")
    args = parser.parse_args()

    print(f"[*] Initiating ShieldNet multi-stage attack simulation on {args.target}:{args.port}")
    
    threads = []
    
    # Launch standard multi-stage behavioral threads
    for i in range(args.threads):
        t = threading.Thread(target=attack_thread, args=(args.target, args.port, 1.0 + (i * 0.4)))
        threads.append(t)
        t.start()
        time.sleep(0.05)

    # Launch DDoS flood component if requested
    if args.ddos:
        print("[!] Activating DDoS High-Rate Flood Component...")
        for _ in range(4):
            t = threading.Thread(target=ddos_flood_thread, args=(args.target, args.port, 15))
            threads.append(t)
            t.start()

    for t in threads:
        t.join()

    print("[*] Full attack sequence completed.")

if __name__ == "__main__":
    main()
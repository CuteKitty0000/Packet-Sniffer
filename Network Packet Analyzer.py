import sys
from scapy.all import sniff, IP, TCP

def packet_handler(pkt):
    if pkt.haslayer(TCP):
        s = pkt[IP].src
        d = pkt[IP].dst
        sp = pkt[TCP].sport
        dp = pkt[TCP].dport
        p = pkt[IP].proto
        pl = str(pkt[TCP].payload)

        output = (
            f"Source IP: {s}\n"
            f"Destination IP: {d}\n"
            f"Source Port: {sp}\n"
            f"Destination Port: {dp}\n"
            f"Protocol: {p}\n"
            f"Payload: {pl[:50]}...\n"
        )

        print(output, end='')
        try:
            with open('packet_sniffer_results.txt', 'a') as f:
                f.write(output)
        except IOError as e:
            print(f"Error writing to file: {e}")

def main():
    print(r''' _        _______  _______ 
( (    /|(  ____ )(  ___  )
|  \  ( || (    )|| (   ) |
|   \ | || (____)|| (___) |
| (\ \) ||  _____)|  ___  |
| | \   || (      | (   ) |
| )  \  || )      | )   ( |
|/    )_)|/       |/     \|
                           ''')
    print("This packet sniffer tool is intended for educational purposes only.")
    
    sniff(filter="tcp", prn=packet_handler, store=0, count=10)
    
    print(f"\nResults saved to: packet_sniffer_results.txt")

if __name__ == "__main__":
    main()

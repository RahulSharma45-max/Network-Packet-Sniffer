from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime
import csv
import os
from collections import defaultdict
from colorama import init, Fore, Style

init(autoreset=True)

class PacketSniffer:
    def __init__(self, filter_protocol=None, save_to_csv=False):
        self.filter_protocol = filter_protocol
        self.save_to_csv = save_to_csv
        self.packet_count = 0
        self.protocol_stats = defaultdict(int)
        if self.save_to_csv:
            self.csv_filename = f"packet_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            self.setup_csv()
    
    def setup_csv(self):
        with open(self.csv_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Timestamp', 'Source IP', 'Destination IP', 
                           'Protocol', 'Source Port', 'Destination Port', 
                           'Packet Size'])
        print(f"{Fore.GREEN}[+] CSV logging enabled: {self.csv_filename}{Style.RESET_ALL}")
    
    def log_to_csv(self, packet_info):
        with open(self.csv_filename, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                packet_info['timestamp'],
                packet_info['src_ip'],
                packet_info['dst_ip'],
                packet_info['protocol'],
                packet_info['src_port'],
                packet_info['dst_port'],
                packet_info['size']
            ])
    
    def get_protocol_name(self, packet):
        if TCP in packet:
            return 'TCP'
        elif UDP in packet:
            return 'UDP'
        elif ICMP in packet:
            return 'ICMP'
        elif ARP in packet:
            return 'ARP'
        else:
            return 'OTHER'
    
    def packet_callback(self, packet):
        if IP not in packet:
            return
        protocol = self.get_protocol_name(packet)
        if self.filter_protocol and protocol != self.filter_protocol.upper():
            return
        self.packet_count += 1
        self.protocol_stats[protocol] += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_port = dst_port = 'N/A'
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        packet_info = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'src_port': src_port,
            'dst_port': dst_port,
            'size': packet_size
        }
        self.display_packet(packet_info)
        if self.save_to_csv:
            self.log_to_csv(packet_info)
    
    def display_packet(self, packet_info):
        protocol_colors = {
            'TCP': Fore.CYAN,
            'UDP': Fore.YELLOW,
            'ICMP': Fore.MAGENTA,
            'ARP': Fore.GREEN,
            'OTHER': Fore.WHITE
        }
        color = protocol_colors.get(packet_info['protocol'], Fore.WHITE)
        print(f"\n{Fore.WHITE}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[Packet #{self.packet_count}] {packet_info['timestamp']}{Style.RESET_ALL}")
        print(f"{color}Protocol: {packet_info['protocol']}{Style.RESET_ALL}")
        print(f"Source IP: {packet_info['src_ip']}:{packet_info['src_port']}")
        print(f"Destination IP: {packet_info['dst_ip']}:{packet_info['dst_port']}")
        print(f"Packet Size: {packet_info['size']} bytes")
    
    def display_statistics(self):
        print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[STATISTICS] Packet Capture Summary{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"Total Packets Captured: {self.packet_count}")
        print("\nPackets per Protocol:")
        for protocol, count in sorted(self.protocol_stats.items()):
            percentage = (count / self.packet_count * 100) if self.packet_count > 0 else 0
            print(f"  {protocol}: {count} ({percentage:.2f}%)")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
    
    def start_sniffing(self, interface=None, packet_count=0):
        print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Network Packet Sniffer Started{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
        if self.filter_protocol:
            print(f"Filter: {self.filter_protocol.upper()} packets only")
        else:
            print("Filter: All packets")
        print(f"Press Ctrl+C to stop capturing...\n")
        try:
            sniff(iface=interface, prn=self.packet_callback, store=0, count=packet_count)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] Stopping packet capture...{Style.RESET_ALL}")
            self.display_statistics()
            if self.save_to_csv:
                print(f"{Fore.GREEN}[+] Packets saved to: {self.csv_filename}{Style.RESET_ALL}")
        except PermissionError:
            print(f"{Fore.RED}[ERROR] Permission denied!{Style.RESET_ALL}")
            print(f"{Fore.RED}Please run this script with administrator/root privileges:{Style.RESET_ALL}")
            print(f"  Windows: Run Command Prompt as Administrator")
            print(f"  Linux/Mac: Use 'sudo python3 packet_sniffer.py'")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")

def display_menu():
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Network Packet Sniffer - Configuration Menu{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    print("Select Protocol Filter:")
    print("  1. All Protocols (No Filter)")
    print("  2. TCP Only")
    print("  3. UDP Only")
    print("  4. ICMP Only")
    choice = input("\nEnter your choice (1-4): ").strip()
    protocol_map = {
        '1': None,
        '2': 'TCP',
        '3': 'UDP',
        '4': 'ICMP'
    }
    filter_protocol = protocol_map.get(choice, None)
    save_csv = input("\nSave packets to CSV file? (y/n): ").strip().lower() == 'y'
    count_input = input("\nNumber of packets to capture (0 for infinite): ").strip()
    try:
        packet_limit = int(count_input)
    except ValueError:
        packet_limit = 0
    return filter_protocol, save_csv, packet_limit

def main():
    filter_protocol, save_csv, packet_limit = display_menu()
    sniffer = PacketSniffer(filter_protocol=filter_protocol, save_to_csv=save_csv)
    sniffer.start_sniffing(packet_count=packet_limit)

if __name__ == "__main__":
    main()

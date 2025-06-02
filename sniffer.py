import socket
import struct

def parse_ip_header(data):
    # Unpack first 20 bytes of the IP header
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])

    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4

    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])

    return {
        'version': version,
        'header_length': ihl,
        'src_ip': src_ip,
        'dest_ip': dest_ip
    }

def main():
    try:
        # Create raw socket for capturing IP packets
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind(("YOUR IP", 0))  # Adjust to your local IP if needed
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        print("📡 Sniffing started on YOUR IP... Press Ctrl+C to stop.\n")

        while True:
            raw_data = sniffer.recvfrom(65565)[0]
            ip_info = parse_ip_header(raw_data)

            print("📦 Captured Packet:")
            print(f"   ➤ Source IP      : {ip_info['src_ip']}")
            print(f"   ➤ Destination IP : {ip_info['dest_ip']}")
            print(f"   ➤ IP Version     : {ip_info['version']}")
            print(f"   ➤ Header Length  : {ip_info['header_length']} bytes")
            print("-" * 50)

    except PermissionError:
        print("🚫 Run this script with sudo.")
    except KeyboardInterrupt:
        print("\n🛑 Sniffing stopped.")

if __name__ == "__main__":
    main()

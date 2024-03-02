from scapy.all import *

TIMEOUT = 0.5
SYN = 0x02
ACK = 0x10
def main():
    ip_search = input('enter ip for scan:')
    for i in range(20,1024):
        syn_segment = TCP(dport=i, flags='S')
        syn_packet = IP(dst=ip_search)/syn_segment
        syn_ack_packet = sr1(syn_packet, timeout = TIMEOUT)
        if syn_ack_packet.haslayer(TCP):
            F = syn_ack_packet['TCP'].flags
            if F & SYN and F & ACK:
                print(f'port {i} is open')
            else:
                print('.')
        else:
                print('.')

if __name__ == "__main__":
    main()
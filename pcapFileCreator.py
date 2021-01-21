import sys
import binascii
import socket


# Custom Foo Protocol Packet
message = ('01 01 00 08'  # Foo Base Header
           '01 02 00 00'  # Foo Message (31 Bytes)
           '00 00 12 30'
           '00 00 12 31'
           '00 00 12 32'
           '00 00 12 33'
           '00 00 12 34'
           'D7 CD EF'  # Foo flags
           '00 00 12 35')

# Global header for pcap 2.4
pcap_global_header = ('D4 C3 B2 A1'
                      '02 00'  # File format major revision (i.e. pcap <2>.4)  
                      '04 00'  # File format minor revision (i.e. pcap 2.<4>)   
                      '00 00 00 00'
                      '00 00 00 00'
                      'FF FF 00 00'
                      '01 00 00 00')

# pcap packet header that must preface every packet
pcap_packet_header = ('AA 77 9F 47'
                      '90 A2 04 00'
                      'XX XX XX XX'  # Frame Size (little endian) 
                      'YY YY YY YY')  # Frame Size (little endian)

eth_header = ('00 00 00 00 00 00'  # Source Mac    
              '00 00 00 00 00 00'  # Dest Mac  
              '08 00')  # Protocol (0x0800 = IP)

ip_header = ('45'  # IP version and header length (multiples of 4 bytes)   
             '00'
             'XX XX'  # Length - will be calculated and replaced later
             '00 00'
             '40 00 40'
             '11'  # Protocol (0x11 = UDP)           
             'YY YY'  # Checksum - will be calculated and replaced later      
             '7F 00 00 01'  # Source IP (Default: 127.0.0.1)         
             '7F 00 00 01')  # Dest IP (Default: 127.0.0.1)

udp_header = ('80 01'
              'XX XX'  # Port - will be replaced later                   
              'YY YY'  # Length - will be calculated and replaced later        
              '00 00')


def getByteLength(str1):
    return len(''.join(str1.split())) / 2


def writeByteStringToFile(bytestring, filename):
    bytelist = bytestring.split()
    bytes = binascii.a2b_hex(''.join(bytelist))
    bitout = open(filename, 'wb')
    bitout.write(bytes)


def generatePCAP(message, port, pcap_file):
    udp = udp_header.replace('XX XX', "%04x" % port)
    udp_len = int(getByteLength(message) + getByteLength(udp_header))
    udp = udp.replace('YY YY', "%04x" % udp_len)

    ip_len = int(udp_len + getByteLength(ip_header))
    ip = ip_header.replace('XX XX', "%04x" % ip_len)
    checksum = ip_checksum(ip.replace('YY YY', '00 00'))
    ip = ip.replace('YY YY', "%04x" % checksum)

    pcap_len = int(ip_len + getByteLength(eth_header))
    hex_str = "%08x" % pcap_len
    reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
    pcap_h = pcap_packet_header.replace('XX XX XX XX', reverse_hex_str)
    pcap_h = pcap_h.replace('YY YY YY YY', reverse_hex_str)

    bytestring = pcap_global_header + pcap_h + eth_header + ip + udp + message
    writeByteStringToFile(bytestring, pcap_file)


# Splits the string into a list of tokens every n characters
def splitN(str1, n):
    return [str1[start:start + n] for start in range(0, len(str1), n)]


# Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):
    # split into bytes
    words = splitN(''.join(iph.split()), 4)

    csum = 0
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum


"""------------------------------------------"""
""" End of functions, execution starts here: """
"""------------------------------------------"""

#############################################################################################################################################################
message = input("What message do you want to send within the packet?\t(Max 31 bytes of information)\n")
message = message.encode("utf-8")
message = message.hex()
#############################################################################################################################################################
port = int(input("What's the port number:\t"))
#############################################################################################################################################################
src_ip_address = str(input("What is the source Ip Adress?\n"))
src_ip_address = binascii.hexlify(socket.inet_aton(
    src_ip_address)).decode().upper()  # checks valid ip then hexififies then decodes to string into making the values uppercase
ip_header = ip_header.replace('YY YY7F 00 00 01', 'YY YY' + src_ip_address)
#############################################################################################################################################################
dst_ip_address = str(input("What is the Destination Ip Adress?\n"))
dst_ip_address = binascii.hexlify(socket.inet_aton(
    dst_ip_address)).decode().upper()  # checks valid ip then hexififies then decodes to string into making the values uppercase
ip_header = ip_header.replace('7F 00 00 01', dst_ip_address)
#############################################################################################################################################################
dst_mac_address = input(
    'What is the source mac adress?\n(Assigning an mac adress changes the protocol of the pcap file to LLC not UDP. Enter 0 to not change the UDP protocol\n')
if dst_mac_address != '0':
    dst_mac_address = dst_mac_address.replace(":", "").upper()
    eth_header = eth_header.replace("00 00 00 00 00 0008 00", dst_mac_address + "08 00")
#############################################################################################################################################################
src_mac_address = input(
    'What is the source mac adress?\n(Assigning an mac adress changes the protocol of the pcap file to LLC not UDP. Enter 0 to not change the UDP protocol)\n')
if src_mac_address != '0':
    src_mac_address = src_mac_address.replace(":", "").upper()
    eth_header = eth_header.replace("00 00 00 00 00 00", src_mac_address)
#############################################################################################################################################################
if len(sys.argv) < 2:
    print('usage: pcapgen.py output_file')
    exit(0)

generatePCAP(message, port, sys.argv[1])

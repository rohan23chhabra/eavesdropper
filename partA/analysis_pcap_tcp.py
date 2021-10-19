import dpkt

FIN = 'FIN'
SYN = 'SYN'
URG = 'URG'
ACK = 'ACK'
PSH = 'PSH'
RST = 'RST'
bigEndian = "big"


class Packet:
    def __init__(self):
        self.srcMac = ''
        self.destMac = ''
        self.srcIP = ''
        self.destIP = ''
        self.srcPort = 0
        self.destPort = 0
        self.tcpHeaderLength = 0
        self.flag = ''
        self.seq = -1
        self.ack = -1
        self.window = -1
        self.timestamp = -1.0

    def __str__(self):
        return 'Src IP: {}, Dest IP: {}, Src Port: {}, Dest Port: {}, TCP Header Length: {}, Flag: {}, Seq: {}, Ack: {}, Window: {}, TS: {}'.format(
            self.srcIP, self.destIP, self.srcPort, self.destPort, self.tcpHeaderLength, self.flag, self.seq, self.ack,
            self.window, self.timestamp)


class Parser:
    def __init__(self, pcapFile):
        self.pcapFile = pcapFile
        self.headerLengthOffset = 46
        self.srcIPOffset = 26
        self.destIPOffset = 30
        self.tcpStart = 34
        self.flagMap = {
            1: FIN,
            2: SYN,
            4: RST,
            8: PSH,
            16: ACK,
            32: URG
        }

    def parse(self):
        packets = []
        for ts, stream in self.pcapFile:
            packet = self.parseStream(stream)
            packet.timestamp = ts
            packets.append(packet)
            break

        return packets

    def parseStream(self, stream):
        packet = Packet()

        # TCP Header length
        packet.tcpHeaderLength = stream[self.headerLengthOffset] >> 4

        # Flag
        flagByte = (stream[self.headerLengthOffset + 1] & 63)
        packet.flag = self.flagMap[flagByte]

        # Source IP
        packet.srcIP = f'{stream[self.srcIPOffset]}'
        for i in range(1, 4):
            tmp = stream[self.srcIPOffset + i]
            st = '.' + f'{tmp}'
            packet.srcIP += st

        # Dest IP
        packet.destIP = f'{stream[self.destIPOffset]}'
        for i in range(1, 4):
            tmp = stream[self.destIPOffset + i]
            st = '.' + f'{tmp}'
            packet.destIP += st

        offset = self.tcpStart

        # Source port
        packet.srcPort = int.from_bytes(stream[offset:offset + 2], bigEndian)
        offset += 2

        # Dest port
        packet.destPort = int.from_bytes(stream[offset:offset + 2], bigEndian)
        offset += 2

        # Seq number
        packet.seq = int.from_bytes(stream[offset:offset + 4], bigEndian)
        offset += 4

        # Ack number
        packet.ack = int.from_bytes(stream[offset:offset + 4], bigEndian)
        offset += 4

        # Skip the header length and flag part as already computed before
        offset += 2

        # Window size
        packet.window = int.from_bytes(stream[offset:offset + 2], bigEndian)
        offset += 2

        print('Src IP: ', packet.srcIP)
        print('Dest IP: ', packet.destIP)
        print('Flag: ', packet.flag)
        print('TCP Header length: ', packet.tcpHeaderLength)
        print('Src port: ', packet.srcPort)
        print('Dest port: ', packet.destPort)
        print('Seq no: ', packet.seq)
        print('Ack no: ', packet.ack)
        print('Window: ', packet.window)
        return packet


def run(pcapFile):
    parser = Parser(pcapFile)
    packets = parser.parse()
    for p in packets:
        print(p)


if __name__ == '__main__':
    filePath = '../assignment2.pcap'
    with open(filePath, 'rb') as file:
        pcapFile = dpkt.pcap.Reader(file)
        run(pcapFile)

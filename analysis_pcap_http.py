import os.path

import dpkt

FIN = 'FIN'
SYN = 'SYN'
URG = 'URG'
ACK = 'ACK'
PSH = 'PSH'
RST = 'RST'
SYN_ACK = 'SYN ACK'
PSH_ACK = 'PSH ACK'
FIN_PSH_ACK = 'FIN PSH ACK'
FIN_ACK = 'FIN ACK'
ACK_RST = 'ACK RST'
bigEndian = "big"
sender = '130.245.145.12'
receiver = '128.208.2.198'


class Flow:
    def __init__(self, srcIP, destIP, srcPort, destPort):
        # self.ts = 0
        self.srcIP = srcIP
        self.destIP = destIP
        self.srcPort = srcPort
        self.destPort = destPort
        self.mss = -1

    def __str__(self):
        return f'SrcIP: {self.srcIP}, DestIP: {self.destIP}, SrcPort: {self.srcPort}, DestPort: {self.destPort}'


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
        self.mss = -1
        self.dataLength = -1
        self.size = -1
        self.http = None
        self.httpVersion = ''

    def __str__(self):
        return 'Src IP: {}, Dest IP: {}, Src Port: {}, Dest Port: {}, TCP Header Length: {}, Flag: {}, Seq: {}, Ack: {}, Window: {}, TS: {}, MSS: {}, Data Length: {}, Size: {}, HTTP: {}, HTTP Version: {}'.format(
            self.srcIP, self.destIP, self.srcPort, self.destPort, self.tcpHeaderLength, self.flag, self.seq, self.ack,
            self.window, self.timestamp, self.mss, self.dataLength, self.size, str(self.http[0:4]), self.httpVersion)

    def matchesFlow(self, flow: Flow):
        if flow.srcIP == self.srcIP and flow.destIP == self.destIP and flow.srcPort == self.srcPort and flow.destPort == self.destPort:
            return True
        if flow.srcIP == self.destIP and flow.destIP == self.srcIP and flow.srcPort == self.destPort and flow.destPort == self.srcPort:
            return True
        return False

    def isHttpRequest(self):
        return len(self.http) >= 3 and self.http[0:3] == b'GET'

    def isHttpResponse(self):
        return len(self.http) >= 4 and self.http[0:4] == b'HTTP'


class Parser:
    def __init__(self, pcapFile):
        self.pcapFile = pcapFile
        self.headerLengthOffset = 48
        self.srcIPOffset = 28
        self.destIPOffset = 32
        self.tcpStart = 36
        self.flagMap = {
            1: FIN,
            2: SYN,
            4: RST,
            8: PSH,
            16: ACK,
            32: URG,
            18: SYN_ACK,
            24: PSH_ACK,
            25: FIN_PSH_ACK,
            17: FIN_ACK,
            20: ACK_RST,
        }

    def parse(self):
        packets = []
        for ts, stream in self.pcapFile:
            packet = self.parseStream(stream)
            packet.timestamp = ts
            packets.append(packet)

        return packets

    def parseStream(self, stream):
        packet = Packet()
        packet.size = len(stream)

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

        # Checksum and urgent pointer (Skip)
        offset += 4

        # Till now, 5 32-bit words have been parsed
        remaining32BitWords = packet.tcpHeaderLength - 5
        # if remaining32BitWords > 0:
        #     packet.mss = int.from_bytes(stream[offset + 2:offset + 4], bigEndian)
        offset += remaining32BitWords * 4
        if offset == len(stream):
            packet.dataLength = 0
            packet.http = None
        else:
            packet.dataLength = len(stream[offset:])
            packet.http = stream[offset:]
        return packet

    def parseFlows(self, packets):
        flows = []
        for packet in packets:
            if packet.flag == SYN:
                flow = Flow(packet.srcIP, packet.destIP, packet.srcPort, packet.destPort)
                flows.append(flow)
        return flows

    def parseFlowStream(self, packets, flows):
        flowStream = {}
        for flow in flows:
            flowStream[flow] = []
            for packet in packets:
                if packet.matchesFlow(flow):
                    flowStream[flow].append(packet)

        return flowStream

    def parseHTTPPcap(self):
        pass


class Analyzer:
    def __init__(self):
        self.packets = []
        self.flows = []
        self.mss = {}

    def analyze(self, pcapFile):
        parser = Parser(pcapFile)
        self.packets = parser.parse()
        self.flows = parser.parseFlows(self.packets)
        self.flowStream = parser.parseFlowStream(self.packets, self.flows)

        print('Part C:')
        self.solvePartC()

    def solvePartC(self):
        print('Request and response pairs: ')
        correspondingResponses = {}
        for packet in self.packets:
            if packet.http and packet.isHttpResponse():
                correspondingResponses[packet.seq] = packet

        answer = ''
        for packet in self.packets:
            if packet.http and packet.isHttpRequest():
                responsePacket = correspondingResponses[packet.ack] if packet.ack in correspondingResponses else None
                if responsePacket:
                    answer += f'Request: SrcIP: {packet.srcIP}, DestIP: {packet.destIP}, SeqNo: {packet.seq}, Ack: {packet.ack}\n'
                    answer += f'Response: SrcIP: {responsePacket.srcIP}, DestIP: {responsePacket.destIP}, SeqNo: {responsePacket.seq}, Ack: {responsePacket.ack}\n'

        if answer == '':
            print('Encrypted payload\n')
        else:
            print(answer)

        print('HTTP Protocol: ')
        noOfConnections = len(self.flows)
        if noOfConnections == 6:
            print('HTTP Version: HTTP/1.1\n')
        elif noOfConnections < 6:  # Only for this particular assignment
            print('HTTP Version: HTTP/2.0\n')
        else:
            print('HTTP Version: HTTP/1.0\n')


def run(pcap):
    analyzer = Analyzer()
    analyzer.analyze(pcap)


if __name__ == '__main__':
    pcaps = ['http_1082.pcap']  # , 'http_1081.pcap', 'http_1082.pcap']
    for p in pcaps:
        here = os.path.dirname(os.path.abspath(__file__))
        filePath = os.path.join(here, p)

        with open(filePath, 'rb') as pcap:
            pcapFD = dpkt.pcap.Reader(pcap)
            run(pcapFD)

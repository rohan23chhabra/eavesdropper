import math
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

    def __str__(self):
        return 'Src IP: {}, Dest IP: {}, Src Port: {}, Dest Port: {}, TCP Header Length: {}, Flag: {}, Seq: {}, Ack: {}, Window: {}, TS: {}, MSS: {}, Data Length: {}, Size: {}'.format(
            self.srcIP, self.destIP, self.srcPort, self.destPort, self.tcpHeaderLength, self.flag, self.seq, self.ack,
            self.window, self.timestamp, self.mss, self.dataLength, self.size)

    def matchesFlow(self, flow: Flow):
        if flow.srcIP == self.srcIP and flow.destIP == self.destIP and flow.srcPort == self.srcPort and flow.destPort == self.destPort:
            return True
        if flow.srcIP == self.destIP and flow.destIP == self.srcIP and flow.srcPort == self.destPort and flow.destPort == self.srcPort:
            return True
        return False


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
            32: URG,
            18: SYN_ACK,
            24: PSH_ACK,
            25: FIN_PSH_ACK,
            17: FIN_ACK,
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
        else:
            packet.dataLength = len(stream[offset:])
        # print('Src IP: ', packet.srcIP)
        # print('Dest IP: ', packet.destIP)
        # print('Flag: ', packet.flag)
        # print('TCP Header length: ', packet.tcpHeaderLength)
        # print('Src port: ', packet.srcPort)
        # print('Dest port: ', packet.destPort)
        # print('Seq no: ', packet.seq)
        # print('Ack no: ', packet.ack)
        # print('Window: ', packet.window)
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
        # print(self.flowStream)

        # print('Part A:')
        # self.solvePartA()
        # print('-------------------Part A done------------------')

        print('Part B:')
        self.solvePartB()
        print('-------------------Part B done------------------')

    def solvePartA(self):
        flowsInitiatedBySender = 0
        for flow in self.flows:
            if flow.srcIP == sender:
                flowsInitiatedBySender += 1

        answer = f'Number of flows initiated by sender = {flowsInitiatedBySender}\n'
        print(answer)

        print('Seq no, ack and window values: ')
        for flowNumber in range(len(self.flows)):
            flow = self.flows[flowNumber]
            count = 0
            answer = f'Flow: {flowNumber + 1}\n'
            for packet in self.flowStream[flow]:
                if packet.dataLength > 0:
                    answer += f'Seq no = {packet.seq}, Ack No = {packet.ack}, Receive window size = {packet.window}\n'
                    count += 1
                    if count == 2:
                        break

            print(answer)

        print('Throughput values: ')
        for flowNumber in range(len(self.flows)):
            flow = self.flows[flowNumber]
            answer = f'Flow: {flowNumber + 1}'
            print(answer)

            totalBytesSent = 0
            initialTime = -1
            lastTime = -1
            for packet in self.flowStream[flow]:
                if packet.srcIP == receiver:
                    totalBytesSent += packet.size
                    if initialTime == -1:
                        initialTime = packet.timestamp
                    lastTime = packet.timestamp

            throughput = totalBytesSent / (lastTime - initialTime)
            answer = f'Throughput at receiver: {throughput} bytes/second\n'
            print(answer)

        empiricalLossRates = []
        empiricalRTTs = []

        print('Loss rates: ')
        for flowNumber in range(len(self.flows)):
            flow = self.flows[flowNumber]
            answer = f'Flow: {flowNumber + 1}'
            print(answer)

            transmissions, totalPacketsSent = self.getTransmissionCounts(flow)

            packetsLost = 0
            for seqNo in transmissions:
                packetsLost += transmissions[seqNo] - 1

            lossRate = packetsLost / totalPacketsSent
            empiricalLossRates.append(lossRate)
            answer = f'Loss rate: {lossRate}\n'
            print(answer)

        print('Estimated RTTs: ')
        for flowNumber in range(len(self.flows)):
            flow = self.flows[flowNumber]
            answer = f'Flow: {flowNumber + 1}'
            print(answer)

            transmissions, _ = self.getTransmissionCounts(flow)

            sentTimes = {}
            receivedTimes = {}
            for packet in self.flowStream[flow]:
                if packet.srcIP == sender and packet.seq not in sentTimes:
                    # Karn's algorithm.
                    # Consider only those packets who are not retransmitted
                    if transmissions[packet.seq] == 1:
                        sentTimes[packet.seq] = packet.timestamp
                elif packet.srcIP == receiver and packet.ack not in receivedTimes:
                    # if transmissions[packet.ack] == 1:
                    receivedTimes[packet.ack] = packet.timestamp

            totalTime = 0
            successfulTransmissions = 0
            for key in sentTimes:
                if key in receivedTimes:
                    successfulTransmissions += 1
                    totalTime += receivedTimes[key] - sentTimes[key]

            rtt = totalTime / successfulTransmissions
            empiricalRTTs.append(rtt)
            answer = f'Estimated RTT: {rtt} seconds\n'
            print(answer)

        mss = []
        for flow in self.flows:
            localMSS = -1
            for packet in self.flowStream[flow]:
                localMSS = max(localMSS, packet.dataLength)
            mss.append(localMSS)

        print('Theoretical throughput: ')
        for flowNumber in range(len(self.flows)):
            flow = self.flows[flowNumber]
            answer = f'Flow: {flowNumber + 1}'
            print(answer)

            theoreticalThroughput = self.getTheoreticalThroughput(mss[flowNumber], empiricalLossRates[flowNumber],
                                                                  empiricalRTTs[flowNumber])
            answer = f'Theoretical throughput = {theoreticalThroughput} bytes/second\n'
            print(answer)

    def getTheoreticalThroughput(self, mss, lossRate, rtt):
        return (math.sqrt(1.5) * mss) / (math.sqrt(lossRate) * rtt)

    def getTransmissionCounts(self, flow):
        transmissions = {}
        totalPacketsSent = 0
        for packet in self.flowStream[flow]:
            if packet.srcIP == sender:
                totalPacketsSent += 1
                if packet.seq not in transmissions:
                    transmissions[packet.seq] = 1
                else:
                    transmissions[packet.seq] += 1

        return transmissions, totalPacketsSent

    def solvePartB(self):
        print('Congestion windows: ')
        for flowNumber in range(len(self.flows)):
            flow = self.flows[flowNumber]
            answer = f'Flow: {flowNumber + 1}'
            print(answer)

            latestPacket = None
            congestionWindows = []
            for packet in self.flowStream[flow]:
                if packet.dataLength > 0 and packet.srcIP == sender:
                    latestPacket = packet
                elif packet.srcIP == receiver and latestPacket and packet.timestamp > latestPacket.timestamp:
                    congestionWindows.append((latestPacket.seq - packet.ack) // latestPacket.dataLength)
                    if len(congestionWindows) == 10:
                        break

            answer = ''
            for cwnd in congestionWindows:
                answer += f'Congestion window size = {cwnd} packets\n'
            print(answer)

        print('Loss analysis: ')
        for flowNumber in range(len(self.flows)):
            flow = self.flows[flowNumber]
            answer = f'Flow: {flowNumber + 1}'
            print(answer)

            ackCounts = {}
            seqCounts = {}
            for packet in self.flowStream[flow]:
                if packet.srcIP == receiver:
                    if packet.ack not in ackCounts:
                        ackCounts[packet.ack] = 1
                    else:
                        ackCounts[packet.ack] += 1
                if packet.srcIP == sender:
                    if packet.seq not in seqCounts:
                        seqCounts[packet.seq] = 1
                    else:
                        seqCounts[packet.seq] += 1

            totalPacketsLost = 0
            tripleDuplicateLoss = 0
            for key in seqCounts:
                totalPacketsLost += seqCounts[key] - 1
                if key in ackCounts:
                    if ackCounts[key] >= 3:
                        tripleDuplicateLoss += seqCounts[key] - 1

            timeoutPackets = totalPacketsLost - tripleDuplicateLoss
            answer = f'Packets lost due to triple duplicate ack = {tripleDuplicateLoss}\n'
            answer += f'Packets lost due to timeout = {timeoutPackets}\n'
            print(answer)


if __name__ == '__main__':
    here = os.path.dirname(os.path.abspath(__file__))
    filePath = os.path.join(here, 'assignment2.pcap')

    analyzer = Analyzer()
    with open(filePath, 'rb') as pcap:
        pcapFD = dpkt.pcap.Reader(pcap)
        analyzer.analyze(pcapFD)



def ipAddressToByteString(ipaddress):
    byte1, byte2, byte3, byte4 = ipaddress.split(".")
    return bytearray([int(byte1), int(byte2), int(byte3), int(byte4)])

def getIpPsuedoHeader(sourceBytes, destBytes, length):
    lengthBytes = length.to_bytes(2, 'big')
    pseudoHeaderBytes = sourceBytes[0:4] + destBytes[0:4] + bytearray([0x00, 0x06]) + lengthBytes
    print("get psuedo header")
    return pseudoHeaderBytes

def compareChecksum(fileAddress, fileData):
    print("using addr file: " + fileAddress)
    print("using data file: " + fileData)
    with open(fileAddress, "r") as file:
        line = file.readline()
        spaceInd = line.find(" ")
        sourceIP = line[:spaceInd]
        destIP = line[spaceInd + 1:]

        sourceIPBytes = ipAddressToByteString(sourceIP)
        destIPBytes = ipAddressToByteString(destIP)

        with open(fileData, "rb") as fileData:
            tcp_data = fileData.read()
            datalineLen = len(tcp_data)

            pseudoheader = getIpPsuedoHeader(sourceIPBytes, destIPBytes, datalineLen)
            
            #have the pseudo header
            tcp_data_checksum = bytearray([tcp_data[16], tcp_data[17]])
            retrievedChecksum = int.from_bytes(tcp_data_checksum, 'big')
            tcp_zero_cksum = tcp_data[:16] + b'\x00\x00' + tcp_data[18:]

            if len(tcp_zero_cksum) % 2 == 1:
                tcp_zero_cksum += b'\x00'

            #get the checksum
            
            data = pseudoheader + tcp_zero_cksum

            offset = 0   # byte offset into data
            total = 0

            while offset < len(data):
                # Slice 2 bytes out and get their value:

                word = int.from_bytes(data[offset:offset + 2], "big")

                offset += 2   # Go to the next 2-byte value

                total += word
                total = (total & 0xffff) + (total >> 16)
            total = (~total) & 0xffff

            if total == retrievedChecksum:
                print("data is correct")
            else:
                print("data is incorrect")


if __name__ == "__main__":
    for i in range(0, 10):
        fileAddrName = "tcp_addrs_" + str(i) + ".txt"
        fileDataName = "tcp_data_" + str(i) + ".dat"
        compareChecksum(fileAddrName, fileDataName)
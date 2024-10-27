




if __name__ == "__main__":
    with open("tcp_addrs_0", "rb") as file:
        line = file.readline()
        spaceInd = line.find(" ")
        sourceIP = line[:spaceInd]
        destIP = line[spaceInd + 1:]

        print("sourceIP: " + str(sourceIP))
        print("destIP: " + str(destIP))
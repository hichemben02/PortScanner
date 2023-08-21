try:
    from datetime import datetime
    import sys
    import socket
    import scapy.all as sc
    import scapy.layers.inet as scli
    import random
except ImportError:
    print("\n Some libraries are missing !!! Please install the requirements.txt")
    sys.exit()


class portScanner():
    def __init__(self, target):
        # Target to scan
        self.target = target

        # List of ports to scan (top 20 most scanned ports)
        self.ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    # Print the result dynamically
    def printResult(self, port, status):
        if status == "Open":
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "////"
            
            return (f"\r{str(port)}\t\t\t\tOpen\t\t\t\t{service}\n")

        elif status == "Filtered":
            return (f"\r{str(port)}\t\t\t\tFiltered\t\t\t\t \n")

        elif status == "Close":
            return (f"\r{str(port)}\t\t\t\tClose\t\t\t\t \n")
        
        elif status == "Open/Filtered":
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "////"
            
            return (f"\r{str(port)}\t\t\t\tOpen/Filtered\t\t\t\t{service}\n")
    
    
    # Scan that sends a TCP packet to the target with a SYN flag to determine open ports   
    def defaultScan(self):
        result = ""
        for port in self.ports:
            # Use a random port as the source port
            #sourcePort = random.randint(1, 10000)

            # Send a TCP packet to the port with SYN flag
            scanstealthResponse = sc.sr1(sc.IP(dst=self.target)/sc.TCP(sport= 8000, dport=port, flags="S"), timeout=1, verbose=False)

            if not scanstealthResponse:
                result = result + self.printResult(port, "Open/Filtered") + "\n"
                continue
            
            if scanstealthResponse and scanstealthResponse.haslayer(sc.TCP):
                flag = scanstealthResponse[sc.TCP].flags

                # If the flag is SA (SYN-ACK) that means the port is open
                if flag == "SA":
                    sendReset = sc.sr(sc.IP(dst=self.target) / sc.TCP(sport=80, dport=port, flags="AR"), timeout=1, verbose=False)
                    result = result + self.printResult(port, "Open") + "\n"

                elif flag == 0x14:
                    result = result + self.printResult(port, "Close") + "\n"

                elif flag == "RA":
                    continue
            
            # Here we check if the packet has a icmp layer, that means it may be filtered
            if scanstealthResponse and scanstealthResponse.haslayer(scli.ICMP):
                
                # list of filter codes
                filterCodes = [1, 2, 3, 9, 10, 13]

                if scanstealthResponse[scli.ICMP].type == 3 and scanstealthResponse[scli.ICMP].code in filterCodes:
                    result = result + self.printResult(port, "Filtered") + "\n"
                    continue
        
        return result
    

    def xmasScan(self):
        result = ""
        for port in self.ports:
            # Use a random port as the source port
            sourcePort = random.randint(1, 10000)

            # Send a TCP packet with FPU flag which makes it a xmas scan
            xmasResponse = sc.sr1(sc.IP(dst=self.target)/sc.TCP(sport= 8000, dport=port, flags="FPU"), timeout=1, verbose=False)

            # Now, if there's no reponse, so the port is open or filtered
            if not xmasResponse:
                result = result + self.printResult(port, "Open/Filtered") + "\n"

            elif xmasResponse.haslayer(sc.TCP):

                if xmasResponse[sc.TCP].flags == 0x14:
                    result = result + self.printResult(port, "Close") + "\n"

            elif xmasResponse.haslayer(scli.ICMP):
                filterCodes = [1, 2, 3, 9, 10, 13]

                if xmasResponse[scli.ICMP].type == 3 and xmasResponse[scli.ICMP].code in filterCodes:
                    result = result + self.printResult(port, "Filtered") + "\n"
                    continue
        
        return result


    def nullScan(self):
        result = ""
        for port in self.ports:
            # Use a random port as the source port
            sourcePort = random.randint(1, 10000)

            # Send a TCP packet with no flags
            nullResponse = sc.sr1(sc.IP(dst=self.target)/sc.TCP(sport= 8000, dport=port, flags=""), timeout=1, verbose=False)

            # Now, if there's no reponse, so the port is open or filtered
            if not nullResponse:
                result = result + self.printResult(port, "Open/Filtered") + "\n"

            elif nullResponse.haslayer(sc.TCP):
                if nullResponse[sc.TCP].flags == 0x14:
                    result = result + self.printResult(port, "Close") + "\n"

            elif nullResponse.haslayer(scli.ICMP):
                filterCodes = [1, 2, 3, 9, 10, 13]

                if nullResponse[scli.ICMP].type == 3 and nullResponse[scli.ICMP].code in filterCodes:
                    result = result + self.printResult(port, "Filtered") + "\n"
                    continue

        return result

    # Send tcp packets with ACK flag to detect filtered ports
    def ackScan(self):
        result = ""
        for port in self.ports:
            # Use a random port as the source port
            sourcePort = random.randint(1, 10000)

            ackResponse = sc.sr1(sc.IP(dst=self.target)/sc.TCP(sport= 8000, dport=port, flags="A"), timeout=1, verbose=False)

            if not ackResponse:
                result = result + self.printResult(port, "Filtered") + "\n"
            
            elif ackResponse.haslayer(sc.TCP):
                if ackResponse[sc.TCP].flags == 0x4:
                    continue

            elif ackResponse.haslayer(scli.ICMP):
                filterCodes = [1, 2, 3, 9, 10, 13]

                if ackResponse[scli.ICMP].type == 3 and ackResponse[scli.ICMP].code in filterCodes:
                    result = result + self.printResult(port, "Filtered") + "\n"
                    continue

        return result

    def resultTable(self):
        return ("\n\nPORT\t\t\t\tSTATUS\t\t\t\tSERVICE\n-----------------------------------------------------------------------------------------\n")
    

def main(target, mode):
    # Checking the input arguments
    """
    if len(sys.argv) == 3:
        # Convert the target to IPv4
        target = socket.gethostbyname(sys.argv[2])
    else:
        print("Usage: python3 scanner.py [OPTION] [TARGET]")
        sys.exit()
    """

    # The tool title
    """
    title = "PORT SCANNER"
    with open("result.txt", "w") as f:
        f.write(f"{title} \n")
        f.write("-" * 50 + "\n")
        f.write(f"Scanning target : {target}\n")
        f.write(f"Scanning starts at {str(datetime.now())}\n")
        f.write("-" * 50)
    """

    scanner = portScanner(target)
    # Check the options of scanning
    with open("result.txt", "w") as f:

        if mode == "-sD":
            f.write(scanner.resultTable())
            f.write(scanner.defaultScan())

        elif mode == "-sX":
            f.write(scanner.resultTable())
            f.write(scanner.xmasScan())

        elif mode == "-sN":
            f.write(scanner.resultTable())
            f.write(scanner.nullScan())

        elif mode == "-sA":
            f.write(scanner.resultTable())
            f.write(scanner.ackScan())

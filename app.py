try:
    from datetime import datetime
    import sys
    import socket
    import pyfiglet
    from colorama import init, Fore
    import scapy.all as sc
    import scapy.layers.inet as scli
    import random
except ImportError:
    print("\n Some libraries are missing !!! Please install the requirements.txt")
    sys.exit()

# Needed colors
init()
GREEN = Fore.GREEN
RESET = Fore.RESET
RED = Fore.RED
CYAN = Fore.CYAN
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA

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
            
            print(f"\r{str(port)}\t\t\t\t{GREEN}Open\t\t\t\t{RESET}{service}\n")

        elif status == "Filtered":
            print(f"\r{str(port)}\t\t\t\t{YELLOW}Filtered\t\t\t\t{RESET} \n")

        elif status == "Close":
            print(f"\r{str(port)}\t\t\t\t{RED}Close\t\t\t\t{RESET} \n")
        
        elif status == "Open/Filtered":
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "////"
            
            print(f"\r{str(port)}\t\t\t\t{YELLOW}Open/Filtered\t\t\t\t{RESET}{service}\n")
    
    
    # Scan that sends a TCP packet to the target with a SYN flag to determine open ports   
    def defaultScan(self):
        for port in self.ports:
            # Use a random port as the source port
            sourcePort = random.randint(1, 10000)

            # Send a TCP packet to the port with SYN flag
            scanstealthResponse = sc.sr1(sc.IP(dst=self.target)/sc.TCP(sport=sourcePort, dport=port, flags="S"), timeout=1, verbose=False)

            if not scanstealthResponse:
                self.printResult(port, "Open/Filtered")
                continue
            
            if scanstealthResponse and scanstealthResponse.haslayer(sc.TCP):
                flag = scanstealthResponse[sc.TCP].flags

                # If the flag is SA (SYN-ACK) that means the port is open
                if flag == "SA":
                    sendReset = sc.sr(sc.IP(dst=self.target) / sc.TCP(sport=80, dport=port, flags="AR"), timeout=1, verbose=False)
                    self.printResult(port, "Open")

                elif flag == 0x14:
                    self.printResult(port, "Close")

                elif flag == "RA":
                    continue
            
            # Here we check if the packet has a icmp layer, that means it may be filtered
            if scanstealthResponse and scanstealthResponse.haslayer(scli.ICMP):
                
                # list of filter codes
                filterCodes = [1, 2, 3, 9, 10, 13]

                if scanstealthResponse[scli.ICMP].type == 3 and scanstealthResponse[scli.ICMP].code in filterCodes:
                    self.printResult(port, "Filtered")
                    continue
        
    

    def xmasScan(self):
        for port in self.ports:
            # Use a random port as the source port
            sourcePort = random.randint(1, 10000)

            # Send a TCP packet with FPU flag which makes it a xmas scan
            xmasResponse = sc.sr1(sc.IP(dst=self.target)/sc.TCP(sport=sourcePort, dport=port, flags="FPU"), timeout=1, verbose=False)

            # Now, if there's no reponse, so the port is open or filtered
            if not xmasResponse:
                self.printResult(port, "Open/Filtered")

            elif xmasResponse.haslayer(sc.TCP):

                if xmasResponse[sc.TCP].flags == 0x14:
                    self.printResult(port, "Close")

            elif xmasResponse.haslayer(scli.ICMP):
                filterCodes = [1, 2, 3, 9, 10, 13]

                if xmasResponse[scli.ICMP].type == 3 and xmasResponse[scli.ICMP].code in filterCodes:
                    self.printResult(port, "Filtered")
                    continue
        


    def nullScan(self):
        for port in self.ports:
            # Use a random port as the source port
            sourcePort = random.randint(1, 10000)

            # Send a TCP packet with no flags
            nullResponse = sc.sr1(sc.IP(dst=self.target)/sc.TCP(sport=sourcePort, dport=port, flags=""), timeout=1, verbose=False)

            # Now, if there's no reponse, so the port is open or filtered
            if not nullResponse:
                self.printResult(port, "Open/Filtered")

            elif nullResponse.haslayer(sc.TCP):
                if nullResponse[sc.TCP].flags == 0x14:
                    self.printResult(port, "Close")

            elif nullResponse.haslayer(scli.ICMP):
                filterCodes = [1, 2, 3, 9, 10, 13]

                if nullResponse[scli.ICMP].type == 3 and nullResponse[scli.ICMP].code in filterCodes:
                    self.printResult(port, "Filtered")
                    continue


    # Send tcp packets with ACK flag to detect filtered ports
    def ackScan(self):
        for port in self.ports:
            # Use a random port as the source port
            sourcePort = random.randint(1, 10000)

            ackResponse = sc.sr1(sc.IP(dst=self.target)/sc.TCP(sport=sourcePort, dport=port, flags="A"), timeout=1, verbose=False)

            if not ackResponse:
                self.printResult(port, "Filtered")
            
            elif ackResponse.haslayer(sc.TCP):
                if ackResponse[sc.TCP].flags == 0x4:
                    continue

            elif ackResponse.haslayer(scli.ICMP):
                filterCodes = [1, 2, 3, 9, 10, 13]

                if ackResponse[scli.ICMP].type == 3 and ackResponse[scli.ICMP].code in filterCodes:
                    self.printResult(port, "Filtered")
                    continue

    def resultTable(self):
        print("\n\nPORT\t\t\t\tSTATUS\t\t\t\tSERVICE\n-----------------------------------------------------------------------------------------\n")
    

def main():
    
    # Checking the input arguments
    if len(sys.argv) == 3:

        # Convert the target to IPv4
        target = socket.gethostbyname(sys.argv[2])
    else:
        print("Usage: python3 scanner.py [OPTION] [TARGET]")
        sys.exit()
    

    # The tool title
    title = pyfiglet.figlet_format("PScan", font = "slant")
    
    print(f"{CYAN}{title} {RESET}\n")
    print("-" * 50 + "\n")
    print(f"Scanning target : {GREEN}{target}{RESET}\n")
    print(f"Scanning starts at {MAGENTA}{str(datetime.now())}{RESET}\n")
    print("-" * 50)

    scanner = portScanner(target)
    # Check the options of scanning
    if sys.argv[1] == "-sD":
        scanner.resultTable()
        scanner.defaultScan()

    elif sys.argv[1] == "-sX":
        scanner.resultTable()
        scanner.xmasScan()

    elif sys.argv[1] == "-sN":
        scanner.resultTable()
        scanner.nullScan()

    elif sys.argv[1] == "-sA":
        scanner.resultTable()
        scanner.ackScan()


if __name__ == "__main__":
    main()

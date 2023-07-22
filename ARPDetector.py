from colorama import Fore, init
import scapy.all as scapy
import threading
import time

init(autoreset=True)


class ARPDetector():
    def __init__(self, Interface):
        self.ARP_MYLOG = []
        self.ARP_RESPONSELOG = []
        self.ARP_TIME = 0
        self.ARP_MYLOG_DETECTED = 0
        self.ARP_RESPONSELOG_DETECTED = 0


        self.ClearEventThread = threading.Thread(target=self.ClearEventLog)
        self.ClearEventThread.start()

        self.Sniffer = scapy.sniff(iface=Interface, store=False, prn=self.Sniffer)



    def Printer(self, Writer):
        for i in Writer:
            print(i)
        return "\n"


    def Sniffer(self, packet):
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            print("------------------------------------------------------------------")
            print(packet.show())
            print("------------------------------------------------------------------")


            if self.ARP_RESPONSELOG_DETECTED and self.ARP_MYLOG_DETECTED > 8:
                print(Fore.RED + "ARP Attack Detected !")
                print(Fore.RED + f"\n\nSource :")
                print(Fore.RED + "-----------------------------------------------------")
                print(self.Printer(self.ARP_MYLOG))
                print("\n", self.Printer(self.ARP_RESPONSELOG))
                break_scanner = input("Scanner Devam Et : ")
                self.ARP_RESPONSELOG_DETECTED -= 8
                self.ARP_MYLOG_DETECTED -= 8



            MyIP = packet[scapy.ARP].psrc
            MyMAC = packet[scapy.ARP].hwsrc
            self.ARP_MYLOG.append({"MyIP": MyIP, "MyMac": MyMAC})

            ResponseMAC = packet[scapy.ARP].hwdst
            ResponseIP = packet[scapy.ARP].pdst
            self.ARP_RESPONSELOG.append({"SourceIP": ResponseIP, "SourceMAC": ResponseMAC})

            self.Printer(self.ARP_MYLOG)
            self.Printer(self.ARP_RESPONSELOG)

            if self.ARP_MYLOG[-1] == {"MyIP": MyIP, "MyMac": MyMAC}:
                self.ARP_MYLOG_DETECTED += 1

            if self.ARP_RESPONSELOG[-1] == {"SourceIP": ResponseIP, "SourceMAC": ResponseMAC}:
                self.ARP_RESPONSELOG_DETECTED += 1




    def ClearEventLog(self):
        # 2 Dakikada Bir Loglar Silinecek Üst Üste Aynı IPden log gelirse Engellenecek
        while True:
            time.sleep(1)
            self.ARP_TIME += 1

            if self.ARP_TIME == 30:
                self.ARP_MYLOG.clear()
                self.ARP_RESPONSELOG.clear()
                self.ARP_TIME -= 30
                self.ARP_RESPONSELOG_DETECTED = 0
                self.ARP_MYLOG_DETECTED = 0

NetworkSecurity = ARPDetector("Wi-Fi")
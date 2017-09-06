"""
NERD module getting information about IPs, IP blocks, BGP prefixes, autonomous systems and organizations from RIRs.
"""

from core.basemodule import NERDModule
import g

import socket
import sys
import logging
import io
import csv
import bisect
import ipaddress

class WhoIS(NERDModule):
    """
    WhoIS module.

    Queries RIRs and whois.cymru.com about newly added IPs,
    it also gathers information about corresponding IP blocks, BGP prefixes, autonomous systems and organizations.

    Stores the following attributes:

    ip:
        bgppref # BGP prefix corresponding to this IP
        ipblock # IP block assigned by a RIR to which this IP belongs to

    bgppref:
        id      # BGP Prefix (CIDR)
        rep     # reputation score
        asn     # list of autonomous systems in which this prefix is observed

    asn:
        id      # ASN
        name    # name of the AS
        rir     # corresponding RIR
        rep     # reputation score
        org     # id of an administrating organization
        bgppref # list of BGP prefixes observed in this AS

    ipblock:
        id      # IP block (example: netrange: 127.0.0.1 - 127.0.0.255)
        name    # name of the IP block
        rir     # corresponding RIR
        descr   # description of the IP block (CIDR or address)
        status  # IP block allocation status
        rep     # reputation score
        org     # id of an administrating organization

    org:
        id      # Organization
        name    # name of the organization
        address # address of the organization
        contact # abuse contact (email or phone)

    Scheme:
        IP ---M:N--- BGP prefix ---M:N--- ASN ---N:1---|
        |                                              |
        |-----N:1--- IP block   ---N:1--- ORG ---------|

    Event flow specification:
        !NEW ip -> getIPInfo -> getBGPPrefInfo
                             -> getASNInfo      -> getOrgInfo
                             -> getBlockInfo    -> getOrgInfo
    """

    def __init__(self):
        # Load files used for mapping IPv4 to RIR and ASN to RIR to the program memory.
        # Both files have to be already sorted.
        self.log = logging.getLogger("WhoISmodule")
        asnFile = g.config.get("whois.asn_file", "/tmp/nerd-whois-asn.csv")
        ipv4File = g.config.get("whois.ipv4_file", "/tmp/nerd-whois-ipv4.csv")
        try:
            self.asn_array = self.loadASN(asnFile)
            self.ipv4_array = self.loadIPv4(ipv4File)
        except OSError as e:
            self.log.error(str(e) + ' -> Unable to start the WhoIS module.')
            return

        # Register all necessary handlers.
        g.um.register_handler(
            self.getIPInfo,
            'ip',
            ('!NEW',),
            ()
        )

        g.um.register_handler(
            self.getASNInfo,
            'asn',
            ('!NEW',),
            ('name', 'rep', 'rir', 'org')
        )

        g.um.register_handler(
            self.getBGPPrefInfo,
            'bgppref',
            ('!NEW',),
            ('rep',)
        )

        g.um.register_handler(
            self.getBlockInfo,
            'ipblock',
            ('!NEW',),
            ('name', 'rep', 'rir', 'descr', 'org', 'status')
        )

        g.um.register_handler(
            self.getOrgInfo,
            'org',
            ('!NEW',),
            ('name', 'address', 'contact')
        )

    def loadASN(self, asnFile):
        self.log.info('Loading information about ASN allocation from file: {}.'.format(asnFile))
        dataFile = open(asnFile, 'r')
        datareader = csv.reader(dataFile, delimiter=',')

        # Create a tuple of 2 arrays: row:([ASN], [RIR])
        data = ([],[])
        for row in datareader:
            data[0].append(int(row[0]))
            data[1].append(row[1])

        return data

    def loadIPv4(self, ipv4File):
        self.log.info('Loading information about IP blocks allocation from file: {}.'.format(ipv4File))
        dataFile = open(ipv4File, 'r')
        datareader = csv.reader(dataFile, delimiter=',')

        # Create a tuple of 2 arrays: row:([IP], [RIR])
        # IPs are in numeric form (long int)
        data = ([],[])
        for row in datareader:
            data[0].append(int(row[0]))
            data[1].append(row[1])

        return data

    def findIPBlockRIR(self, ip):
        int_ip = int(ipaddress.ip_address(ip))
        pos = bisect.bisect_left(self.ipv4_array[0], int_ip)
        try:
            if self.ipv4_array[0][pos] != int_ip:
                pos -= 1
        except IndexError as e:
                pos -= 1

        rir = self.ipv4_array[1][pos]
        if rir[0] == 'R':
            if rir.find(':') != -1:
                rir = rir.split(':')[1]
                self.log.warning('Observed IP address {} from reserved IP block. Querying still possible to: {}.'.format(ip, rir))
                return rir, True
            else:
                self.log.warning('Observed IP address {} from reserved IP block. Querying not possible.'.format(ip))
                return None, True

        return rir, False

    def findASNRIR(self, asn):
        pos = bisect.bisect_left(self.asn_array[0], asn)
        try:
            if self.asn_array[0][pos] != asn:
                pos -= 1
        except IndexError as e:
                pos -= 1

        rir = self.asn_array[1][pos]
        if rir[0] == 'R':
            rir = rir.split(':')[1]
            self.log.warning('Observed reserved ASN {}. Querying still possible to: {}.'.format(asn, rir))
            return rir, True
        elif rir[0] == 'U':
            self.log.warning('Observed unalloctaed ASN {}. Querying impossible.'.format(asn))
            return None, True

        return rir, False

    def getIPInfo(self, ekey, rec, updates):
        etype, ip = ekey
        if etype != 'ip':
            return None

        actions = []

        # Perform initial query to whois.cymru.com server to get list of ASNs, BGP prefix and RIR.
        resp_list = self.receiveData('-p -o ' + ip, 'whois.cymru.com', self.parseCymru)
        if resp_list == None:
            self.log.warning('Unable to acquire BGP prefix or ASN from whois.cymru.com. IP: {}. Aborting ASN and BGP prefix record creation.'.format(ip))
        else:
            asn_list = []
            bgp_pref_list = []

            for asn in resp_list:
                bgp_pref_list.append(asn['BGPPrefix'])
                # Create a new ASN (if not already present) and append BGP prefix to its list.
                g.um.update(('asn', int(asn['AS'])), [('add_to_set', 'bgppref', asn['BGPPrefix'])])
                # Append all ASNs to the currently observed BGP prefix for later update.
                asn_list.append(('add_to_set', 'asn', int(asn['AS'])))

            if len(set(bgp_pref_list)) != 1:
                self.log.warning('Observed multiple BGP prefixes for a given IP: {}.\n{}'.format(ip, bgp_pref_list))

            # Create a new BGP prefix (if not already present) and append all ASNs to its list.
            g.um.update(('bgppref', resp_list[0]['BGPPrefix']), asn_list)

            # Add BGP Prefix to the IP record
            actions.append(('set', 'bgppref', resp_list[0]['BGPPrefix']))

        rir, reserved = self.findIPBlockRIR(ip)
        if rir == None:
            return actions

        # Attempt to find netrange of the corresponding smallest IP block.
        inet = self.getInet(ip, rir)
        if inet == None:
            self.log.warning('Unable to find IP block for IP: {} in RIR: {}. Aborting IP block record creation.'.format(ip, rir))
            return actions

        # Add IP block to the IP record
        actions.append(('set', 'ipblock', inet))

        # Create a new IP block (if not already present).
        g.um.update(('ipblock', inet), [])
        return actions

    def getInet(self, ip, rir):
        map_dict = {
           'inetnum' : 'inetnum'
        }

        # Parse IP block from the corresponding RIR.
        if rir == 'lacnic':
            ret = self.receiveData(ip, 'whois.lacnic.net', self.parseRIR, (map_dict, 1))
            if ret == None:
                return None

            inet = ipaddress.ip_network(ret['inetnum'])
            return str(inet.network_address) + " - " + str(inet.broadcast_address)
        elif rir == 'arin':
            return self.receiveData('- n ' + ip, 'whois.arin.net', self.parseArinInet)
        else:
            ret = self.receiveData('-r -T inetnum ' + ip, 'whois.' + rir + '.net', self.parseRIR, (map_dict, 1))
            if ret != None:
                ret = ret['inetnum']

            return ret

    def getBGPPrefInfo(self, ekey, rec, updates):
        etype, bgp_pref = ekey
        if etype != 'bgppref':
            return None

        actions = []
        actions.append(('set', 'rep', 0))

        return actions

    def getASNInfo(self, ekey, rec, updates):
        etype, asn = ekey
        if etype != 'asn':
            return None

        # Perform a lookup for the RIR corresponding to this ASN.
        rir, reserved = self.findASNRIR(asn)
        if rir == None:
            # This branch should never happen, because unallocated blocks are filtered in parseCymru function.
            return None

        data_dict = {}
        actions = []
        actions.append(('set', 'rep', 0))
        if reserved:
            actions.append(('set', 'rir', 'Reserved:' + rir))
        else:
            actions.append(('set', 'rir', rir))

        # Parse ASN information from the corresponding RIR.
        if rir == 'lacnic':
            map_dict = {
                'ownerid' : 'org'
            }

            data_dict = self.receiveData('AS' + str(asn), 'whois.lacnic.net', self.parseRIR, (map_dict, 1))
            if data_dict == None:
                self.log.warning('Unable to find ASN: {} in RIR: {}. Aborting record creation.'.format(asn, rir))
                return actions
        elif rir == 'arin':
            map_dict = {
                'ASName' : 'name',
                'OrgId' : 'org'
            }

            data_dict = self.receiveData('+ a = ' + str(asn), 'whois.arin.net', self.parseRIR, (map_dict, 2))
            if data_dict == None:
                self.log.warning('Unable to find ASN: {} in RIR: {}. Aborting record creation.'.format(asn, rir))
                return actions
        else:
            map_dict = {
                'as-name' : 'name',
                'org' : 'org'
            }

            data_dict = self.receiveData('-r -T aut-num AS' + str(asn), 'whois.' + rir + '.net', self.parseRIR, (map_dict, 2))
            if data_dict == None:
                self.log.warning('Unable to find ASN: {} in RIR: {}. Aborting record creation.'.format(asn, rir))
                return actions

        for key in data_dict.keys():
            if key == 'org':
                # Create a new record of the organization, if not already present.
                g.um.update(('org', rir + ':' + data_dict[key]), [])
                actions.append(('set', key, rir + ':' + data_dict[key]))
            else:
                actions.append(('set', key, data_dict[key]))

        return actions

    def getBlockInfo(self, ekey, rec, updates):
        etype, ip_block = ekey
        if etype != 'ipblock':
            return None

        actions = []
        data_dict = {}

        # Perform a lookup for the RIR corresponding to this IP block.
        first_ip = ip_block.split()[0]
        rir, reserved = self.findIPBlockRIR(first_ip)
        if rir == None:
            return actions

        actions.append(('set', 'rep', 0))
        if reserved:
            actions.append(('set', 'rir', 'Reserved:' + rir))
        else:
            actions.append(('set', 'rir', rir))
        # Parse IP block information from the corresponding RIR.
        if rir == 'lacnic':
            map_dict = {
                'ownerid' : 'org',
                'status' : 'status'
            }

            data_dict = self.receiveData(first_ip, 'whois.lacnic.net', self.parseRIR, (map_dict, 2))
            if data_dict == None:
                self.log.warning('Unable to find IP Block: {} in RIR: {}. Aborting record creation.'.format(ip_block, rir))
                return actions
        elif rir == 'arin':
            map_dict = {
                'OrgId' : 'org',
                'NetType' : 'status'
            }

            # To ensure we get only one match in the database, we must first obtain NetHandle.
            ret = self.receiveData('- n ' + first_ip, 'whois.arin.net', self.parseArinNetHandle)
            if ret == None:
                self.log.warning('Unable to find IP Block: {} in RIR: {}. Aborting record creation.'.format(ip_block, rir))
                return actions

            data_dict = self.receiveData('+ n = ' + ret, 'whois.arin.net', self.parseRIR, (map_dict, 2))
            if data_dict == None:
                self.log.warning('Unable to find IP Block: {} in RIR: {}. Aborting record creation.'.format(ip_block, rir))
                return actions
        else:
            map_dict = {
                'netname' : 'name',
                'descr' : 'descr',
                'org' : 'org',
                'status' : 'status'
            }

            data_dict = self.receiveData('-r -T inetnum ' + first_ip, 'whois.' + rir + '.net', self.parseRIR, (map_dict, 4))
            if data_dict == None:
                self.log.warning('Unable to find IP Block: {} in RIR: {}. Aborting record creation.'.format(ip_block, rir))
                return actions

        for key in data_dict.keys():
            if key == 'org':
                # Create a new record of the organization, if not already present.
                g.um.update(('org', rir + ':' + data_dict[key]), [])
                actions.append(('set', key, rir + ':' + data_dict[key]))
            else:
                actions.append(('set', key, data_dict[key]))

        return actions

    def getOrgInfo(self, ekey, rec, updates):
        etype, org_full = ekey
        if etype != 'org':
            return None

        # Parse RIR from the ID.
        prefix = org_full.find(':')
        rir = org_full[:prefix]
        org = org_full[prefix + 1:]
        actions = []
        data_dict = {}

        # Parse information about the organization from the corresponding RIR.
        if rir == 'lacnic':
            map_dict = {
                'owner' : 'name',
                'address' : 'address',
                'country' : 'address',
                'phone' : 'contact'
            }

            data_dict = self.receiveData(org, 'whois.lacnic.net', self.parseRIR, (map_dict, 3))
            if data_dict == None:
                self.log.warning('Unable to find organization: {} in RIR: {}. Attempting "whois.registro.br".'.format(org, rir))
                map_dict = {
                    'owner' : 'name',
                    'responsible' : 'contact'
                }

                # Unfortunately, the information about LACNIC organizations might be stored on "whois.registro.br" server.
                data_dict = self.receiveData(org, 'whois.registro.br', self.parseRIR, (map_dict, 2))
                if data_dict == None:
                    self.log.warning('Unable to find organization: {} in whois.registro.br. Aborting record creation.'.format(org))
                    return actions

        elif rir == 'arin':
            map_dict = {
                'Org' : 'name',
                'Address' :  'address',
                'City' : 'address',
                'StateProv' : 'address',
                'PostalCode' : 'address',
                'Country' : 'address',
                'OrgAbuseEmail' : 'contact'
            }

            data_dict = self.receiveData('+ o = ' + org, 'whois.arin.net', self.parseRIR, (map_dict, 3))
            if data_dict == None:
                self.log.warning('Unable to find organization: {} in RIR: {}. Aborting record creation.'.format(org, rir))
                return actions
        else:
            map_dict = {
                'org-name' : 'name',
                'address' : 'address',
                'abuse-mailbox' : 'contact'
            }

            data_dict = self.receiveData('-r -T organisation ' + org, 'whois.' + rir + '.net', self.parseRIR, (map_dict, 3))
            if data_dict == None:
                self.log.warning('Unable to find organization: {} in RIR: {}. Aborting record creation.'.format(org, rir))
                return actions

        for key in data_dict:
            actions.append(('set', key, data_dict[key]))

        return actions

    def receiveData(self, query, host, parse_func, args = ()):
        """
        Wrapper function for communicating and parsing information from whois servers.
        Function attempts to connect and receive data from the whois server for a second time
        in case of a connection failure.

        Arguments:
        query -- string to be sent to the whois server
        host -- hostname of the whois server
        parse_func -- function for parsing data received from the whois server,
            possible functions: parseCymru, parseArinInet, parseArinNetHandle, parseRIR
        args -- tuple of arguments required by the parsing function

        Returns:
        The return value depends on the function used for parsing (string/dictionary/list).
        Returns None if an error occurs.
        """
        counter = 0
        while True:
            if counter == 2:
                self.log.error('Unable to receive data from ' + host)
                return None

            counter += 1
            resp = self.sendRequest(query, host)
            if resp == None:
                self.log.warning('Attempt #{} to receive data from {} failed.'.format(counter, host))
                continue

            result = parse_func(resp, args)
            if result == None or len(result) == 0:
                self.log.warning('Attempt #{} to parse data from {} with query: "{}" either failed or provided no useful information.'.format(counter, host, query))
                self.log.debug(resp)
                continue

            return result

    def parseCymru(self, data, args):
        """
        Function used for parsing data received from whois.cymru.com.
        Needs no values in tuple "args".

        Returns:
        list of dictionaries
        """
        buf = io.StringIO(data)
        header = buf.readline()
        header = ''.join(header.split())

        ret = []
        while True:
            vals = buf.readline()
            if not vals:
                break
            vals = ''.join(vals.split())
            d = dict(zip(header.split('|'), vals.split('|')))
            if 'BGPPrefix' not in d.keys() or d['BGPPrefix'] == 'NA' or 'AS' not in d.keys() or d['AS'] == 'NA' or self.findASNRIR(int(d['AS'])) == (None, True):
                continue

            ret.append(d)

        return ret

    def parseArinInet(self, data, args):
        """
        Function used for parsing netrange from the minimalistic data received from whois.arin.com.
        Needs no values in tuple "args".

        Returns:
        string
        """
        buf = io.StringIO(data)
        result = ""
        while True:
            line = buf.readline()
            if not line:
                break

            # Skip comments and empty lines.
            if line.strip() == '' or line[0] == '#':
                continue

            beg = line.find(") ")
            if beg != -1:
                result = line[beg + 2:-1]

        return result

    def parseArinNetHandle(self, data, args):
        """
        Function used for parsing NetHandle from the minimalistic data received from whois.cymru.com.
        Needs no values in tuple "args".

        Returns:
        string
        """
        buf = io.StringIO(data)
        result = ""
        while True:
            line = buf.readline()
            if not line:
                break

            # Skip comments and empty lines.
            if line.strip() == '' or line[0] == '#':
                continue

            beg = line.find("(NET")
            if beg != -1:
                end = line.find(')', beg + 1)
                result = line[beg + 1:end]

        return result

    def parseRIR(self, data, args):
        """
        Function used for parsing data received from all RIRs.

        Arguments:
            args -- expects a tuple of a dictionary and an integer
                    -> dictionary -- a dictionary used for specifying lines to be parsed and their mapping
                    -> integer -- number of unique values in the dictionary used for mapping
                                  it prevents the parser from parsing too many information from the responses of whois servers
                                  especially useful when parsing data from LACNIC

        Returns:
        dictionary
        """
        if len(args) != 2:
            self.log.error('Function parseRIR(data, args) expects a tuple of 2 arguments (dictionary, int) in the argument "args".')
            return None

        mapping_dict, unique_vals = args
        buf = io.StringIO(data)
        count = 0
        result_dict = {}

        while True:
            line = buf.readline()
            if not line:
                break

            # Skip comments and empty lines.
            if line.strip() == '' or line[0] == '%' or line[0] == '#':
                continue

            # Remove spaces.
            vals = ' '.join(line.split())
            vals = vals.split(':')

            if vals[0] in mapping_dict:
                if mapping_dict[vals[0]] in result_dict:
                    result_dict[mapping_dict[vals[0]]] += "\n" + vals[1].strip()
                else:
                    result_dict[mapping_dict[vals[0]]] = vals[1].strip()
                    count += 1

                if count == unique_vals:
                    break

        return result_dict

    def sendRequest(self, query, hostname, port = 43):
        try:
            # Find IPv6 and IPv4 address.
            info = socket.getaddrinfo(hostname, port, 0, 0, socket.SOL_TCP)
            ipv6 = None
            ipv4 = None
            for i in info:
                if not ipv6 and len(i[4]) == 4:
                    ipv6 = i[4]
                if not ipv4 and len(i[4]) == 2:
                    ipv4 = i[4]

            try:
                # It is possible that host does not have IPv6 address or it is not possible to create IPv6 socket.
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(ipv6)
            except (socket.error, TypeError) as e:
                # Create IPv4 socket if IPv6 socket is not an option.
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(ipv4)

            s.send((query).encode('idna') + b"\r\n")
            response = b''
            while True:
                tmp = s.recv(4096)
                response += tmp
                if not tmp:
                    s.close()
                    break
        except socket.error as e:
            self.log.error('Socket error: ' + str(e))
            s.close()
            return None

        response = response.decode('utf-8', errors = 'replace')
        return response

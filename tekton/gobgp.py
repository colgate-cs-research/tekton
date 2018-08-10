#!/usr/bin/env python
"""
GoBGP specific configurations generator
Tested with GoBGP 1.33
"""
import itertools

from ipaddress import IPv4Interface
from ipaddress import IPv6Interface
from ipaddress import IPv4Network
from ipaddress import IPv6Network
from ipaddress import ip_network
from ipaddress import ip_address
from ipaddress import ip_interface

from tekton.graph import NetworkGraph
from tekton.bgp import Access
from tekton.bgp import ActionSetCommunity
from tekton.bgp import ActionSetLocalPref
from tekton.bgp import ActionString
from tekton.bgp import ActionASPathPrepend
from tekton.bgp import ActionSetNextHop
from tekton.bgp import ASPathList
from tekton.bgp import CommunityList
from tekton.bgp import RouteMap
from tekton.bgp import RouteMapLine
from tekton.bgp import MatchCommunitiesList
from tekton.bgp import MatchIpPrefixListList
from tekton.bgp import MatchAsPath
from tekton.bgp import MatchNextHop
from tekton.bgp import IpPrefixList

from tekton.utils import is_empty
from tekton.utils import is_symbolic


__author__ = "Aaron Gember-Jacobson"
__email__ = "agemberjacobson@colgate.edu"


class GoBGPConfigGen(object):
    """Generate GoBGP specific configurations"""

    def __init__(self, g, prefix_map=None):
        assert isinstance(g, NetworkGraph)
        self.g = g
        self.prefix_map = prefix_map or {}
        self.nettype = (IPv4Network, IPv6Network)
        self._next_announced_prefix = int(ip_address(u'128.0.0.0'))
        self._next_as_paths = {}
        for node in self.g.routers_iter():
            self._next_as_paths[node] = itertools.count(1)

    def prefix_lookup(self, prefix):
        if isinstance(prefix, self.nettype):
            return prefix
        if prefix in self.prefix_map:
            return self.prefix_map[prefix]
        ip = ip_address(self._next_announced_prefix)
        net = ip_network(u"%s/24" % ip)
        self._next_announced_prefix += 256
        self.prefix_map[prefix] = net
        return net

    def gen_community_list(self, community_list):
        """
        Generate config lines for community list
        :param community_list:
        :return: configs string
        """
        assert isinstance(community_list, CommunityList)
        config = '[[defined-sets.bgp-defined-sets.community-sets]]\n'
        list_id = community_list.list_id
        config += ' community-set-name = "%d"\n' % list_id
        # FIXME: Handle access
        access = community_list.access.value
        communities = '","'.join([c.value for c in community_list.communities if not is_empty(c)])
        config += ' community-list = ["%s"]\n' % communities
        return config

    def gen_ip_prefix_list(self, node, prefix_list):
        """
        Generate config lines for ip prefix-list
        :param prefix_list:
        :return: configs string
        """
        assert isinstance(prefix_list, IpPrefixList)
        config = '[[defined-sets.prefix-sets]]\n'
        # FIXME: Handle access 
        access = prefix_list.access.value
        networks = prefix_list.networks
        name = prefix_list.name
        config += ' prefix-set-name = "%s"\n' % name
        for i, network in enumerate(networks):
            if is_empty(network):
                continue
            network = self.prefix_lookup(network)
            lineno = (i + 1) * 10
            network = ip_network(unicode(network))
            addr = str(getattr(network, 'network_address', network))
            prefixlen = getattr(network, 'prefixlen', 32)
            config += ' [[defined-sets.prefix-sets.prefix-list]]\n'
            config += '  ip-prefix = "%s/%d"\n' % (addr, prefixlen)
        return config

    def gen_as_path_list(self, node, as_path_list):
        """
        Generate config lines for AS PATH list
        :param prefix_list:
        :return: configs string
        """
        config = '[[defined-sets.bgp-defined-sets.as-path-sets]]\n'
        # FIXME: Handle access
        access = as_path_list.access.value
        as_path = as_path_list.as_paths
        name = as_path_list.list_id
        config += ' as-path-set-name = "%s"\n' % name
        config += ' as-path-list = ["^%s"]\n' % '_'.join([str(t) for t in as_path[1:]])
        return config

    def gen_all_interface_configs(self, node):
        """
        Iterate over all interfaces (including loopbacks) to generate their configs
        :param node: router name
        :return: string configs
        """
        config = 'router %s ' % node
        for i,neighbor in enumerate(self.g.neighbors(node)):
            iface = self.g.get_edge_iface(node, neighbor)
            addr = self.g.get_iface_addr(node, iface)
            config += 'eth%d:%s ' % (i, addr)

        # Loop back interface
        for lo in sorted(self.g.get_loopback_interfaces(node)):
            addr = self.g.get_loopback_addr(node, lo)
            desc = self.g.get_loopback_description(node, lo)
            #config += self.gen_iface_config(node, lo, addr, desc, True, None)
        return config

    def gen_all_communities_lists(self, node):
        """
        Get all communities list defined for the router
        :param node: router
        :return: config string
        """
        config = ""
        comm_lists = self.g.get_bgp_communities_list(node)
        for num in comm_lists:
            comm_list = comm_lists[num]
            config += self.gen_community_list(comm_list)
            config += "\n"
        return config

    def gen_all_as_path_lists(self, node):
        """
        Get all as path list defined for the router
        :param node: router
        :return: config string
        """
        config = ""
        as_path_lists = self.g.get_as_path_list(node)
        for as_path in as_path_lists.values():
            config += self.gen_as_path_list(node, as_path)
            config += "\n"
        return config

    def gen_all_ip_prefixes(self, node):
        """
        Generate all the ip prefixes lists
        :param node:
        :return:
        """
        config = ''
        lists = self.g.get_ip_preflix_lists(node)
        for l in lists:
            prefix_list = lists[l]
            config += self.gen_ip_prefix_list(node, prefix_list)
            config += "\n"
        return config

    def gen_route_map_match(self, node, match):
        config = ''
        if isinstance(match, MatchCommunitiesList):
            config += '[policy-definitions.statements.conditions.bgp-conditions.match-community-set]\n'
            config += '   community-set = "%d"\n' % match.match.list_id
            config += '   match-set-options = "any"'
        elif isinstance(match, MatchIpPrefixListList):
            name = match.match.name
            ips = self.g.get_ip_preflix_lists(node)
            err = "IP list '%s' is not registered at Node '%s': %s" % (name, node, ips)
            assert name in ips, err
            if not all([is_empty(p) for p in ips[match.match.name].networks]):
                config += '[policy-definitions.statements.conditions.match-prefix-set]\n'
                config += '   prefix-set = "%s"\n' % match.match.name
                config += '   match-set-options = "any"'
        elif isinstance(match, MatchAsPath):
            list_no = None
            for tmp in self.g.get_as_path_list(node).values():
                if tmp.as_paths == match.match:
                    list_no = tmp.list_id
            if not list_no:
                list_no = self._next_as_paths[node].next()
                as_path = ASPathList(list_id=list_no, access=Access.permit, as_paths=match.match)
                self.g.add_as_path_list(node, as_path)
            config += '[policy-definitions.statements.conditions.bgp-conditions.match-as-path-set]\n'
            config += '   as-path-set = "%s"\n' % list_no
            config += '   match-set-options = "any"'
        elif isinstance(match, MatchNextHop):
            next_hop = match.match
            parsed = next_hop.split('-') if isinstance(next_hop, basestring) else None
            if parsed and self.g.has_node(parsed[0]):
                router = parsed[0]
                iface = '/'.join(parsed[1:])
                next_hop = self.g.get_interface_loop_addr(router, iface)
                self.prefix_map[match.match] = next_hop
            if hasattr(next_hop, 'ip'):
                next_hop = next_hop.ip
            config += '# UNHANDLED: match ip next-hop %s' % next_hop
        else:
            raise ValueError('Unknown match type %s' % match)
        return config

    def gen_route_map_action(self, action):
        config = ''
        if isinstance(action, ActionSetLocalPref):
            config += '[policy-definitions.statements.actions.bgp-actions]\n'
            config += '   set-local-pref = %d' % action.value
        elif isinstance(action, ActionSetCommunity):
            comms = '","'.join([c.value for c in action.communities])
            config += '[policy-definitions.statements.actions.bgp-actions.set-community]\n'
            if action.additive:
                config += ' additive'
                contig += '   options = "add"\n'
            config += '[policy-definitions.statements.actions.bgp-actions.set-community.set-community-method]\n'
            config += '     communities-lists = ["%s"]' % comms
        elif isinstance(action, ActionSetNextHop):
            if '-' in action.value:
                router = action.value.split('-')[0]
                iface = '/'.join(action.value.split('-')[1:])
                addr = self.g.get_interface_loop_addr(router, iface)
                ip = addr.ip
            else:
                ip = ip_address(action.value)
            config += '[policy-definitions.statements.actions.bgp-actions]\n'
            config += '   set-next-hop = "%s"' % str(ip)
        elif isinstance(action, ActionASPathPrepend):
            config += '[policy-definitions.statements.actions.bgp-actions.set-as-path-prepend]\n'
            config += '   as = "%s"' % ' '.join([str(x) for x in action.value])
        elif isinstance(action, ActionString):
            raise ValueError('Unhandled action type %s' % action.value)
            #config = '%s' % action.value
        else:
            raise ValueError('Unknown action type %s' % action)
        return config

    def gen_route_map(self, node, routemap, route_map_neighbor):
        assert isinstance(routemap, RouteMap)
        config = '[[policy-definitions]]\n'
        name = routemap.name
        config += ' name = "%s"\n' % name
        for line in routemap.lines:
            if is_empty(line.lineno) or is_empty(line.access):
                continue
            no = line.lineno
            access = line.access.value if hasattr(line.access, 'value') else Access.permit
            config += ' [[policy-defintions.statements]]\n'
            config += '  name = "%s"\n' % no
            if name in route_map_neighbor:
                config += '  [policy-definitions.statements.conditions.match-neighbor-set]\n'
                config += '   neighbor-set = "%s"\n' % route_map_neighbor[name]
                config += '   match-set-options = "any"\n'
            for match in line.matches:
                config += '  %s\n' % self.gen_route_map_match(node, match)
            if access == 'permit':
                config += '  [policy-defintions.statements.actions]\n'
                config += '   route-disposition = "accept-route"\n'
            elif access == 'deny':
                config += '  [policy-defintions.statements.actions]\n'
                config += '   route-disposition = "reject-route"\n'
            for action in line.actions:
                config += '  %s\n' % self.gen_route_map_action(action)
        return config

    def gen_all_route_maps(self, node, route_map_neighbor):
        config = ''
        maps = self.g.get_route_maps(node)
        for name in sorted(maps):
            routemap = maps[name]
            config += self.gen_route_map(node, routemap, route_map_neighbor)
            config += '\n'
        return config

    def gen_global_config(self, node, route_map_neighbor):
        """
        Generates the BGP specific configurations
        :param node: router
        :return: configs string
        """
        config = ""
        asn = self.g.get_bgp_asnum(node)
        if not asn:
            # Router doesn't have BGP configured
            return ""
        config += '[global.config]\n'
        config += ' as = %d\n' % asn
        router_id = self.g.get_bgp_router_id(node)
        if router_id and not is_empty(router_id):
            if is_symbolic(router_id):
                router_id = router_id.get_value()
            config += ' router-id = "%s"\n' % ip_address(router_id)

        import_maps = []
        export_maps = []
        for neighbor in sorted(self.g.get_bgp_neighbors(node)):
            import_map = self.g.get_bgp_import_route_map(node, neighbor)
            if import_map:
                import_maps += [import_map]
                assert import_map not in route_map_neighbor
                route_map_neighbor[import_map] = neighbor
            export_map = self.g.get_bgp_export_route_map(node, neighbor)
            if export_map:
                export_maps += [export_map]
                assert export_map not in route_map_neighbor
                route_map_neighbor[export_map] = neighbor

        config += ' [global.apply-policy.config]\n'
        if len(import_maps) > 0:
            config += '  import-policy-list = ["%s"]\n' % '","'.join(import_maps)
        if len(export_maps) > 0:
            config += '  export-policy-list = ["%s"]\n' % '","'.join(export_maps)
        return config + '\n'

    def gen_zebra(self, node):
        config = '[zebra]\n'
        config += ' [zebra.config]\n'
        config += '  enabled = true\n'
        config += '  url = "unix:/tmp/%s.zserv.api"\n' % node
        config += '  redistribute-route-type-list = ["static"]\n'
        config += '  version = 4\n'
        return config + '\n'

    def gen_bmp(self, node):
        config = '[[bmp-servers]]\n'
        config += ' [bmp-servers.config]\n'
        config += '  address = "10.0.255.254"\n'
        config += '  port = 11019\n'
        config += '  route-monitoring-policy = "local-rib"\n'
        return config + '\n'
           
    def gen_all_announcements(self, node):
        config = ''
        announcements = self.g.get_bgp_announces(node)
        for ann in announcements:
            net, mask, route_map = None, None, None
            if isinstance(ann, (IPv4Network, IPv6Network)):
                net = ann.network_address
                mask = ann.netmask
            elif ann in self.g.get_loopback_interfaces(node):
                addr = self.g.get_loopback_addr(node, ann)
                net = addr.network.network_address
                mask = addr.netmask
            elif self.g.has_node(ann) and self.g.is_network(ann):
                iface = self.g.get_edge_iface(node, ann)
                addr = self.g.get_edge_iface(node, iface)
                net = addr.network.network_address
                mask = addr.netmask
            route_map = announcements[ann].get('route_map', None)
            assert net, "No network address in announcement: %s" % ann
            assert mask, "No network mask in announcement: %s" % ann
            assert not route_map, "Cannot handle route-maps"
            config += 'ip route %s %s null0\n' % (net, mask)
        return config

    def gen_all_neighbors(self, node):
        config = ''
        for neighbor in sorted(self.g.get_bgp_neighbors(node)):
            if not self.g.is_router(neighbor):
                continue
            neighbor_asn = self.g.get_bgp_asnum(neighbor)
            iface = self.g.get_bgp_neighbor_iface(node, neighbor)
            if is_empty(iface):
                err = "Interface for BGP peering is not defined {}->{}:{}".\
                    format(node, neighbor, iface)
                assert not is_empty(iface), err
            if iface in self.g.get_loopback_interfaces(neighbor):
                neighboraddr = self.g.get_loopback_addr(neighbor, iface)
            else:
                neighboraddr = self.g.get_iface_addr(neighbor, iface)
            assert neighbor_asn is not None, 'AS number is not set for %s' % neighbor
            err = "BGP Peer address of {} is not set: {}.{}".format(node, neighbor, iface)
            assert neighboraddr is not None and not is_empty(neighboraddr), err
            # Check if the neighbor is peering with the loopback of this node
            source_iface = self.g.get_bgp_neighbor_iface(node, neighbor)
            update_source = source_iface in self.g.get_loopback_interfaces(node)
            config += '[[neighbors]]\n'
            description = self.g.get_bgp_neighbor_description(node, neighbor)
            if description:
                config += ' # %s\n' % description
            config += ' [neighbors.config]\n'
            config += '  peer-as = %s\n' % neighbor_asn
            config += '  neighbor-address = "%s"\n' % neighboraddr.ip
            # FIXME: required?
            #if update_source:
            #    config += " neighbor %s update-source %s\n" % (neighboraddr.ip, source_iface)
            #config += " neighbor %s send-community\n" % neighboraddr.ip
            import_map = self.g.get_bgp_import_route_map(node, neighbor)
            export_map = self.g.get_bgp_export_route_map(node, neighbor)
            if import_map or export_map:
                config += '\n[[defined-sets.neighbor-sets]]\n'
                config += ' neighbor-set-name = "%s"\n' % neighbor
                config += ' neighbor-info-list = ["%s"]\n' % neighboraddr.ip
        return config

    def gen_external_announcements(self, node):
        #assert self.g.is_peer(node)
        # Find the next free loopback interface
        next_lo = 0
        while "lo{}".format(next_lo) in self.g.get_loopback_interfaces(node):
            next_lo += 1
        ifaces = []
        lines = []
        lineno = 5
        for ann, attrs in self.g.get_bgp_advertise(node).iteritems():
            iface = attrs.get('loopback')
            if not iface:
                net = self.prefix_lookup(ann.prefix)
                addr = ip_interface(u"%s/%d" % (net.hosts().next(), net.prefixlen))
                iface = "lo%s" % next_lo
                desc = "For %s" % ann.prefix
                self.g.set_loopback_addr(node, iface, addr)
                self.g.set_loopback_description(node, iface, desc)
            else:
                addr = self.g.get_loopback_addr(node, iface)
                net = addr.network
            # Announce network
            self.g.add_bgp_announces(node, iface)
            # Prepend AS Path
            if ann.as_path and len(ann.as_path) > 1:
                iplist = IpPrefixList(name="L_%s" % next_lo,
                                      access=Access.permit, networks=[net])
                self.g.add_ip_prefix_list(node, iplist)
                match = MatchIpPrefixListList(iplist)
                action = ActionASPathPrepend(ann.as_path)
                line = RouteMapLine(matches=[match],
                                    actions=[action],
                                    access=Access.permit,
                                    lineno=lineno)
                lines.append(line)
                ifaces.append(iface)
                lineno += 5
            next_lo += 1
        if lines:
            allow = RouteMapLine(matches=None, actions=None, access=Access.permit, lineno=100)
            lines.append(allow)
            rmap = RouteMap(name="Export_%s" % node, lines=lines)
            self.g.add_route_map(node, rmap)
            for neighbor in self.g.get_bgp_neighbors(node):
                err = "External peers cannot have predefined export route-maps (Peer %s)" % node
                assert not self.g.get_bgp_export_route_map(node, neighbor), err
                self.g.add_bgp_export_route_map(node, neighbor, rmap.name)

    def gen_zebra_preamble(self, node):
        config = 'hostname %s\n' % node
        config += '!\n'
        config += 'password mysecret\n'
        config += 'enable password mysecret\n'
        config += '!\n'
        config += 'log file /tmp/%s.zebra.log\n' % node
        config += '!\n'
        return config

    def gen_router_config(self, node):
        """
        Get the router configs
        :param node: router
        :return: configs string
        """
        assert self.g.is_router(node)
        #if self.g.is_peer(node):
        self.gen_external_announcements(node)

        route_map_neighbor = {}

        gobgp = "# %s\n\n" % node
        gobgp += self.gen_global_config(node, route_map_neighbor)
        gobgp += self.gen_zebra(node)
        gobgp += self.gen_bmp(node)
        gobgp += self.gen_all_neighbors(node)
        gobgp += self.gen_all_communities_lists(node)
        gobgp += self.gen_all_ip_prefixes(node)
        gobgp += self.gen_all_as_path_lists(node)
        gobgp += self.gen_all_route_maps(node, route_map_neighbor)

        zebra = self.gen_zebra_preamble(node)
        zebra += self.gen_all_announcements(node)

        return (gobgp, zebra)

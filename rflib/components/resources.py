import networkx as nx
import logging
import threading

from rflib.defs import *
from rflib.components.modifiers import *
from rflib.components.configuration import *

log = logging.getLogger('rfserver')

def net_addr(ip, mask):
    net_addr_bin = []
    ip_split = ip.split('.')
    mask_split = mask.split('.')
    if len(ip_split) == len(mask_split):
        for i in range(len(ip_split)):
            net_addr_bin.append( str( int(ip_split[i]).__and__(int(mask_split[i])) ) )
    net_addr = '.'.join(net_addr_bin)
    return net_addr


class Port(object):
    def __init__(self, id, port_no):
        super(Port, self).__init__()
        self.id = id
        self.port = port_no

    def __eq__(self, other):
        return self.id == other.id and self.port == other.port

    def __hash__(self):
        return hash((self.id, self.port))

    def __str__(self):
        return 'Port<%s, %s>' % (self.id, self.port)

class Link(object):
    def __init__(self, src, dst):
        super(Link, self).__init__()
        self.src = src
        self.dst = dst

    def has_node(self, other):
        eq = False

        if other.src:
            eq = (self.src == other.src)
        if other.dst:
            eq = (self.dst == other.dst)
        return eq

    def __eq__(self, other):
        #return self.src == other.src and self.dst == other.dst
        return (self.src == other.src and self.dst == other.dst) or (self.src == other.dst and self.dst == other.src)

    def __hash__(self):
        #return hash((self.src, self.dst))
        return hash((self.src, self.dst)) + hash((self.dst, self.src))

    def __str__(self):
        return 'LINK<%s, %s>' % (self.src, self.dst)


class Topology(object):
    def __init__(self, topo_id, topo_type):
        self.topo = nx.Graph(topo=topo_type)
        self.topo_type = topo_type
        self.topo_id = topo_id

    def get_topo(self):
        return self.topo

    def get_topo_id(self):
        return self.topo_id

    def set_topo_id(self, value):
        self.topo_id = value

    def build_topo_phy(self):
        if self.topo.graph['topo'] != 'phy':
            return False
        dps = self.get_dps()
        links = self.get_links()
        for dpid in dps.keys():
            if dpid not in self.topo.nodes():
                self.topo.add_node(dpid)
        for dpid in self.topo.nodes():
            if dpid not in dps.keys():
                self.topo.remove_node(dpid)
        for link in links.keys():
            data_ = {'src':link.src.id,'dst':link.dst.id,'src_port':link.src.port,'dst_port':link.dst.port}
            if (link.src.id, link.dst.id) not in self.topo.edges():
                self.topo.add_edge(link.src.id, link.dst.id, data_ )
            else:
                self.topo.remove_edge(link.src.id, link.dst.id)
                self.topo.add_edge(link.src.id, link.dst.id, data_ )

        #TODO topology update and check links removal
        for (src, dst, data_) in self.topo.edges(data=True):
            srcid = data_['src']
            dstid = data_['dst']
            srcport = data_['src_port']
            dstport = data_['dst_port']
            link = Link(Port(srcid,srcport),Port(dstid,dstport))
            if link not in links.keys():
                self.topo.remove_edge(src,dst)

        return True

    def build_topo_vir(self):
        if self.topo.graph['topo'] != 'vir':
            return False
        vms = self.get_vms()
        links = self.get_links()
        for vmid in vms.keys():
            if vmid not in self.topo.nodes():
                #self.topo.add_node(vmid, vms[vmid])
                self.topo.add_node(vmid)
        for vmid in self.topo.nodes():
            if vmid not in vms.keys():
                self.topo.rm_node(vmid)
        for link in links.keys():
            if (link.src.id, link.dst.id) not in self.topo.edges():
                data_ = {'src':link.src.id,'dst':link.dst.id,'src_port':link.src.port,'dst_port':link.dst.port}
                self.topo.add_edge(link.src.id, link.dst.id, data_)
        for (src, dst, data_) in self.topo.edges(data=True):
            srcid = data_['src']
            dstid = data_['dst']
            srcport = data_['src_port']
            dstport = data_['dst_port']
            link = Link(Port(srcid, srcport), Port(dstid, dstport))
            if link not in links.keys():
                self.topo.remove_edge(src,dst)

        return True

    def update_topo(self):
        if self.topo.graph['topo'] == 'phy':
            self.build_topo_phy()
        if self.topo.graph['topo'] == 'vir':
            self.build_topo_vir()

    def chk_topo_conn(self):
        return nx.is_connected(self.topo)


class Datapath():
    def __init__(self, dpid, port=None):
        self.dpid = dpid
        self.meter_ids = 1
        self.group_ids = 1
        self.flows = {} # flow format 'dst_port':(addr,mask,srchw,dsthw,is_multipath) adicionar campos table,groupid,metertable,
        self.meters = {}
        self.groups = {}
        if port:
            self.ports = [port] #portnum
        else:
            self.ports = []

    def get_meters(self):
        return self.meters

    def add_meter(self):
        meter_id = self.meter_ids
        self.meters[meter_id] = {'bands':[]}
        self.meter_ids += 1
        return meter_id

    def rm_meter(self, meter_id):
        if meter_id in self.meters.keys():
            del self.meters[meter_id]
            return True
        return False

    def add_meter_band(self, meter_id, rate, burst=0, prec_level=None, experimenter=None, meter_type='drop'):
        if meter_id in self.meters.keys():
            meter = {'rate':rate, 'burst':burst, 'meter_type':meter_type, 'prec_level':prec_level, 'experimenter':experimenter}
            if meter not in self.meters[meter_id]['bands']:
                self.meters[meter_id]['bands'].append(meter)
            return True

    def rm_meter_band(self, meter_id, meter_type='drop'):
        if meter_id in self.meters.keys():
            meters = [meter for meter in self.meters[meter_id]['bands'] if meter['meter_type']==meter_type]
            if meters and meter[0] in self.meters[meter_id]['bands']:
                self.meters[meter_id]['bands'].remove(meter[0])
            return True
        return False

    def get_groups(self):
        return self.groups

    def add_group(self, group_type='select'):
        group = {'group_type':group_type, 'buckets':[], 'actions':{}, 'bucket_actions_id':1}
        group_id = self.group_ids
        self.group_ids += 1
        self.groups[group_id] = group
        return group_id

    def rm_group(self, group_id):
        if group_id in self.groups.keys():
            del self.groups[group_id]
            return True
        return False

    def add_group_bucket(self, group_id, port, bucket_weight=1, watch_port=None, watch_group=None, bucket_actions=None):
        if group_id in self.groups.keys():
            bucket_actions_id = self.groups[group_id]['bucket_actions_id']
            self.groups[group_id]['actions'][bucket_actions_id] = bucket_actions
            self.groups[group_id]['bucket_actions_id'] += 1
            group_bucket = {'port':port, 'bucket_weight':bucket_weight, 'watch_port':watch_port,
                    'watch_group':watch_group, 'bucket_actions_id':bucket_actions_id}
            self.groups[group_id]['buckets'].append(group_bucket)
            return True
        return False

    def rm_group_bucket(self, group_id, port, bucket_weight=1, watch_port=None, watch_group=None, bucket_actions_id=None):
        group_bucket = {'port':port, 'bucket_weight':bucket_weight, 'watch_port':watch_port,
                'watch_group':watch_group, 'bucket_actions_id':bucket_actions_id}
        if group_id in self.groups.keys():
            if group_bucket in self.groups[group_id]['buckets']:
                del self.groups[group_id]['actions'][bucket_actions_id]
                self.groups[group_id]['buckets'].remove(group_bucket)
            return True
        return False

    def add_port(self, port):
        if port not in self.ports:
            self.ports.append(port)

    def rm_port(self, port):
        if port in self.ports:
            self.ports.remove(port)

    def add_flows(self, ct_id, flows):
        for flow in flows:
            dst_port = flow['actions']['dst_port']
            addr = flow['matches']['address']
            table_id = 0
            if 'table_id' in flow.keys():
                table_id = flow['options']['table_id']
            if not 'options' in flow.keys():
                flow['options'] = {}
            flow['options']['ct_id'] = ct_id
            flow['options']['dp_id'] = self.dpid
            flow['options']['table_id'] = table_id
            flow_add = {}
            flow_add.update(flow)
            if dst_port in self.ports:
                if not dst_port in self.flows.keys():
                    self.flows[dst_port] = []
                if flow_add not in self.flows[dst_port]:
                    self.flows[dst_port].append(flow_add)

    def rm_flows(self, ct_id, flows):
        for flow in flows:
            dst_port = flow['actions']['dst_port']
            addr = flow['matches']['address']
            mask = flow['matches']['netmask']
            flow_del = {}
            flow_del.update(flow)
            if dst_port in self.flows.keys():
                flows_ = [ flow_ for flow_ in self.flows[dst_port] if (flow_['matches']['address'] == addr and flow_['matches']['netmask'] == mask) ]
                if flows_:
                    self.flows[dst_port].remove( flows_[0] )
                    if not self.flows[dst_port]:
                        del self.flows[dst_port]
            return True

    def update_flow(self, flow, update_item, update_value):
        dst_port = flow['actions']['dst_port']
        if flow in self.flows[dst_port]:
            flow[update_item] = update_value
            return True
        return False

    def get_ports(self):
        return self.ports

    def get_flows(self):
        return self.flows

    def get_flows_by_port(self,port):
        return self.flows.get(port, None)

    def get_flows_by_addr(self, addr=None):
        flows_by_addr = []
        addrs = []
        if addr:
            for dst_port in self.flows.keys():
                if self.flows[dst_port]['address'] == addr:
                    flows_by_addr.append(self.flows[dst_port])
        else:
            for dst_port in self.flows.keys():
                if self.flows[dst_port]['address'] not in addrs:
                    addrs.append(self.flows[dst_port]['address'])
                    flows_by_addr.append(self.get_flows_by_addr(addr=self.flows[dst_port]['address']))
        return flows_by_addr


class TopoPhysical(Topology):
    def __init__(self, topo_id, ct_id):
        super(TopoPhysical, self).__init__(topo_id=topo_id, topo_type='phy')
        self.ct_id = ct_id
        self.dps = {}                       #Mapping dpid:(Datapath object)
        self.links = {}                     #links srcdpid, srcport, dstdpid, dstport
        self.map_vm_dp_id = {}              #Mapping vmid:[dpid]
        self.map_vm_dp_port = {}            #Mapping '(vmid, vmport)':(dpid,dport)
        self.map_vs_dp_port = {}            #Mapping '(vsid, vsport)':(dpid,dport):

    def get_ct_id(self):
        return self.ct_id

    def set_ct_id(self, value):
        self.ct_id = value

    def get_dps(self):
        return self.dps

    def get_links(self):
        return self.links

    def get_map_vmid(self, vmid):
        if vmid in self.map_vm_dp_id.keys():
            return self.map_vm_dp_id[vmid]
        else:
            return None

    def get_map_vm_dp_id(self):
        return self.map_vm_dp_id

    def get_map_vs_dp_port(self):
        return self.map_vs_dp_port

    def get_map_vm_dp_port(self):
        return self.map_vm_dp_port

    def reg_map_vmid(self, vmid, dpid):
        if vmid not in self.map_vm_dp_id.keys():
            self.map_vm_dp_id[vmid] = [dpid]
        elif dpid not in self.map_vm_dp_id[vmid]:
            self.map_vm_dp_id[vmid].append(dpid)

    def ureg_map_vmid(self, vmid, dpid):
        if vmid in self.map_vm_dp_id.keys():
            self.map_vm_dp_id[vmid].remove(dpid)
            if not self.map_vm_dp_id[vmid]:
                del self.map_vm_dp_id[vmid]

    def reg_map_vs_dp_port(self, vsid, vsport, dpid, dpport):
        if (vsid,vsport) not in self.map_vs_dp_port.keys():
            self.map_vs_dp_port[(vsid,vsport)] = (dpid,dpport)

    def ureg_map_vs_dp_port(self, vsid, vsport):
        if (vsid,vsport) in self.map_vs_dp_port.keys():
            del self.map_vs_dp_port[(vsid,vsport)]

    def reg_map_vm_dp_port(self, vmid, vmport, dpid, dpport):
        if (vmid,vmport) not in self.map_vm_dp_port.keys():
            self.map_vm_dp_port[(vmid, vmport)] = (dpid, dpport)
            self.reg_map_vmid(vmid, dpid)

    def ureg_map_vm_dp_port(self, vmid, vmport, dpid, dpport):
        if (vmid,vmport) in self.map_vm_dp_port.keys():
            del self.map_vm_dp_port[(vmid,vmport)]
            if not vmid in self.map_vm_dp_port.keys()[0]:
                self.ureg_map_vmid(vmid,dpid)

    def reg_dp(self, dpid, port):
        if dpid in self.dps.keys():
            self.update_dp(dpid, port=port, flows=None, is_removal=False)
        else:
            self.dps[dpid] = Datapath(dpid, port)

    def update_dp(self, dpid, port=None, flows=None, is_removal=False):
        if dpid in self.dps:
            if is_removal:
                if port:
                    self.dps[dpid].rm_port(port)
                if flows:
                    self.dps[dpid].rm_flows(self.ct_id, flows)
            else:
                if port:
                    self.dps[dpid].add_port(port)
                if flows:
                    self.dps[dpid].add_flows(self.ct_id, flows)

    def ureg_dp(self, dpid):
        if dpid in self.dps:
            del self.dps[dpid]

    def reg_link(self, src_dpid, src_port_no, dst_dpid, dst_port_no):
        src = Port(src_dpid, src_port_no)
        dst = Port(dst_dpid, dst_port_no)
        link = Link(src,dst)
        link_rvrse = Link(dst,src)
        if link not in self.links.keys() and link_rvrse not in self.links.keys():
            self.links[link] = {'max_bandwidth':0, 'bandwidth':0}

    def ureg_link(self, src_dpid, src_port_no, dst_dpid, dst_port_no):
        src = Port(src_dpid, src_port_no)
        dst = Port(dst_dpid, dst_port_no)
        link = Link(src,dst)
        if link in self.links.keys():
            del self.links[link]

    def get_link(self, src_dpid, src_port, dst_dpid, dst_port):
        src = Port(src_dpid, src_port)
        dst = Port(dst_dpid, dst_port)
        link_src = Link(src, dst)
        link_dst = Link(dst, src)
        if link_src in self.links.keys():
            return link_src
        elif link_dst in self.links.keys():
            return link_dst
        else:
            return None

    def get_link_pair(self, dpid, port):
        links = self.links.keys()
        src = Port(dpid, port)
        dst = Port(dpid, port)
        eq_dst = [ link.dst for link in links if src == link.src]
        eq_src = [ link.src for link in links if dst == link.dst]
        if eq_dst:
            return eq_dst[0]
        elif eq_src:
            return eq_src[0]
        else:
            return None

    def get_link_data(self, src_dpid, src_port, dst_dpid, dst_port):
        src = Port(src_dpid, src_port)
        dst = Port(dst_dpid, dst_port)
        link = Link(src, dst)
        if link in self.links.keys():
            return self.links[link]
        else:
            return None

    def get_link_datas(self, link):
        if link in self.links.keys():
            return self.links[link]
        else:
            return None

    def get_dp_controller(self, dpid):
        if dpid in self.dps.keys():
            return self.get_ct_id()

    def get_dp_flows(self, dpid, port=None):
        if port:
            return self.dps[dpid].get_flows_by_port(port)
        else:
            return self.dps[dpid].get_flows()

    def get_dp_ports(self, dpid):
        return self.dps[dpid].get_ports()

    def get_dp_flows_by_addr(self, dpid, addr=None):
        return self.dps[dpid].get_flows_by_addr(addr=addr)

    def update_dp_flow(self, dpid, flow, update_item, update_value):
        if dpid in self.dps.keys():
            if self.dps[dpid].update_flow(flow, update_item, update_value):
                return True
        return False

    def dp_meter(self, dpid, meter_id=None, rate=0, burst=0, meter_type='drop',
            prec_level=None, experimenter=None, add_rem=True):
        if dpid in self.dps.keys():
            if add_rem:
                return self.dps[dpid].add_meter()
            else:
                return self.dps[dpid].rm_meter(meter_id)

    def dp_meter_bands(self, dpid, meter_id=None, rate=0, burst=0, meter_type='drop',
            prec_level=None, experimenter=None, add_rem=True):
        if dpid in self.dps.keys():
            if add_rem:
                return self.dps[dpid].add_meter_band(meter_id, rate,
                        burst=burst,
                        prec_level=None,
                        experimenter=None,
                        meter_type=meter_type)
            else:
                return self.dps[dpid].rm_meter_band(meter_id, meter_type=meter_type)

    def dp_group(self, dpid, group_id=None, group_type='select', add_rem=True):
        if dpid in self.dps.keys():
            if add_rem:
                return self.dps[dpid].add_group(group_type=group_type)
            else:
                return self.dps[dpid].rm_group(group_id)

    def dp_group_buckets(self, dpid, group_id=None, port=None, bucket_weight=1,
            watch_port=None, watch_group=None, bucket_actions=None, add_rem=True):
        if dpid in self.dps.keys():
            if add_rem:
                return self.dps[dpid].add_group_bucket(self, group_id, port,
                        bucket_weight=bucket_weight,
                        watch_port=watch_port,
                        watch_group=watch_group,
                        bucket_actions=bucket_actions)
            else:
                return self.dps[dpid].rm_group_bucket(self, group_id, port,
                        bucket_weight=bucket_weight,
                        watch_port=watch_port,
                        watch_group=watch_group,
                        bucket_actions=bucket_actions)

                def get_dp_meters(self, dpid):
                    if dpid in self.dps.keys():
                        self.dps[dpid].get_meters()

    def get_dp_groups(self, dpid):
        if dpid in self.dps.keys():
            self.dps[dpid].get_groups()


class VM():
    def __init__(self, vmid, intfs=None, vs_id=None, vs_port=None):
        self.id = vmid
        self.intfs = {}     #Mapping dict 'name:[numero, macaddr, ipaddr, mask]' by msg InterfaceRegister
        self.routes = {}    #Mapping: dict 'port:[routes]'
        self.addrs = []
        if intfs:
            self.add_intfs(intfs)

    def add_intfs(self, intfs):
        intfsname = intfs['name']
        intfsnum = intfs['vm_port']
        hwaddr = intfs['hwaddress']
        ipaddr = intfs['address']
        mask = intfs['netmask']
        netaddr = net_addr(ipaddr, mask)
        if intfsnum not in self.intfs.keys():
            self.intfs[intfsnum] = {
                    'name':intfsname,
                    'hwaddress':hwaddr,
                    'address':ipaddr,
                    'netmask':mask,
                    'netaddr':netaddr}
            self.add_addr(ipaddr)

    def rm_intfs(self, intfsnum):
        if intfsnum in self.intfs.keys():
            del self.intfs[intfsnum]
            self.rm_addr(self.intfs[intfsnum]['address'])

    def has_addr(self, addr):
        if addr in self.addrs:
            return True
        else:
            return False

    def get_intf_by_addr(self, addr):
        if addr in self.addrs:
            for intfnum in self.intfs.keys():
                if self.intfs[intfnum]['address'] == addr:
                    return self.intfs[intfnum]
        return None

    def add_addr(self, addr):
        if addr not in self.addrs:
            self.addrs.append(addr)

    def rm_addr(self, addr):
        if addr in self.addrs:
            self.addrs.remove(addr)

    def add_route(self, route):
        dst_port = route['actions']['dst_port']
        is_multipath = False
        is_resilience = False
        bandwidth = 0
        if 'bandwidth' in route.keys():
            bandwidth = route['bandwidth']
        route_add = {'is_multipath':is_multipath,
                'is_resilience':is_resilience,
                'bandwidth':bandwidth}
        route_add.update( route )
        if dst_port not in self.routes.keys():
            self.routes[dst_port] = [ route_add ]
            return True
        else:
            if route_add not in self.routes[dst_port]:
                self.routes[dst_port].append( route_add )
                return True
        return False

    def rm_route(self, route):
        dst_port = route['actions']['dst_port']
        addr = route['matches']['address']
        netmask = route['matches']['netmask']
        if dst_port in self.routes.keys():
            routes_ = [ route_ for route_ in self.routes[dst_port]
                    if (route_['matches']['address'] == addr and route_['matches']['netmask'] == netmask) ]
            if routes_:
                self.routes[dst_port].remove( routes_[0] )
            return True
        return False

    def get_routes(self):
        return self.routes

    def get_routes_by_port(self, port):
        return self.routes.get(port,None)

    def get_routes_by_addr(self, addr=None):
        routes_by_addr = []
        addrs = []
        if addr:
            for dst_port in self.routes.keys():
                for route in self.routes[dst_port]:
                    if route['matches']['address'] == addr:
                        routes_by_addr.append(route)
        else:
            for dst_port in self.routes.keys():
                for route in self.routes[dst_port]:
                    if route['matches']['address'] not in addrs:
                        addrs.append(route['matches']['address'])
                        routes_by_addr.append(self.get_routes_by_addr(addr=route['matches']['address']))
        return routes_by_addr

    def get_intfs(self):
        return self.intfs

    def get_intfs_by_num(self, intfsnum):
        if intfsnum in self.intfs.keys():
            return self.intfs[intfsnum]
        else:
            return None


class TopoVirtual(Topology):
    def __init__(self, topo_id):
        super(TopoVirtual, self).__init__(topo_id=topo_id, topo_type='vir')
        self.vms = {}                       #Mapping vmid:(VM object)
        self.links = {}                     #links srcvsid, srcvsport, dstvsid, dstvsport
        self.map_dp_vm_id = {}              #Mapping dpid:[vmid]
        self.map_dp_vm_port = {}            #Mapping '(dpid,dport)':(vmid, vmport)
        self.map_vs_vm_port = {}            #Mapping '(vsid,vsport)':(vmid,vmport)

    def get_vms(self):
        return self.vms

    def get_umapped_vms(self):
        mapped_vmids = set(reduce(lambda x, y: x+y, self.map_dp_vm_id.values(), []))
        umapped_items = filter(lambda x: x[0] not in mapped_vmids, self.vms.items())
        umapped_vms = dict(unmapped_items)
        return umapped_vms

    def get_links(self):
        return self.links

    def get_map_dp_vm_id(self):
        return self.map_dp_vm_id

    def get_map_vs_vm_port(self):
        return self.map_vs_vm_port

    def get_map_dp_vm_port(self):
        return self.map_dp_vm_port

    def reg_map_dpid(self, dpid, vmid):
        if dpid not in self.map_dp_vm_id.keys():
            self.map_dp_vm_id[dpid] = [vmid]
        elif vmid not in self.map_dp_vm_id[dpid]:
            self.map_dp_vm_id[dpid].append(vmid)

    def ureg_map_dpid(self, dpid, vmid):
        if dpid in self.map_dp_vm_id.keys():
            self.map_dp_vm_id[dpid].remove(vmid)
            if not self.map_dp_vm_id[dpid]:
                del self.map_dp_vm_id[dpid]

    def get_map_dpid(self, dpid):
        if dpid in self.map_dp_vm_id.keys():
            return self.map_dp_vm_id[dpid]

    def reg_map_dp_vm_port(self, dpid, dpport, vmid, vmport):
        if (dpid,dpport) not in self.map_dp_vm_port.keys():
            self.map_dp_vm_port[(dpid,dpport)] = (vmid,vmport)
            self.reg_map_dpid(dpid, vmid)

    def ureg_map_dp_vm_port(self, dpid, dpport, vmid, vmport):
        if (dpid,dpport) in self.map_dp_vm_port.keys():
            del self.map_dp_vm_port[(dpid,dpport)]
            if not dpid in self.map_dp_vm_port.keys()[0]:
                self.ureg_map_dpid(dpid, vmid)

    def reg_map_vs_vm_port(self, vsid, vsport, vmid, vmport):
        if (vsid,vsport) not in self.map_vs_vm_port.keys():
            self.map_vs_vm_port[(vsid,vsport)] = (vmid,vmport)

    def ureg_map_vs_vm_port(self, vsid, vsport):
        if (vsid,vsport) in self.map_vs_vm_port.keys():
            del self.map_vs_vm_port[(vsid,vsport)]

    def reg_vm(self, vmid, intfs):
        if vmid in self.vms.keys():
            self.update_vm(vmid, intfs=intfs, routes=None, is_removal=False)
        else:
            self.vms[vmid] = VM(vmid, intfs=intfs)

    def ureg_vm(self, vmid, intfs):
        if vmid in self.vms.keys():
            del self.vms[vmid]

    def update_vm(self, vmid, intfs=None, routes=None, is_removal=False):
        if vmid in self.vms.keys():
            if is_removal:
                if intfs:
                    self.vms[vmid].rm_intfs(intfs)
                if routes:
                    self.vms[vmid].rm_route(routes)
            else:
                if intfs:
                    self.vms[vmid].add_intfs(intfs)
                if routes:
                    self.vms[vmid].add_route(routes)

    def get_vm_routes(self, vmid, port=None):
        if vmid in self.vms.keys():
            if port:
                return self.vms[vmid].get_routes_by_port(port)
            else:
                return self.vms[vmid].get_routes()

    def get_vm_routes_by_addr(self, vmid, addr=None):
        if vmid in self.vms.keys():
            return self.vms[vmid].get_routes_by_addr(addr=addr)

    def get_vm_intf(self, vmid, intf_num=None):
        if vmid in self.vms.keys():
            if intf_num:
                return self.vms[vmid].get_intfs_by_num(intf_number)
            else:
                return self.vms[vmid].get_intfs()

    def reg_link(self, src_vmid, src_intf, dst_vmid, dst_intf, vsid_src=None, vsid_src_port=None, vsid_dst=None, vsid_dst_port=None):
        src = Port(src_vmid, src_intf)
        dst = Port(dst_vmid, dst_intf)
        link = Link(src,dst)
        link_rvrse = Link(dst,src)
        if link not in self.links.keys() and link_rvrse not in self.links.keys():
            self.links[link] = {'vsid_src':vsid_src, 'vsid_src_port':vsid_src_port, 'vsid_dst':vsid_dst, 'vsid_dst_port':vsid_dst_port}

    def update_link(self, src_vmid, src_intf, dst_vmid, dst_intf, vsid_src=None, vsid_src_port=None, vsid_dst=None, vsid_dst_port=None):
        src = Port(src_vmid, src_intf)
        dst = Port(dst_vmid, dst_intf)
        link = Link(src,dst)
        if link in self.links:
            self.links[link] = {'vsid_src':vsid_src, 'vsid_src_port':vsid_src_port, 'vsid_dst':vsid_dst, 'vsid_dst_port':vsid_dst_port}

    def ureg_link(self, src_vmid, src_intf, dst_vmid, dst_intf):
        src = Port(src_vmid, src_intf)
        dst = Port(dst_vmid, dst_intf)
        link = Link(src,dst)
        if link in self.links:
            del self.links[link]

    def get_vm_has_addr(self, vmid, addr):
        if self.vms[vmid].has_addr(addr):
            return True
        else:
            return False

    def get_vm_intf_by_addr(self, vmid, addr):
        vm_intf = self.vms[vmid].get_intf_by_addr(addr)
        return vm_intf


class Topologies():
    def __init__(self):
        self.modifiers = Modifiers()
        self.algorithms = Algorithms()
        self.phy_topos = {}
        self.vir_topos = {}
        self.topo_mapping = {}

    def build_graph(self, topo_phy, topo_vir):
        topo_phy.build_topo_phy()
        self.algorithms.map_topos(topo_phy, topo_vir)
        topo_vir.build_topo_vir()

    def reg_topo(self, topo_id, topo_type, ct_id=None):
        if topo_type == 'phy':
            if topo_id not in self.phy_topos.keys():
                topo_phy = TopoPhysical(topo_id, ct_id)
                self.phy_topos[topo_id] = topo_phy

        if topo_type == 'vir':
            if topo_id not in self.vir_topos.keys():
                topo_vir = TopoVirtual(topo_id)
                self.vir_topos[topo_id] = topo_vir

    def map_topo(self, phy_topo, vir_topo):
        self.topo_mapping[phy_topo] = vir_topo

    def get_topo(self, topo_id, topo_type):
        if topo_type == 'vir':
            if topo_id in self.vir_topos.keys():
                return self.vir_topos[topo_id]
        if topo_type == 'phy':
            if topo_id in self.phy_topos.keys():
                return self.phy_topos[topo_id]
        return None

    def get_phy_topos(self):
        return self.phy_topos

    def get_vir_topos(self):
        return self.vir_topos

    def mod_vir_topo(self, topo_vir, msg):
        msg_type =  msg.get_type()
        if msg_type == INTERFACE_REGISTER:
            topo_vir.reg_vm(msg.get_vm_id(), msg.to_dict())
        if msg_type == VIRTUAL_PLANE_MAP:
            topo_vir.reg_map_vs_vm_port(msg.get_vs_id(), msg.get_vs_port(),
                    msg.get_vm_id(), msg.get_vm_port())
        if msg_type == ROUTE_MOD:
            route = self.modifiers.convert_routemod_to_route(msg)
            is_removal = True if msg.get_mod()==1 else False
            topo_vir.update_vm(msg.get_id(), intfs=None, routes=route, is_removal=is_removal)

    def mod_phy_topo(self, topo_phy, msg):
        msg_type =  msg.get_type()
        if msg_type == DATAPATH_PORT_REGISTER:
            topo_phy.reg_dp(msg.get_dp_id(), msg.get_dp_port())
        if msg_type == DATAPATH_DOWN:
            topo_phy.ureg_dp(msg.get_dp_id())
        if msg_type == DATA_PLANE_LINK:
            if msg.get_is_removal():
                topo_phy.ureg_link(msg.get_dp_src_id(), msg.get_dp_src_port(),
                        msg.get_dp_dst_id(), msg.get_dp_dst_port())
            else:
                topo_phy.reg_link(msg.get_dp_src_id(), msg.get_dp_src_port(),
                        msg.get_dp_dst_id(), msg.get_dp_dst_port())
        if msg_type == DATA_PLANE_MAP:
            topo_phy.reg_map_vs_dp_port(msg.get_vs_id(), msg.get_vs_port(),
                    msg.get_dp_id(), msg.get_dp_port())

    def mod_phy_mapping(self, topo_phy, vs_id, vs_port, vm_id, vm_port):
        topo_phy_map_vs_dp_port = topo_phy.get_map_vs_dp_port()
        if (vs_id,vs_port) in topo_phy_map_vs_dp_port.keys():
            dp_id,dp_port = topo_phy_map_vs_dp_port[(vs_id,vs_port)]
            topo_phy.reg_map_vm_dp_port(vm_id, vm_port, dp_id, dp_port)

    def mod_vir_mapping(self, topo_vir, vs_id, vs_port, dp_id, dp_port):
        map_vs_vm_port = topo_vir.get_map_vs_vm_port()
        if (vs_id,vs_port) in map_vs_vm_port.keys():
            vm_id,vm_port = map_vs_vm_port[(vs_id,vs_port)]
            topo_vir.reg_map_dp_vm_port(dp_id, dp_port, vm_id, vm_port)

    def chk_vir_phy_map(self, vir_topo, phy_topo):
        map_vs_vm_port = vir_topo.get_map_vs_vm_port()
        map_vs_dp_port = phy_topo.get_map_vs_dp_port()
        for (vsid,vsport) in map_vs_vm_port.keys():
            if (vsid,vsport) not in map_vs_dp_port.keys():
                return False
        return True

    #Checks if virtual and physical are ready for mapping
    #I.e., if all topoVirtual routes will be adequated to the topoPhysical accordingly to the mapping between them
    def chk_topos(self, topo_phy, topo_vir):
        map_dp_vm_port = topo_vir.get_map_dp_vm_port()
        map_vm_dp_port = topo_phy.get_map_vm_dp_port()
        vms_queue = []
        vms_visited = []
        vms = topo_vir.get_vms()
        vms_queue.extend(vms.keys())

        while vms_queue:
            vmid_src = vms_queue.pop()
            vmid_src_routes = []
            dpids_connected = []
            vmid_conn = False

            vmid_src_routes += topo_vir.get_vm_routes_by_addr(vmid_src)

            vmid_src_intfs = topo_vir.get_vm_intf(vmid_src, intf_num=None)

            for intf_num in vmid_src_intfs.keys():
                if (vmid_src, int(intf_num)) in map_vm_dp_port.keys():
                    dpid,dpport = map_vm_dp_port[(vmid_src, int(intf_num))]
                    dp_pair = topo_phy.get_link_pair(dpid, dpport)
                    if dp_pair:
                        dpids_connected.append( (dp_pair.id, dp_pair.port ) )

            for route in vmid_src_routes:
                if (vmid_src, int(route['actions']['dst_port'])) in map_vm_dp_port.keys():
                    dpid_src, dpport_src = map_vm_dp_port[(vmid_src, int(route['actions']['dst_port']))]
                    pair = topo_phy.get_link_pair(dpid_src, dpport_src)
                    if pair:
                        link = topo_phy.get_link(dpid_src, dpport_src, pair.id, pair.port)
                        if dpid_src != link.src.id:
                            dpid_dst = link.src.id
                            dpport_dst = link.src.port
                        elif dpid_src != link.dst.id:
                            dpid_dst = link.dst.id
                            dpport_dst = link.dst.port

                        if (dpid_dst,dpport_dst) in map_dp_vm_port.keys():
                            vmid_dst, vmport_dst = map_dp_vm_port[(dpid_dst,dpport_dst)]
                            if vmid_dst not in vms_queue and vmid_dst not in vms_visited:
                                vms_queue.append(vmid_dst)
                        vms_visited.append(vmid_src)
                        if (pair.id, pair.port) in dpids_connected:
                            vmid_conn = True
            if not vmid_conn:
                return False
        return True

    def chk_vir_topo_conn(self, topo_vir):
        links_vir = topo_vir.get_links()
        map_vs_vm_port = topo_vir.get_map_vs_vm_port()
        conn = False

        for link_vir in links_vir.keys():
            (src_vmid, src_intf) = link_vir.src.id, link_vir.src.port
            (dst_vmid, dst_intf) = link_vir.dst.id, link_vir.dst.port

            if (src_vmid, src_intf) in map_vs_vm_port.values() \
                    and (dst_vmid, dst_intf) in map_vs_vm_port.values():
                vsid_src,vsid_src_port = map_vs_vm_port.keys()[map_vs_vm_port.values().index( (src_vmid, src_intf) )]
                vsid_dst,vsid_dst_port = map_vs_vm_port.keys()[map_vs_vm_port.values().index( (dst_vmid, dst_intf) )]

                if (vsid_src,vsid_src_port) and (vsid_dst,vsid_dst_port):
                    conn = True
                else:
                    conn = False
        return conn

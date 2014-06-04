from rflib.components.resources import *

class Algorithms(object):
    def __init__(self):
        self.id_ = 0

    #Checks topoPhysical full connectivity and updates topoVirtual links accordingly to topoPhysical links
    def map_topos(self, topoPhysical, topoVirtual):
        if ( topoPhysical.chk_topo_conn() ):
            map_dp_vm_port = topoVirtual.get_map_dp_vm_port()
            dps_phy = topoPhysical.get_dps()
            map_vs_vm_port = topoVirtual.get_map_vs_vm_port()
            links_phy = topoPhysical.get_links()
            for link in links_phy.keys():
                src = link.src
                dst = link.dst
                if (src.id, src.port) in map_dp_vm_port.keys()
                    and (dst.id, dst.port) in map_dp_vm_port.keys():
                    (src_vmid, src_intf) = map_dp_vm_port[(src.id, src.port)]
                    (dst_vmid, dst_intf) = map_dp_vm_port[(dst.id, dst.port)]
                    if (src_vmid, src_intf) in map_vs_vm_port.values()
                        and (dst_vmid, dst_intf) in map_vs_vm_port.values():
                        vsid_src,vsid_src_port = map_vs_vm_port.keys()[map_vs_vm_port.values().index( (src_vmid, src_intf) )]
                        vsid_dst,vsid_dst_port = map_vs_vm_port.keys()[map_vs_vm_port.values().index( (dst_vmid, dst_intf) )]
                        if (vsid_src,vsid_src_port) and (vsid_dst,vsid_dst_port):
                            topoVirtual.reg_link(
                                    src_vmid, src_intf,
                                    dst_vmid, dst_intf,
                                    vsid_src=vsid_src, vsid_src_port=vsid_src_port,
                                    vsid_dst=vsid_dst, vsid_dst_port=vsid_dst_port)
                    else:
                        topoVirtual.reg_link(
                                src_vmid, src_intf,
                                dst_vmid, dst_intf,
                                vsid_src=None,
                                vsid_src_port=None,
                                vsid_dst=None, vsid_dst_port=None)

            links_vir = topoVirtual.get_links()
            num_vir_links = len(links_vir)
            log.info("Mapping topos: topo virt links %s", num_vir_links)

            num_phy_links = len(links_phy)
            log.info("Mapping topos: topo phy links %s", num_phy_links)

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <time.h>

#include <string>
#include <vector>
#include <cstring>
#include <iostream>

#include "converter.h"
#include "FlowTable.h"
#ifdef FPM_ENABLED
#include "FPMServer.hh"
#endif /* FPM_ENABLED */

using namespace std;

void HTPollingFunc(struct rtnl_handle *rth, FlowTable *table){
    rtnl_listen(rth, FlowTable::HTUpdateCB, table);
}

void GWResolverFunc(FlowTable *table){
    table->resolveGateways();
}

#ifndef FPM_ENABLED
void RTPollingFunc(struct rtnl_handle *rth, FlowTable *table){
    rtnl_listen(rth, FlowTable::RTUpdateCB, table);
}
#else
void FPMServerFunc(FMPServer *server){
    server->start();
}

#endif /* FPM_ENABLED */

int rta_to_ip(unsigned char family, const void *ip, IPAddress& result) {
    if (family == AF_INET) {
        result = IPAddress(reinterpret_cast<const struct in_addr *>(ip));
    } else if (family == AF_INET6) {
        result = IPAddress(reinterpret_cast<const struct in6_addr *>(ip));
    } else {
        fprintf(stderr, "Unrecognised nlmsg family");
        return -1;
    }

    if (result.toString() == "") {
        fprintf(stderr, "Blank IP address. Dropping Route\n");
        return -1;
    }
    return 0;
}

// TODO: implement a way to pause the flow table updates when the VM is not
//       associated with a valid datapath


static int FlowTable::HTUpdateCB(const struct sockaddr_nl *, struct nlmsghdr *n, void *table){
    table->updateHostTable(n);
}

static int FlowTable::RTUpdateCB(const struct sockaddr_nl *, struct nlmsghdr *n, void *table){
    table->updateRouteTable(n);
}

FlowTable::FlowTable(uint64_t vm_id, map<string, Interface> interfaces, IPCMessageService *ipc, vector<uint32_t> *down_ports){
    this->vm_id = vm_id;
    this->interfaces = interfaces;
    this->ipc = ipc;
    this->down_ports = down_ports;

    family = AF_UNSPEC;
    groups = ~0U;
    llink = 0;
    laddr = 0;
    lroute = 0;
    fpmServer = NULL;

    rtnl_open(&rth_host, RTMGRP_NEIGH);
    rtnl_open(&rth_route, RTMGRP_IPV4_MROUTE | RTMGRP_IPV4_ROUTE
                        | RTMGRP_IPV6_MROUTE | RTMGRP_IPV6_ROUTE);
}

FlowTable:~FlowTable(){
#ifdef FPM_ENABLED
    if (fpmServer != NULL) delete fpmServer;
#endif /* FPM_ENABLED */
}

void FlowTable::start(){
    NTPolling = boost:thread(&HTPollingFunc, &rth_host, this);

#ifdef FPM_ENABLED
    std::count << "FPM interface enabled\n";
    fpmServer = new fpmServer(this);
    FPMClient = boost:thread(&FPMServerFunc, fpmServer);
#else
    std::count << "Netlink interface enabled\n";
    RTPolling = boost::thread(&RTPollingFunc, &rth_route, this);
#endif /* FPM_ENABLED */

    GWResolver = boost:thread(&GWResolverFunc, this);
    GWResolver.join();
}

void FlowTable::clear(){
    this->routeTable.clear();
    boost::lock_guard<boost::mutex> lock(hostTableMutex);
    this->hostTable.clear();
}

void FlowTable::interrupt(){
    HTPolling.interrupt();
    GWResolver.interrupt();
#ifdef FPM_ENABLED
    FPMClient.interrupt();
#else
    RTPolling.interrupt();
#endif /* FPM_ENABLED */
}

int FlowTable::updateHostTable(struct nlmsghdr *n) {
    struct ndmsg *ndmsg_ptr = (struct ndmsg *) NLMSG_DATA(n);
    struct rtattr *rtattr_ptr;

    char intf[IF_NAMESIZE + 1];
    memset(intf, 0, IF_NAMESIZE + 1);

    boost::this_thread::interruption_point();

    if (if_indextoname((unsigned int) ndmsg_ptr->ndm_ifindex, (char *) intf) == NULL) {
        perror("HostTable");
        return 0;
    }
    /*
    if (ndmsg_ptr->ndm_state != NUD_REACHABLE) {
        cout << "ndm_state: " << (uint16_t) ndmsg_ptr->ndm_state << endl;
        return 0;
    }
    */
    boost::scoped_ptr<HostEntry> hentry(new HostEntry());

    char mac[2 * IFHWADDRLEN + 5 + 1];
    memset(mac, 0, 2 * IFHWADDRLEN + 5 + 1);

    rtattr_ptr = (struct rtattr *) RTM_RTA(ndmsg_ptr);
    int rtmsg_len = RTM_PAYLOAD(n);

    for (; RTA_OK(rtattr_ptr, rtmsg_len); rtattr_ptr = RTA_NEXT(rtattr_ptr, rtmsg_len)) {
        switch (rtattr_ptr->rta_type) {
        case RTA_DST: {
            if (rta_to_ip(ndmsg_ptr->ndm_family, RTA_DATA(rtattr_ptr),
                          hentry->address) < 0) {
                return 0;
            }
            break;
        }
        case NDA_LLADDR:
            if (strncpy(mac, ether_ntoa(((ether_addr *) RTA_DATA(rtattr_ptr))), sizeof(mac)) == NULL) {
                perror("HostTable");
                return 0;
            }
            break;
        default:
            break;
        }
    }

    hentry->hwaddress = MACAddress(mac);
    if (getInterface(intf, "host", hentry->interface) != 0) {
        return 0;
    }

    if (strlen(mac) == 0) {
        fprintf(stderr, "Received host entry with blank mac. Ignoring\n");
        return 0;
    }

    switch (n->nlmsg_type) {
        case RTM_NEWNEIGH: {
            sendToHw(RMT_ADD, *hentry);

            string host = hentry->address.toString();
            {
                // Add to host table
                boost::lock_guard<boost::mutex> lock(hostTableMutex);
                hostTable[host] = *hentry;
            }
            {
                // If we have been attempting neighbour discovery for this
                // host, then we can close the associated socket.
                boost::lock_guard<boost::mutex> lock(ndMutex);
                map<string, int>::iterator iter = pendingNeighbours.find(host);
                if (iter != pendingNeighbours.end()) {
                    if (close(iter->second) == -1) {
                        perror("pendingNeighbours");
                    }
                    pendingNeighbours.erase(host);
                }
            }

            std::cout << "netlink->RTM_NEWNEIGH: ip=" << host << ", mac=" << mac
                      << std::endl;
            break;
        }
        /* TODO: enable this? It is causing serious problems. Why?
        case RTM_DELNEIGH: {
            std::cout << "netlink->RTM_DELNEIGH: ip=" << ip << ", mac=" << mac << std::endl;
            sendToHw(RMT_DELETE, *hentry);
            // TODO: delete from hostTable
            boost::lock_guard<boost::mutex> lock(hostTableMutex);
            break;
        }
        */
    }

    return 0;
}

int FlowTable::updateRouteTable(struct nlmsghdr *n) {
    struct rtmsg *rtmsg_ptr = (struct rtmsg *) NLMSG_DATA(n);

    boost::this_thread::interruption_point();

    if (!((n->nlmsg_type == RTM_NEWROUTE || n->nlmsg_type == RTM_DELROUTE) &&
          rtmsg_ptr->rtm_table == RT_TABLE_MAIN)) {
        return 0;
    }

    boost::scoped_ptr<RouteEntry> rentry(new RouteEntry());

    char intf[IF_NAMESIZE + 1];
    memset(intf, 0, IF_NAMESIZE + 1);

    /* MULTIPATH ROUTE ENTRIES */
    int num_rentries_multipath = MAX_RENTRIES_MULTIPATH;
    int rt_multipath = 0;
    bool is_multipath = false;
    char gwmp[num_rentries_multipath][INET_ADDRSTRLEN];
    char intfmp[num_rentries_multipath][IF_NAMESIZE + 1];
    for (int i = 0; i<num_rentries_multipath; i++){
        memset(gwmp[i], 0, INET_ADDRSTRLEN);
        memset(intfmp[i], 0, IF_NAMESIZE + 1);
    }

    struct rtattr *rtattr_ptr;
    rtattr_ptr = (struct rtattr *) RTM_RTA(rtmsg_ptr);
    int rtmsg_len = RTM_PAYLOAD(n);

    for (; RTA_OK(rtattr_ptr, rtmsg_len); rtattr_ptr = RTA_NEXT(rtattr_ptr, rtmsg_len)) {
        switch (rtattr_ptr->rta_type) {
        case RTA_DST:
            if (rta_to_ip(rtmsg_ptr->rtm_family, RTA_DATA(rtattr_ptr),
                          rentry->address) < 0) {
                return 0;
            }
            break;
        case RTA_GATEWAY:
            if (rta_to_ip(rtmsg_ptr->rtm_family, RTA_DATA(rtattr_ptr),
                          rentry->gateway) < 0) {
                return 0;
            }
            break;
        case RTA_OIF:
            if_indextoname(*((int *) RTA_DATA(rtattr_ptr)), (char *) intf);
            break;
        case RTA_MULTIPATH: {
            struct rtnexthop *rtnhp_ptr = (struct rtnexthop *) RTA_DATA(rtattr_ptr);
            int rtnhp_len = RTA_PAYLOAD(rtattr_ptr);
            is_multipath = true;
            for (;;) {
                if (rtnhp_len < (int) sizeof(*rtnhp_ptr)) {
                    break;
                }

                if (rtnhp_ptr->rtnh_len > rtnhp_len) {
                    break;
                }

                if (rtnhp_ptr->rtnh_len > sizeof(*rtnhp_ptr) ){
                    if_indextoname(rtnhp_ptr->rtnh_ifindex, (char *) intfmp[rt_multipath]);             
                    int attrlen = rtnhp_ptr->rtnh_len - sizeof(*rtnhp_ptr);
                    struct rtattr *attr = RTNH_DATA(rtnhp_ptr);
                    while (RTA_OK(attr,attrlen)){
                        if ((attr->rta_type <= RTA_MAX) && (attr->rta_type == RTA_GATEWAY)) {
                            inet_ntop(AF_INET, RTA_DATA(attr), gwmp[rt_multipath], 128);
                        /*
                        if (rta_to_ip(rtmsg_ptr->rtm_family, RTA_DATA(rtattr_ptr), rentry->gateway) < 0) {
                            return 0;
                        }
                        */
                            //std::cout << "New multipath gw: " << gwmp[rt_multipath] << ", numero: " << rt_multipath << ", tipo: " << n->nlmsg_type << ", int: " << intfmp[rt_multipath] << std::endl;
                        }
                        attr = RTA_NEXT(attr, attrlen);
                    }
                }

                rtnhp_len -= NLMSG_ALIGN(rtnhp_ptr->rtnh_len);
                rtnhp_ptr = RTNH_NEXT(rtnhp_ptr);
                rt_multipath++;
            }//End for(;;)
        }
            break;
        default:
            break;
        }
    }

    if (is_multipath == true) {
        for (int intfnum = 0; intfnum<rt_multipath; intfnum++) {
            if (getInterface(intfmp[intfnum], "route", rentry->interface) != 0) {
                return 0;
            }
        }
    }
    else{    
        if (getInterface(intf, "route", rentry->interface) != 0) {
            return 0;
        }
    }

    rentry->netmask = IPAddress(IPV4, rtmsg_ptr->rtm_dst_len);
    string net = rentry->address.toString();
    string mask = rentry->netmask.toString();
    string gw;

    switch (n->nlmsg_type) {
        case RTM_NEWROUTE:
            if (is_multipath == true){
                for (int i = 0; i<rt_multipath; i++){
                    if (inet_addr(gwmp[i]) == INADDR_NONE) {
                        return 0;
                    }
                    rentry->gateway = IPAddress(IPV4, gwmp[i]);
                    gw = rentry->gateway.toString();
                    std::cout << "netlink->RTM_NEWROUTE (RTA_MULTIPATH): net=" << net << ", mask="
                              << mask << ", gw=" << gw << std::endl;
                    pendingRoutes.push(PendingRoute(RMT_ADD, *rentry));
                }
            }
            else{
                gw = rentry->gateway.toString();
                std::cout << "netlink->RTM_NEWROUTE: net=" << net << ", mask="
                          << mask << ", gw=" << gw << std::endl;
                pendingRoutes.push(PendingRoute(RMT_ADD, *rentry));
            }
            break;
        case RTM_DELROUTE:
            if (is_multipath == true){
                for (int i = 0; i<rt_multipath; i++){
                    if (inet_addr(gwmp[i]) == INADDR_NONE) {
                        return 0;
                    }
                    rentry->gateway = IPAddress(IPV4, gwmp[i]);
                    gw = rentry->gateway.toString();
                    std::cout << "netlink->RTM_DELROUTE (RTA_MULTIPATH): net=" << net << ", mask="
                              << mask << ", gw=" << gw << std::endl;
                    pendingRoutes.push(PendingRoute(RMT_DELETE, *rentry));
                }
            }
            else{
                gw = rentry->gateway.toString();
                std::cout << "netlink->RTM_DELROUTE: net=" << net << ", mask="
                          << mask << ", gw=" << gw << std::endl;
                pendingRoutes.push(PendingRoute(RMT_DELETE, *rentry));
            }
            break;
    }
    return 0;
}

void FlowTable::resolveGateways() {
    while (true) {
        boost::this_thread::interruption_point();

        PendingRoute pr;
        pendingRoutes.wait_and_pop(pr);

        bool existingEntry = false;
        std::list<RouteEntry>::iterator iter = routeTable.begin();
        for (; iter != routeTable.end(); iter++) {
            if (pr.second == *iter) {
                existingEntry = true;
                break;
            }
        }

        if (existingEntry && pr.first == RMT_ADD) {
            fprintf(stdout, "Received duplicate route addition for route %s\n",
                    pr.second.address.toString().c_str());
            continue;
        }

        if (!existingEntry && pr.first == RMT_DELETE) {
            fprintf(stdout, "Received route removal for %s but route %s.\n",
                    pr.second.address.toString().c_str(), "cannot be found");
            continue;
        }

        const RouteEntry& re = pr.second;
        if (pr.first != RMT_DELETE &&
                findHost(re.address) == MAC_ADDR_NONE) {
            /* Host is unresolved. Attempt to resolve it. */
            if (resolveGateway(re.gateway, re.interface) < 0) {
                /* If we can't resolve the gateway, put it to the end of the
                 * queue. Routes with unresolvable gateways will constantly
                 * loop through this code, popping and re-pushing. */
                fprintf(stderr, "An error occurred while %s %s/%s.\n",
                        "attempting to resolve", re.address.toString().c_str(),
                        re.netmask.toString().c_str());
                pendingRoutes.push(pr);
                continue;
            }
        }

        if (sendToHw(pr.first, pr.second) < 0) {
            fprintf(stderr, "An error occurred while pushing route %s/%s.\n",
                    re.address.toString().c_str(),
                    re.netmask.toString().c_str());
            pendingRoutes.push(pr);
            continue;
        }

        if (pr.first == RMT_ADD) {
            routeTable.push_back(pr.second);
        } else if (pr.first == RMT_DELETE) {
            routeTable.remove(pr.second);
        } else {
            fprintf(stderr, "Received unexpected RouteModType (%d)\n", pr.first);
        }
    }
}

/**
 * Initiates the gateway resolution process for the given host.
 *
 * Returns:
 *  0 if address resolution is currently being performed
 * -1 on error (usually an issue with the socket)
 */
int FlowTable::resolveGateway(const IPAddress& gateway, const Interface& iface) {
    if (is_port_down(iface.port)) {
        return -1;
    }

    string gateway_str = gateway.toString();

    // If we already initiated neighbour discovery for this gateway, return.
    boost::lock_guard<boost::mutex> lock(ndMutex);
    if (pendingNeighbours.find(gateway_str) != pendingNeighbours.end()) {
        return 0;
    }

    // Otherwise, we should go ahead and begin the process.
    int sock = initiateND(gateway_str.c_str());
    if (sock == -1) {
        return -1;
    }
    pendingNeighbours[gateway_str] = sock;
    return 0;
}


/**
 * Get the local interface corresponding to the given interface number.
 *
 * On success, overwrites given interface pointer with the active interface
 * and returns 0;
 * On error, prints to stderr with appropriate message and returns -1.
 */
int FlowTable::getInterface(const char *ifName, const char *type, Interface &intf) {
    map<string, Interface>::iterator it = interfaces.find(ifName);
    if (it == interfaces.end()) {
        fprintf(stderr, "Interface %s not found, dropping %s entry\n",
                intf, type);
        return -1;
    }
    if (!it->second.active) {
        fprintf(stderr, "Interface %s inactive, dropping %s entry\n",
                intf, type);
        return -1;
    }
    intf = it->second;
    return 0;
}


/**
 * Begins the neighbour discovery process to the specified host.
 *
 * Returns an open socket on success, or -1 on error.
 */
int FlowTable::initiateND(const char *hostAddr) {
    int s, flags;
    struct sockaddr_storage store;
    struct sockaddr_in *sin = (struct sockaddr_in*)&store;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&store;

    memset(&store, 0, sizeof(store));

    if (inet_pton(AF_INET, hostAddr, &sin->sin_addr) == 1) {
        store.ss_family = AF_INET;
    } else if (inet_pton(AF_INET6, hostAddr, &sin6->sin6_addr) == 1) {
        store.ss_family = AF_INET6;
    } else {
        fprintf(stderr, "Invalid IP address \"%s\" for resolution. Dropping\n",
                hostAddr);
        return -1;
    }

    if ((s = socket(store.ss_family, SOCK_STREAM, 0)) < 0) {
        perror("socket() failed");
        return -1;
    }

    // Prevent the connect() call from blocking
    flags = fcntl(s, F_GETFL, 0);
    if (fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl() failed");
        close(s);
        return -1;
    }

    connect(s, (struct sockaddr *)&store, sizeof(store));
    return s;
}


/**
 * Find the MAC Address for the given host in a thread-safe manner.
 *
 * This searches the internal hostTable structure for the given host, and
 * returns its MAC Address. If the host is unresolved, this will return
 * FlowTable::MAC_ADDR_NONE. Neighbour Discovery is not performed by this
 * function.
 */
const MACAddress& FlowTable::findHost(const IPAddress& host) {
    boost::lock_guard<boost::mutex> lock(hostTableMutex);
    map<string, HostEntry>::iterator iter;
    iter = hostTable.find(host.toString());
    if (iter != hostTable.end()) {
        return iter->second.hwaddress;
    }

    return MAC_ADDR_NONE;
}

bool FlowTable::is_port_down(uint32_t port) {
    vector<uint32_t>::iterator it;
    for (it=down_ports->begin() ; it < down_ports->end(); it++)
        if (*it == port)
            return true;
    return false;
}

int FlowTable::setEthernet(RouteMod& rm, const Interface& local_iface, const MACAddress& gateway) {
    /* RFServer adds the Ethernet match to the flow, so we don't need to. */
    // rm.add_match(Match(RFMT_ETHERNET, local_iface.hwaddress));

    if (rm.get_mod() != RMT_DELETE) {
        rm.add_action(Action(RFAT_SET_ETH_SRC, local_iface.hwaddress));
        rm.add_action(Action(RFAT_SET_ETH_DST, gateway));
    }

    return 0;
}

int FlowTable::setIP(RouteMod& rm, const IPAddress& addr, const IPAddress& mask) {
    if (addr.getVersion() == IPV4) {
        rm.add_match(Match(RFMT_IPV4, addr, mask));
    } else if (addr.getVersion() == IPV6) {
        rm.add_match(Match(RFMT_IPV6, addr, mask));
    } else {
        fprintf(stderr, "Cannot send route with unsupported IP version\n");
        return -1;
    }
    uint16_t priority = PRIORITY_LOW;
    priority += (mask.toPrefixLen() * PRIORITY_BAND);
    rm.add_option(Option(RFOT_PRIORITY, priority));

    return 0;
}

int FlowTable::sendToHw(RouteModType mod, const RouteEntry& re) {
    const string gateway_str = re.gateway.toString();
    if (mod == RMT_DELETE) {
        return sendToHw(mod, re.address, re.netmask, re.interface, MAC_ADDR_NONE);
    } else if (mod == RMT_ADD) {
        const MACAddress& remoteMac = findHost(re.gateway);
        if (remoteMac == MAC_ADDR_NONE) {
            fprintf(stderr, "Cannot Resolve %s\n", gateway_str.c_str());
            return -1;
        }
        return sendToHw(mod, re.address, re.netmask, re.interface, remoteMac);
    }

    fprintf(stderr, "Unhandled RouteModType (%d)\n", mod);
    return -1;
}

int FlowTable::sendToHw(RouteModType mod, const HostEntry& he) {
    boost::scoped_ptr<IPAddress> mask;

    if (he.address.getVersion() == IPV6) {
        mask.reset(new IPAddress(IPV6, FULL_IPV6_PREFIX));
    } else if (he.address.getVersion() == IPV4) {
        mask.reset(new IPAddress(IPV4, FULL_IPV4_PREFIX));
    } else {
        fprintf(stderr, "Received HostEntry with unsupported IP version\n");
        return -1;
    }

    return sendToHw(mod, he.address, *mask.get(), he.interface, he.hwaddress);
}

int FlowTable::sendToHw(RouteModType mod, const IPAddress& addr, const IPAddress& mask, const Interface& local_iface, const MACAddress& gateway) {
    if (is_port_down(local_iface.port)) {
        fprintf(stderr, "Cannot send RouteMod for down port\n");
        return -1;
    }

    RouteMod rm;

    rm.set_mod(mod);
    rm.set_id(vm_id);

    if (setEthernet(rm, local_iface, gateway) != 0) {
        return -1;
    }
    if (setIP(rm, addr, mask) != 0) {
        return -1;
    }

    /* Add the output port. Even if we're removing the route, RFServer requires
     * the port to determine which datapath to send to. */
    rm.add_action(Action(RFAT_OUTPUT, local_iface.port));

    ipc->send(RFCLIENT_RFSERVER_CHANNEL, RFSERVER_ID, rm);
    return 0;
}


#ifdef FPM_ENABLED
/*
 * Add or remove a Push, Pop or Swap operation matching on a label only
 * For matching on IP, update FTN (not yet implemented) is needed
 *
 * TODO: If an error occurs here, the NHLFE is silently dropped. Fix this.
 */
void FlowTable::updateNHLFE(nhlfe_msg_t *nhlfe_msg) {
    RouteMod msg;

    if (nhlfe_msg->table_operation == ADD_LSP) {
        msg.set_mod(RMT_ADD);
    } else if (nhlfe_msg->table_operation == REMOVE_LSP) {
        msg.set_mod(RMT_DELETE);
    } else {
        std::cerr << "Unrecognised NHLFE table operation" << std::endl;
        return;
    }
    msg.set_id(vm_id);

    // We need the next-hop IP to determine which interface to use.
    int version = nhlfe_msg->ip_version;
    uint8_t* ip_data = reinterpret_cast<uint8_t*>(&nhlfe_msg->next_hop_ip);
    IPAddress gwIP(version, ip_data);

    // Get our interface for packet egress.
    Interface iface;
    map<string, HostEntry>::iterator iter;
    iter = hostTable.find(gwIP.toString());
    if (iter == hostTable.end()) {
        std::cerr << "Failed to locate interface for LSP" << std::endl;
        return;
    } else {
        iface = iter->second.interface;
    }

    if (is_port_down(iface.port)) {
        std::cerr << "Cannot send route via inactive interface" << std::endl;
        return;
    }

    // Get the MAC address corresponding to our gateway.
    const MACAddress& gwMAC = findHost(gwIP);
    if (gwMAC == MAC_ADDR_NONE) {
        std::cerr << "Failed to resolve gwMAC IP for NHLFE" << std::endl;
        return;
    }

    if (setEthernet(msg, iface, gwMAC) != 0) {
        return;
    }

    // Match on in_label only - matching on IP is the domain of FTN not NHLFE
    msg.add_match(Match(RFMT_MPLS, nhlfe_msg->in_label));

    if (nhlfe_msg->nhlfe_operation == PUSH) {
        msg.add_action(Action(RFAT_PUSH_MPLS, ntohl(nhlfe_msg->out_label)));
    } else if (nhlfe_msg->nhlfe_operation == POP) {
        msg.add_action(Action(RFAT_POP_MPLS, (uint32_t)0));
    } else if (nhlfe_msg->nhlfe_operation == SWAP) {
        msg.add_action(Action(RFAT_SWAP_MPLS, ntohl(nhlfe_msg->out_label)));
    } else {
        std::cerr << "Unknown lsp_operation" << std::endl;
        return;
    }

    msg.add_action(Action(RFAT_OUTPUT, iface.port));

    ipc->send(RFCLIENT_RFSERVER_CHANNEL, RFSERVER_ID, msg);

    return;
}
#endif /* FPM_ENABLED */

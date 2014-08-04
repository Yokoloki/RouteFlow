#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>
#include <syslog.h>
#include <cstdlib>
#include <boost/thread.hpp>
#include <iomanip>

#include "RFClient.hh"
#include "converter.h"
#include "defs.h"
#include "FlowTable.h"

#define BUFFER_SIZE 23 /* Mapping packet size. */

using namespace std;

/* Get the IP, mask, broadcast addresses of the interface */
int get_addresses(const char * ifname, uint8_t ipaddr[], uint8_t mask[], uint8_t broad[]){
	struct sockaddr_in sin;
	struct ifreq ifr;
	struct packet_mreq mr;
	int sock;
	in_addr ip_addr;
	in_addr subnet;
	in_addr broadcast;

	memset(&sin, 0, sizeof(struct sockaddr));
	memset(&ifr, 0, sizeof(ifr));
	memset(&mr, 0, sizeof(mr));
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		return -1;
	}

	// get the IP address
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	if (-1 == ioctl(sock, SIOCGIFADDR, &ifr)) {
		perror("ioctl(SIOCGIFHWADDR) - get IP address");
	}
	std::memcpy(&sin, &ifr.ifr_addr, sizeof(struct sockaddr));
	ip_addr = sin.sin_addr;
    syslog(LOG_INFO, "IP %s - %s\n" , ifname , inet_ntoa(ip_addr) );

	// get the subnet mask
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock, SIOCGIFNETMASK, &ifr)< 0)    {
		perror("ioctl(SIOCGIFHWADDR) - get subnet");
	}
	std::memcpy(&sin, &ifr.ifr_addr, sizeof(struct sockaddr));
	subnet = sin.sin_addr;
    syslog(LOG_INFO, "Mask %s - %s\n" , ifname , inet_ntoa(subnet) );

	// get the broadcast address
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock, SIOCGIFBRDADDR, &ifr)< 0)    {
		perror("ioctl(SIOCGIFHWADDR) - get broadcast address");
	}
	std::memcpy(&sin, &ifr.ifr_addr, sizeof(struct sockaddr));
	broadcast = sin.sin_addr;
    syslog(LOG_INFO, "Broad %s - %s\n" , ifname , inet_ntoa(broadcast) );

	close(sock);

    std::memcpy(ipaddr, &ip_addr, 4 );
    std::memcpy(mask, &subnet, 4 );
    std::memcpy(broad, &broadcast, 4 );
	return 0;
}

/* Get the MAC address of the interface. */
int get_hwaddr_byname(const char * ifname, uint8_t hwaddr[]) {
    struct ifreq ifr;
    int sock;

    if ((NULL == ifname) || (NULL == hwaddr)) {
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';

    if (-1 == ioctl(sock, SIOCGIFHWADDR, &ifr)) {
        perror("ioctl(SIOCGIFHWADDR) ");
        return -1;
    }

    std::memcpy(hwaddr, ifr.ifr_ifru.ifru_hwaddr.sa_data, IFHWADDRLEN);

    close(sock);

    return 0;
}

/* Get the interface associated VM identification number. */
uint64_t get_interface_id(const char *ifname) {
    if (ifname == NULL)
        return 0;

    uint8_t mac[6];
    uint64_t id;
    stringstream hexmac;

    if (get_hwaddr_byname(ifname, mac) == -1)
        return 0;

    for (int i = 0; i < 6; i++)
        hexmac << std::hex << setfill ('0') << setw (2) << (int) mac[i];
    hexmac >> id;
    return id;
}

/*
int addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data, int alen) {
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if(NLMSG_ALIGN(n->nlmsg_len) + len > maxlen) return -1;
    rta = (struct rtattr*)(((char*)n) + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + len;
    return 0;
}
*/

void startFlowTable(FlowTable *table) {
    table->start();
}

RFClient::RFClient(uint64_t id, const string &address) {
    this->id = id;
    syslog(LOG_INFO, "Starting RFClient (vm_id=%s)", to_string<uint64_t>(this->id).c_str());
    ipc = (IPCMessageService*) new MongoIPCMessageService(address, MONGO_DB_NAME, to_string<uint64_t>(this->id));

    if(rtnl_open(&rth, 0) < 0){
        fprintf(stderr, "cannot open rtnetlink\n");
        exit(1);
    }

    this->init_ports = 0;
    this->load_interfaces();

    for (map<int, Interface>::iterator it = this->interfaces.begin() ; it != this->interfaces.end(); it++) {
        Interface i = it->second;
        ifacesMap[i.name] = i;

        PortRegister msg(this->id, i.port, i.hwaddress);
        this->ipc->send(RFCLIENT_RFSERVER_CHANNEL, RFSERVER_ID, msg);
        syslog(LOG_INFO, "Registering client port (vm_port=%d)", i.port);
    }

    flowTable = new FlowTable(this->id, this->ifacesMap, this->ipc, &(this->down_ports));
    boost::thread t(&startFlowTable, flowTable);
    t.detach();

    ipc->listen(RFCLIENT_RFSERVER_CHANNEL, this, this, true);
}

bool RFClient::process(const string &, const string &, const string &, IPCMessage& msg) {
    int type = msg.get_type();
    if (type == PORT_CONFIG) {
        PortConfig *config = dynamic_cast<PortConfig*>(&msg);
        uint32_t vm_port = config->get_vm_port();
        uint32_t operation_id = config->get_operation_id();

        if (operation_id == 0) {
            syslog(LOG_INFO,
                   "Received port configuration (vm_port=%d)",
                   vm_port);
            vector<uint32_t>::iterator it;
            for (it=down_ports.begin(); it < down_ports.end(); it++)
                if (*it == vm_port)
                    down_ports.erase(it);
            send_port_map(vm_port);
        }
        else if (operation_id == 1) {
            syslog(LOG_INFO,
                   "Received port reset (vm_port=%d)",
                   vm_port);
            down_ports.push_back(vm_port);
        }
    }
    else if (type == ROUTE_MOD) {
        RouteMod *rm= dynamic_cast<RouteMod*>(&msg);
        if (rm->get_id() != id) {
            fprintf(stderr, "Unexpected RouteMod Msg Target for VM %lld\n", rm->get_id());
            return false;
        }
        uint8_t mod = rm->get_mod();
        int cmd;
        if (mod == RMT_ADD + 48) {
            cmd = RTM_NEWROUTE;
        }
        else if (mod == RMT_DELETE + 48) {
            cmd = RTM_DELROUTE;
        }
        else {
            printf("Unexpected RouteMod Msg with mod=%d\n", mod);
            return false;
        }
        std::vector<Match> matches = rm->get_matches();
        std::vector<Action> actions = rm->get_actions();
        std::vector<Option> options = rm->get_options();

        int family = -1;
        uint8_t *addr;
        int prefixlen;
        for(int i=0; i<matches.size(); i++){
            if(matches[i].getType() == RFMT_IPV4){
                family = AF_INET;
                addr = new uint8_t[4];
                const ip_match *net = matches[i].getIPv4();
                memcpy(addr, &(net->addr), 4);
                IPAddress mask(&(net->mask));
                prefixlen = mask.toPrefixLen();
            }
            else if(matches[i].getType() == RFMT_IPV6){
                family = AF_INET6;
                addr = new uint8_t[16];
                const ip6_match *net = matches[i].getIPv6();
                memcpy(addr, &(net->addr), 16);
                IPAddress mask(&(net->mask));
                prefixlen = mask.toPrefixLen();
            }
        }
        uint32_t oif = -1;
        for(int i=0; i<actions.size(); i++){
            if(actions[i].getType() == RFAT_OUTPUT){
                oif = actions[i].getUint32();
            }
        }
        uint16_t metric = 1;
        for(int i=0; i<options.size(); i++){
            if(options[i].getType() == RFOT_PRIORITY){
                metric = options[i].getUint16();
            }
        }
        if (family == -1 || oif == -1){
            printf("Broken RouteMod: %s\n", rm->str().c_str());
            delete addr;
            return false;
        }

        delete addr;
        return mod_route(cmd, family, addr, prefixlen, oif, metric);
    }
    else {
        return false;
    }

    return true;
}

bool RFClient::mod_route(int cmd, int family, uint8_t *addr, int prefixlen, uint32_t oif, uint16_t metric) {
    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char buf[1024];
    } req;
    memset(&req, 0, sizeof(req));

    int bytelen = (family == AF_INET ? 4:16);

    //Init
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
    req.n.nlmsg_type = cmd;
    req.r.rtm_family = family;
    req.r.rtm_table = RT_TABLE_MAIN;

    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_type = RTN_UNICAST;

    req.r.rtm_dst_len = prefixlen;
    addattr_l(&req.n, sizeof(req), RTA_DST, addr, bytelen);
    addattr_l(&req.n, sizeof(req), RTA_PRIORITY, &metric, 4);
    addattr_l(&req.n, sizeof(req), RTA_OIF, &oif, 4);

    //Optional
    //addattr_l(&req.n, sizeof(req), RTA_GATEWAY, gateway, bytelen);
    //addattr_l(&req.n, sizeof(req), RTA_PREFSRC, src, bytelen);

    int ret = rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL);
    if(ret < 0){
        printf("rtnl_talk failed %d\n", ret);
        return false;
    }
    printf("mod_route\n");
    return true;
}

int RFClient::send_packet(const char ethName[], uint64_t vm_id, uint8_t port) {
    char buffer[BUFFER_SIZE];
    uint16_t ethType;
    struct ifreq req;
    struct sockaddr_ll sll;
    uint8_t srcAddress[IFHWADDRLEN];
    uint8_t dstAddress[IFHWADDRLEN] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    int SockFd = socket(PF_PACKET, SOCK_RAW, htons(RF_ETH_PROTO));

    strcpy(req.ifr_name, ethName);

    if (ioctl(SockFd, SIOCGIFFLAGS, &req) < 0) {
        fprintf(stderr, "ERROR! ioctl() call has failed: %s\n", strerror(errno));
        exit(1);
    }

    /* If the interface is down we can't send the packet. */
    printf("FLAG %d\n", req.ifr_flags & IFF_UP);
    if (!(req.ifr_flags & IFF_UP))
        return -1;

    /* Get the interface index. */
    if (ioctl(SockFd, SIOCGIFINDEX, &req) < 0) {
        fprintf(stderr, "ERROR! ioctl() call has failed: %s\n", strerror(errno));
        exit(1);
    }

    int ifindex = req.ifr_ifindex;

    int addrLen = sizeof(struct sockaddr_ll);

    if (ioctl(SockFd, SIOCGIFHWADDR, &req) < 0) {
        fprintf(stderr, "ERROR! ioctl() call has failed: %s\n", strerror(errno));
        exit(1);
    }
    int i;
    for (i = 0; i < IFHWADDRLEN; i++)
        srcAddress[i] = (uint8_t) req.ifr_hwaddr.sa_data[i];

    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifindex;

    if (bind(SockFd, (struct sockaddr *) &sll, addrLen) < 0) {
        fprintf(stderr, "ERROR! bind() call has failed: %s\n", strerror(errno));
        exit(1);
    }

    memset(buffer, 0, BUFFER_SIZE);

    memcpy((void *) buffer, (void *) dstAddress, IFHWADDRLEN);
    memcpy((void *) (buffer + IFHWADDRLEN), (void *) srcAddress, IFHWADDRLEN);
    ethType = htons(RF_ETH_PROTO);
    memcpy((void *) (buffer + 2 * IFHWADDRLEN), (void *) &ethType, sizeof(uint16_t));
    memcpy((void *) (buffer + 14), (void *) &vm_id, sizeof(uint64_t));
    memcpy((void *) (buffer + 22), (void *) &port, sizeof(uint8_t));
    return (sendto(SockFd, buffer, BUFFER_SIZE, 0, (struct sockaddr *) &sll, (socklen_t) addrLen));

}

/* Set the MAC address of the interface. */
int RFClient::set_hwaddr_byname(const char * ifname, uint8_t hwaddr[], int16_t flags) {
    struct ifreq ifr;
    int sock;

    if ((NULL == ifname) || (NULL == hwaddr)) {
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
    ifr.ifr_ifru.ifru_flags = flags & (~IFF_UP);

    if (-1 == ioctl(sock, SIOCSIFFLAGS, &ifr)) {
        perror("ioctl(SIOCSIFFLAGS) ");
        return -1;
    }

    ifr.ifr_ifru.ifru_hwaddr.sa_family = ARPHRD_ETHER;
    std::memcpy(ifr.ifr_ifru.ifru_hwaddr.sa_data, hwaddr, IFHWADDRLEN);

    if (-1 == ioctl(sock, SIOCSIFHWADDR, &ifr)) {
        perror("ioctl(SIOCSIFHWADDR) ");
        return -1;
    }

    ifr.ifr_ifru.ifru_flags = flags | IFF_UP;

    if (-1 == ioctl(sock, SIOCSIFFLAGS, &ifr)) {
        perror("ioctl(SIOCSIFFLAGS) ");
        return -1;
    }

    close(sock);

    return 0;
}

/* Get all names of the interfaces in the system. */
void RFClient::load_interfaces() {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    int intfNum;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit( EXIT_FAILURE);
    }

    /* Walk through linked list, maintaining head pointer so we
     can free list later. */
    intfNum = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        family = ifa->ifa_addr->sa_family;

        if (family == AF_PACKET && strcmp(ifa->ifa_name, "eth0") != 0 && strcmp(ifa->ifa_name, "lo") != 0) {
	        get_hwaddr_byname(ifa->ifa_name, hwaddress);
	        string ifaceName = ifa->ifa_name;
	        size_t pos = ifaceName.find_first_of("123456789");
	        string port_num = ifaceName.substr(pos, ifaceName.length() - pos + 1);
	        uint32_t port_id = atoi(port_num.c_str());
            uint8_t ipaddr[4];
			uint8_t mask[4];
			uint8_t broad[4];
			get_addresses(ifa->ifa_name, ipaddr, mask, broad);

	        Interface interface;
	        interface.port = port_id;
	        interface.name = ifaceName;
	        interface.hwaddress = MACAddress(hwaddress);
            interface.address = IPAddress(IPV4, ipaddr);
            interface.netmask = IPAddress(IPV4, mask);
	        interface.active = true;

		    InterfaceRegister msg(interface.name, this->id, interface.port, interface.address, interface.netmask, interface.hwaddress);
		    this->ipc->send(RFCLIENT_RFSERVER_CHANNEL, RFSERVER_ID, msg);
	        
            printf("Loaded interface %s\n", interface.name.c_str());

	        this->interfaces[interface.port] = interface;
	        intfNum++;
        }
    }

    /* Free list. */
    freeifaddrs(ifaddr);
}

void RFClient::send_port_map(uint32_t port) {
    Interface i = this->interfaces[port];
    if (send_packet(i.name.c_str(), this->id, i.port) == -1)
        syslog(LOG_INFO, "Error sending mapping packet (vm_port=%d)",
               i.port);
    else
        syslog(LOG_INFO, "Mapping packet was sent to RFVS (vm_port=%d)",
               i.port);
}

int main(int argc, char* argv[]) {
    char c;
    stringstream ss;
    string id;
    string address = MONGO_ADDRESS;

    while ((c = getopt (argc, argv, "n:i:a:")) != -1)
        switch (c) {


            case 'n':
                fprintf (stderr, "Custom naming not supported yet.");
                exit(EXIT_FAILURE);
                /* TODO: support custom naming for VMs.
                if (!id.empty()) {
                    fprintf (stderr, "-i is already defined");
                    exit(EXIT_FAILURE);
                }
                id = optarg;
                */
                break;
            case 'i':
                if (!id.empty()) {
                    fprintf(stderr, "-n is already defined");
                    exit(EXIT_FAILURE);
                }
                id = to_string<uint64_t>(get_interface_id(optarg));
                break;
            case 'a':
                address = optarg;
                break;
            case '?':
                if (optopt == 'n' || optopt == 'i' || optopt == 'a')
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint(optopt))
                    fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
                return EXIT_FAILURE;
            default:
                abort();
        }


    openlog("rfclient", LOG_NDELAY | LOG_NOWAIT | LOG_PID, SYSLOGFACILITY);
    RFClient s(get_interface_id(DEFAULT_RFCLIENT_INTERFACE), address);

    return 0;
}



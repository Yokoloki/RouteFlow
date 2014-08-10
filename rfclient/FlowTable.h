#ifndef FLOWTABLE_HH_
#define FLOWTABLE_HH_

#include <list>
#include <map>
#include <stdint.h>
#include <boost/thread.hpp>
#include "libnetlink.hh"
#include "SyncQueue.h"

#include "fpm.h"
#include "fpm_lsp.h"

#include "ipc/IPC.h"
#include "ipc/RFProtocol.h"
#include "types/IPAddress.h"
#include "types/MACAddress.h"
#include "defs.h"

#include "Interface.hh"
#include "RouteEntry.hh"
#include "HostEntry.hh"

using namespace std;

#define FULL_IPV4_PREFIX 32
#define FULL_IPV6_PREFIX 128
#define MAX_RENTRIES_MULTIPATH 128
static const MACAddress MAC_ADDR_NONE("00:00:00:00:00:00");


// TODO: recreate this module from scratch without all the static stuff.
// It is a little bit challenging to devise a decent API due to netlink
class FlowTable {
    public:
        static int HTUpdateCB(const struct sockaddr_nl *, struct nlmsghdr *n, void *ptr);
        static int RTUpdateCB(const struct sockaddr_nl *, struct nlmsghdr *n, void *ptr);

        FlowTable(uint64_t vm_id, map<string, Interface> interfaces, IPCMessageService *ipc, vector<uint32_t> *down_ports);
        ~FlowTable();

        void start();
        void interrupt();
        void clear();

        int updateHostTable(struct nlmsghdr *n);
        int updateRouteTable(struct nlmsghdr *n);
        void resolveGateways();
        int getGatewayByIfidx(unsigned int idx, uint8_t *gw);



#ifdef FPM_ENABLED
        void updateNHLFE(nhlfe_msg_t *nhlfe_msg);
#else
        int updateRouteTable(const struct sockaddr_nl*,
                                    struct nlmsghdr*, void*);
#endif /* FPM_ENABLED */

    private:
        int family;
        unsigned groups;
        int llink;
        int laddr;
        int lroute;

        map<string, Interface> interfaces;
        vector<uint32_t>* down_ports;
        IPCMessageService* ipc;
        uint64_t vm_id;

        boost::thread GWResolver;
        boost::thread HTPolling;
        struct rtnl_handle rth_host;

#ifdef FPM_ENABLED
        boost::thread FPMClient;
        FPMServer *fpmServer;
#else
        boost::thread RTPolling;
        struct rtnl_handle rth_route;
#endif /* FPM_ENABLED */
        typedef std::pair<RouteModType, RouteEntry> Route;
        SyncQueue<Route> pendingRoutes;
        list<RouteEntry> routeTable;

        boost::mutex hostTableMutex;
        map<string, HostEntry> hostTable;

        boost::mutex ndMutex;
        map<string, int> pendingNeighbours;

        boost::mutex gwMutex;
        map<unsigned int, uint8_t*> ifidx_to_gw;

        bool is_port_down(uint32_t port);
        int getInterface(const char *intf, const char *type,
                                Interface& iface);

        int initiateND(const char *hostAddr);
        int resolveGateway(const IPAddress&, const Interface&);
        const MACAddress& findHost(const IPAddress& host);

        int setEthernet(RouteMod& rm, const Interface& local_iface,
                               const MACAddress& gateway);
        int setIP(RouteMod& rm, const IPAddress& addr,
                         const IPAddress& mask);
        int sendToHw(RouteModType, const RouteEntry&);
        int sendToHw(RouteModType, const HostEntry&);
        int sendToHw(RouteModType, const IPAddress& addr,
                            const IPAddress& mask, const Interface&,
                            const MACAddress& gateway);
};

#endif /* FLOWTABLE_HH_ */

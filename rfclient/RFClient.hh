#include <net/if.h>
#include <map>
#include <set>
#include <vector>

#include "ipc/IPC.h"
#include "ipc/MongoIPC.h"
#include "ipc/RFProtocol.h"
#include "ipc/RFProtocolFactory.h"
#include "FlowTable.h"

class RFClient : private RFProtocolFactory, private IPCMessageProcessor {
    public:
        RFClient(uint64_t id, const string &address);

    private:
        FlowTable* flowTable;
        IPCMessageService* ipc;
        struct rtnl_handle rth;
        uint64_t id;

        map<string, Interface> ifacesMap;
        map<int, Interface> interfaces;
        vector<uint32_t> down_ports;
        set<uint64_t> routes;

        uint8_t hwaddress[IFHWADDRLEN];
        int init_ports;

        bool process(const string &from, const string &to, const string &channel, IPCMessage& msg);

        bool mod_route(int cmd, int family, uint8_t *addr, int prefixlen, uint32_t oif, uint16_t metric);
        int send_packet(const char ethName[], uint64_t vm_id, uint8_t port);
        int set_hwaddr_byname(const char * ifname, uint8_t hwaddr[], int16_t flags);
        void load_interfaces();
        void send_port_map(uint32_t port);
};

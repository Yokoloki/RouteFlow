from rflib.types.Match import *
from rflib.types.Action import *
from rflib.types.Instruction import *
from rflib.types.Meter import *
from rflib.types.Group import *
from rflib.types.Option import *
from rflib.ipc.RFProtocol import *


class RouteMods():
    def __init__(self):
        self.id_ = 1

    def unpack_matches(self, route, matches):
        route_matches = {}
        route_matches_types = []
        for m in matches:
            match = Match.from_dict(m)
            if match._type == RFMT_IPV4:
                value = bin_to_int(match._value)
                addr = value >> 32
                mask = value & ((1 << 32) - 1)
                route_matches_types.append(RFMT_IPV4)
                route_matches['ethtype'] = ETHERTYPE_IP
                route_matches['address'] = addr
                route_matches['netmask'] = mask
            elif match._type == RFMT_IPV6:
                v = match._value
                addr = tuple((ord(v[i]) << 8) | ord(v[i + 1])
                             for i in range(0, 16, 2))
                mask = tuple((ord(v[i]) << 8) | ord(v[i + 1])
                             for i in range(16, 32, 2))
                route_matches_types.append(RFMT_IPV6)
                route_matches['ethtype'] = ETHERTYPE_IPV6
                route_matches['address'] = addr
                route_matches['netmask'] = mask
            elif match._type == RFMT_ETHERNET:
                route_matches_types.append(RFMT_ETHERNET)
                route_matches['dst_hwaddress'] = match._value
            elif match._type == RFMT_ETHERTYPE:
                route_matches_types.append(RFMT_ETHERTYPE)
                route_matches['ethtype'] = bin_to_int(match._value)
            elif match._type == RFMT_NW_PROTO:
                route_matches_types.append(RFMT_NW_PROTO)
                route_matches['ipproto'] = bin_to_int(match._value)
            elif match._type == RFMT_TP_SRC:
                route_matches_types.append(RFMT_TP_SRC)
                route_matches['ipproto'] = IPPROTO_TCP
                route_matches['tp_src_port'] = bin_to_int(match._value)
            elif match._type == RFMT_TP_DST:
                route_matches_types.append(RFMT_TP_DST)
                route_matches['ipproto'] = IPPROTO_TCP
                route_matches['tp_dst_port'] = bin_to_int(match._value)
            elif match._type == RFMT_IN_PORT:
                route_matches_types.append(RFMT_IN_PORT)
                route_matches['in_port'] = bin_to_int(match._value)
            elif TLV.optional(match):
                log.info("Dropping unsupported Match (type: %s)" % match._type)
            else:
                log.warning("Failed to serialise Match (type: %s)" % match._type)
        route['matches'] = route_matches
        route['matches_types'] = route_matches_types

    def unpack_actions(self, route, action_tlvs):
        route_actions = {}
        route_action_types = []
        for a in action_tlvs:
            action = Action.from_dict(a)
            if action._type == RFAT_OUTPUT:
                port = bin_to_int(action._value)
                route_actions['dst_port'] = port
                route_action_types.append(RFAT_OUTPUT)
            elif action._type == RFAT_SET_ETH_SRC:
                srcMac = action._value
                route_actions['src_hwaddress'] = srcMac
                route_action_types.append(RFAT_SET_ETH_SRC)
            elif action._type == RFAT_SET_ETH_DST:
                dstMac = action._value
                route_actions['dst_hwaddress'] = dstMac
                route_action_types.append(RFAT_SET_ETH_DST)
            elif action._type == RFAT_GROUP:
                group_id = bin_to_int(action._value)
                route_actions['group_id'] = group_id
                route_action_types.append(RFAT_GROUP)
            elif action._type == RFAT_PUSH_MPLS:
                label = bin_to_int(action._value)
                route_actions['label'] = label
                route_action_types.append(RFAT_PUSH_MPLS)
            elif action._type == RFAT_POP_MPLS:
                ethertype = bin_to_int(action._value)
                route_actions['ethertype'] = ethertype
                route_action_types.append(RFAT_POP_MPLS)
            elif action.optional():
                log.info("Dropping unsupported Action (type: %s)" % action._type)
            else:
                log.warning("Failed to serialise Action (type: %s)" % action._type)
        route['actions'] = route_actions
        route['actions_types'] = route_action_types

    def unpack_instructions(self, route, instruction_tlvs):
        route_instructions = {}
        route_instructions_types = []
        for a in instruction_tlvs:
            instruction = Instruction.from_dict(a)
            if instruction._type == RFIT_METER:
                meter_id = bin_to_int(instruction._value)
                route_instructions['meter_id'] = meter_id
                route_instructions_types.append(RFIT_METER)
            elif instruction._type == RFIT_APPLY_ACTIONS:
                route_instructions_types.append(RFIT_APPLY_ACTIONS)
            elif instruction._type == RFIT_WRITE_ACTIONS:
                route_instructions_types.append(RFIT_WRITE_ACTIONS)
            elif instruction._type == RFIT_CLEAR_ACTIONS:
                route_instructions_types.append(RFIT_CLEAR_ACTIONS)
            elif instruction._type == RFIT_WRITE_METADATA:
                metadata,metadata_mask = bin_to_int(instruction._value)
                route_instructions_types.append(RFIT_WRITE_METADATA)
                route_instructions['metadata'] = metadata
                route_instructions['metadata_mask'] = metadata_mask
            elif instruction._type == RFIT_GO_TABLE:
                next_table_id = bin_to_int(instruction._value)
                route_instructions_types.append(RFIT_GO_TABLE)
                route_instructions['next_table_id'] = next_table_id
            elif instruction.optional():
                log.info("Dropping unsupported instruction (type: %s)" % instruction._type)
            else:
                log.warning("Failed to serialise instruction (type: %s)" % instruction._type)
        route['instructions'] = route_instructions
        route['route_instructions_types'] = route_instructions_types

    def unpack_options(self, route, options):
        route_options = {}
        route_options_types = []
        for o in options:
            option = Option.from_dict(o)
            if option._type == RFOT_PRIORITY:
                route_options["priority"] = bin_to_int(option._value)
                route_options_types.append(RFOT_PRIORITY)
            elif option._type == RFOT_IDLE_TIMEOUT:
                route_options["idle_timeout"] = bin_to_int(option._value)
                route_options_types.append(RFOT_IDLE_TIMEOUT)
            elif option._type == RFOT_HARD_TIMEOUT:
                route_options["hard_timeout"] = bin_to_int(option._value)
                route_options_types.append(RFOT_HARD_TIMEOUT)
            elif option._type == RFOT_CT_ID:
                pass
            elif option.optional():
                log.info("Dropping unsupported Option (type: %s)" % option._type)
            else:
                log.warning("Failed to serialise Option (type: %s)" % option._type)
        route['options'] = route_options
        route['options_types'] = route_options_types

    def pack_matches(self, routemod, route):
        route_matches = route['matches']
        route_matches_types = route['matches_types']
        for match_type in route_matches_types:
            if match_type == RFMT_IPV4:
                ethtype = route_matches['ethtype']
                addr = route_matches['address']
                mask = route_matches['netmask']
                routemod.add_match(Match.ETHERTYPE(ethtype))
                routemod.add_match(Match.IPV4(addr, mask))
            elif match_type == RFMT_IPV6:
                ethtype = route_matches['ethtype']
                addr = route_matches['address']
                mask = route_matches['netmask']
                routemod.add_match(Match.ETHERTYPE(ethtype))
                routemod.add_match(Match.IPV4(addr, mask))
            elif match_type == RFMT_ETHERNET:
                dst_hwaddress = route_matches['dst_hwaddress']
                routemod.add_match(Match.ETHERNET(dst_hwaddress))
            elif match_type == RFMT_ETHERTYPE:
                ethtype = route_matches['ethtype']
                routemod.add_match(Match.ETHERTYPE(ethtype))
            elif match_type == RFMT_NW_PROTO:
                ipproto = route_matches['ipproto']
                routemod.add_match(Match.NW_PROTO(ipproto))
            elif match_type == RFMT_TP_SRC:
                ipproto = route_matches['ipproto']
                tp_src_port = route_matches['tp_src_port']
                routemod.add_match(Match.NW_PROTO(ipproto))
                routemod.add_match(Match.TP_SRC(tp_src_port))
            elif match_type == RFMT_TP_DST:
                ipproto = route_matches['ipproto']
                tp_dst_port = route_matches['tp_dst_port']
                routemod.add_match(Match.NW_PROTO(ipproto))
                routemod.add_match(Match.TP_SRC(tp_dst_port))
            elif match_type == RFMT_IN_PORT:
                in_port = route_matches['in_port']
                routemod.add_match(Match.IN_PORT(in_port))

    def pack_actions(self, routemod, route):
        route_actions = route['actions']
        route_actions_types = route['actions_types']
        for action_type in route_actions_types:
            if action_type == RFAT_OUTPUT:
                port = route_actions['dst_port']
                routemod.add_action(Action.OUTPUT(port))
            elif action_type == RFAT_SET_ETH_SRC:
                srcMac = route_actions['src_hwaddress']
                routemod.add_action(Action.SET_ETH_SRC(srcMac))
            elif action_type == RFAT_SET_ETH_DST:
                dstMac = route_actions['dst_hwaddress']
                routemod.add_action(Action.SET_ETH_DST(dstMac))
            elif action_type == RFAT_GROUP:
                group_id = route_actions['group_id']
                routemod.add_action(Action.GROUP(group_id))
            elif action_type == RFAT_PUSH_MPLS:
                label = route_actions['label']
                routemod.add_action(Action.PUSH_MPLS(label))
            elif action_type == RFAT_POP_MPLS:
                ethertype = route_actions['ethertype']
                routemod.add_action(Action.POP_MPLS(ethertype))

    def pack_instructions(self, routemod, route):
        route_instructions = route['instructions']
        route_instructions_types = route['instructions_types']
        for instruction_type in route_instructions_types:
            if instruction_type == RFIT_METER:
                meter_id = route_instructions['meter_id']
                routemod.add_instructions(Instruction.METER(meter_id))
            elif instruction_type == RFIT_APPLY_ACTIONS:
                routemod.add_instructions(Instruction.APPLY_ACTIONS())
            elif instruction_type == RFIT_WRITE_ACTIONS:
                routemod.add_instructions(Instruction.WRITE_ACTIONS())
            elif instruction_type == RFIT_CLEAR_ACTIONS:
                routemod.add_instructions(Instruction.CLEAR_ACTIONS())
            elif instruction_type == RFIT_WRITE_METADATA:
                metadata = route_instructions['metadata']
                metadata_mask = route_instructions['metadata_mask']
                routemod.add_instructions(Instruction.WRITE_METADATA(metadata, metadata_mask))
            elif instruction_type == RFIT_GO_TABLE:
                next_table_id = route_instructions['next_table_id']
                routemod.add_instructions(Instruction.GO_TABLE(next_table_id))

    def pack_options(self, routemod, route):
        route_options = route['options']
        route_options_types = route['options_types']
        for option_type in route_options_types:
            if option_type == RFOT_PRIORITY:
                priority = route_options["priority"]
                routemod.add_option(Option.PRIORITY(priority))
            elif option_type == RFOT_IDLE_TIMEOUT:
                idle_timeout = route_options["idle_timeout"]
                routemod.add_option(Option.IDLE_TIMEOUT(idle_timeout))
            elif option_type == RFOT_HARD_TIMEOUT:
                hard_timeout = route_options["hard_timeout"]
                routemod.add_option(Option.HARD_TIMEOUT(hard_timeout))
            elif option_type == RFOT_TABLE:
                table_id = route_options["table_id"]
                routemod.add_option(Option.TABLE(table_id))
            elif option_type == RFOT_CT_ID:
                ct_id = route_options["ct_id"]
                routemod.add_option(Option.CT_ID(ct_id))

    def apply_route_matches(self, route, matches):
        if not "matches" in route.keys():
            route["matches"] = {}
        route_matches_types = []
        for match in matches.keys():
            if match == "address":
                route["matches"]["address"] = matches[match]
                route_matches_types.append()
            if match == "netmask":
                route["matches"]["netmask"] = matches[match]
                route_matches_types.append()
            if match == "dst_hwaddress":
                route["matches"]["dst_hwaddress"] = matches[match]
                route_matches_types.append(RFMT_ETHERNET)
            if match == "ethtype":
                route["matches"]["ethtype"] = matches[match]
                route_matches_types.append(RFMT_ETHERTYPE)
            if match == "ipproto":
                route["matches"]["ipproto"] = matches[match]
                route_matches_types.append(RFMT_NW_PROTO)
            if match == "tp_src_port":
                route["matches"]["tp_src_port"] = matches[match]
                route_matches_types.append(RFMT_TP_SRC)
            if match == "tp_dst_port":
                route["matches"]["tp_dst_port"] = matches[match]
                route_matches_types.append(RFMT_TP_DST)
            if match == "in_port":
                route["matches"]["in_port"] = matches[match]
                route_matches_types.append(RFMT_IN_PORT)
        if not "matches_types" in route.keys():
            route["matches_types"] = route_matches_types
        else:
            route["matches_types"].extend( [ match for match in route_matches_types if match not in route["matches_types"] ] )

    def apply_route_actions(self, route, actions):
        if not "actions" in route.keys():
            route["actions"] = {}
        route_actions_types = []
        for action in actions.keys():
            if action == "dst_port":
                route["actions"]["dst_port"] = actions[action]
                route_actions_types.append(RFAT_OUTPUT)
            if action == "src_hwaddress":
                route["actions"]["src_hwaddress"] = actions[action]
                route_actions_types.append(RFAT_SET_ETH_SRC)
            if action == "dst_hwaddress":
                route["actions"]["dst_hwaddress"] = actions[action]
                route_actions_types.append(RFAT_SET_ETH_DST)
            if action == "group_id":
                route["actions"]["group_id"] = actions[action]
                route_actions_types.append(RFAT_GROUP)
            if action == "label":
                route["actions"]["label"] = actions[action]
                route_actions_types.append(RFAT_PUSH_MPLS)
            if action == "ethertype":
                route["actions"]["ethertype"] = actions[action]
                route_actions_types.append(RFAT_POP_MPLS)
        if not "actions_types" in route.keys():
            route["actions_types"] = route_actions_types
        else:
            route["actions_types"].extend( [ action for action in route_actions_types if action not in route["actions_types"] ] )

    def apply_route_instructions(self, route, instructions):
        if not "instructions" in route.keys():
            route["instructions"] = {}
        route_instructions_types = []
        for instruction in instructions.keys():
            if instruction == "meter_id":
                route["instructions"]["meter_id"] = instructions[instruction]
                route_instructions_types.append(RFIT_METER)
            if instruction == "apply_actions":
                route_instructions_types.append(RFIT_APPLY_ACTIONS)
            if instruction == "write_actions":
                route_instructions_types.append(RFIT_WRITE_ACTIONS)
            if instruction == "clear_actions":
                route_instructions_types.append(RFIT_CLEAR_ACTIONS)
            if instruction == "metadata":
                route["instructions"]["metadata"] = instructions[instruction]
                route_instructions_types.append(RFIT_WRITE_METADATA)
            if instruction == "metadata_mask":
                route["instructions"]["metadata_mask"] = instructions[instruction]
            if instruction == "next_table_id":
                route["instructions"]["next_table_id"] = instructions[instruction]
                route_instructions_types.append(RFIT_GO_TABLE)
        if not "instructions_types" in route.keys():
            route["instructions_types"] = route_instructions_types
        else:
            route["instructions_types"].extend( [ instruction for instruction in route_instructions_types if instruction not in route["instructions_types"] ] )

    def apply_route_options(self, route, options):
        if not "options" in route.keys():
            route["options"] = {}
        route_options_types = []
        for option in options.keys():
            if option == "priority":
                route["options"]["priority"] = options[option]
                route_options_types.append(RFOT_PRIORITY)
            if option == "hard_timeout":
                route["options"]["hard_timeout"] = options[option]
                route_options_types.append(RFOT_HARD_TIMEOUT)
            if option == "idle_timeout":
                route["options"]["idle_timeout"] = options[option]
                route_options_types.append(RFOT_IDLE_TIMEOUT)
            if option == "table_id":
                route["options"]["table_id"] = options[option]
                route_options_types.append(RFOT_TABLE)
            if option == "ct_id":
                route["options"]["ct_id"] = options[option]
                route_options_types.append(RFOT_CT_ID)
        if not "options_types" in route.keys():
            route["options_types"] = route_options_types
        else:
            route["options_types"].extend( [ option for option in route_options_types if option not in route["options_types"] ] )


class GroupMods():
    def __init__(self):
        self.id_ = 2

    def pack_group_buckets(self, groupmod, group_buckets, group_actions):
        for group_bucket in group_buckets:
            group_bucket_id = groupmod.add_group_bucket()
            bucket_weight = group_bucket['bucket_weight']
            watch_port = group_bucket['watch_port']
            watch_group = group_bucket['watch_group']
            bucket_actions_id = group_bucket['bucket_actions_id']
            groupmod.add_group_bucket_attribs(group_bucket_id, Group.SET_WEIGHT(bucket_weight))
            groupmod.add_group_bucket_attribs(group_bucket_id, Group.SET_WATCH_PORT(watch_port))
            groupmod.add_group_bucket_attribs(group_bucket_id, Group.SET_WATCH_GROUP(watch_group))
            groupmod.add_group_bucket_attribs(group_bucket_id, Group.SET_ACTIONS(bucket_actions_id))

    def pack_group_actions(self, groupmod, group_actions):
        for action_id in group_actions.keys():
            action = group_actions[action_id]
            if action == "dst_port":
                dst_port = group_actions[action_id][action]
                groupmod.add_group_bucket_action_attribs(action_id, Action.OUTPUT(dst_port))
            if action == "src_hwaddress":
                src_hwaddress = group_actions[action_id][action]
                groupmod.add_group_bucket_action_attribs(action_id, Action.SET_ETH_SRC(src_hwaddress))
            if action == "dst_hwaddress":
                dst_hwaddress = group_actions[action_id][action]
                groupmod.add_group_bucket_action_attribs(action_id, Action.SET_ETH_DST(dst_hwaddress))
            if action == "group_id":
                group_id = group_actions[action_id][action]
                groupmod.add_group_bucket_action_attribs(action_id, Action.GROUP(group_id))
            if action == "label":
                label = group_actions[action_id][action]
                groupmod.add_group_bucket_action_attribs(action_id, Action.PUSH_MPLS(label))
            if action == "ethertype":
                ethertype = group_actions[action_id][action]
                groupmod.add_group_bucket_action_attribs(action_id, Action.POP_MPLS(ethertype))


class MeterMods():
    def __init__(self):
        self.id_ = 3

    def pack_meter_bands(self, metermod, meters):
        for meter in meters:
            meter_type = meters['meter_type']
            if meter_type == Meter._TYPE_DROP:
                meter_rate = meter['rate']
                meter_burst_size = meter['burst']
                metermod.add_meter_bands(Meter._TYPE_DROP, Meter.SET_RATE(meter_rate))
                metermod.add_meter_bands(Meter._TYPE_DROP, Meter.SET_BURST(meter_burst_size))
            elif meter_type == Meter._TYPE_DSCP_REMARK:
                meter_rate = meter['rate']
                meter_burst_size = meter['burst']
                meter_prec_level = meter['prec_level']
                metermod.add_meter_bands(Meter._TYPE_DROP, Meter.SET_RATE(meter_rate))
                metermod.add_meter_bands(Meter._TYPE_DROP, Meter.SET_BURST(meter_burst_size))
                metermod.add_meter_bands(Meter._TYPE_DROP, Meter.SET_PREC_LEVEL(meter_prec_level))
            elif meter_type == Meter._TYPE_EXPERIMENTER:
                meter_rate = meter['rate']
                meter_burst_size = meter['burst']
                meter_experimenter = meter['experimenter']
                metermod.add_meter_bands(Meter._TYPE_DROP, Meter.SET_RATE(meter_rate))
                metermod.add_meter_bands(Meter._TYPE_DROP, Meter.SET_BURST(meter_burst_size))
                metermod.add_meter_bands(Meter._TYPE_DROP, Meter.SET_EXP(meter_experimenter))


class Modifiers():
    def __init__(self):
        self.routemods = RouteMods()
        self.metermods = MeterMods()
        self.groupmods = GroupMods()

    def convert_routemod_to_route(self, routemod):
        route = {}
        self.routemods.unpack_matches(route, routemod.get_matches())
        self.routemods.unpack_actions(route, routemod.get_actions())
        self.routemods.unpack_instructions(route, routemod.get_instructions())
        self.routemods.unpack_options(route, routemod.get_options())
        return route

    def convert_route_to_routemod(self, route):
        routemod = RouteMod()
        self.routemods.pack_matches(routemod, route)
        self.routemods.pack_actions(routemod, route)
        self.routemods.pack_instructions(routemod, route)
        self.routemods.pack_options(routemod, route)
        return routemod

    def configure_physical_topology_flows(self, flows, matches, actions, options, instructions):
        flows_configured = []
        for flow in flows:
            self.routemods.apply_route_matches(flow, matches)
            self.routemods.apply_route_actions(flow, actions)
            self.routemods.apply_route_instructions(flow, instructions)
            self.routemods.apply_route_options(flow, options)
            flows_configured.append(flow)
        return flows_configured

    def pack_physical_topology_flows(self, flows):
        flows_packed = []
        for flow in flows:
            routemod = RouteMod()
            self.routemods.pack_actions(routemod, flow)
            self.routemods.pack_instructions(routemod, flow)
            self.routemods.pack_matches(routemod, flow)
            self.routemods.pack_options(routemod, flow)
            flows_packed.append(routemod)
        return flows_packed

    def pack_physical_topology_groups(self, groups):
        groups_packed = []
        for group_id in groups.keys():
            groupmod = GroupMod()
            group = groups[group_id]
            groupmod.set_group_id(group_id)
            groupmod.set_group_type(group['group_type'])
            self.groupmods.pack_group_buckets(groupmod, group['buckets'], group['actions'])
            self.groupmods.pack_group_actions(groupmod, group['actions'])
            groups_packed.append(groupmod)
        return groups_packed

    def pack_physical_topology_meters(self, meters):
        meters_packed = []
        for meter_id in meters.keys():
            metermod = MeterMod()
            meter = meters[meter_id]
            self.metermods.pack_meter_bands(metermod, meter['bands'])
            meters_packed.append(metermod)
        return meters_packed

    def convert_physical_topology_flows(self, flows, options):
        flows_converted = []
        for flow in flows:
            self.routemods.apply_route_options(flow, options)
            flow_converted = self.routemods.convert_route_to_routemod(flow)
            flows_converted.append(flow_converted)
        return flows_converted

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import mpls
from ryu.lib.packet import tcp
from ryu.ofproto import ofproto_v1_3

import snakepeople


class SimpleServiceFunction(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp_parser = dp.ofproto_parser

        message = dp.ofproto_parser.OFPFlowMod(
            datapath=dp,
            table_id=0,
            command=dp.ofproto.OFPFC_ADD,
            priority=100,
            match=ofp_parser.OFPMatch(in_port=1),
            instructions=[
                ofp_parser.OFPInstructionActions(
                    dp.ofproto.OFPIT_APPLY_ACTIONS,
                    [
                        ofp_parser.OFPActionOutput(
                            ofproto_v1_3.OFPP_CONTROLLER,
                            ofproto_v1_3.OFPCML_NO_BUFFER,
                        )
                    ],
                ),
            ],
        )
        dp.send_msg(message)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp_parser = dp.ofproto_parser

        pkt = packet.Packet(msg.data)
        payload = pkt.protocols[-1]

        if isinstance(payload, (bytes, bytearray)):
            new_payload = snakepeople.translate(
                payload.decode('utf-8'),
            ).encode('utf-8')

            new_pkt = packet.Packet()
            new_pkt.add_protocol(pkt.get_protocol(ethernet.ethernet))
            new_pkt.add_protocol(pkt.get_protocol(mpls.mpls))
            pkt_ip = pkt.get_protocol(ipv4.ipv4)
            pkt_ip.csum = 0
            pkt_ip.total_length = 0
            new_pkt.add_protocol(pkt_ip)
            pkt_tcp = pkt.get_protocol(tcp.tcp)
            pkt_tcp.csum = 0
            new_pkt.add_protocol(pkt_tcp)
            new_pkt.add_protocol(new_payload)
            new_pkt.serialize()
            pkt = new_pkt

        actions = [ofp_parser.OFPActionOutput(port=2)]
        out = ofp_parser.OFPPacketOut(
            datapath=dp,
            buffer_id=ofproto_v1_3.OFP_NO_BUFFER,
            in_port=ofproto_v1_3.OFPP_CONTROLLER,
            data=pkt.data,
            actions=actions,
        )
        dp.send_msg(out)

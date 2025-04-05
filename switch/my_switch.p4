/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x0800;
const bit<16> TYPE_ARP   = 0x0806;
const bit<8>  PROTO_ICMP = 1;
const bit<8>  PROTO_TCP   = 6;
const bit<8>  PROTO_UDP   = 17;

const bit<4> MQTT_PUBLISH = 0b0011; 
const bit<4> MQTT_CONNECT = 0b0001;   

const bit<32> CLONE_SESSION_ID = 1;

const bit<16> ARP_HTYPE = 0x0001;    
const bit<16> ARP_PTYPE = TYPE_IPV4; 
const bit<8>  ARP_HLEN  = 6;         
const bit<8>  ARP_PLEN  = 4;         
const bit<16> ARP_REQ   = 1;           
const bit<16> ARP_REPLY = 2;         

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}
header arp_t {
    bit<16>   h_type;
    bit<16>   p_type;
    bit<8>    h_len;
    bit<8>    p_len;
    bit<16>   op_code;
    macAddr_t src_mac;
    ip4Addr_t src_ip;
    macAddr_t dst_mac;
    ip4Addr_t dst_ip;
}
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;                   
    bit<16> length_;
    bit<16> checksum;
}
header icmp_t {
    bit<8> icmp_type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<32> unused;
}
header mqtt_t {
    bit<4> msgType; 
    bit<4> flags;
}
header mqtt_publish_t {             
    bit<16> msg_length;             
    bit<8> topic_length;         
    bit<96> topic_name; 
}
header mqtt_connect_t {
    bit<16> length;  
    bit<8> protocol_length; 
    bit<32> protocol_name;    
    bit<8> protocol_level;    
    bit<8> connect_flags;   

}
header dns_t {
    bit<88> data;
    bit<80> data1;
    bit<80> data2;   
}
header dns_query_t {
    bit<256> qry_name; 
    bit<16> type;       
    bit<16> class;     
}
header http_t {
    bit<88> data;
    bit<160> payload;
    bit<160> payload1;
    //bit<160> payload2;
}
header mbtcp_t {
    bit<16> len;
    bit<16> trans_id;
    bit<8>  unit_id;
}
struct digest_data_t {
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    bit<16> icmp_checksum;
    bit<16> icmp_seq_le;
    bit<32> icmp_unused;
}
struct digest_data_t2 {
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<4>  tcp_dataOffset;
    bit<32> tcp_ack_raw;
    bit<16> tcp_checksum;
    bit<32> tcp_seq;
    bit<9>  tcp_flags;
}
struct digest_data_t3 {
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
}
struct digest_data_t4 {
    bit<88> dns_data;
    bit<80> dns_data1;
    bit<80> dns_data2;        
    /*
    bit<16> dns_qry_type;
    bit<256> dns_qry_name;
    //bit<16> dns_qry_name_len;*/

}
struct digest_data_t5 {
    bit<160> http_payload;
    bit<160> http_payload1;
    //bit<160> http_payload2;
}
struct digest_data_t6 {  //mqtt_publish
    bit<4> mqtt_msgType;   
    bit<16> mqtt_msg_length;             
    bit<8> mqtt_topic_length;         
    bit<96> mqtt_topic_name;  
}
struct digest_data_mqtt_connect {  
    bit<4> mqtt_msgType;  
    bit<16> mqtt_length;  
    bit<8> mqtt_protocol_length; 
    bit<32> mqtt_protocol_name;    
    bit<8> mqtt_protocol_level;    
    bit<8> mqtt_connect_flags;   
}
struct digest_data_t7 {
    bit<16> mbtcp_len;
    bit<16> mbtcp_trans_id;
    bit<8>  mbtcp_unit_id;   
}
struct digest_data_t8 {
    ip4Addr_t src_ip;
    ip4Addr_t dst_ip;
    bit<16> arp_opcode;
    bit<8>  arp_hw_size;
} 
struct metadata {

}
struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
    icmp_t       icmp;
    mqtt_t       mqtt;
    dns_t        dns;
    http_t       http;
    mbtcp_t      mbtcp;
    mqtt_publish_t mqtt_publish;
    mqtt_connect_t mqtt_connect;
}


parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
          TYPE_ARP: parse_arp;
          TYPE_IPV4: parse_ipv4;
          default: accept;
        }
    }
   state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.op_code) {
          ARP_REQ: accept;
          default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
          PROTO_ICMP: parse_icmp;
          PROTO_TCP: parse_tcp;
          PROTO_UDP: parse_udp;
          default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort) {
            1883: parse_mqtt;
            502: parse_mbtcp;
            80: parse_http;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            53: parse_dns;
            default: accept;
        }
    }
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
    state parse_mqtt {
        packet.extract(hdr.mqtt);
        transition select(hdr.mqtt.msgType) {
            MQTT_PUBLISH: parse_mqtt_publish;  
            MQTT_CONNECT: parse_mqtt_connect;
            default: accept;
        }
    }
    state parse_mqtt_publish {
        packet.extract(hdr.mqtt_publish);
        transition accept;
    }
    state parse_mqtt_connect {
        packet.extract(hdr.mqtt_connect);  
        transition accept;
    }
    state parse_dns {
        packet.extract(hdr.dns);
        transition accept;
    }
    state parse_http {
        packet.extract(hdr.http);
        transition accept;
    }
    state parse_mbtcp {
        packet.extract(hdr.mbtcp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata
                ) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action send_digest_icmp() {
        digest<digest_data_t>(1, {
            hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr,
            hdr.icmp.checksum, 
            hdr.icmp.sequence_number, 
            hdr.icmp.unused
        });
    }
    action send_digest_tcp(){
            digest<digest_data_t2>(1, {
            hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr,
            hdr.tcp.srcPort,
            hdr.tcp.dstPort,
            hdr.tcp.dataOffset,
            hdr.tcp.ackNo, 
            hdr.tcp.checksum, 
            hdr.tcp.seqNo,
            hdr.tcp.flags      
            });
    }
    action send_digest_udp() {
        digest<digest_data_t3>(1, { 
            hdr.ipv4.srcAddr, 
            hdr.ipv4.dstAddr,
            hdr.udp.srcPort,
            hdr.udp.dstPort
        });
    }
    action send_digest_dns() {
        //bit<256> dns_qry_name = hdr.dns.qry_name;
        digest<digest_data_t4>(1, { 
            hdr.dns.data,
            hdr.dns.data1,
            hdr.dns.data2
            /*hdr.dns.qtype,
            hdr.dns.qry_name*/
        });
    }
    action send_digest_http() {
        digest<digest_data_t5>(1, { 
            hdr.http.payload,
            hdr.http.payload1
            //hdr.http.payload2

        });
    }
    action send_digest_mqtt_publish() {
        digest<digest_data_t6>(1, { 
            hdr.mqtt.msgType,
            hdr.mqtt_publish.msg_length,             
            hdr.mqtt_publish.topic_length,
            hdr.mqtt_publish.topic_name
        });
    }
    action send_digest_mqtt_connect() {
        digest<digest_data_mqtt_connect>(1, { 
            hdr.mqtt.msgType,
            hdr.mqtt_connect.length,  
            hdr.mqtt_connect.protocol_length, 
            hdr.mqtt_connect.protocol_name,    
            hdr.mqtt_connect.protocol_level,    
            hdr.mqtt_connect.connect_flags  

        });
    }
    action send_digest_mbtcp() {
        digest<digest_data_t7>(1, { 
            hdr.mbtcp.len,
            hdr.mbtcp.trans_id,
            hdr.mbtcp.unit_id
        });
    }action send_digest_arp() {
        digest<digest_data_t8>(1, { 
            hdr.arp.src_ip,
            hdr.arp.dst_ip,
            hdr.arp.op_code,
            hdr.arp.h_len
        });
    }
    table idps_arp_exact {
        key = {
            hdr.ethernet.etherType: exact;
            hdr.arp.src_ip: exact;
            hdr.arp.dst_ip: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    table idps_icmp_exact {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    table idps_udp_exact {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.srcPort:  exact;
            hdr.udp.dstPort:  exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    table idps_tcp_exact {
        key = {
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.srcPort:  exact;
            hdr.tcp.dstPort:  exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    apply {
        bit<8> dropped = 0;
        if (hdr.ethernet.isValid() && hdr.ethernet.etherType == 0x0806) {
            if (idps_arp_exact.apply().hit) {
                dropped = 1;
            }
        } else if (hdr.ipv4.isValid()) {
            if (hdr.tcp.isValid() && dropped == 0) {
                if (idps_tcp_exact.apply().hit) {
                    dropped = 1;
                }
            } else if (hdr.udp.isValid() && dropped == 0) {
                if (idps_udp_exact.apply().hit) {
                        dropped = 1;
                }
            } else if (hdr.icmp.isValid() && dropped == 0) {
                    if (idps_icmp_exact.apply().hit) {
                        dropped = 1;
                }
            }
        }
        if (dropped != 1) {
            if (hdr.ipv4.protocol == 1) {
                send_digest_icmp();
            }else if (hdr.udp.dstPort == 53){
                send_digest_udp();
                send_digest_dns();
            }else if (hdr.ipv4.protocol == 6 && hdr.tcp.dstPort == 80){
                send_digest_tcp();
                send_digest_http();
            }else if (hdr.ipv4.protocol == 6 && hdr.tcp.dstPort == 1883 && hdr.mqtt.msgType == MQTT_PUBLISH){
                send_digest_tcp();
                send_digest_mqtt_publish();
            }else if (hdr.ipv4.protocol == 6 && hdr.tcp.dstPort == 1883 && hdr.mqtt.msgType == MQTT_CONNECT){
                send_digest_tcp();
                send_digest_mqtt_connect();
            }else if (hdr.ipv4.protocol == 6 && hdr.tcp.dstPort == 501){
                send_digest_tcp();
                send_digest_mbtcp();
            }else if (hdr.ethernet.etherType == 0x0806){
                send_digest_arp();
            }else if (hdr.ipv4.protocol == 6){
                send_digest_tcp();
            }else if (hdr.ipv4.protocol == 17){
                send_digest_udp();
            }
            standard_metadata.egress_port = (standard_metadata.ingress_port + 1) % 2;
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        /* update_checksum(
            hdr.icmp.isValid(),
            {
              hdr.icmp.icmp_type,
              hdr.icmp.icmp_code,
              hdr.icmp.identifier,
              hdr.icmp.sequence_number,
              hdr.icmp.timestamp
            },
              hdr.icmp.checksum,
              HashAlgorithm.csum16);
        */
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.dns);
        packet.emit(hdr.mbtcp);
        packet.emit(hdr.http);
        packet.emit(hdr.mqtt);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;


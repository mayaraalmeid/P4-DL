import queue
import sys
import threading
import socket
import struct
import os
import logging
import google.protobuf.text_format
from google.rpc import status_pb2, code_pb2
import grpc
from p4.v1 import p4runtime_pb2
from p4.v1 import p4runtime_pb2_grpc
import hashlib
import time
import pandas as pd
from openvino.runtime import Core
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn import preprocessing
import joblib
import warnings


device_id = 1
P4INFO = os.getenv('P4INFO', 'my_switch.p4info.txt')
P4BIN = os.getenv('P4BIN', 'my_switch.json')
digest1_id = 389926700  # Digest 1
digest2_id = 400421736  # Digest 2 
digest3_id = 388292598  # Digest 3
digest4_id = 393427603  # Digest 4
digest5_id = 395175119  # Digest 5
digest6_id = 390021170  # Digest 6
digest_id_mqttCO = 391205060  # Digest mqttCO
digest7_id = 401616276  # Digest 7
digest8_id = 397052169  # Digest 8

logging.basicConfig(
    format='%(asctime)s.%(msecs)03d: %(process)d: %(levelname).1s/%(name)s: %(filename)s:%(lineno)d: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO
)
send_queue = queue.Queue()

recv_queue = queue.Queue()

def gen_handshake(election_id):
    req = p4runtime_pb2.StreamMessageRequest()
    arbitration = req.arbitration
    arbitration.device_id = device_id
    eid = arbitration.election_id
    eid.high = election_id[0]
    eid.low = election_id[1]
    return req

def check_handshake():
    try:
        rep = recv_queue.get(timeout=2)
        if rep is None:
            logging.critical("Failed to establish session with server")
            sys.exit(1)
        is_primary = (rep.arbitration.status.code == code_pb2.OK)
        logging.debug("Session established, client is '%s'", 'primary' if is_primary else 'backup')
        if not is_primary:
            logging.info("You are not the primary client, you only have read access to the server")
        else:
            logging.info('You are primary')
    except queue.Empty:
        logging.warning("No handshake response received in time")
        sys.exit(1)

def int_to_ip(int_value):
    return socket.inet_ntoa(struct.pack('!I', int_value))

def reverse_bytes(member):
    return int.from_bytes(member.bitstring[::-1], byteorder='big')


aux_queue = queue.Queue()  

campos = [
    "src_addr", "dst_addr", "srcport", "dstport", "udp.stream", "udp.time_delta", "dns.qry.type", "dns.qry.name", "icmp.checksum", "icmp.seq_le", "icmp.unused", "tcp.ack_raw", "tcp.checksum", "tcp.seq", "tcp.flags", "tcp.len", "tcp.ack", "http.content.length", "http.request.method", "http.referer", "http_request_version", 
    "http.response", "http.tls.port", "mqtt.conack.flags", "mqtt.conflag.cleansess", "mqtt.conflags", "mqtt.hdrflags", "mqtt.len", "mqtt.msg_decoded_as", "mqtt.msgtype", "mqtt.proto_len", "mbtcp.len", "mbtcp.trans_id", "mbtcp.unit_id", "arp_opcode", "arp_hw_size", "processed"
]

dados = pd.DataFrame(columns=["digest_id"] + campos)
def process_digest1(digest): 
    global dados
    novos_dados = []
    for _, tuple_data in enumerate(digest.data):
        src_addr = None
        dst_addr = None
        icmp_checksum = None
        icmp_seq_le = None
        icmp_unused = None
        protocolo = "ICMP"

        for member_idx, member in enumerate(tuple_data.tuple.members):
            member_value_decimal = reverse_bytes(member)

            if member_idx == 0:
                src_addr = member_value_decimal
            elif member_idx == 1:
                dst_addr = member_value_decimal
            elif member_idx == 2:
                icmp_checksum = member_value_decimal
            elif member_idx == 3:
                icmp_seq_le = member_value_decimal
            elif member_idx == 4:  
                icmp_unused = member_value_decimal

        src_ip = int_to_ip(src_addr) if src_addr is not None else "N/A"
        dst_ip = int_to_ip(dst_addr) if dst_addr is not None else "N/A"
        digest_data = {
            "digest_id": digest.digest_id,
            "src_addr": src_ip,
            "dst_addr": dst_ip,
            "protocolo": protocolo,
            "icmp.checksum": icmp_checksum,
            "icmp.seq_le": icmp_seq_le,
            "icmp.unused": icmp_unused
        }
        
        process_proto(digest_data)

def process_digest2(digest):
    global dados
    novos_dados = []
    for _, tuple_data in enumerate(digest.data):
        src_addr = None
        dst_addr = None
        tcp_srcport = None
        tcp_dstport = None
        tcp_Ack_raw = None
        tcp_checksum = None
        tcp_seq = None
        tcp_flags = None
        tcp_len = None
        tcp_ack = None
        protocolo = "TCP"
        
        for member_idx, member in enumerate(tuple_data.tuple.members):
            member_value_decimal = reverse_bytes(member)

            if member_idx == 0:
                src_addr = member_value_decimal
            elif member_idx == 1:
                dst_addr = member_value_decimal
            elif member_idx == 2:
                tcp_srcport = member_value_decimal
            elif member_idx == 3:
                tcp_dstport = member_value_decimal    
            elif member_idx == 4:
                tcp_dataoff = member_value_decimal
                tcp_len = tcp_dataoff * 4
            elif member_idx == 5:
                tcp_Ack_raw = member_value_decimal
            elif member_idx == 6:
                tcp_checksum = member_value_decimal
            elif member_idx == 7:
                tcp_seq = member_value_decimal
            elif member_idx == 8:
                tcp_flags = member_value_decimal
            elif member_idx == 9:
                tcp_len = member_value_decimal
        
        src_ip = int_to_ip(src_addr) if src_addr is not None else "N/A"
        dst_ip = int_to_ip(dst_addr) if dst_addr is not None else "N/A"


        tcp_flags_info = []
        if tcp_flags is not None:
            if tcp_flags & 0b00000001:  # FIN
                tcp_flags_info.append("tcp.connection.fin")
            if tcp_flags & 0b00000010:  # SYN
                tcp_flags_info.append("tcp.connection.syn")
            if tcp_flags & 0b00000100:  # RST
                tcp_flags_info.append("tcp.connection.rst")
            if tcp_flags & 0b00010000:  # ACK
                tcp_flags_info.append("tcp.flags.ack")
            if tcp_flags & 0b00000010 and tcp_flags & 0b00010000:  # SYN-ACK
                tcp_flags_info.append("tcp.connection.synack")


        if tcp_seq is None or tcp_Ack_raw is None:
            logging.info("SeqNo is N/A, handling only ack")
            tcp_ack = None
        else:
            tcp_ack = tcp_Ack_raw - tcp_seq

        digest_data = {
            "digest_id": digest.digest_id,
            "src_addr": src_ip,
            "dst_addr": dst_ip,
            "srcport": tcp_srcport,
            "dstport": tcp_dstport,
            "protocolo": protocolo,
            "tcp.ack_raw": tcp_Ack_raw,
            "tcp.checksum": tcp_checksum,
            "tcp.seq": tcp_seq,
            "tcp.flags": tcp_flags,
            "tcp.len": tcp_len,
            "tcp.ack": tcp_ack
        } 

        for flag in tcp_flags_info:
            digest_data[flag] = True

        for campo in ["tcp.connection.syn", "tcp.flags.ack", "tcp.connection.rst", "tcp.connection.fin", "tcp.connection.synack"]:
            if campo not in digest_data:
                digest_data[campo] = False

        if(tcp_dstport == 80):
            aux_queue.put(digest_data)
            return

        if(tcp_dstport == 501):
            aux_queue.put(digest_data)
            return

        if(tcp_dstport == 1883):
            aux_queue.put(digest_data)
            return
        
        process_proto(digest_data)
        


def process_digest3(digest):
    global dados
    novos_dados = []
    for _, tuple_data in enumerate(digest.data): 
        src_addr = None
        dst_addr = None
        udp_srcport = None
        udp_dstport = None
        udp_stream = None
        udp_time = None
        protocolo = "UDP"

        for member_idx, member in enumerate(tuple_data.tuple.members): 
            member_value_decimal = reverse_bytes(member)
            if member_idx == 0:
                src_addr = member_value_decimal
            elif member_idx == 1:
                dst_addr = member_value_decimal
            elif member_idx == 2:
                udp_srcport = member_value_decimal
            elif member_idx == 3:
                udp_dstport = member_value_decimal

        src_ip = int_to_ip(src_addr) if src_addr is not None else "N/A"
        dst_ip = int_to_ip(dst_addr) if dst_addr is not None else "N/A"
        timestamp = time.time()
        
        chave_fluxo = (src_ip, dst_ip, udp_srcport, udp_dstport)

        if chave_fluxo in fluxos:
            primeiro_timestamp = fluxos[chave_fluxo]
            delta_tempo = timestamp - primeiro_timestamp

            udp_time = delta_tempo
            
            fluxos[chave_fluxo] = timestamp
        else:
            fluxos[chave_fluxo] = timestamp

        hash_input = f"{src_ip}:{dst_ip}:{udp_srcport}:{udp_dstport}".encode('utf-8')

        udp_stream = hashlib.sha256(hash_input).hexdigest()

        digest_data = {
            "digest_id": digest.digest_id,
            "src_addr": src_ip,
            "dst_addr": dst_ip,
            "protocolo": protocolo,
            "srcport": udp_srcport,
            "dstport": udp_dstport,
            "udp.stream": udp_stream,
            "udp.time_delta": udp_time
        }
        if (udp_dstport == 53):
            aux_queue.put(digest_data)
            return
        
        process_proto(digest_data)


def extract_dns_fields(bitstring):
    index = 0
    bitstring_length = len(bitstring)
    print(f"Processing bitstring of length {bitstring_length} bytes.") 

    domain_parts = []
    while index < bitstring_length:
        length = bitstring[index]
        print(f"Length byte: {length}") 
        index += 1
        if length == 0:  
            print("End of domain name detected.")  
            break
        if index + length > bitstring_length:
            raise IndexError("Bitstring muito curto para extrair o nome do domínio")
        
        part = bitstring[index:index + length]
        print(f"Domain part (raw): {part}") 
        try:
            domain_parts.append(part.decode('ascii'))  
        except UnicodeDecodeError:
            print(f"Failed to decode part: {part.hex()}")  
            domain_parts.append(part.hex())  
        index += length

    domain_name = '.'.join(domain_parts)
    print(f"Domain Name Extracted: {domain_name}")  

 
    if index + 2 > bitstring_length:
        raise IndexError("Bitstring muito curto para extrair o tipo de query")
    query_type = int.from_bytes(bitstring[index:index + 2], byteorder='big')
    print(f"Query Type: {query_type}") 
    index += 2


    if index + 2 > bitstring_length:
        raise IndexError("Bitstring muito curto para extrair a classe de query")
    query_class = int.from_bytes(bitstring[index:index + 2], byteorder='big')
    print(f"Query Class: {query_class}")
    index += 2

    return {
        'domain_name': domain_name,
        'query_type': query_type,
        'query_class': query_class
    }


def process_digest4(digest):
    global dados
    for _, tuple_data in enumerate(digest.data): 
        concatenated_bitstring = b""
        #print(digest.data)
        for member_idx, member in enumerate(tuple_data.tuple.members):
            #print(f"Member {member_idx} bitstring: {member.bitstring}")
            concatenated_bitstring += member.bitstring
        
        try:
            dns_data = extract_dns_fields(concatenated_bitstring)
            digest_data = {
                "dns.qry.name": dns_data['domain_name'],
                "dns.qry.type": dns_data['query_type'],
                "dns.qry.class": dns_data['query_class']
            }

            #print(f"Digest Data: {digest_data}")
        except IndexError as e:
            print(f"Erro ao processar digest: {e}")



        # concatenated_bitstring_str = ''.join(
        #     f"\\{byte:03o}" if byte < 32 or byte > 126 else chr(byte)
        #     for byte in concatenated_bitstring
        # )

        # dns_data = extract_dns_fields_extended(concatenated_bitstring)

        # digest_data = {
        #     "dns.qry.type": dns_data['query_type'],
        #     "dns.qry.name": dns_data['domain_name'],
        #     "dns.qry.class": dns_data['query_class'],
        #     "dns.transaction_id": dns_data['transaction_id'],
        #     "dns.flags": dns_data['flags']
        # }
        # if(not aux_queue.empty()):
        #     digest_anterior = aux_queue.get()
        #     digest_full = {**digest_anterior, **digest_data}
        #     process_proto(digest_full)
        #     return


def process_digest5(digest):
    global dados
    http_method_map = {
        1: "GET",
        2: "POST",
        3: "PUT",
        4: "DELETE",
        5: "PATCH",
        6: "HEAD",
        7: "OPTIONS"
    }

    for _, tuple_data in enumerate(digest.data):
        http_content_length = None  # Numérico (deixa como está)
        http_request_method = None  # String (mapeado)
        http_referer = None  # String (URL)
        http_request_version = None  # String (versão HTTP)
        http_response = None  # Numérico (deixa como está)
        http_tls_port = None  # Numérico (deixa como está)
        #print(digest.data)

        for member_idx, member in enumerate(tuple_data.tuple.members):
            member_value_decimal = reverse_bytes(member) 

            if member_idx == 0:
                http_content_length = member_value_decimal
            elif member_idx == 1:
                http_request_method = http_method_map.get(member_value_decimal, "UNKNOWN")
            elif member_idx == 2:
                http_referer = bytearray(member).decode('utf-8', errors='replace') 
            elif member_idx == 3:
                http_request_version = bytearray(member).decode('utf-8', errors='replace') 
            elif member_idx == 4:  
                http_response = member_value_decimal
            elif member_idx == 5:  
                http_tls_port = member_value_decimal

        digest_data = {
            "http.content.length": http_content_length,
            "http.request_method": http_request_method, 
            "http.referer": http_referer,  
            "http.request.version": http_request_version, 
            "http.response": http_response,  
            "http.tls.port": http_tls_port  
        }

        if not aux_queue.empty():
            digest_anterior = aux_queue.get()
            digest_full = {**digest_anterior, **digest_data}
            process_proto(digest_full)
            return


def process_digest6(digest):
    global dados
    for _, tuple_data in enumerate(digest.data):
        mqtt_hdr_flags = None
        mqtt_len = None
        mqtt_topic_len = None
        mqtt_topic = None
        for member_idx, member in enumerate(tuple_data.tuple.members):
            member_value_decimal = reverse_bytes(member)

            if member_idx == 0:
                mqtt_hdr_flags = member_value_decimal
            elif member_idx == 1:
                mqtt_len = member_value_decimal
            elif member_idx == 2:
                mqtt_topic_len = member_value_decimal
            elif member_idx == 3:
                mqtt_topic = member.bitstring.decode("utf-8") if hasattr(member, "bitstring") else None

        digest_data = {
            "mqtt.hdrflags": mqtt_hdr_flags,
            "mqtt.len": mqtt_len,
            "mqtt.topic_len": mqtt_topic_len,
            "mqtt.topic": mqtt_topic,
        }
        #print(digest_data)
        if(not aux_queue.empty()):
            digest_anterior = aux_queue.get()
            digest_full = {**digest_anterior, **digest_data}
            process_proto(digest_full)
            return
def process_digest_id_mqttCO(digest):
    global dados
    for _, tuple_data in enumerate(digest.data):
        mqtt_hdr_flags = None
        mqtt_len = None
        mqtt_protoname_len = None
        mqtt_protoname = None
        mqtt_protoname_level = None
        mqtt_connect_flags = None

        for member_idx, member in enumerate(tuple_data.tuple.members):
            member_value_decimal = reverse_bytes(member)

            if member_idx == 0:
                mqtt_hdr_flags = member_value_decimal
            elif member_idx == 1:
                mqtt_len = member_value_decimal
            elif member_idx == 2:
                mqtt_protoname_len = member_value_decimal
            elif member_idx == 3:
                mqtt_protoname_ = member.bitstring.decode("utf-8") if hasattr(member, "bitstring") else None
                mqtt_protoname = mqtt_protoname_[::-1] 
            elif member_idx == 4:
                mqtt_protoname_level = member_value_decimal
            elif member_idx == 5:
                mqtt_connect_flags = member_value_decimal

        digest_data = {
            "mqtt.hdrflags": mqtt_hdr_flags,
            "mqtt.len": mqtt_len,
            "mqtt.proto_len": mqtt_protoname_len,
            "mqtt.protoname": mqtt_protoname, 
            "mqtt.ver": mqtt_protoname_level,
            "mqtt.conflags": mqtt_connect_flags
        }
        #print(digest_data)

        if not aux_queue.empty():
            digest_anterior = aux_queue.get()
            digest_full = {**digest_anterior, **digest_data}
            process_proto(digest_full)
            return

def process_digest7(digest):
    global dados
    for _, tuple_data in enumerate(digest.data):
        mbtcp_len = None
        mbtcp_trans_id = None
        mbtcp_unit_id - None
        for member_idx, member in enumerate(tuple_data.tuple.members):
            member_value_decimal = reverse_bytes(member)
            if member_idx == 0:
                mbtcp_len = member_value_decimal
            elif member_idx == 1:
                mbtcp_trans_id = member_value_decimal
            elif member_idx == 2:
                mbtcp_unit_id = member_value_decimal

        digest_data = {
            "mbtcp.len": mbtcp_len,
            "mbtcp.trans_id": mbtcp_trans_id,
            "mbtcp.unit_id": mbtcp_unit_id
        }

        if(not aux_queue.empty()):
            digest_anterior = aux_queue.get()
            digest_full = {**digest_anterior, **digest_data}
            process_proto(digest_full)
            return

def process_digest8(digest):
    global dados
    for _, tuple_data in enumerate(digest.data):
        src_addr = None
        dst_addr = None
        arp_opcode = None
        arp_hw_size = None

        for member_idx, member in enumerate(tuple_data.tuple.members):
            member_value_decimal = reverse_bytes(member)
            if member_idx == 0:
                src_addr = member_value_decimal
            elif member_idx == 1:
                dst_addr = member_value_decimal
            elif member_idx == 2:
                arp_opcode = member_value_decimal
            elif member_idx == 3:
                arp_hw_size = member_value_decimal

        src_ip = int_to_ip(src_addr) if src_addr is not None else "N/A"
        dst_ip = int_to_ip(dst_addr) if dst_addr is not None else "N/A"

        digest_data = {
            "digest_id": digest.digest_id,
            "src_addr": src_ip,
            "dst_addr": dst_ip,
            "arp.opcode": arp_opcode,   
            "arp.hw.size": arp_hw_size
        }
        process_proto(digest_data)

def stream(stub):
    def recv_handler(responses):
        try:
            for response in responses:
                #logging.info('Recebendo resposta')
                if hasattr(response, 'digest'):
                    digest_list = response.digest
                    if isinstance(digest_list, p4runtime_pb2.DigestList):
                        if digest_list.digest_id == digest1_id:
                            process_digest1(digest_list)
                        elif digest_list.digest_id == digest2_id:
                            process_digest2(digest_list)
                        elif digest_list.digest_id == digest3_id:
                            process_digest3(digest_list)
                        elif digest_list.digest_id == digest4_id:
                            process_digest4(digest_list)
                        elif digest_list.digest_id == digest5_id:
                            process_digest5(digest_list)
                        elif digest_list.digest_id == digest_id_mqttCO:
                            process_digest_id_mqttCO(digest_list)
                        elif digest_list.digest_id == digest6_id:
                            process_digest6(digest_list)
                        elif digest_list.digest_id == digest7_id:
                            process_digest7(digest_list)
                        elif digest_list.digest_id == digest8_id:
                            process_digest8(digest_list)


                recv_queue.put(response)
        except grpc.RpcError as e:
            logging.error(f'Erro de RPC: {e}')
            if e.code() == grpc.StatusCode.CANCELLED:
                logging.info('Canal encerrado pelo servidor')

    responses = stub.StreamChannel(iter(send_queue.get, None))
    logging.info('Canal criado')
    recv_thread = threading.Thread(target=recv_handler, args=(responses,))
    recv_thread.start()
    send_queue.put(gen_handshake(election_id=(0, 1)))
    check_handshake()
    logging.info('Handshake concluído')
    return recv_thread

def process_proto(digest):
    global dados

    novos_dados = []
    for campo in campos:
        if campo not in digest:
            digest[campo] = None
    novos_dados.append(digest)

    df_novos_dados = pd.DataFrame(novos_dados)
    df_novos_dados = df_novos_dados.dropna(how='all', axis=1)
    df_novos_dados = df_novos_dados.dropna(how='all', axis=0)
    dados = dados.dropna(how='all', axis=1)

    if not df_novos_dados.empty:
        dados = pd.concat([dados, df_novos_dados], ignore_index=True)

        if not dados.empty:
            inference_thread = threading.Thread(target=run_inference, args=(dados.iloc[-1:],))
            inference_thread.start()

def encode_text_dummy(dados, name):
    if name in dados.columns:
        dummies = pd.get_dummies(dados[name], prefix=name)
        dados = dados.drop(name, axis=1)
        dados = pd.concat([dados, dummies], axis=1)  
    return dados  

ataques_detectados = []
def run_inference(data):
    core = Core()
    compiled_model = core.compile_model("/home/pi/cnn2/saved_model.xml", "CPU")
   # compiled_model = core.compile_model("/home/pi/modelos_convertidos/gru_convert/saved_model.xml", "CPU")
    #compiled_model = core.compile_model("/home/pi/modelos_convertidos/lstm_convert/saved_model.xml", "CPU")
    scaler = joblib.load("/home/pi/scaler.pkl")

    pacotes_originais = []
    for _, row in data.iterrows():
        # Captura informações originais do pacote antes do pré-processamento
        pacote_info = {
            "src_ip": row.get("src_addr"),
            "dst_ip": row.get("dst_addr"),
            "protocolo": row.get("protocolo"),
            "src_port": row.get("srcport") if row.get("protocolo") in ["TCP", "UDP"] else None,
            "dst_port": row.get("dstport") if row.get("protocolo") in ["TCP", "UDP"] else None
            
        }
        pacotes_originais.append(pacote_info)

    cols_to_encode = [#'http.request.method', 'http.referer', 'http.request.version', 
                      #'dns.qry.name.len',
                        'mqtt.conack.flags', 'mqtt.protoname', 'mqtt.topic']

    for col in cols_to_encode:
        data = encode_text_dummy(data, col)

    colunas_necessarias = [
        'tcp.ack', 'tcp.ack_raw', 'tcp.seq', 'udp.stream', 'Unnamed: 0', 
        'dns.qry.name', 'icmp.checksum', 'icmp.seq_le', 'tcp.checksum', 'tcp.len', 
        'http.content_length', 'dns.qry.qu', 'mqtt.hdrflags', 'tcp.flags', 'udp.time_delta', 
        'http.referer-0', 'http.request.method-0', 'http.request.version-0', 'mqtt.len', 
        'mqtt.protoname-0.0', 'mqtt.conack.flags-0.0', 'mqtt.topic-0.0', 'dns.qry.name.len-0.0', 
        'mqtt.topic_len', 'http.request.version-HTTP/1.1', 'http.request.method-GET', 'http.response', 
        'mqtt.msgtype', 'dns.qry.name.len-0', 'mqtt.topic-0', 'mqtt.protoname-0', 'mqtt.conack.flags-0', 
        'dns.qry.name.len-1.0', 'arp.hw.size', 'tcp.connection.syn', 'http.request.version-0.0', 
        'http.request.method-0.0', 'tcp.flags.ack', 'http.request.version-HTTP/1.0', 'tcp.connection.rst', 
        'mqtt.proto_len', 'mqtt.ver', 'http.referer-0.0', 'arp.opcode', 'mqtt.conflags', 'http.referer-127.0.0.1', 
        'http.request.method-TRACE', 'tcp.connection.fin', 'http.request.method-POST', 'mqtt.protoname-MQTT', 
        'mqtt.conflag.cleansess', 'mqtt.conack.flags-0x00000000', 'mqtt.topic-Temperature_and_Humidity', 
        'tcp.connection.synack', 'dns.retransmission', 'http.referer-() { _; } >_[$($())] { echo 93e4r0-CVE-2014-6278: true; echo;echo; }', 
        'mbtcp.trans_id', 'mbtcp.len', 'http.request.method-OPTIONS', 'http.request.method-PROPFIND', 
        'http.request.version-Src=javascript:alert(\'Vulnerable\')><Img Src=\\" HTTP/1.1', 'http.request.version--a HTTP/1.1', 
        'dns.qry.name.len-0.debian.pool.ntp.org', 'dns.qry.name.len-3.debian.pool.ntp.org', 'dns.qry.name.len-2.debian.pool.ntp.org', 
        'dns.qry.name.len-1.debian.pool.ntp.org', 'http.request.version-script>alert(1)/script><\\" HTTP/1.1', 
        'http.request.version--al&ABSOLUTE_PATH_STUDIP=http://cirt.net/rfiinc.txt?? HTTP/1.1', 'http.referer-TESTING_PURPOSES_ONLY', 
        'http.request.version--al&_PHPLIB[libdir]=http://cirt.net/rfiinc.txt?? HTTP/1.1', 'http.request.method-PUT', 'http.request.version-> HTTP/1.1', 
        'http.request.method-SEARCH', 'http.request.version-/etc/passwd|?data=Download HTTP/1.1', 
        "http.request.version-name=a><input name=i value=XSS>&lt;script>alert('Vulnerable')</script> HTTP/1.1", 
        'mbtcp.unit_id', 'http.request.version-By Dr HTTP/1.1', 'dns.retransmit_request', 'dns.retransmit_request_in', 
        'dns.qry.name.len-raspberrypi.local', 'mqtt.conack.flags-1574358', 'mqtt.conack.flags-1574359', 
        'dns.qry.name.len-null-null.local', 'dns.qry.name.len-_googlecast._tcp.local', 'mqtt.conack.flags-1461383', 
        'mqtt.conack.flags-1461384', 'mqtt.conack.flags-1461589', 'mqtt.conack.flags-1461591', 
        'mqtt.conack.flags-1461073', 'mqtt.conack.flags-1471198', 'mqtt.conack.flags-1471199', 'mqtt.conack.flags-1461074', 
        'icmp.unused'
    ]

    data = data.copy()

    colunas_presentes = [coluna for coluna in colunas_necessarias if coluna in data.columns]
    colunas_ausentes = set(colunas_necessarias) - set(colunas_presentes)
    for coluna in colunas_ausentes:
        data.loc[:, coluna] = 0
    colunas_excedentes = set(data.columns) - set(colunas_necessarias)
    data = data.drop(columns=colunas_excedentes)
    
    for col in data.columns:
        data[col] = pd.to_numeric(data[col], errors='coerce').fillna(0)
        
    def hex_to_dec(value):
        try:
            return int(value, 16)
        except ValueError:
            return np.nan

    hex_columns = []
    for col in data.columns:
        if data[col].apply(lambda x: isinstance(x, str) and x.startswith('0x')).any():
            hex_columns.append(col)
    for col in hex_columns:
        data[col] = data[col].apply(hex_to_dec)
        
    data = data.reindex(columns=colunas_necessarias)
    #dados_de_entrada = scaler.transform(data).astype(np.float32)
    dados_de_entrada = scaler.transform(data).astype(np.float32).reshape(-1, 93, 1)
    infer_request = compiled_model.create_infer_request()
    warnings.filterwarnings("ignore", category=DeprecationWarning)


    label_mapping = { 
        0: 'Normal', 
        1: 'MITM', 
        2: 'Uploading', 
        3: 'Ransomware', 
        4: 'SQL_injection', 
        5: 'DDoS_HTTP', 
        6: 'DDoS_TCP', 
        7: 'Password', 
        8: 'Port_Scanning', 
        9: 'Vulnerability_scanner', 
        10: 'Backdoor', 
        11: 'XSS', 
        12: 'Fingerprinting', 
        13: 'DDoS_UDP', 
        14: 'DDoS_ICMP' 
    }
    
    index = data.index[0]
    row = data.iloc[0]
    start_time_total = time.time()
    entry_identifier = index
    print(f"Processando entrada: {entry_identifier}")
    entrada_processada = np.expand_dims(dados_de_entrada[0], axis=0)
    
    infer_request.infer(inputs=entrada_processada)
    output = infer_request.get_output_tensor().data
    end_time_total = time.time()
    result_df = pd.DataFrame(output)

    predicted_label = result_df.idxmax(axis=1).iloc[0]
    if predicted_label == 0:
        result = 'Normal'
    else:
        result = 'Ataque'
        ultima_info = pacotes_originais[-1]

        if ultima_info["protocolo"] == "TCP": 
            add_drop_rule( table_id=49309361, src_ip=ultima_info["src_ip"], dst_ip=ultima_info["dst_ip"], src_port=ultima_info["src_port"], dst_port=ultima_info["dst_port"] )
        elif ultima_info["protocolo"] == "UDP":
            add_drop_rule( table_id=42654069, src_ip=ultima_info["src_ip"], dst_ip=ultima_info["dst_ip"], src_port=ultima_info["src_port"], dst_port=ultima_info["dst_port"] )
        else: 
            add_drop_rule( table_id=44005277, src_ip=ultima_info["src_ip"], dst_ip=ultima_info["dst_ip"] )

        ataques_detectados.append(ultima_info)

    total_time = end_time_total - start_time_total
    print(f"Resultado para a entrada {entry_identifier}: {result}")
    print(f"Tempo total de processamento para a entrada {entry_identifier}: {total_time:.6f} segundos")
    
# print(ataques_detectados)


'''def add_drop_rule():
    request = p4runtime_pb2.WriteRequest()
    request.device_id = 1

    update = request.updates.add()
    update.type = p4runtime_pb2.Update.INSERT
    table_entry = update.entity.table_entry
    table_entry.table_id = 44005277 

    match_src = table_entry.match.add()
    match_src.field_id = 1 
    match_src.exact.value = b'\x0A\x00\x00\x01'  

    match_dst = table_entry.match.add()
    match_dst.field_id = 2  
    match_dst.exact.value = b'\x0A\x00\x00\x02' 

    action = table_entry.action.action
    action.action_id = 25652968 

    try:
        stub.Write(request)
        print("Regra de drop inserida com sucesso.")
    except grpc.RpcError as e:
        print(f"Erro ao inserir a regra de drop: {e.details()} (Code: {e.code()})")
'''

def add_drop_rule(table_id, src_ip, dst_ip, src_port=None, dst_port=None):
    request = p4runtime_pb2.WriteRequest()
    request.device_id = 1

    update = request.updates.add()
    update.type = p4runtime_pb2.Update.INSERT
    table_entry = update.entity.table_entry
    table_entry.table_id = table_id

    match_src = table_entry.match.add()
    match_src.field_id = 1  
    match_src.exact.value = bytes(map(int, src_ip.split('.')))

    match_dst = table_entry.match.add()
    match_dst.field_id = 2  
    match_dst.exact.value = bytes(map(int, dst_ip.split('.')))

    if src_port is not None and dst_port is not None:
        match_src_port = table_entry.match.add()
        match_src_port.field_id = 3  
        match_src_port.exact.value = src_port.to_bytes(2, byteorder='big')

        match_dst_port = table_entry.match.add()
        match_dst_port.field_id = 4  
        match_dst_port.exact.value = dst_port.to_bytes(2, byteorder='big')

    action = table_entry.action.action
    action.action_id = 25652968 

    try:
        stub.Write(request)
        
        
        #print(f"Regra de drop inserida com sucesso na tabela {table_id}.")
    except grpc.RpcError as e:
        print(f"Erro ao inserir a regra de drop: {e.details()} (Code: {e.code()})")
    


def insert_digest(stub, digest_id):
    req = p4runtime_pb2.WriteRequest()
    req.device_id = device_id
    req.election_id.high = 0
    req.election_id.low = 1
    req.role_id = 0
    update = req.updates.add()
    update.type = p4runtime_pb2.Update.INSERT
    digest_entry = update.entity.digest_entry
    digest_entry.digest_id = digest_id
    digest_entry.config.max_timeout_ns = 0
    digest_entry.config.max_list_size = 50
    digest_entry.config.ack_timeout_ns = 100000
    response = stub.Write(req)

def set_fwd_pipe_config(stub, p4info_path, bin_path):
    req = p4runtime_pb2.SetForwardingPipelineConfigRequest()
    req.device_id = device_id
    election_id = req.election_id
    election_id.high = 0
    election_id.low = 1
    req.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
    with open(p4info_path, 'r') as f1:
        with open(bin_path, 'rb') as f2:
            try:
                google.protobuf.text_format.Merge(f1.read(), req.config.p4info)
            except google.protobuf.text_format.ParseError:
                logging.error("Erro ao analisar P4Info")
                raise
            req.config.p4_device_config = f2.read()
    return stub.SetForwardingPipelineConfig(req)

fluxos = {}
def client_main(stub):
    set_fwd_pipe_config(stub, P4INFO, P4BIN)
    logging.info('Pipeline configurado com sucesso')
    logging.info('Inserindo digests...')
    insert_digest(stub, digest1_id)
    insert_digest(stub, digest2_id)
    insert_digest(stub, digest3_id)
    insert_digest(stub, digest4_id)
    insert_digest(stub, digest5_id)
    insert_digest(stub, digest6_id)
    insert_digest(stub, digest_id_mqttCO)
    insert_digest(stub, digest7_id)
    insert_digest(stub, digest8_id)
    logging.info('Digests inseridos com sucesso')


with grpc.insecure_channel('localhost:50051') as channel:
    stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)
    recv_t   = stream(stub)
    # # Regra ICMP
    # add_drop_rule( table_id=44005277, src_ip="10.0.0.1", dst_ip="10.0.0.2")

    # # Regra para UDP
    # add_drop_rule(table_id=42654069, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=5678)

    # # Regra para TCP
    # add_drop_rule(table_id=49309361, src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=5678)
    try:
        client_main(stub)
        
        while True:
            cmd = input('> ')
            if cmd.lower() in ('exit', 'quit'):
                break
    except (KeyboardInterrupt, EOFError):
        pass
    except Exception as e:
        logging.error(traceback.format_exc())
    send_queue.put(None)
    recv_t.join()

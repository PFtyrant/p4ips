from netaddr import EUI, IPAddress

p4 = bfrt.P4Zeek.pipe
cpu_mirror = 5
port3_mirror = 7
port5_trunc  = 9

def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
    
    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members

    for table_types in (['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR'],
                        ['SELECTOR'],
                        ['ACTION_PROFILE']):
        for table in p4.info(return_info=True, print_info=False):
            if table['type'] in table_types:
                if verbose:
                    print("Clearing table {:<40} ... ".format(table['full_name']), end='', flush=True)
                table['node'].clear(batch=batching)
                if verbose:
                    print('Done')
                    
clear_all(verbose=True)

# ing_port_acl = p4.Ingress.port_acl
# ing_port_acl.entry_with_acl_mirror(flag=0, mirror_session = cpu_mirror).push()
# ing_port_acl.entry_with_acl_mirror(ingress_port=56, mirror_session = cpu_mirror).push()
# ing_port_acl.entry_with_acl_mirror(ingress_port=57, mirror_session = cpu_mirror).push()
# ing_port_acl.entry_with_acl_mirror(ingress_port=58, mirror_session = cpu_mirror).push()
# ing_port_acl.entry_with_acl_mirror(ingress_port=59, mirror_session = cpu_mirror).push()

# print("entry_with_acl_mirror is set already")

L3_forward = p4.Ingress.L3_forward
L3_forward.entry_with_forward(dst_addr=IPAddress('10.0.1.1'),   port=56).push()  # C++ part is useless!!!!
L3_forward.entry_with_forward(dst_addr=IPAddress('10.0.1.2'),   port=57).push()
L3_forward.entry_with_forward(dst_addr=IPAddress('10.0.1.3'),   port=58).push()
L3_forward.entry_with_forward(dst_addr=IPAddress('10.0.1.4'),   port=59).push()

Payload_check = p4.Ingress.Payload_check
# Payload_check.entry_with_set_forward(total_len=40, ihl=5, data_offset=5, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=44, ihl=5, data_offset=6, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=48, ihl=5, data_offset=7, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=52, ihl=5, data_offset=8, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=56, ihl=5, data_offset=9, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=60, ihl=5, data_offset=10, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=64, ihl=5, data_offset=11, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=68, ihl=5, data_offset=12, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=72, ihl=5, data_offset=13, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=76, ihl=5, data_offset=14, yes=1).push()
# Payload_check.entry_with_set_forward(total_len=80, ihl=5, data_offset=15, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=40, ihl=5, data_offset=5, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=44, ihl=5, data_offset=6, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=48, ihl=5, data_offset=7, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=52, ihl=5, data_offset=8, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=56, ihl=5, data_offset=9, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=60, ihl=5, data_offset=10, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=64, ihl=5, data_offset=11, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=68, ihl=5, data_offset=12, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=72, ihl=5, data_offset=13, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=76, ihl=5, data_offset=14, yes=1).push()
Payload_check.entry_with_set_forward_2(total_len=80, ihl=5, data_offset=15, yes=1).push()
# Payload_check = p4.Ingress.Payload_check
# Payload_check.entry_with_ppush(total_len=40, ihl=5, data_offset=5, push=1).push()
# Payload_check.entry_with_ppush(total_len=44, ihl=5, data_offset=6, push=1).push()
# Payload_check.entry_with_ppush(total_len=48, ihl=5, data_offset=7, push=1).push()
# Payload_check.entry_with_ppush(total_len=52, ihl=5, data_offset=8, push=1).push()
# Payload_check.entry_with_ppush(total_len=56, ihl=5, data_offset=9, push=1).push()
# Payload_check.entry_with_ppush(total_len=60, ihl=5, data_offset=10, push=1).push()
# Payload_check.entry_with_ppush(total_len=64, ihl=5, data_offset=11, push=1).push()
# Payload_check.entry_with_ppush(total_len=68, ihl=5, data_offset=12, push=1).push()
# Payload_check.entry_with_ppush(total_len=72, ihl=5, data_offset=13, push=1).push()
# Payload_check.entry_with_ppush(total_len=76, ihl=5, data_offset=14, push=1).push()
# Payload_check.entry_with_ppush(total_len=80, ihl=5, data_offset=15, push=1).push()
# for i in range(5, 16):
#     for j in range(5, 16):
#         Payload_check.entry_with_ppush(total_len=(i+j)*4, ihl=i, data_offset=j, push=1).push()

# LoopbackorDigest = p4.Ingress.LoopbackorDigest
# LoopbackorDigest.entry_with_set_digest1(ingress_port=56, yes=1).push()
# LoopbackorDigest.entry_with_set_digest1(ingress_port=57, yes=1).push()
# LoopbackorDigest.entry_with_set_digest1(ingress_port=58, yes=1).push()
# LoopbackorDigest.entry_with_set_digest1(ingress_port=59, yes=1).push()
# LoopbackorDigest.entry_with_set_digest2(ingress_port=60, yes=2).push()
# LoopbackorDigest.entry_with_loopback_(ingress_port=61, yes=3).push()
# LoopbackorDigest.entry_with_loopback_(ingress_port=62, yes=3).push()
# LoopbackorDigest.entry_with_loopback_(ingress_port=63, yes=3).push()


# Check_exec = p4.Ingress.Check_exec
# Check_exec.entry_with_check_seqence(if_push=0, protocol=6).push()

# add_seq_alu = p4.Ingress.add_seq_alu
# add_seq_alu.operation_register_sync()

# _sequence_received = p4.Ingress.add_seq_alu
# _sequence_received.operation_register_sync()


mirror_cfg = bfrt.mirror.cfg
mirror_cfg.entry_with_normal(
    sid=5, direction='BOTH', session_enable=True,
    ucast_egress_port=64, ucast_egress_port_valid=1, max_pkt_len=120).push()  # 2^14 = 16384  --> bytes not bits (start from header)
    # ucast_egress_port=192, ucast_egress_port_valid=1, max_pkt_len=120).push()  # 2^14 = 16384  --> bytes not bits (start from header)

# mirror_cfg.entry_with_normal(
#     sid=7, direction='BOTH', session_enable=True,
#     ucast_egress_port=3, ucast_egress_port_valid=1, max_pkt_len=16384).push()

# mirror_cfg.entry_with_normal(
#     sid=9, direction='BOTH', session_enable=True,
#     ucast_egress_port=5, ucast_egress_port_valid=1, max_pkt_len=100).push()

bfrt.complete_operations()
# for t in ["ing_port_acl", "L3_forward", "Payload_check", "mirror_cfg"]:
for t in ["L3_forward", "Payload_check", "mirror_cfg"]:
# for t in ["LoopbackorDigest", "L3_forward", "Payload_check"]:
# for t in ["L3_forward", "Payload_check"]:
    print ("\nTable {}:".format(t))
    exec("{}.dump(table=True)".format(t))

# def run_pd_rpc(cmd_or_code, no_print=False):
#     import subprocess
#     path = os.path.join(os.environ['HOME'], "/root/P4Zeek/run_pd_rpc", "run_pd_rpc.py")
#     command = [path]
#     if isinstance(cmd_or_code, str):
#         if cmd_or_code.startswith(os.sep):
#             command.extend(["--no-wait", cmd_or_code])
#         else:
#             command.extend(["--no-wait", "--eval", cmd_or_code])
#     else:
#         command.extend(cmd_or_code)
#     result = subprocess.check_output(command).decode("utf-8")[:-1]
#     if not no_print:
#         print(result)        
#     return result
# run_pd_rpc(os.path.join(os.environ['HOME'],"/root/P4Zeek/run_pd_rpc/setup.py"))

print("END")
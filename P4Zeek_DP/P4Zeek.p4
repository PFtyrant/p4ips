/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

typedef bit<9> PortID_t;
// typedef bit<8> ind_t;
typedef bit<32> data_t;
typedef bit<1> bit_t;
typedef bit<17> ind_t;
// #define NUMBER  1024 // 65535
#define NUMBER  131072 // 65536 131072 max 262144
#define RE_PORT 196
/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/

const bit<16> ETHERTYPE_IPV4   = 0x0800;
const bit<16> ETHERTYPE_RECORD = 0xBF03;
/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*
 * This is a common "preamble" header that must be present in all internal
 * headers. The only time you do not need it is when you know that you are
 * not going to have more than one internal header type ever
 */
#define PADDING @padding

/* Standard ethernet header */
header ethernet_h { // total = 112 bits / 14 bytes
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header record_h {
    bit<48>   in_time;
}

header ipv4_h {  // total = 160 bits / 20 bytes
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header tcp_h { // minimum size of 160 bits / 20 bytes 
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<1> cwr;
    bit<1> ecn;
    bit<1> urg;
    bit<1> ack;
    bit<1> push;
    bit<1> reset;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h { // 64 bits / 8 bytes 
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

/* Ingress mirroring information */
#if __TARGET_TOFINO__ == 1
const bit<3> ING_PORT_MIRROR = 0;  /* Choose between different mirror types */
const bit<3> EGR_PORT_MIRROR = 0;
#elif __TARGET_TOFINO__ == 2
const bit<4> ING_PORT_MIRROR = 0;  /* Choose between different mirror types */
const bit<4> EGR_PORT_MIRROR = 0;
#endif

header ing_port_mirror_h { // 16 bytes + 12 + 4
    bit<32>  ip_src_addr;  // 4 byte
    bit<32>  ip_dst_addr;  // 4 byte
    bit<16>  src_port;  // 2 byte
    bit<16>  dst_port;  // 2 byte
    bit<8>   protocol;  // 1 byte
    @padding bit<4> pad0;    bit<4>   ihl;  // 1 byte
    @padding bit<4> pad1;    bit<4>   data_offset;  // 1 byte
    bit<48> in_time;  // 6 bytes
    bit<8>   times;  // 1 byte
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {  // 
    ethernet_h         ethernet;
    record_h           record;
    ipv4_h             ipv4;
    tcp_h tcp;
    udp_h udp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    MirrorId_t mirror_session;
    bit<2> do_action;
    bit<1> next_table;
    bit<1> first_in;
    bit<1> first_out;
    bit<1> set_rule;
    
    bit<16> src_port;
    bit<16> dst_port;
    ind_t hash_value;
    ind_t hash_value2;
    ind_t hash_value3;
    ind_t hash_value4;
    bit<48> in_time;
    bit<4> data_offset;
    bit<8> times;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{

    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);  // what is it? it can't be removed or error!!!
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_RECORD : parse_record;
            ETHERTYPE_IPV4 : parse_ipv4;
        }
    }

    state parse_record {
        pkt.extract(hdr.record);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6  : parse_tcp;  // use default protocol number
            17  : parse_udp;
            default : accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;        
    }    
}

    /***************** M A T C H - A C T I O N  *********************/

control cal_ipv4_hash(in my_ingress_headers_t hdr, in bit<16> src_port, in bit<16> dst_port, out ind_t hash_value)(bit<32> coeff)
{
    CRCPolynomial<bit<32>>(
        coeff, 
        true,
        false,
        false,
        0xFFFFFFFF,
        0xFFFFFFFF) poly;

    Hash<ind_t>(HashAlgorithm_t.CUSTOM, poly) hash_algo;

    action do_hash(){
        hash_value = hash_algo.get({  // do hash 
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr,
            src_port,
            dst_port
        });
    }
    apply{
        do_hash();
    }
}

// control cal_ipv4_hash2(in my_ingress_headers_t hdr, in bit<16> src_port, in bit<16> dst_port, out ind_t hash_value)(bit<32> coeff)
// {
//     CRCPolynomial<bit<32>>(
//         coeff, 
//         false,
//         false,
//         false,
//         0x00000000,
//         0x00000000) poly;

//     Hash<ind_t>(HashAlgorithm_t.CUSTOM, poly) hash_algo2;

//     action do_hash(){
//         hash_value = hash_algo2.get({  // do hash 
//             hdr.ipv4.protocol,
//             hdr.ipv4.src_addr,
//             hdr.ipv4.dst_addr,
//             src_port,
//             dst_port
//         });
//     }
//     apply{
//         do_hash();
//     }
// }

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
    // Hash<ind_t>(HashAlgorithm_t.CRC32) hash;
    cal_ipv4_hash(coeff=0x04C11DB7) hash;  // CRC32
    cal_ipv4_hash(coeff=0x1EDC6F41) hash2;  // CRC32c
    cal_ipv4_hash(coeff=0xA833982B) hash3;  // CRC32d
    // cal_ipv4_hash2(coeff=0x814141AB) hash4;  // CRC32q

    action take_TCP_port(){
        meta.src_port = hdr.tcp.src_port;
        meta.dst_port = hdr.tcp.dst_port;
        meta.data_offset = hdr.tcp.data_offset;
    }
    action take_UDP_port(){
        meta.src_port = hdr.udp.src_port;
        meta.dst_port = hdr.udp.dst_port;
        meta.data_offset = 2; // due to *4
    }

    action bypass(){
        meta.next_table = 0;
        meta.do_action = 1;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action set_recirculate(){
        ig_tm_md.ucast_egress_port = RE_PORT;
    }

    action add_header(){
        hdr.record.setValid();
        hdr.ethernet.ether_type = ETHERTYPE_RECORD;
        hdr.record.in_time = ig_prsr_md.global_tstamp; // not need
        ig_tm_md.ucast_egress_port = RE_PORT;
    }

    action remove_header(){
        hdr.record.setInvalid();
        hdr.ethernet.ether_type = ETHERTYPE_IPV4;
    }

    /********* MIRRORING ************/
    action mirror() {
        ig_dprsr_md.mirror_type = ING_PORT_MIRROR;
        meta.mirror_session = 5;
        meta.in_time = ig_prsr_md.global_tstamp;
    }

    // ---------------- For Malware_Detection
    action set_drop(bit<2> yes){ // 2
        meta.do_action = yes;
        meta.set_rule = 1; // need to add!!
    }

    action set_forward(bit<2> yes){ // 1
        meta.do_action = yes;
        meta.set_rule = 1;
    }

    action move_next(){
        meta.next_table = 1;
    }
    // ---------------- For Malware_Detection

    table malware_detection{
        key = {
            hdr.ipv4.src_addr : exact;
            hdr.ipv4.dst_addr : exact;
            meta.src_port    : exact;
            meta.dst_port    : exact;
            hdr.ipv4.protocol : exact;
        }
        actions = {
            set_drop;
            set_forward;
            move_next;
        }
        // size = 524288;  // 這邊應該是會有很多的entry，所以他開了一個很大的size
        size = 100000;  // 這邊應該是會有很多的entry，所以他開了一個很大的size table和register是共享同一個SRAM，所以不能開太大
        const default_action = move_next;  // table miss，代表初次進入，將digest設成1，代表第一次做digest
    }

    action forward(PortID_t port){
        ig_tm_md.ucast_egress_port = port;
    }

    table L3_forward{  
        key = {
            hdr.ipv4.dst_addr : exact;
        }
        actions = {
            forward;
        }
    }
    
    action unknown(){ // 0
        meta.do_action = 0;
    }

    action set_forward_2(bit<2> yes){ // 1
        meta.do_action = yes;
    }

    table Payload_check{
        key = {
            hdr.ipv4.total_len : exact;
            hdr.ipv4.ihl : exact;
            hdr.tcp.data_offset : exact;
        }
        actions = {
            set_forward_2;
            unknown;
        }

        const default_action = unknown;
    }

    // action hash_5_tuple(){
    //     meta.hash_value = hash.get({  // do hash 
    //         hdr.ipv4.protocol,
    //         hdr.ipv4.src_addr,
    //         hdr.ipv4.dst_addr,
    //         meta.src_port,
    //         meta.dst_port
    //     });
    // }

    Register<data_t, ind_t>(NUMBER, 0) check_reg;  // bit<16> for index and bit<32> for data
    RegisterAction<data_t, ind_t, bit_t>(check_reg)
    check_action = {
        void apply(inout data_t register_data, out bit_t result){
            if (register_data == 0){
                result = 0;
                register_data = 1;
            }
            else {
                result = 1;
            }
        }
    }; 

    // action check_first_in(){
    //     meta.first_in = check_action.execute(meta.hash_value);
    // }

    RegisterAction<data_t, ind_t, bit_t>(check_reg)
    check_out_first = {
        void apply(inout data_t register_data, out bit_t result){
            if (register_data == 2){
                // result = 2;
                result = 0;
            }
            else if (register_data == 1){
                result = 1;
                register_data = 2;
            }
        }
    };

    // action sendTS(){
    //     meta.first_out = check_out_first.execute(meta.hash_value);
    // }

    Register<data_t, ind_t>(NUMBER, 0) check_reg2;  // bit<16> for index and bit<32> for data
    RegisterAction<data_t, ind_t, bit_t>(check_reg2)
    check_action2 = {
        void apply(inout data_t register_data, out bit_t result){
            if (register_data == 0){
                result = 0;
                register_data = 1;
            }
            else {
                result = 1;
            }
        }
    }; 

    RegisterAction<data_t, ind_t, bit_t>(check_reg2)
    check_out_first2 = {
        void apply(inout data_t register_data, out bit_t result){
            if (register_data == 2){
                // result = 2;
                result = 0;
            }
            else if (register_data == 1){
                result = 1;
                register_data = 2;
            }
        }
    };

    Register<data_t, ind_t>(NUMBER, 0) check_reg3;  // bit<16> for index and bit<32> for data
    RegisterAction<data_t, ind_t, bit_t>(check_reg3)
    check_action3 = {
        void apply(inout data_t register_data, out bit_t result){
            if (register_data == 0){
                result = 0;
                register_data = 1;
            }
            else {
                result = 1;
            }
        }
    }; 

    RegisterAction<data_t, ind_t, bit_t>(check_reg3)
    check_out_first3 = {
        void apply(inout data_t register_data, out bit_t result){
            if (register_data == 2){
                // result = 2;
                result = 0;
            }
            else if (register_data == 1){
                result = 1;
                register_data = 2;
            }
        }
    };

    // Register<bit<32>, ind_t>(NUMBER, 0) check_reg4;  // bit<16> for index and bit<32> for data
    // RegisterAction<bit<32>, ind_t, bit<1>>(check_reg4)
    // check_action4 = {
    //     void apply(inout bit<32> register_data, out bit<1> result){
    //         if (register_data == 0){
    //             register_data = 1;
    //             result = 1;
    //         }
    //         else{
    //             result = 0;
    //         }
    //     }
    // }; 

    // RegisterAction<bit<32>, ind_t, bit<1>>(check_reg4)
    // check_out_first4 = {
    //     void apply(inout bit<32> register_data, out bit<1> result){
    //         if (register_data == 1){
    //             register_data = 2;
    //             result = 1;
    //         }
    //         else{
    //             result = 0;
    //         }
    //     }
    // };

    apply {
        bit_t first_in1 = 0;
        bit_t first_in2 = 0;
        bit_t first_in3 = 0;
        // bit<1> first_in4 = 0;
        bit_t first_out1 = 0;
        bit_t first_out2 = 0;
        bit_t first_out3 = 0;
        // bit<1> first_out4 = 0;
        if(hdr.record.isValid()){
            remove_header();
            mirror();
            meta.times = 2;
            bypass();
        }

        if(hdr.ipv4.protocol == 17){  // for UDP
            take_UDP_port(); // 紀錄ip和port到metadata
        }
        else if(hdr.ipv4.protocol == 6){      // for TCP
            take_TCP_port(); // 紀錄ip和port到metadata
        }
        else{
            bypass();
        }

        if(hdr.ipv4.protocol == 17 || hdr.ipv4.protocol == 6){
            malware_detection.apply();
        }

        if(meta.next_table == 1){
            Payload_check.apply();
        }

        if(meta.do_action > 0){
            if(meta.do_action == 1){
                L3_forward.apply();
                // if(meta.set_rule == 1){
                //     // hash_5_tuple();
                //     // sendTS();
                //     hash.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value);
                //     hash2.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value2);
                //     hash3.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value3);
                //     // hash4.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value4);
                //     first_out1 = check_out_first.execute(meta.hash_value);
                //     first_out2 = check_out_first2.execute(meta.hash_value2);
                //     first_out3 = check_out_first3.execute(meta.hash_value3);
                //     // first_out4 = check_out_first4.execute(meta.hash_value4);

                //     if (first_out1 == 0 && first_out2 == 0){
                //         if (first_out3 == 0){
                //         // if (first_out3 == 1 && first_out4 == 1){
                //             meta.first_out = 0;
                //         }
                //         else{
                //             meta.first_out = 1;
                //         }
                //     }
                //     else{
                //         meta.first_out = 1;
                //     }
                // }
                // if(meta.first_out == 1){
                //     add_header();
                // }
            }
            else if(meta.do_action == 2){
                drop();
            }
            if(meta.set_rule == 1){
                // hash_5_tuple();
                // sendTS();
                hash.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value);
                hash2.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value2);
                hash3.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value3);
                // hash4.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value4);
                first_out1 = check_out_first.execute(meta.hash_value);
                first_out2 = check_out_first2.execute(meta.hash_value2);
                first_out3 = check_out_first3.execute(meta.hash_value3);
                // first_out4 = check_out_first4.execute(meta.hash_value4);

                if (first_out1 == 0 && first_out2 == 0){
                    if (first_out3 == 0){
                    // if (first_out3 == 1 && first_out4 == 1){
                        meta.first_out = 0;
                    }
                    else{
                        meta.first_out = 1;
                    }
                }
                else{
                    meta.first_out = 1;
                }
            }
            if(meta.first_out == 1){
                add_header();
                ig_dprsr_md.drop_ctl = 0;
            }
        }
        // else if(meta.do_action == 2){
        //     drop();
        // }
        else{
            // hash_5_tuple();
            // check_first_in();
            hash.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value);
            hash2.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value2);
            hash3.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value3);
            // hash4.apply(hdr, meta.src_port, meta.dst_port, meta.hash_value4);
            first_in1 = check_action.execute(meta.hash_value);
            first_in2 = check_action2.execute(meta.hash_value2);
            first_in3 = check_action3.execute(meta.hash_value3);
            // first_in4 = check_action4.execute(meta.hash_value4);
            
            if (first_in1 != 0 && first_in2 != 0){
                if (first_in3 != 0){
                // if (first_in3 == 1 && first_in4 == 1){
                    meta.first_in = 0;
                }
                else{
                    meta.first_in = 1;
                }
            }
            else{
                meta.first_in = 1;
            }

            if(meta.first_in == 1){
                mirror();
                meta.times = 1;
                ig_tm_md.ucast_egress_port = RE_PORT;
            }
            else{
                set_recirculate();
            }
        }
        ig_tm_md.bypass_egress = 1;   
    }
}

   /*********************  D E P A R S E R  ************************/

#ifdef FLEXIBLE_HEADERS
#define PAD(field)  field
#else
#define PAD(field)  0, field
#endif

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Mirror()   ing_port_mirror;

    apply {
        /*
         * If there is a mirror request, create a clone.
         * Note: Mirror() externs emits the provided header, but also
         * appends the ORIGINAL ingress packet after those
         */

        if (ig_dprsr_md.mirror_type == ING_PORT_MIRROR) {
            ing_port_mirror.emit<ing_port_mirror_h>(
                meta.mirror_session,
                {                   
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    meta.src_port,
                    meta.dst_port,
                    hdr.ipv4.protocol,
                    PAD(hdr.ipv4.ihl),
                    PAD(meta.data_offset),
                    meta.in_time,
                    meta.times
                });
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {

}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {

}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/
control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{   
    apply {

    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md,
    in    egress_intrinsic_metadata_t               eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t   eg_prsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;

#include <bf_rt/bf_rt_info.hpp>
#include <bf_rt/bf_rt_init.hpp>
#include <bf_rt/bf_rt_common.h>
#include <bf_rt/bf_rt_table_key.hpp>
#include <bf_rt/bf_rt_table_data.hpp>
#include <bf_rt/bf_rt_table.hpp>
#include <bf_rt/bf_rt_learn.hpp>
#include <bf_rt_mirror/bf_rt_mirror_table_impl.hpp> // new add
#include <bf_rt_mirror/bf_rt_mirror_table_data_impl.hpp> // new add
#include <bf_rt_mirror/bf_rt_mirror_table_key_impl.hpp> // new add
#include <getopt.h>
#include <lld/bf_ts_if.h>
#include <map>
#include <fstream>
#include <math.h>
#include <algorithm>
#include <queue>
#include <vector>
#include <sys/time.h>
#include <cstdlib>
#include <iostream>  // this line added by me  
#include <time.h> // new add
#include <thread> // new add
#include <mutex> // new add

#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include "threadpool.hpp"
// #include "get_cpu.hpp"
#include <sstream>
#include <sys/wait.h>
#include <signal.h>
// #include <chrono>

#ifdef __cplusplus
extern "C" {
#endif
#include <bf_switchd/bf_switchd.h>

#ifdef __cplusplus
}
#endif
typedef std::uint8_t byte;
#define PayloadArray byte[40]
#define input_size 40
#define layer1_nodes 128
#define layer2_nodes 128
#define output_size 2
#define thread_number 4
char* nflow;

// std::vector<CPUData> entries1;
// std::vector<CPUData> entries2; 
// pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
std::mutex mu; 
std::mutex mu2; 
std::mutex mu3; 
ThreadPool tp(thread_number);
double ave_parse_time = 0.0;
double ave_add_entry_time = 0.0;
double ave_NN_time = 0.0;
double ave_mod_entry_time = 0.0;
// double ave_prediction_time = 0.0;

double max_parse_time = 0.0;
double max_add_entry_time = 0.0;
double max_NN_time = 0.0;
double max_mod_entry_time = 0.0;
// double max_prediction_time = 0.0;

double ave_response_time = 0.0;
double max_response_time = 0.0;
double max_pin1_response_time = 0.0;
double max_pin2_response_time = 0.0;
double max_pin3_response_time = 0.0;

double ave_mir_ts = 0.0;
double max_mir_ts = 0.0;
double ave_control_res = 0.0;
double max_control_res = 0.0;
double ave_total_res = 0.0;
double max_total_res = 0.0;
double ave_port_to_cpu = 0.0;
double max_port_to_cpu = 0.0;
double ave_ingree_to_control = 0.0;
double max_ingree_to_control = 0.0;


// uint64_t start_p4, end_p4;
// uint64_t NN_bare_start = 0;
// uint64_t NN_bare_end = 0;
int sendp = 0;
static int ii = 0;
static bool fisrtIn = true;
//**********************

static struct timespec res_start, res_end, res_diff;
struct timespec pa_start, pa_end, wait_start, wait_end, NN_start, NN_end, Mod_start, Mod_end, diff_tt, pin1_tt, pin2_tt, pin3_tt;

class malware_detection_Key {  // 用struct做key group
public:
  uint64_t srcIP;
  uint64_t dstIP;
  // char* srcIP;
  // char* dstIP;
  uint64_t srcport;
  uint64_t dstport;
  uint64_t protocol;
  bool operator< (const malware_detection_Key &k1) const{
    return (((k1.srcIP<this->srcIP) || ((k1.srcIP==this->srcIP)&&(k1.dstIP < this->dstIP)) || ((k1.srcIP==this->srcIP)&&(k1.dstIP == this->dstIP)&&(k1.srcport < this->srcport)) ||
     ((k1.srcIP==this->srcIP)&&(k1.dstIP == this->dstIP)&&(k1.srcport == this->srcport)&&(k1.dstport < this->dstport)) || ((k1.srcIP==this->srcIP)&&(k1.dstIP == this->dstIP)&&(k1.srcport == this->srcport)&&(k1.dstport == this->dstport)&&(k1.protocol < this->protocol))));
  }
};


struct CmpFunc{
  bool operator() (const struct malware_detection_Key k1, const struct malware_detection_Key k2)const{
    // return (((k1.srcIP!=k2.srcIP) || (k1.dstIP != k2.dstIP) || (k1.srcport != k2.srcport) || (k1.dstport != k2.dstport) || (k1.protocol != k2.protocol)));
    return (!((k1.srcIP==k2.srcIP) && (k1.dstIP == k2.dstIP) && (k1.srcport == k2.srcport) && (k1.dstport == k2.dstport) && (k1.protocol == k2.protocol)));
  }
};

struct datas{
  uint64_t ingree_to_control;
  uint64_t NN_time;
  uint64_t control;
  uint64_t total_time;
  uint64_t ingress_ts;
  uint64_t control_start_ts;
  uint64_t control_end_ts;
  malware_detection_Key f_tuple;
  int label;
};

std::vector<datas> filevec;

struct cpu_data{
  double uptime;
  uint64_t utime;
  uint64_t stime;
  uint64_t cutime;
  uint64_t cstime;
  uint64_t starttime;
  timespec ts;
};

cpu_data start_get;
cpu_data end_get;
// uint64_t start_p4, end_p4;

// static struct timeval start, end, diff, p_start, p_end, p_diff;
// static struct timespec start_tt, end_tt, diff_tt;
// static bool notexited;

static int valid_packetCount = 0;
static int to_CPU_port_Count = 0;
// static uint64_t d_time = 0;
#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14  // bytes
#define SIZE_UDP 8
#define SIZE_MIRROR 31  // 15+8
// five tuple
class sniff_fivetuple{  // total 16 bytes + 12 + 4
    // uint8_t pad;  // 1 bytes
public:
    uint32_t src_addr;  // 4 bytes          
    uint32_t dst_addr;  // 4 bytes   
    uint16_t src_port;  // 2 bytes 
    uint16_t dst_port;  // 2 bytes 
    uint8_t protocol;  // 1 bytes 
    uint8_t l3len;  // 1 bytes 
    uint8_t l4len;  // 1 bytes 
    uint8_t in_time1;
    uint8_t in_time2;
    uint8_t in_time3;
    uint8_t in_time4;
    uint8_t in_time5;
    uint8_t in_time6;
    uint8_t times;
    // uint8_t eg_time1;
    // uint8_t eg_time2;
    // uint8_t eg_time3;
    // uint8_t eg_time4;
    // uint8_t eg_time5;
    // uint8_t eg_time6;
    // uint16_t in_time_16;
    // uint32_t in_time_32;
    // uint16_t eg_time_16;
    // uint32_t eg_time_32;
    // uint32_t seqnum;
    // uint8_t seqnum1;
    // uint8_t seqnum2;
    // uint8_t seqnum3;
    // uint8_t seqnum4;
    // uint64_t ingress_mac_tstamp;
    

    bool operator< (const sniff_fivetuple &k1) const{
    return (((k1.src_addr<this->src_addr) || ((k1.src_addr==this->src_addr)&&(k1.dst_addr < this->dst_addr)) || ((k1.src_addr==this->src_addr)&&(k1.dst_addr == this->dst_addr)&&(k1.src_port < this->src_port)) ||
     ((k1.src_addr==this->src_addr)&&(k1.dst_addr == this->dst_addr)&&(k1.src_port == this->src_port)&&(k1.dst_port < this->dst_port)) || ((k1.src_addr==this->src_addr)&&(k1.dst_addr == this->dst_addr)&&(k1.src_port == this->src_port)&&(k1.dst_port == this->dst_port)&&(k1.protocol < this->protocol))));
  }

};

struct metadata{ // 22 bytes
    uint64_t ingress_mac_tstamp;  // 8
    uint64_t egress_global_tstamp;  // 8
    uint16_t ingress_port;  // 2
    uint32_t deq_qdepth;  // 4
};

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
    #define IP_RF 0x8000		/* reserved fragment flag */
    #define IP_DF 0x4000		/* don't fragment flag */
    #define IP_MF 0x2000		/* more fragments flag */
    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src; /* source and dest address */
    struct in_addr ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct sniff_udp{
    uint16_t udp_sport;             /* source port */
    uint16_t udp_dport;             /* destination port */
    uint16_t udp_len;               /* source port */
    uint16_t udp_sum;               /* source port */
};

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */
    u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

const struct sniff_ethernet *ethernet; /* The ethernet header */
// const struct sniff_fivetuple *f_tuple; /* The ethernet header */
const struct metadata *mdata; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const struct sniff_udp *udp_hdr; /* The UDP header */
// const unsigned char *payload; /* Packet payload */ 
const uint8_t *payload; /* Packet payload */ 

u_int size_ip;
u_int size_tcp;
uint64_t i_ts;
// uint64_t max_response_time_p4 = 0;
// double ave_response_time_p4 = 0.0;
//**********************
// ------ mongodb --------
pid_t mongodb_pid;
int mongodb_fd[2]; // READ_END: 0, WRITE_END: 1

void childHandler(int signo) { 
    int status;
    std::cout << "wait child pid!!!\n";
    while (waitpid(-1, &status, WNOHANG) > 0) {  // 收屍目前掉剩下的小孩，如果fork失敗就會handler
    //do nothing
    } 
}

void mongodb_initial()
{  
  pipe(mongodb_fd); 
  // signal(SIGCHLD, childHandler);
  if ((mongodb_pid = fork()) < 0) {
    printf("fork error!!\n");
  }  
  else if(mongodb_pid == 0) {
    // sleep (20);
    close(mongodb_fd[1]);
    dup2(mongodb_fd[0], STDIN_FILENO);
    close(mongodb_fd[0]);
    char *param[] = {(char*)"python3", (char*)"send_mongodb.py", (char*)NULL};        
    execvp("python3", param);
  } 
  else {
    close(mongodb_fd[0]);   
  }
}

void send_msg_mongodb(std::string msg)
{
  msg += "\n";
  // std::cout << msg << std::endl;    
  write(mongodb_fd[1], msg.c_str(), msg.size() + 1);
}
// ------ mongodb end --------
/***********************************************************************************
 * This sample cpp application code is based on the P4 program P4Zeek.p4
 * Please refer to the P4 program and the generated bf-rt.json for information
 *on
 * the tables contained in the P4 program, and the associated key and data
 *fields.
 **********************************************************************************/

namespace bfrt {
namespace examples {
namespace P4Zeek {
struct timespec diff_fun(struct timespec start, struct timespec end) {
    struct timespec temp;
    temp.tv_sec = end.tv_sec-start.tv_sec;
    temp.tv_nsec = end.tv_nsec-start.tv_nsec;
    return temp;
}

// Structure definition to represent the key of the smac table



std::map<sniff_fivetuple, int> parse_map;
std::map<malware_detection_Key, uint64_t> f_tuple_map;
std::map<sniff_fivetuple, int>::iterator iter2;
std::map<malware_detection_Key, uint64_t>::iterator iter_f;
std::map<malware_detection_Key, int, CmpFunc> five_tuple_map;
std::map<malware_detection_Key, int, CmpFunc>::iterator iter;

typedef std::map<struct malware_detection_Key, uint8_t   , CmpFunc> map_t;
struct malware_detectionData {
  uint64_t set_yes;
};

struct malware_detectionData_drop {
  uint64_t set_yes;
};

struct malware_detectionData_waiting {
  uint64_t set_yes;
};
// Structure definition to represent the data of the ipRoute table for action
// "route"

namespace {
// Key field ids, table data field ids, action ids, Table object required for
// interacting with the table
// initialization with nullptr

const bfrt::BfRtInfo *bfrtInfo = nullptr;
const bfrt::BfRtTable *malware_detection = nullptr;

std::shared_ptr<bfrt::BfRtSession> session;

// std::unique_ptr<bfrt::BfRtTableGetFlag> malware_bfrtTableflag;

std::unique_ptr<bfrt::BfRtTableKey> malware_bfrtTableKey;
std::unique_ptr<bfrt::BfRtTableData> malware_bfrtTableData_drop;
std::unique_ptr<bfrt::BfRtTableData> malware_bfrtTableData_NoAction;
std::unique_ptr<bfrt::BfRtTableData> malware_bfrtTableData_waiting;

// Key field ids  malware_detection
bf_rt_id_t dst_addr_key_field_id = 0;
bf_rt_id_t src_addr_key_field_id = 0;
bf_rt_id_t src_port_key_field_id = 0;
bf_rt_id_t dst_port_key_field_id = 0;
bf_rt_id_t protocol_key_field_id = 0;

// Action Ids
bf_rt_id_t drop_action_id =0;
bf_rt_id_t NoAction_action_id = 0;
bf_rt_id_t waiting_action_id = 0; // new add

// Data field Ids for smac hit action
bf_rt_id_t drop_field_id = 0;
bf_rt_id_t NoAction_field_id = 0;
bf_rt_id_t waiting_field_id = 0;

// Learn_get Value
uint64_t hash_value = 0;
uint64_t ingresstime = 0;

bool ts_state = false;
bool ts_on    = true;
uint64_t now_timestamp = 10001;
uint64_t offset_timestamp = 3;
// uint64_t global_timestamp = 0;
uint64_t baresync_ts_ns = 0;


#define ALL_PIPES 0xffff
bf_rt_target_t dev_tgt;

}  // anonymous namespace

// // MAP for Merge between five_tuple and payload
// // typedef std::map<malware_detection_Key, int, Check> map_f_t;
// std::map<malware_detection_Key, int, Check> five_tuple_map;
// std::map<malware_detection_Key, int, Check>::iterator iter;

std::map<malware_detection_Key, uint64_t , CmpFunc> time_map;
std::map<malware_detection_Key, PayloadArray, CmpFunc> Payload_map;


// NN Model Array
long double layer1[input_size][layer1_nodes];
long double bias1[layer1_nodes];
long double layer2[layer1_nodes][layer2_nodes];
long double bias2[layer2_nodes];
long double layer3[layer2_nodes][output_size];
long double bias3[output_size];
// long double layer1_output[layer1_nodes];
// long double layer2_output[layer2_nodes];
// long double output[output_size];

// This function does the initial setUp of getting bfrtInfo object associated
// with the P4 program from which all other required objects are obtained
void setUp() {
  dev_tgt.dev_id = 0;
  dev_tgt.pipe_id = ALL_PIPES;
  // Get devMgr singleton instance
  auto &devMgr = bfrt::BfRtDevMgr::getInstance();

  // Get bfrtInfo object from dev_id and p4 program name
  auto bf_status = devMgr.bfRtInfoGet(dev_tgt.dev_id, "P4Zeek", &bfrtInfo);
  // Check for status
  assert(bf_status == BF_SUCCESS);

  // Create a session object
  session = bfrt::BfRtSession::sessionCreate();
}

// Get the GLOBAL TIMESTAMP
void TS_STATE_CHECK(){  // to get timestamp
  auto bf_status = bf_ts_global_ts_state_get(dev_tgt.dev_id, &ts_state);
  // assert(bf_status == BF_SUCCESS); // by me
  if(ts_state == false){
    auto bf_status = bf_ts_global_ts_state_set(dev_tgt.dev_id, ts_on);
    assert(bf_status == BF_SUCCESS);
    printf("Turn TS ON!!!!!\n");
  }
  printf("TS is ON~~~~\n");
}
void SetTS(){
  auto bf_status = bf_ts_global_ts_value_set(dev_tgt.dev_id, now_timestamp);
  assert(bf_status == BF_SUCCESS);

  printf("Timestamp set OK~\n");
}
void SetOS(){
  auto bf_status = bf_ts_global_ts_offset_set(dev_tgt.dev_id, offset_timestamp);
  assert(bf_status == BF_SUCCESS);
}
void GetTS(uint64_t* global_timestamp){ // just get timestamp but calculate
  auto bf_status =  bf_ts_global_baresync_ts_get(dev_tgt.dev_id, global_timestamp, &baresync_ts_ns);  // it is real time to get??
  // auto bf_status =  bf_ts_global_baresync_ts_get(dev_tgt.dev_id, &global_timestamp, &baresync_ts_ns);  // it is real time to get??
  // auto bf_status =  bf_ts_global_ts_value_get(dev_tgt.dev_id, &global_timestamp);  // it is real time to get??
  assert(bf_status == BF_SUCCESS);
  // printf("time : %lu \n", global_timestamp);
}

//Set the NN_Model Array Value
void Set_NN_Model(){  // 直接開好陣列，把參數存在文字檔裡面讀
  std::cout << "Set_NN_Model\n";
  std::ifstream fin1("cnn/layer1.txt");
  if(!fin1){
    printf("Layer1 failed to open the file!\n");
  }
  for(int i=0;i<=input_size;i++){
      for(int k=0;k<layer1_nodes;k++){
          if (i<input_size){
              fin1 >> layer1[i][k];  // use stream feed into array
          }
          else{
              fin1 >> bias1[k];
          }              
      }
  }
  fin1.close();

  std::ifstream fin2("cnn/layer2.txt");
  if(!fin2){
      printf("Layer2 failed to open the file!\n");
  }
  for(int i=0;i<=layer1_nodes;i++){
      for(int k=0;k<layer2_nodes;k++){
          if (i<layer1_nodes){
              fin2 >> layer2[i][k];
          }
          else{
              fin2 >> bias2[k];
          }              
      }
  }
  fin2.close();

      std::ifstream fin3("cnn/layer3.txt");
  if(!fin3){
    printf("Layer3 failed to open the file!\n");
  }
  for(int i=0;i<=layer2_nodes;i++){
      for(int k=0;k<output_size;k++){
          if (i<layer2_nodes){
              fin3 >> layer3[i][k];
          }
          else{
              fin3 >> bias3[k];
          }              
      }
  }
  fin3.close();
}

// int NN_Prediction(uint8_t *payload_ptr){
int NN_Prediction(const uint8_t *payload_ptr){
  long double layer1_output[layer1_nodes];
  long double layer2_output[layer2_nodes];
  long double output[output_size];
  // struct timeval start, end, diff, p_start, p_end, p_diff;
  // struct timespec start_tt, end_tt, diff_tt;
  // clock_gettime(CLOCK_MONOTONIC, &start_tt);
  
  // gettimeofday(&start, NULL);
  byte Array[40];
  for(int i=0; i<40; i++){
    Array[i] = *(payload_ptr +i);
  }
  for(int i=0; i<layer1_nodes; i++){
      layer1_output[i] = 0;
      for(int j=0; j<40; j++){
          layer1_output[i] = layer1_output[i] + Array[j]*layer1[j][i];
      }
      layer1_output[i] = layer1_output[i] + bias1[i];   //Ax+b
      if (layer1_output[i]<0){
          layer1_output[i] = 0 ;   // Relu
      }
    }
  for(int i=0; i<layer2_nodes; i++){
    layer2_output[i] = 0;
    for(int j=0; j<layer1_nodes; j++){
        layer2_output[i] = layer2_output[i] + layer1_output[j]*layer2[j][i];
    }
    layer2_output[i] = layer2_output[i] + bias2[i];
    if (layer2_output[i]<0){
        layer2_output[i] = 0 ;
    }
  }
  for(int i=0; i<output_size; i++){
    output[i] = 0;
    for(int j=0; j<layer2_nodes; j++){
        output[i] = output[i] + layer2_output[j]*layer3[j][i];
    }
    output[i] = output[i] + bias3[i];
  }


  float sum = 0;
  for (int i=0; i < output_size; i++){
      sum = sum + exp(output[i]);
  }
  for (int i=0; i < output_size; i++){
      output[i] = exp(output[i])/sum;
  }
  int n = sizeof(output) / sizeof(output[0]); 
  int lebal;
  for(int i=0; i<output_size; i++){
    if(output[i] == *std::max_element(output, output+n)){
          lebal = i;
    }
  }
  // gettimeofday(&end, NULL);
  // timersub(&end, &start, &diff);

  // clock_gettime(CLOCK_MONOTONIC, &end_tt);
  // diff_tt = diff_fun(start_tt, end_tt);
  // double time_used = (double) diff_tt.tv_sec*1000000000 + (double) diff_tt.tv_nsec;

  // double time_used = diff_tt.tv_sec + (double) diff_tt.tv_nsec;
  // double time_used = (double) diff_tt.tv_nsec;
  // double time_used = diff.tv_sec + (double) diff.tv_usec;

  // printf("Prediction time : %lf nsec.\n", time_used);
  // ave_prediction_time += time_used;
  // printf("ave Prediction time : %lf nsec.\n", (ave_prediction_time / valid_packetCount));
  // max_prediction_time = std::max(max_prediction_time, time_used);
  // printf("max_prediction_time : %lf nsec.\n", max_prediction_time);

  return lebal;
}


// This function does the initial set up of getting key field-ids, action-ids
// and data field ids associated with the smac table. This is done once
// during init time.
void tableSetUp() { 
  // create table object
  // Get table object from name
  auto bf_status =
      bfrtInfo->bfrtTableFromNameGet("Ingress.malware_detection", &malware_detection);
  assert(bf_status == BF_SUCCESS);

  // Get action Ids for hit and miss actions
  //   bf_status =
  //       malware_detection->actionIdGet("Ingress.forward", &forward_action_id);
  //   assert(bf_status == BF_SUCCESS);

  bf_status =
      malware_detection->actionIdGet("Ingress.set_drop", &drop_action_id);
      malware_detection->actionIdGet("Ingress.set_forward", &NoAction_action_id);
      // malware_detection->actionIdGet("Ingress.set_waiting", &waiting_action_id);
  assert(bf_status == BF_SUCCESS);

  // Get field-ids for key field and data fields
  bf_status = malware_detection->keyFieldIdGet("hdr.ipv4.dst_addr",
                                       &dst_addr_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = malware_detection->keyFieldIdGet("hdr.ipv4.src_addr",
                                       &src_addr_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = malware_detection->keyFieldIdGet("meta.src_port",
                                       &src_port_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = malware_detection->keyFieldIdGet("meta.dst_port",
                                       &dst_port_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = malware_detection->keyFieldIdGet("hdr.ipv4.protocol",
                                       &protocol_key_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = malware_detection->dataFieldIdGet("yes",drop_action_id, // dataField means parameter 跟上面的keyField不一樣
                                                 &drop_field_id);
  assert(bf_status == BF_SUCCESS);

  bf_status = malware_detection->dataFieldIdGet("yes",NoAction_action_id,
                                                 &NoAction_field_id);
  assert(bf_status == BF_SUCCESS);

  // bf_status = malware_detection->dataFieldIdGet("yes",waiting_action_id,
  //                                                &waiting_field_id);
  // assert(bf_status == BF_SUCCESS);
  
  std::cout << "set table debug\n";
   
  /**********************************************************************
  * DATA FIELD ID GET FOR "drop" ACTION
  **********************************************************************/
 
  // Allocate key and data once, and use reset across different uses // Allocate should be installed
  bf_status = malware_detection->keyAllocate(&malware_bfrtTableKey);  // make key be added into table
  assert(bf_status == BF_SUCCESS);

  bf_status = malware_detection->dataAllocate(&malware_bfrtTableData_drop);
  assert(bf_status == BF_SUCCESS);

  bf_status = malware_detection->dataAllocate(&malware_bfrtTableData_NoAction);
  assert(bf_status == BF_SUCCESS);

  // bf_status = malware_detection->dataAllocate(&malware_bfrtTableData_waiting);
  // assert(bf_status == BF_SUCCESS);

}

// This function sets the passed in ip_dst and vrf value into the key object
// passed using the setValue methods on the key object
void malware_detection_key_setup(const malware_detection_Key &malware_key, bfrt::BfRtTableKey *table_key){
  // Set value into the key object. Key type is "EXACT"
  auto bf_status =
      table_key->setValue(src_addr_key_field_id, malware_key.srcIP);
      table_key->setValue(dst_addr_key_field_id, malware_key.dstIP);
      table_key->setValue(src_port_key_field_id, malware_key.srcport);
      table_key->setValue(dst_port_key_field_id, malware_key.dstport);
      table_key->setValue(protocol_key_field_id, malware_key.protocol);
  assert(bf_status == BF_SUCCESS);
  return;
}

// void malware_detection_data_setup_for_drop(const malware_detectionData_drop &malware_data, 
void malware_detection_data_setup_for_drop(const malware_detectionData &malware_data, 
                                      bfrt::BfRtTableData *table_data){
  auto bf_status = 
      table_data->setValue(drop_field_id, static_cast<uint64_t>(malware_data.set_yes));
  assert(bf_status == BF_SUCCESS);
}

void malware_detection_drop_entry_add(const malware_detection_Key &malware_key, const malware_detectionData &malware_data){
  malware_detection ->keyReset(malware_bfrtTableKey.get());
  malware_detection ->dataReset(drop_action_id, malware_bfrtTableData_drop.get());
  malware_detection_key_setup(malware_key, malware_bfrtTableKey.get());
  malware_detection_data_setup_for_drop(malware_data, malware_bfrtTableData_drop.get());
  auto bf_status = malware_detection->tableEntryAdd(
  // auto bf_status = malware_detection->tableEntryMod(
    *session, dev_tgt, *malware_bfrtTableKey, *malware_bfrtTableData_drop);

  // assert(bf_status == BF_SUCCESS); // command by myself
  // printf("That Flow was set Drop already~\n");
  // GetTS();
}
void malware_detection_data_setup_for_NoAction(const malware_detectionData &malware_data, 
                                      bfrt::BfRtTableData *table_data){
  auto bf_status = 
      table_data->setValue(NoAction_field_id,static_cast<uint64_t>(malware_data.set_yes));
  assert(bf_status == BF_SUCCESS);
}

void malware_detection_NoAction_entry_add(const malware_detection_Key &malware_key, const malware_detectionData &malware_data){
  // std::shared_ptr<bfrt::BfRtTableKey> malware_bfrtTableKey_temp(move(malware_bfrtTableKey));
  // std::shared_ptr<bfrt::BfRtTableData> malware_bfrtTableData_NoAction_temp(move(malware_bfrtTableData_NoAction));
  // std::cout << "test 673\n";
  // malware_detection ->keyReset(malware_bfrtTableKey_temp.get());
  // std::cout << "test 675\n";
  // malware_detection ->dataReset(NoAction_action_id, malware_bfrtTableData_NoAction_temp.get());
  malware_detection ->keyReset(malware_bfrtTableKey.get());
  malware_detection ->dataReset(NoAction_action_id, malware_bfrtTableData_NoAction.get());
  // std::cout << "test 679\n";
  // malware_detection_key_setup(malware_key, malware_bfrtTableKey_temp.get());
  // std::cout << "test 681\n";
  // malware_detection_data_setup_for_NoAction(malware_data, malware_bfrtTableData_NoAction_temp.get());
  // std::cout << "test 683\n";
  malware_detection_key_setup(malware_key, malware_bfrtTableKey.get());
  malware_detection_data_setup_for_NoAction(malware_data, malware_bfrtTableData_NoAction.get());
  
  
  auto bf_status = malware_detection->tableEntryAdd(  // add entry here  here will add overlaped entry
  // auto bf_status = malware_detection->tableEntryMod(  // add entry here  here will add overlaped entry
    // *session, dev_tgt, *malware_bfrtTableKey_temp, *malware_bfrtTableData_NoAction_temp);
    *session, dev_tgt, *malware_bfrtTableKey, *malware_bfrtTableData_NoAction);
  // bf_status = malware_detection->tableEntryDel(*session, dev_tgt, *malware_bfrtTableKey);
  // std::cout << "test 692\n";
  // assert(bf_status == BF_SUCCESS);
  // printf("That Flow was set NoAction already~\n");
  // GetTS();
}

/*
void malware_detection_NoAction_entry_get(const malware_detection_Key &malware_key, const BfRtTable::BfRtTableGetFlag &flag){
  malware_detection ->keyReset(malware_bfrtTableKey.get());
  // malware_detection ->dataReset(NoAction_action_id, malware_bfrtTableData_NoAction.get());
  malware_detection_key_setup(malware_key, malware_bfrtTableKey.get());
  // malware_detection_data_setup_for_NoAction(malware_data, malware_bfrtTableData_NoAction.get());
  
  auto bf_status = malware_detection->tableEntryGet(
    *session, dev_tgt, *malware_bfrtTableKey, flag, malware_bfrtTableData_NoAction.get());
  bf_status = malware_bfrtTableData_NoAction->actionIdGet(&NoAction_action_id);
  
  malware_detectionData set_fwd_check;
  // bf_status = malware_bfrtTableData_NoAction->getValue(NoAction_action_id, &set_fwd_check);
  // std::cout << "set_fwd_check.set_yes = " << set_fwd_check.set_yes << std::endl;
    
  // auto bf_status = malware_detection->tableEntryAdd(  // add entry here  here will add overlaped entry
  //   *session, dev_tgt, *malware_bfrtTableKey, *malware_bfrtTableData_NoAction);
}
*/

// void malware_detection_data_setup_for_waiting(const malware_detectionData_waiting &malware_data, 
//                                       bfrt::BfRtTableData *table_data){
//   auto bf_status = 
//       table_data->setValue(waiting_field_id,static_cast<uint64_t>(malware_data.set_yes));
//   assert(bf_status == BF_SUCCESS);
// }
// void malware_detection_waiting_entry_add(const malware_detection_Key &malware_key, const malware_detectionData_waiting &malware_data){
//   malware_detection ->keyReset(malware_bfrtTableKey.get());
//   malware_detection ->dataReset(waiting_action_id, malware_bfrtTableData_waiting.get());
//   malware_detection_key_setup(malware_key, malware_bfrtTableKey.get());
//   malware_detection_data_setup_for_waiting(malware_data, malware_bfrtTableData_waiting.get());
  

//   auto bf_status = malware_detection->tableEntryAdd(  // add entry here  here will add overlaped entry
//     *session, dev_tgt, *malware_bfrtTableKey, *malware_bfrtTableData_waiting);

//   // assert(bf_status == BF_SUCCESS);
//   // printf("That Flow was set waiting already~\n");
//   // GetTS();
// }

void printfile(){
  uint64_t total_time_s = 0;
  uint64_t total_time_e = 0;
  double total_time;
  uint64_t Hz = 100;
  double cpu_usage;
  double total_NN_time = 0.0;

  std::string file = "output.txt";
  std::ofstream outfile(file.c_str());
  // if(filevec.size() > 1){
  //   std::cout << "filevec[filevec.size()-1].ingress_ts = " << filevec[filevec.size()-1].ingress_ts << std::endl;
  //   std::cout << "filevec[filevec.size()-2].ingress_ts = " << filevec[filevec.size()-2].ingress_ts << std::endl;
  //   std::cout << "filevec.size() = " << filevec.size() << std::endl;
  //   if(filevec[filevec.size()-1].ingress_ts-filevec[filevec.size()-2].ingress_ts > 100000)  // delete useless information
  //     filevec.erase(filevec.end());
  // }
  int max_in2, min_in1; // for ingress timestamp record
  outfile << "ingree_to_control NN_time control total_time ingress_ts control_start_ts control_end_ts ingress_ts2 label" << std::endl;
  for(int i=0; i<filevec.size(); i++){
    if(i<filevec.size()){
      iter_f = f_tuple_map.find(filevec[i].f_tuple);
      if(i == 0){
        max_in2 = iter_f->second;
        min_in1 = filevec[i].ingress_ts;
      }
      else{
        if(iter_f->second > max_in2){
          max_in2 = iter_f->second;
        }
        if(filevec[i].ingress_ts < min_in1){
          min_in1 = filevec[i].ingress_ts;
        }
      }
      outfile << filevec[i].ingree_to_control << " " << filevec[i].NN_time << " " 
      << filevec[i].control << " " << iter_f->second - filevec[i].ingress_ts << " "
      << filevec[i].ingress_ts << " " << filevec[i].control_start_ts << " " << filevec[i].control_end_ts << " " << iter_f->second << " " << filevec[i].label << std::endl;
      struct in_addr srcIPStr;
      struct in_addr dstIPStr;  
      srcIPStr.s_addr = htonl(filevec[i].f_tuple.srcIP);
      dstIPStr.s_addr = htonl(filevec[i].f_tuple.dstIP);

      std::string str = std::string(inet_ntoa(srcIPStr)) + " " + std::string(inet_ntoa(dstIPStr)) + " "
                    + std::to_string(filevec[i].f_tuple.srcport) + " " + std::to_string(filevec[i].f_tuple.dstport) + " "
                    // + std::to_string(filevec[i].f_tuple.protocol) + " " + std::to_string(iter_f->second - filevec[i].ingress_ts) + " "
                    + std::to_string(filevec[i].f_tuple.protocol) + " " + std::to_string(filevec[i].NN_time) + " "
                    + std::to_string(filevec[i].label) + " " + std::to_string(filevec[i].ingress_ts) + " " + std::to_string(iter_f->second);
      
      // send_msg_mongodb(str);
      total_NN_time+=filevec[i].NN_time;
    }
  }
  outfile << "\nave_ingree_to_control ave_NN_time ave_control_res ave_total_res correct_ave_NN_time" << std::endl;
  outfile << (uint64_t)(ave_ingree_to_control/valid_packetCount/1000) << " " << (uint64_t)(ave_NN_time / valid_packetCount/1000) << " "
    << (uint64_t)(ave_control_res/valid_packetCount/1000) << " " << (uint64_t)(ave_total_res / valid_packetCount/1000) << " " << (uint64_t) (total_NN_time / int(filevec.size()))<< std::endl;
  outfile << "max_ingree_to_control max_NN_time max_control_res max_total_res" << std::endl;  
  outfile << (uint64_t)(max_ingree_to_control/1000) << " " << (uint64_t)(max_NN_time/1000) << " " 
  << (uint64_t)(max_control_res/1000) << " " << (uint64_t)(max_total_res/1000) << std::endl;
  iter_f = f_tuple_map.find(filevec[filevec.size()-1].f_tuple);
  if(valid_packetCount!=0)
    outfile << "average total response time = " << (uint64_t)(max_in2 - min_in1)/valid_packetCount << std::endl;
    // outfile << "average total response time = " << (uint64_t)(iter_f->second - filevec[0].ingress_ts)/valid_packetCount << std::endl;
  /*
  total_time_s += start_get.utime + start_get.stime + start_get.cutime + start_get.cstime;
  total_time_e += end_get.utime + end_get.stime + end_get.cutime + end_get.cstime;
  double total_time_sw = (end_get.starttime - start_get.starttime);
  timespec diff_tt = diff_fun(start_get.ts, end_get.ts);
  total_time = (double) diff_tt.tv_nsec + (double) diff_tt.tv_sec*1000000000;
  cpu_usage = 100 * ((double(total_time_e-total_time_s) / Hz)*1000000000 / total_time);
  double cpu_usage_sw = 100 * ((double(total_time_e-total_time_s) / Hz)*1000000000 / total_time_sw);
  // outfile << "double((total_time_e-total_time_s) / Hz)*1000000000 = " << double((total_time_e-total_time_s) / Hz)*1000000000 << std::endl;
  
  outfile << std::endl;
  outfile << "total_time_s = " << total_time_s << std::endl;
  outfile << "total_time_e = " << total_time_e << std::endl;
  // std::cout << "diff_tt.tv_nsec = " << diff_tt.tv_nsec << "  |  " << "diff_tt.tv_sec = " << diff_tt.tv_sec << std::endl;
  outfile << "start_get.starttime = " << start_get.starttime << std::endl;
  outfile << "end_get.starttime = " << end_get.starttime << std::endl;
  outfile << "total_time = " << total_time << std::endl;
  outfile << "thread number : " << thread_number << "  |  cpu_usage : " << cpu_usage << "%  |  cpu_usage_sw : " << cpu_usage_sw << std::endl;
  */
  outfile.close();
  std::cout << "file has been writen!" << std::endl;
}

void printdata(){
  fprintf(stderr, "\nvalid_packetCount = %d\n", valid_packetCount);
  fprintf(stderr, "numbers of rule  = %d\n", filevec.size());
  fprintf(stderr, "to_CPU_port_Count = %d\n", to_CPU_port_Count);
  fprintf(stderr, "ave_ingree_to_control : %lf µs.\n", (ave_ingree_to_control / valid_packetCount) / 1000);
  fprintf(stderr, "max_ingree_to_control : %lf µs.\n", max_ingree_to_control / 1000); 
  fprintf(stderr, "ave_NN_time : %lf µs.\n", (ave_NN_time / valid_packetCount) / 1000);
  fprintf(stderr, "max_NN_time : %lf µs.\n", max_NN_time / 1000); 
  fprintf(stderr, "ave_control_res = %lf µs.\n", ave_control_res / valid_packetCount / 1000);
  fprintf(stderr, "max_control_res = %lf µs.\n", max_control_res / 1000);
  fprintf(stderr, "ave_total_res = %lf µs.\n", ave_total_res / valid_packetCount / 1000);
  fprintf(stderr, "max_total_res = %lf µs.\n", max_total_res / 1000);
}

void readstat(cpu_data &temp){  
  std::ifstream fileStat__("/proc/uptime");
  std::ifstream fileStat("/proc/"+ std::to_string(getpid())+"/stat");
  std::string line;
  std::string t_;
  struct timespec ;

  // while(std::getline(fileStat__, line)){
  //   std::istringstream ss(line);
  //   ss >> temp.uptime >> t_;
  // }
  uint64_t temp_time;
  clock_gettime(CLOCK_MONOTONIC, &temp.ts);
  GetTS(&temp_time);
  temp.starttime = double(temp_time);

  while(std::getline(fileStat, line)){
    // std::cout << line << std::endl;
    std::istringstream ss(line);

    for(int i = 0; i < 13; i++)
				ss >> t_;
    
    ss >> temp.utime; // #14
    // cout << "temp.utime = " << temp.utime << std::endl; // #14
    ss >> temp.stime; // #15
    // cout << "temp.stime = " << temp.stime << std::endl; // #15
    ss >> temp.cutime; // #16
    // cout << "temp.cutime = " << temp.cutime << std::endl; // #16
    ss >> temp.cstime; // #17
    // cout << "temp.cstime = " << temp.cstime << std::endl; // #17 

    // for(int i = 0; i < 4; i++) // #18~#22
		// 		ss >> t_;

    // ss >> temp.starttime;
  
  }

  fileStat__.close();
  fileStat.close();
}

void calstat(){
  uint64_t total_time_s = 0;
  uint64_t total_time_e = 0;
  double total_time;
  uint64_t Hz = 100;
  double cpu_usage;

  total_time_s += start_get.utime + start_get.stime + start_get.cutime + start_get.cstime;
  total_time_e += end_get.utime + end_get.stime + end_get.cutime + end_get.cstime;
  // total_time = (end_get.starttime - start_get.starttime);
  timespec diff_tt = diff_fun(start_get.ts, end_get.ts);
  total_time = (double) diff_tt.tv_nsec*1000000000 + (double) diff_tt.tv_sec;
  cpu_usage = 100 * ((double(total_time_e-total_time_s) / Hz)*1000000000 / total_time);


  std::cout << "double((total_time_e-total_time_s) / Hz)*1000000000 = " << double((total_time_e-total_time_s) / Hz)*1000000000 << std::endl;
  std::cout << "total_time_s = " << total_time_s << std::endl;
  std::cout << "total_time_e = " << total_time_e << std::endl;
  std::cout << "diff_tt.tv_nsec = " << diff_tt.tv_nsec << "  |  " << "diff_tt.tv_sec = " << diff_tt.tv_sec << std::endl;
  // std::cout << "start_get.starttime = " << start_get.starttime << std::endl;
  // std::cout << "end_get.starttime = " << end_get.starttime << std::endl;
  std::cout << "total_time = " << total_time << std::endl;
  std::cout << "cpu_usage = " << cpu_usage << "%" << std::endl;
}

// void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
void packetHandler(const u_char* packet) {
// void* packetHandler(void *arg) {
    // const u_char* packet = (const u_char*) arg;
    // std::cout << "enter packethandler\n";
    uint64_t start_p4, end_p4;
    uint64_t NN_bare_start = 0;
    uint64_t NN_bare_end = 0;
    // uint64_t global_timestamp = 0;
    const uint8_t *payload; /* Packet payload */ 
    
    GetTS(&start_p4);
    // start_p4 = global_timestamp;
    // static struct timespec res_start, res_end, res_diff;
    // struct timespec pa_start, pa_end, wait_start, wait_end, NN_start, NN_end, Mod_start, Mod_end, diff_tt, pin1_tt, pin2_tt, pin3_tt;
    
    const struct sniff_fivetuple *f_tuple;
    // const struct record *seqnum_record;
    malware_detection_Key five_tuple, five_tuple2;
    datas temp;
    temp.ingree_to_control = 0;
    temp.control = 0;
    temp.control_start_ts = 0;
    temp.control_end_ts = 0;
    temp.ingress_ts = 0;
    temp.NN_time = 0;
    temp.total_time = 0;
    
    // ------------------parse----------------------
    // clock_gettime(CLOCK_MONOTONIC, &pa_start);
    // res_start = pa_start;

    // pthread_mutex_lock( &mutex1 );
    ++to_CPU_port_Count;
    
    // ethernet = (struct sniff_ethernet*)(packet);
    // ------------------------------------------------------------------------------------------------------------
    f_tuple = (struct sniff_fivetuple*)(packet);
    // std::cout << "enter CPU!!\n";
    // printf("f_tuple->src_addr = %lu\n", uint64_t(htonl(f_tuple->src_addr)));

    if(!(f_tuple->protocol == IPPROTO_UDP || f_tuple->protocol == IPPROTO_TCP)){
      // temp.control_start_ts = (uint64_t) (start_p4/1000);
      // filevec.push_back(temp);
      // std::thread first_thread(printdata);
      printdata();
      printfile();
      // calstat();
      // PrintStats(entries1, entries2);
      // first_thread.join();
      return;
    }
    // std::cout << "pass and parse\n";
    
    five_tuple.srcIP = uint64_t(htonl(f_tuple->src_addr));
    five_tuple.dstIP = uint64_t(htonl(f_tuple->dst_addr));
    five_tuple.protocol = uint64_t (f_tuple->protocol);
    five_tuple.srcport = uint64_t(htons(f_tuple -> src_port));
    five_tuple.dstport = uint64_t(htons(f_tuple -> dst_port));

    five_tuple2.dstIP = uint64_t(htonl(f_tuple->src_addr));
    five_tuple2.srcIP = uint64_t(htonl(f_tuple->dst_addr));
    five_tuple2.protocol = uint64_t (f_tuple->protocol);
    five_tuple2.dstport = uint64_t(htons(f_tuple -> src_port));
    five_tuple2.srcport = uint64_t(htons(f_tuple -> dst_port));

    uint64_t in_time, eg_time;
    in_time = ((uint64_t) f_tuple->in_time1)*(uint64_t)pow(256, 5)+
    ((uint64_t) f_tuple->in_time2)*(uint64_t)pow(256, 4)+
    ((uint64_t) f_tuple->in_time3)*(uint64_t)pow(256, 3)+
    ((uint64_t) f_tuple->in_time4)*(uint64_t)pow(256, 2)+
    ((uint64_t) f_tuple->in_time5)*(uint64_t)pow(256, 1)+
    ((uint64_t) f_tuple->in_time6)*(uint64_t)pow(256, 0);
    
    if(f_tuple->times == 2){
      // iter_f = f_tuple_map.find(five_tuple);
      mu3.lock();
      if(in_time == 0)
        f_tuple_map[five_tuple] = 111;
      else{
        f_tuple_map[five_tuple] = in_time/1000;
        // if(iter_f == f_tuple_map.end()){
        //   f_tuple_map.insert(std::pair<malware_detection_Key, uint64_t>(five_tuple, in_time/1000));
        // }
      }
      mu3.unlock();
        // f_tuple_map[five_tuple] = in_time/1000;
      // iter_f = f_tuple_map.find(five_tuple);
      // if(iter_f == f_tuple_map.end()){
      //   f_tuple_map.insert(std::pair<malware_detection_Key, uint64_t>(five_tuple, in_time/1000)); // second in_time
      // }
      return;
    }

    // std::cout << "f_tuple->in_time1 = " << (int) f_tuple->in_time1 << std::endl;
    // std::cout << "f_tuple->in_time2 = " << (int) f_tuple->in_time2 << std::endl;
    // std::cout << "f_tuple->in_time3 = " << (int) f_tuple->in_time3 << std::endl;
    // std::cout << "f_tuple->in_time4 = " << (int) f_tuple->in_time4 << std::endl;
    // std::cout << "f_tuple->in_time5 = " << (int) f_tuple->in_time5 << std::endl;
    // std::cout << "f_tuple->in_time6 = " << (int) f_tuple->in_time6 << std::endl;
    // std::cout << "f_tuple->eg_time1 = " << (int) f_tuple->eg_time1 << std::endl;
    // std::cout << "f_tuple->eg_time2 = " << (int) f_tuple->eg_time2 << std::endl;
    // std::cout << "f_tuple->eg_time3 = " << (int) f_tuple->eg_time3 << std::endl;
    // std::cout << "f_tuple->eg_time4 = " << (int) f_tuple->eg_time4 << std::endl;
    // std::cout << "f_tuple->eg_time5 = " << (int) f_tuple->eg_time5 << std::endl;
    // std::cout << "f_tuple->eg_time6 = " << (int) f_tuple->eg_time6 << std::endl;

    size_ip = (u_int)(f_tuple ->l3len & 0x0f) * 4;
    size_tcp = (u_int)(f_tuple ->l4len & 0x0f) * 4;

    // clock_gettime(CLOCK_MONOTONIC, &wait_end);

    // malware_detectionData set_fwd_check;
    // malware_detection_NoAction_entry_get(five_tuple, BfRtTable::BfRtTableGetFlag::GET_FROM_SW);
    
    payload = (uint8_t *)(packet + SIZE_MIRROR + SIZE_ETHERNET + size_ip + size_tcp);  
    // ++valid_packetCount;
    // std::cout << "tp.numTaskRemaining = " << tp.numTaskRemaining << std::endl;
    // ---------------NN_Prediction---------------------
    // clock_gettime(CLOCK_MONOTONIC, &NN_start);
    GetTS(&NN_bare_start);
    // NN_bare_start = global_timestamp;
    // pin3_tt = NN_start;
    int label = NN_Prediction(payload);  // here do prediction
    GetTS(&NN_bare_end);
    // NN_bare_end = global_timestamp;
    // clock_gettime(CLOCK_MONOTONIC, &NN_end);
    // ---------------NN_Prediction---------------------


    // ---------------add detection entry---------------------
    // clock_gettime(CLOCK_MONOTONIC, &Mod_start);    
    malware_detectionData set_action;
    mu.lock();
    ++valid_packetCount;
    if (valid_packetCount%atoi(nflow) == 2){
      readstat(start_get);
    }
    // label = 0; // for test to use add entry
    // pthread_mutex_lock( &mutex1 );
    if(label == 0){
      set_action.set_yes = 1; // forward
      malware_detection_NoAction_entry_add(five_tuple, set_action);
      malware_detection_NoAction_entry_add(five_tuple2, set_action);
    }
    else if(label == 1){
      set_action.set_yes = 2; // drop
      malware_detection_drop_entry_add(five_tuple, set_action);  // it is malware and drop
      malware_detection_drop_entry_add(five_tuple2, set_action);  // it is malware and drop
    }
    if (valid_packetCount%atoi(nflow) == 0){
      readstat(end_get); 
    }
    mu.unlock();
    // clock_gettime(CLOCK_MONOTONIC, &Mod_end);
    // -------------add detection entry-----------------------
    
    GetTS(&end_p4);
    // end_p4 = global_timestamp;
    double time_used;
    if(five_tuple.srcport == 7 && five_tuple.dstport == 5001 && five_tuple.protocol == 17)
      return;

    // diff_tt = diff_fun(NN_start, NN_end);
    // time_used = (double) diff_tt.tv_sec*1000000000 + (double) diff_tt.tv_nsec;
    // ave_NN_time += time_used;
    // max_NN_time = std::max(max_NN_time, time_used);
    // temp.NN_time = (uint64_t) (time_used/1000);

    // diff_tt = diff_fun(Mod_start, Mod_end);
    // time_used = (double) diff_tt.tv_sec*1000000000 + (double) diff_tt.tv_nsec;
    // ave_mod_entry_time += time_used;
    // max_mod_entry_time = std::max(max_mod_entry_time, time_used);

    // in_time = ((uint64_t) (f_tuple->in_time1)) << 40+
    // ((uint64_t) (f_tuple->in_time2)) << 32+
    // ((uint64_t) (f_tuple->in_time3)) << 24+
    // ((uint64_t) (f_tuple->in_time4)) << 16+
    // ((uint64_t) (f_tuple->in_time5)) << 8+
    // ((uint64_t) (f_tuple->in_time6)) << 0;
    // in_time = ((uint64_t) f_tuple->in_time1)+((uint64_t) f_tuple->in_time2)+((uint64_t) f_tuple->in_time3)+((uint64_t) f_tuple->in_time4)+((uint64_t) (f_tuple->in_time5))+((uint64_t) f_tuple->in_time6);

    // eg_time = ((uint64_t) f_tuple->eg_time1)*(uint64_t)pow(256, 5)+
    // ((uint64_t) f_tuple->eg_time2)*(uint64_t)pow(256, 4)+
    // ((uint64_t) f_tuple->eg_time3)*(uint64_t)pow(256, 3)+
    // ((uint64_t) f_tuple->eg_time4)*(uint64_t)pow(256, 2)+
    // ((uint64_t) f_tuple->eg_time5)*(uint64_t)pow(256, 1)+
    // ((uint64_t) f_tuple->eg_time6)*(uint64_t)pow(256, 0);
    uint64_t d_time = 0;
    d_time = NN_bare_end - NN_bare_start;
    ave_NN_time += (double) d_time;
    max_NN_time = std::max(max_NN_time, (double)d_time);
    temp.NN_time = (uint64_t) (d_time/1000);

    d_time = start_p4 - in_time;
    ave_ingree_to_control += (double) d_time;
    max_ingree_to_control = std::max(max_ingree_to_control, (double)d_time);
    temp.ingree_to_control = (uint64_t) (d_time/1000);

    d_time = end_p4 - start_p4;
    ave_control_res += (double) d_time;
    max_control_res = std::max(max_control_res, (double)d_time);
    temp.control = (uint64_t) (d_time/1000);
    temp.control_start_ts = (uint64_t) (start_p4/1000);
    temp.control_end_ts = (uint64_t) (end_p4/1000);
    temp.ingress_ts = (uint64_t) (in_time/1000);

    d_time = end_p4 - in_time;
    ave_total_res += (double) d_time;
    max_total_res = std::max(max_total_res, (double)d_time);
    temp.total_time = (uint64_t) (d_time/1000);

    temp.f_tuple.srcIP = five_tuple.srcIP;
    temp.f_tuple.dstIP = five_tuple.dstIP;
    temp.f_tuple.protocol = five_tuple.protocol;
    temp.f_tuple.srcport = five_tuple.srcport;
    temp.f_tuple.dstport = five_tuple.dstport;
    temp.label = label;
    
    mu2.lock(); // new add
    filevec.push_back(temp);
    mu2.unlock();
    // uint32_t seqhash;
    // seqhash = ((uint32_t) f_tuple->seqnum1)*(uint32_t)pow(256, 3)+
    // ((uint32_t) f_tuple->seqnum2)*(uint32_t)pow(256, 2)+
    // ((uint32_t) f_tuple->seqnum3)*(uint32_t)pow(256, 1)+
    // ((uint32_t) f_tuple->seqnum4)*(uint32_t)pow(256, 0);
    // std::cout << "# " << seqhash << "   d_time = " << d_time << " ns" << std::endl;
}

// void threadhandler(const u_char* packet){
void threadhandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet){
    // std::cout << "main thread~~~\n";
    // pthread_t t; // 宣告 pthread 變數
    // if (valid_packetCount%atoi(nflow) == 2){
    //   readstat(start_get);
    // }
    // readstat(start_get);
    // ReadStatsCPU(entries1);
    tp.addTask([=] {packetHandler(packet);});
    // ReadStatsCPU(entries2); 
    // std::thread first_thread(packetHandler, packet);
    // first_thread.detach();
    // pthread_create(&t, NULL, packetHandler, (void*)packet); // 建立子執行緒
    // pthread_join(t, NULL);
    // if (valid_packetCount%atoi(nflow) == 0){
    //   readstat(end_get);
    // }
    return;
}


int parse2detect(){
    std::string dev = "enp4s0f1";
    // char *dev;
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // descr = pcap_open_live(dev.c_str(), 65535, 1, -1, errbuf); // 65535最大，表示不切割封包
    descr = pcap_open_live(dev.c_str(), 150, 1, -1, errbuf); // 65535最大，表示不切割封包
    if (descr == NULL) {
        std::cout << "pcap_open_live() failed: " << errbuf << std::endl;
        return 1;
    }

    // if (pcap_loop(descr, -1, packetHandler, NULL) < 0) { // so program stop here with handler?
    if (pcap_loop(descr, -1, threadhandler, NULL) < 0) { // so program stop here with handler?
        std::cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }
    
    
}

}  // P4Zeek
}  // examples
}  // bfrt

static bf_status_t Init_bf_switchd(bf_switchd_context_t *switchd_ctx,
                            const char *progname) {
  if ((switchd_ctx = (bf_switchd_context_t *)calloc(
           1, sizeof(bf_switchd_context_t))) == NULL) {
    printf("Cannot Allocate switchd context\n");
    exit(1);
  }

  char *install_dir;
  char target_conf_file[100];
  if (getenv("SDE") == NULL) {
    fprintf(stderr, "SDE is not set\n", strerror(errno));
    exit(EXIT_SUCCESS);
  }
  install_dir = getenv("SDE_INSTALL");
  sprintf(target_conf_file, "%s/share/p4/targets/tofino/%s.conf", install_dir,
          progname);

  switchd_ctx->install_dir = install_dir;
  switchd_ctx->conf_file = target_conf_file;
  switchd_ctx->skip_p4 = false;
  switchd_ctx->skip_port_add = false;
  switchd_ctx->running_in_background = true;
  // switchd_main_ctx->dev_sts_thread = true;
  // switchd_main_ctx->dev_sts_port = THRIFT_PORT_NUM;

  switchd_ctx->running_in_background = true;
  return bf_switchd_lib_init(switchd_ctx);  // to this line with some problems
}

int main(int argc, char **argv) {
  bf_switchd_context_t *switchd_ctx;  // switch context
  if ((switchd_ctx = (bf_switchd_context_t *)calloc(
           1, sizeof(bf_switchd_context_t))) == NULL) {
    printf("Cannot Allocate switchd context\n");
    exit(1);
  }
  
  bf_status_t status = Init_bf_switchd(switchd_ctx, "P4Zeek");
  bfrt::examples::P4Zeek::setUp();
  bfrt::examples::P4Zeek::SetTS();
  bfrt::examples::P4Zeek::SetOS();
  bfrt::examples::P4Zeek::tableSetUp();
  std::cout << "prepare Set_NN_Model \n";
  bfrt::examples::P4Zeek::Set_NN_Model();
  system("bfshell -f cmd/bfshell_commands.txt");
  system("bfshell -b cmd/bfrt_python_script.py");
  printf("---------bfshell finish-------------\n");
  // ------------ mongodb ----------  
  // mongodb_initial();
  // ------------ mongodb end ----------
  nflow = argv[1];
  std::cout << "nflow = " << nflow << std::endl; 
  // pthread_create(&t1, NULL, send_pkt, NULL);
  long number_of_processors = sysconf(_SC_NPROCESSORS_ONLN);
  std::cout << "number_of_processors = " << number_of_processors << std::endl;
  unsigned int nthreads = std::thread::hardware_concurrency();
  std::cout << "std::thread::hardware_concurrency = " << nthreads << std::endl;
  unsigned int eax=11,ebx=0,ecx=1,edx=0;
  asm volatile("cpuid"
          : "=a" (eax),
            "=b" (ebx),
            "=c" (ecx),
            "=d" (edx)
          : "0" (eax), "2" (ecx)
          : );
printf("Cores: %d\nThreads: %d\nActual thread: %d\n",eax,ebx,edx);
  tp.vectorsize();
  bfrt::examples::P4Zeek::parse2detect(); // main of control plane
  // pthread_join(t1, NULL);
  
  return status;
}



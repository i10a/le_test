#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/bitstring.h>
#include <sys/select.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netgraph/ng_message.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define L2CAP_SOCKET_CHECKED
#include <bluetooth.h>
#include "/usr/src/usr.sbin/bluetooth/hccontrol/hccontrol.h"

int timeout = 30;

/**
   LE Read Local Supported Features

   Vol.2/Part E/7.8.3
 */
static int
le_read_local_supported_features(int s)
{
  ng_hci_le_read_local_supported_features_rp rp;
  int e, n;

  n = sizeof(rp);
  e = hci_simple_request(s,
                         NG_HCI_OPCODE(NG_HCI_OGF_LE,
                                       NG_HCI_OCF_LE_READ_LOCAL_SUPPORTED_FEATURES),
                         (void *)&rp, &n);
  printf("* LE_Read_Local_Supported_Features: %d %d %lu\n", e, rp.status, rp.le_features);

  return e;
}

/**
   Read BD_ADDR

   Vol2/Part E/7.4.6
 */
static int
read_bd_addr(int s, bdaddr_t *bdaddr)
{
  ng_hci_read_bdaddr_rp rp;
  int n = sizeof(rp);
  int e = hci_simple_request(s,
                             NG_HCI_OPCODE(NG_HCI_OGF_INFO,
                                           NG_HCI_OCF_READ_BDADDR),
                             (void *)&rp, &n);
  if(e == 0){
    if(bdaddr)
      memcpy(bdaddr, &(rp.bdaddr), sizeof(*bdaddr));
    char buf[18];

    bt_ntoa(&(rp.bdaddr), buf);
    printf("* Read_BD_ADDR: %s\n", buf);
  }
  return e;
}

/**
   Set Event Mask

   Vol2/Part E/7.3.1
 */
static int
set_event_mask(int s, uint64_t mask)
{
  ng_hci_set_event_mask_cp semc;
  ng_hci_set_event_mask_rp rp;
  int i, n, e;

  n = sizeof(rp);
  for(i=0; i< NG_HCI_EVENT_MASK_SIZE;i++){
    semc.event_mask[i] = mask & 0xff;
    mask >>= 8;
  }
  e = hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_HC_BASEBAND,
                                   NG_HCI_OCF_SET_EVENT_MASK),
                  (void *)&semc, sizeof(semc),
                  (void *)&rp, &n);

  printf("* Set_Event_Mask: %d %d\n",e, rp.status);

  return e;
}

/**
   LE Set Event Mask

   Vol2/Part E/7.8.1
 */
static int
le_set_event_mask(int s, uint64_t mask)
{
  ng_hci_le_set_event_mask_cp semc;
  ng_hci_le_set_event_mask_rp rp;
  int i, n ,e;

  n = sizeof(rp);
  for(i=0; i< NG_HCI_LE_EVENT_MASK_SIZE;i++){
    semc.event_mask[i] = mask & 0xff;
    mask >>= 8;
  }
  e = hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LE,
                                   NG_HCI_OCF_LE_SET_EVENT_MASK),
                  (void *)&semc, sizeof(semc),
                  (void *)&rp, &n);

  printf("* LE_Set_Event_Mask: %d %d\n",e, rp.status);

  return e;
}

/**
   Read Buffer Size

   Vol2/Part E/7.4.5
 */
static int
read_buffer_size(int s)
{
  ng_hci_read_buffer_size_rp brp;
  int n, e;

  n = sizeof(brp);
  e = hci_simple_request(s,
                         NG_HCI_OPCODE(NG_HCI_OGF_INFO,
                                       NG_HCI_OCF_READ_BUFFER_SIZE),
                         (void *)&brp, &n);
  printf("* Read_Buffer_Size: %d %d %d %d %d %d \n", e, brp.status,
         brp.max_acl_size,
         brp.max_sco_size,
         brp.num_acl_pkt,
         brp.num_sco_pkt);

  return e;
}

/**
   LE Read Buffer Size

   Vol2/Part E/7.8.2
 */
static int
le_read_buffer_size(int s)
{
  ng_hci_le_read_buffer_size_rp rp;
  int n, e;

  n = sizeof(rp);
  e = hci_simple_request(s,
                         NG_HCI_OPCODE(NG_HCI_OGF_LE,
                                       NG_HCI_OCF_LE_READ_BUFFER_SIZE),
                         (void *)&rp, &n);

  printf("* LE_Read_Buffer_Size: %d %d %d %d\n", e, rp.status, rp.hc_le_data_packet_length,
         rp.hc_total_num_le_data_packets);

  if(rp.status == 0 && rp.hc_le_data_packet_length == 0)
    read_buffer_size(s);

  return e;
}

/**
   LE Set Scan Param

   Vol2/Part E/7.8.10
 */
static int
le_set_scan_param(int s, int type, int interval, int window, int adrtype, int policy)
{
  ng_hci_le_set_scan_parameters_cp cp;
  ng_hci_le_set_scan_parameters_rp rp;
  int e, n;

  n = sizeof(rp);
  cp.le_scan_type = type;
  cp.le_scan_interval = interval;
  cp.own_address_type = adrtype;
  cp.le_scan_window = window;
  cp.scanning_filter_policy = policy;
  e = hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LE,
                                   NG_HCI_OCF_LE_SET_SCAN_PARAMETERS),
                  (void *)&cp, sizeof(cp),
                  (void *)&rp, &n);

  printf("* LE_Set_Scan_Param %d %d %d\n", e, rp.status, n);
  printf("  Scan_Type: %d\n", type);
  printf("  LE_Scan_interval: %d\n", interval);
  printf("  LE_Scan_window: %d\n", window);
  printf("  Scanning_filter_policy: %d\n", policy);
  printf("  Own_Address_Type: %d\n", adrtype);

  return e;
}

/**
 */
static int
le_scan_result(int s)
{
  unsigned char buffer[512];
  ng_hci_event_pkt_t  *e = (ng_hci_event_pkt_t *) buffer;
  int i,j,k,l;
  int n;
  int err;
  int numrecord;
  int sig_str;

  printf("* Scanning....\n");
  n = sizeof(buffer);
  if ((err = hci_recv(s, (char *)buffer, &n)) == ERROR){
    return (ERROR);
  }

  if (n < sizeof(*e)) {
    printf("Size: %d\n", n);
    errno = EMSGSIZE;
    return (ERROR);
  }

  if (e->type != NG_HCI_EVENT_PKT) {
    printf("Event: %d\n", e->type);
    errno = EIO;
    return (ERROR);
  }

  printf("  Result: %x %x\n", e->event, e->length);
  printf("  Subevent: %d\n", buffer[3]);
  numrecord = buffer[4];
  printf("  NumRecord: %d\n", numrecord);
  j = 5;
  for(i=0; i < numrecord; i++){
    int length_data;
    printf("  Eventtype: %d\n", buffer[j]);
    j++;
    printf("  AddrType: %d\n", buffer[j]);
    j++;
    printf("  Addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
     buffer[j+5],buffer[j+4],buffer[j+3],
     buffer[j+2],buffer[j+1],buffer[j]);
    j += 6;
    length_data = buffer[j];
    printf("  Length_Data %d\n", length_data);
    j++;
    printf("  Data:");
    l = 0;
    for(k=0; k<length_data;k++){
      if(l==0){
        printf("\n");
        l = buffer[j];
        switch(buffer[j+1]){
        case 0x1: // Vol.3 Part C 18.1
          printf("    Flags: ");
          break;
        case 0x2: // Vol.3 Part C 18.2
        case 0x3:
        case 0x4:
        case 0x5:
        case 0x6:
        case 0x7:
          printf("    UUID: ");
          break;
        case 0x8:
        case 0x9:
          printf("    Local Name: ");
          break;
        case 0xa:
          printf("    TX Power: ");
          break;
        default:
          printf("    %02x: ", buffer[j+1]);
          break;
        }
      }else{
        l--;
        printf("%02x ", buffer[j]);
      }
      j++;
    }
    sig_str = ((char*)buffer)[j];
    printf("\n  ");

    printf("RSSI: %x (%d db)\n", buffer[j], sig_str);
  }
  return 0;
}

/**
   Vol.2/Part E/7.8.27
 */
static int
le_read_supported_status(int s)
{
	ng_hci_le_read_supported_status_rp rp;
	int e;
	int n = sizeof(rp);
	e = hci_simple_request(s,
			       NG_HCI_OPCODE(NG_HCI_OGF_LE,
					     NG_HCI_OCF_LE_READ_SUPPORTED_STATUS),
			       (void *)&rp, &n);
	printf("* LE_Read_Supported_Feature_Status: %d %d %lx\n", e, rp.status, rp.le_status);

	return 0;

}


/**
   Vol.2/Part E/7.8.11
 */
static int
le_set_scan_enable(int s, int enable)
{
  ng_hci_le_set_scan_enable_cp cp;
  ng_hci_le_set_scan_enable_rp rp;
  int e,n;

  cp.le_scan_enable = enable;
  cp.filter_duplicates = 0;
  n = sizeof(rp);
  e = hci_request(s, NG_HCI_OPCODE(NG_HCI_OGF_LE,
           NG_HCI_OCF_LE_SET_SCAN_ENABLE),
      (void *)&cp, sizeof(cp), (void *)&rp, &n);

  printf("* LE_Set_Scan_Enable: %d %d %d %d\n", enable, e, rp.status, n);
  return 0;

}

static int
open_socket(char *node)
{
  struct sockaddr_hci addr;
  int s;
  struct ng_btsocket_hci_raw_filter flt;
  socklen_t slen;

  s = socket(PF_BLUETOOTH, SOCK_RAW, BLUETOOTH_PROTO_HCI);
  if(s < 0)
    err(2, "Could not create socket");

  memset(&addr, 0, sizeof(addr));
  addr.hci_len = sizeof(addr);
  addr.hci_family = AF_BLUETOOTH;

  strncpy(addr.hci_node, node, sizeof(addr.hci_node));
  if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    err(2, "Could not bind socket, node=%s", node);

  if (connect(s, (struct sockaddr *) &addr, sizeof(addr)) < 0)
    err(3, "Could not connect socket, node=%s", node);

  slen = sizeof(flt);
  if (getsockopt(s, SOL_HCI_RAW, SO_HCI_RAW_FILTER,  &flt, &slen) < 0) {
    perror("Can't set HCI filter");
    exit(1);
  }

  bit_set(flt.event_mask, NG_HCI_EVENT_LE -1);
  if (setsockopt(s, SOL_HCI_RAW, SO_HCI_RAW_FILTER,  &flt, sizeof(flt)) < 0) {
    perror("Can't set HCI filter");
    exit(1);
  }

  return s;
}

static int
le_l2connect(bdaddr_t *bd, int addr_type)
{
  struct sockaddr_l2cap l2c;
  int s;

  s = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
  l2c.l2cap_len = sizeof(l2c);
  l2c.l2cap_family = AF_BLUETOOTH;
  l2c.l2cap_psm = 0;
  l2c.l2cap_cid = NG_L2CAP_ATT_CID;
  l2c.l2cap_bdaddr_type = (addr_type == 0 ? BDADDR_LE_PUBLIC : BDADDR_LE_RANDOM);
  bcopy(bd, &l2c.l2cap_bdaddr, sizeof(*bd));

  if(connect(s, (struct sockaddr *) &l2c, sizeof(l2c))!= 0){
    perror("connect");
    return -1;
  }

  return 0;
}

static int
usage()
{
  fprintf(stderr, "le_enable [-a bd_addr] [-n node] [-p] [-r]\n");
  exit(1);
}
int
main(int argc, char *argv[])
{
  int s, s2;
  char *node = "ubt0hci";
  int has_bdaddr = 0;
  int peer_addr_type = 0;
  bdaddr_t bd;
  int ch;

  while((ch = getopt(argc, argv, "a:n:pr")) != -1){
    switch(ch){
    case 'a':
      has_bdaddr = bt_aton(optarg, &bd);
      break;
    case 'n':
      node = strdup(optarg);
      break;
    case 'p':
      peer_addr_type = 0;
      break;
    case 'r':
      peer_addr_type = 1;
      break;
    case '?':
    default:
      usage();
    }
  }
  s = open_socket(node);

  /* Vol.6 Part D 2.1 INITIAL SETUP */
  le_read_local_supported_features(s);
  set_event_mask(s,0x20001fffffffffff);
  le_set_event_mask(s, 0x1f);
  le_read_buffer_size(s);
  le_read_supported_status(s);
  read_bd_addr(s, NULL);

  /* Vol.6 Part D 4.1 PASSIVE SCANNING */
  le_set_scan_param(s, 0, 0x12, 0x12, peer_addr_type, 0);

  le_set_scan_enable(s,1);
  le_scan_result(s);
  le_set_scan_enable(s,0);

  if(has_bdaddr){
    s2 = le_l2connect(&bd, peer_addr_type);
    /* some code here*/
    close(s2);
  }
  close(s);
  return 0;
}


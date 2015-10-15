/*
 * transport.c
 *
 * CS536 PA2 (Reliable Transport)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "mysock_impl.h"
#include "stcp_api.h"
#include "transport.h"
#include <sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>


#ifndef LOCAL_WINDOW_SIZE
#define LOCAL_WINDOW_SIZE 3072
#endif

#ifndef DEBUG
#define DEBUG true
#endif

#ifndef HEADER_SIZE
#define HEADER_SIZE 20
#endif

#ifndef PACKET_SIZE
#define PACKET_SIZE 536
#endif

#ifndef TIMEOUT
#define TIMEOUT 1000
#endif
enum STATE { CSTATE_ESTABLISHED, CSTATE_FIN_WAIT1, CSTATE_FIN_WAIT2,CSTATE_CLOSE_WAIT, CSTATE_LAST_ACK, TIMEWAIT };    /* obviously you should have more states */



typedef struct packet_t {
    struct timeval sent;
    packet_t *next;
    packet_t *prev;
    size_t len;
    uint32_t tries;
    tcp_seq seq;
    char *payload;
} packet;
/* this structure is global to a mysocket descriptor */
typedef struct {
    bool_t done;    /* TRUE once connection is closed */
    bool_t r_fin;
    bool_t l_fin;
    bool_t is_active;
    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */
    tcp_seq th_local, th_remote, send_base;
} context_t;

/********************** MY GLOBAL ADDITIONS **************************/
int length=-1;
// double transmitted=0.0, current=0.0;
// bool_t isctrl = true;
uint16_t window;
tcp_seq last_ack;
STATE current_state;

typedef struct wqueue {
    uint32_t front;
    uint32_t back;
    uint32_t size;
    uint32_t max;
    packet_t *buffer;
} queue;


typedef struct ooorder {
  packet_t *tail;
  packet_t *head;
} outoforder;



static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
// static void clear_hdr(tcphdr *);
// static int enqueue(wqueue *, tcphdr *, char *, size_t);
// static packet_t *dequeue(wqueue *);
// // static void print_packet(char *);
// // static void print_queue(wqueue *);
// void cumulative_ack(wqueue *, tcp_seq);
// int check_timeout(wqueue *);
// unsigned long int tv2ms(struct timeval *);
// void retransmit_ack(mysocket_t, wqueue *, tcp_seq);
// uint32_t scanbuffer(wqueue *);
// void insert(ooorder *, packet_t *);
// void remove(ooorder *r_buf, tcp_seq);
// // void print_ooorder(ooorder *);
// int topinorder(mysocket_t, ooorder *, tcp_seq);
// // void get_fsize(char *line);
// // void print_progress(double);

unsigned long int tv2ms(struct timeval *a) {
    return ((a->tv_sec * 1000) + (a->tv_usec / 1000));
} // tv2ms()

unsigned short int checksum(char *addr, int count)
{
  register int sum = 0;

  // Main summing loop
  while(count > 1)
  {
    addr++;
    sum = sum + *((unsigned short int*) addr);
    count = count - 2;
  }

  // Add left-over byte, if any
  if (count > 0)
    sum = sum + *((char *) addr);

  // Fold 32-bit sum to 16 bits
  while (sum>>16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return(~sum);
}
/********************************************************************/

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */

tcphdr* convert_to_network(tcphdr* hdr){

  struct tcphdr *t = (struct tcphdr *) calloc(1, sizeof(struct tcphdr));
  memcpy(t, hdr, sizeof(struct tcphdr));
  t->th_seq = htonl(hdr->th_seq);
  t->th_ack = htonl(hdr->th_ack);
  t->th_win = htons(hdr->th_win);
  t->th_sum = htons(hdr->th_sum);
  return t;
}

tcphdr* convert_to_host(tcphdr* hdr){
  struct tcphdr *t = (struct tcphdr *) calloc(1, sizeof(struct tcphdr));
  memcpy(t, hdr, sizeof(struct tcphdr));
  t->th_seq = ntohl(hdr->th_seq);
  t->th_ack = ntohl(hdr->th_ack);
  t->th_win = ntohs(hdr->th_win);
  t->th_sum = ntohs(hdr->th_sum);
  return t;
}

char check(wqueue *queue){
  if(queue->size == 0){
    return 'z';
  }
  else
    return 'n';
}
packet_t *dequeue(wqueue *queue) {
  packet_t *p = NULL;
  switch (check(queue)) {
    case 'z':
      p = NULL;
      break;
    case 'n':
      p = &(queue->buffer[queue->front]);
      while(true){
        queue->front = (queue->front+1) % queue->max;
        queue->size -= p->len;
        break;
      }
      break;
    default :
      break;
  }

  return p;
}

int check_list1(packet_t* start){
  if(start->next == NULL){
    return 1;
  }
  return 2;
}


int check_list2(packet_t* start){
  if(start->prev == NULL){
    return 1;
  }
  return 2;
}


void remove_from_linked_list1(packet_t* start, ooorder* r_buf){
  switch (check_list1(start)) {
    case 1:
      r_buf->tail = start->prev;
      if (r_buf->tail != NULL) {
        r_buf->tail->next = NULL;
      }
      break;
    case 2:
      start->next->prev = start->prev;
      break;
  }
}

void remove_from_linked_list2(packet_t* start, ooorder* r_buf){
  switch (check_list2(start)) {
    case 1:
      r_buf->head = start->next;
      if (r_buf->head != NULL){
         r_buf->head->prev = NULL;
       }
       break;
    case 2:
      start->prev->next = start->next;
      break;
  }
}

void remove(ooorder *r_buf, tcp_seq seq) {
  packet_t *start = r_buf->head;
  for(;;){
    if (start != NULL) {
        if (start->seq == seq) {
          remove_from_linked_list1(start, r_buf);
          remove_from_linked_list2(start, r_buf);
        }
        start = start->next;
    }
    else{
      break;
    }
  }
}


void transport_init(mysocket_t sd, bool_t is_active)
  {
      context_t *ctx;

      ctx = (context_t *) calloc(1, sizeof(context_t));
      assert(ctx);

      generate_initial_seq_num(ctx);

      ctx->th_local  = ctx->initial_sequence_num+1;
      ctx->send_base = ctx->initial_sequence_num+1;

      ctx->l_fin = false, ctx->r_fin = false;
      struct tcphdr *snd_header = (struct tcphdr *) calloc(1, sizeof(struct tcphdr));
      struct tcphdr *rcv_header = (struct tcphdr *) calloc(1, sizeof(struct tcphdr));
      struct tcphdr *t;
      if(is_active){
        //Send a SYN packet
        ctx->is_active = true;
        snd_header->th_flags = TH_SYN;
        //seq = x
        snd_header->th_seq = ctx->initial_sequence_num;
        snd_header->th_win = LOCAL_WINDOW_SIZE;
        window = LOCAL_WINDOW_SIZE;
        if (DEBUG) {
          fprintf(stderr, "sending: seq = %d\n", snd_header->th_seq);
        }

        // t = convert_to_network(snd_header);
        t = convert_to_network(snd_header);
        stcp_network_send(sd, (void *) t, sizeof(struct tcphdr), NULL);
        //Recieve the response for SYN
        stcp_network_recv(sd, (void *)rcv_header, sizeof(struct tcphdr));
        rcv_header = convert_to_host(rcv_header);


        //Handle erro for fail handshake
        if (rcv_header->th_flags != (TH_SYN | TH_ACK)) {
          snd_header->th_flags = TH_FIN;
          stcp_network_send(sd, (void *)convert_to_network(snd_header), sizeof(struct tcphdr), NULL);
          errno = ECONNREFUSED;
          perror("erro for fail handshake");
          return;
        }else if (snd_header->th_seq + 1 != rcv_header->th_ack){
          snd_header->th_flags = TH_FIN;
          stcp_network_send(sd, (void *)convert_to_network(snd_header), sizeof(struct tcphdr), NULL);
          errno = ECONNREFUSED;
          perror("erro for fail handshake");
          return;
        }
        snd_header->th_flags = TH_ACK;
        snd_header->th_seq = rcv_header->th_ack;
        snd_header->th_ack = rcv_header->th_seq + 1;
        if (DEBUG) {
          fprintf(stderr, "sending: seq = %d ack = %d\n", snd_header->th_seq, snd_header->th_ack);
        }

        stcp_network_send(sd, (void *)convert_to_network(snd_header), sizeof(struct tcphdr), NULL);
        ctx->th_remote = rcv_header->th_seq+1;
      } else{
        ctx->is_active = false;
        //Wait for one to arrive

        stcp_network_recv(sd, (void *)rcv_header, sizeof(struct tcphdr));
        rcv_header = convert_to_host(rcv_header);
        ctx->th_remote = rcv_header->th_seq+1;
        window = rcv_header->th_win;
        // snd_header = rcv_header;
        if (rcv_header->th_flags != TH_SYN) {
          snd_header->th_flags = TH_FIN;
          stcp_network_send(sd, (void *)convert_to_network(snd_header), sizeof(struct tcphdr), NULL);
          return;
        }else if(rcv_header->th_seq > 255){
          snd_header->th_flags = TH_FIN;
          stcp_network_send(sd, (void *)convert_to_network(snd_header), sizeof(struct tcphdr), NULL);
          return;
        }

        snd_header->th_flags = TH_SYN|TH_ACK;
        // seq = y
        snd_header->th_seq = ctx->initial_sequence_num;
        // ack = rcv_header seq + 1
        snd_header->th_ack = rcv_header->th_seq + 1;
        if (DEBUG) {
          fprintf(stderr, "sending: seq = %d ack = %d\n", snd_header->th_seq, snd_header->th_ack);
        }

        stcp_network_send(sd, (void *)convert_to_network(snd_header), sizeof(struct tcphdr), NULL);
        stcp_network_recv(sd, (void *)rcv_header, sizeof(struct tcphdr));
        rcv_header = convert_to_host(rcv_header);


        if (rcv_header->th_flags != TH_ACK) {
            errno = ECONNREFUSED; perror("erro for fail handshake");
            return;
        }

      }
      ctx->connection_state = CSTATE_ESTABLISHED;
      stcp_unblock_application(sd);


      ctx->th_local++;
      ctx->th_remote++;
      ctx->send_base = ctx->th_local;
      current_state = CSTATE_ESTABLISHED;
      control_loop(sd, ctx);

      /* do any cleanup here */
      free(ctx);
      free(snd_header);
      free(rcv_header);
  }


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx) {
    assert(ctx);
    int t = 0;
    #ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
    #else
    /* you have to fill this up */
    srand(*(unsigned int *)&t);
    int r = rand();
    ctx->initial_sequence_num = r%256;
    #endif
}

 void cumulative_ack(wqueue *queue, tcp_seq ack) {
   // printf("*********ACK: %d********\n", ack);
   // print_queue(queue);
   uint32_t i = queue->front;
   while( i<queue->back ) {
       if (queue->buffer[i].seq < ack -1) {
         dequeue(queue);
       }
       else break;
       i++;
   }
 }




 char sw(packet_t* start, tcp_seq seq){
   if (start->seq < seq){
     return 'l';
   }
   else if(start->seq == seq){
     return 'e';
   }
   return 'u';
 }

 int correct_list(mysocket_t sd, ooorder *r_buf, tcp_seq seq, packet_t * start){
   int newack = -2;
   for (;;) {
     if(start == NULL)
       break;
     switch (sw(start, seq)) {
       case 'l':
         remove(r_buf, start->seq);
         break;
       case 'e':
         char data[PACKET_SIZE-HEADER_SIZE] = {0};
         memcpy(data, start->payload, start->len);
         stcp_app_send(sd, data, start->len);

         newack = start->seq + start->len;
         tcp_seq t = seq;
         seq += start->len;
         remove(r_buf, t);

         break;
     }
     start = start->next;
   }
   return newack;
 }
 int topinorder(mysocket_t sd, ooorder *r_buf, tcp_seq seq) {
     int newack = -2;
     packet_t *start;
     start = r_buf->head;
     newack = correct_list(sd, r_buf, seq, start);
     return newack;
 }


 bool_t check_has_head(ooorder *r_buf){
   if(r_buf->head == NULL){
     return false;
   }
   return true;
 }
 void insert(ooorder *r_buf,  packet_t *pack) {
    switch (check_has_head(r_buf)) {
      case false:
        pack->next = NULL;
        pack->prev = NULL;
        r_buf->head = pack;
        r_buf->tail = pack;
      break;
        case true:
        pack->next = NULL;
        pack->prev = r_buf->tail;
        pack->prev->next = pack;
        r_buf->tail = pack;
        break;
    }
 }

 void retransmit_ack(mysocket_t sd, wqueue *queue, tcp_seq ack) {
     uint i = queue->front;
     uint end = queue->back;
     while ( i < end ){
         if (queue->buffer[i].seq < ack){
             stcp_network_send(sd, queue->buffer[i].payload, PACKET_SIZE, NULL);
           }
           i++;
         }
 }

 void clear_hdr(tcphdr *hdr) {
   while(true){
     hdr->th_flags = 0;
     hdr->th_ack = 0;
     hdr->th_seq = 0;
     hdr->th_win = 0;
     break;
   }
 }

 int check_timeout(wqueue *queue) {
     struct timeval now;
     uint32_t i = queue->front;
     uint32_t end = queue->back;
     gettimeofday(&now, NULL);
     while ( i < end ) {
         if (queue->buffer[i].tries == 40){
           return -2;
         }
         for(;;){
           if ( ( tv2ms(&now) - tv2ms(&queue->buffer[i].sent) ) > TIMEOUT )
               return i;
            break;
           }
         i++;
     }
     return -1;
 }

 packet_t init_packet(tcphdr *hdr, ssize_t len, size_t length, char* packet){
   packet_t pack;
   gettimeofday(&pack.sent, NULL);
   pack.seq = hdr->th_seq;
   pack.payload = (char *) malloc(len);
   pack.tries = 1;
   pack.len = length;
   memcpy(pack.payload, packet, len);
   return pack;
 }
 void add_to_queue(wqueue *queue, ssize_t len, packet_t pack){
   queue->size += len-HEADER_SIZE;
   queue->buffer[queue->back] = pack;
   queue->back = (queue->back+1) % queue->max;
 }

 char* combine_packet(tcphdr* hdr, char* data, ssize_t len){
   char *packet = (char *) calloc(1, len);
   memcpy(packet, hdr, sizeof(tcphdr));
   if( *data != '\0' )
    memcpy(&packet[HEADER_SIZE], data, len-HEADER_SIZE);
  else
    memcpy(&packet[HEADER_SIZE], data, len-HEADER_SIZE);
   return packet;
 }

 int enqueue(wqueue *queue, tcphdr *hdr, char *data, size_t length) {
     ssize_t len = length+HEADER_SIZE;
     char* packet = combine_packet(hdr, data, len);
     packet_t pack = init_packet(hdr, len, length, packet);
     add_to_queue(queue, len, pack);
     return len;
 }

char temp(context_t *ctx, tcphdr *hdr){
  if (ctx->send_base < hdr->th_ack && ctx->l_fin && ctx->r_fin) {
    return 't';
  }

  if(ctx->send_base < hdr->th_ack){
    return 'r';
  }
  if (ctx->l_fin && ctx->r_fin) {
    return 'c';
  }
}

void send_ack(tcphdr *hdr, mysocket_t sd, tcp_seq remote){
  hdr->th_flags = TH_ACK;
  hdr->th_ack = remote;
  stcp_network_send(sd, convert_to_network(hdr), HEADER_SIZE, NULL);
}

packet_t* record(tcp_seq seq, size_t rcvd, char* data, ooorder r_buf){
  packet_t *pack = (packet_t *) calloc(1, sizeof(packet_t));
  pack->seq = seq;
  pack->len = rcvd;
  pack->payload = (char *) malloc(rcvd);
  memcpy(pack->payload, data, rcvd);
  return pack;
}
static void control_loop(mysocket_t sd, context_t *ctx) {
    assert(ctx);
    tcphdr *hdr;
    hdr = (tcphdr *) calloc(1, sizeof(tcphdr));
    wqueue s_queue;
    s_queue.front = ctx->th_local;
    s_queue.back = ctx->th_local;
    s_queue.size = 0;
    s_queue.max = window;
    s_queue.buffer = (struct packet_t *) calloc(window, sizeof(struct packet_t));
    ooorder r_buf;
    r_buf.head = NULL;
    r_buf.tail = NULL;
    timespec to;
    to.tv_sec = time(NULL) + 2;
    to.tv_nsec = 0;
    timespec t;
    t.tv_sec = time(NULL) + 2;
    t.tv_nsec = 0;
    while (!ctx->done)
    {
        unsigned int event = 0;
        event = stcp_wait_for_event(sd, APP_DATA | NETWORK_DATA, &t);
        if (event & APP_DATA) {
            if (ctx->th_local < ctx->send_base + window) {
                if(window > 0){
                  hdr->th_win = window;
                }
                hdr->th_seq = ctx->th_local;
                char data[PACKET_SIZE - HEADER_SIZE] = {0};

                size_t len = stcp_app_recv(sd, data, (PACKET_SIZE - HEADER_SIZE));

                hdr->th_sum = checksum(data, len);
                size_t sent = stcp_network_send(sd, convert_to_network(hdr), HEADER_SIZE, data, len, NULL)-HEADER_SIZE;
                enqueue(&s_queue, convert_to_network(hdr), data, sent);
                printf("Send: %d\n",hdr->th_seq );
                last_ack = hdr->th_seq;

                ctx->th_local += sent;

                clear_hdr(hdr);
            }
        }
        if (event & NETWORK_DATA) {
            char buf[PACKET_SIZE] = {0};
            size_t rcvd = stcp_network_recv(sd, buf, PACKET_SIZE)-HEADER_SIZE;
            memcpy(hdr, buf, HEADER_SIZE);
            hdr = convert_to_host(hdr);
            char data[PACKET_SIZE - HEADER_SIZE] = {0};

            memcpy(data, &(buf[HEADER_SIZE]), rcvd);
            bool_t flag = false;
            switch(current_state){
              case CSTATE_FIN_WAIT1:
                if(hdr->th_ack-hdr->th_seq == 1){
                  printf("%d %d CSTATE_FIN_WAIT1\n",hdr->th_seq,hdr->th_ack );
                  current_state = CSTATE_FIN_WAIT2;
                }
                else
                  continue;
                break;
              case CSTATE_FIN_WAIT2:
                if(hdr->th_flags == TH_FIN){
                  stcp_fin_received(sd);
                  flag = true;
                  hdr->th_ack = hdr->th_seq + 1;
                  printf("SEND: %d %d CSTATE_FIN_WAIT2\n",hdr->th_seq, hdr->th_ack );
                  stcp_network_send(sd, (void *)convert_to_network(hdr), sizeof(struct tcphdr), NULL);
                  current_state = TIMEWAIT;
                }
                else
                  continue;
                break;

              case CSTATE_LAST_ACK:
                if(hdr->th_flags == TH_FIN){
                  stcp_fin_received(sd);
                  flag = true;
                }
                else
                  continue;
                break;
            }

            if(flag)
              break;
            if( ctx->is_active && hdr->th_sum != checksum(data,rcvd)){
              hdr->th_flags = TH_ACK;
              hdr->th_ack = ctx->th_remote;
              stcp_network_send(sd, convert_to_network(hdr), HEADER_SIZE, NULL);
              continue;
            }
            if (hdr->th_flags == TH_ACK && hdr->th_ack < (ctx->th_local+window-1) ) {

              bool_t f = false;
              switch (temp(ctx, hdr)) {
                case 't':
                  ctx->send_base = hdr->th_ack;
                  cumulative_ack(&s_queue, hdr->th_ack);
                  retransmit_ack(sd, &s_queue, hdr->th_ack);
                  ctx->done = true;
                  f = true;
                  break;
                case 'r':
                  ctx->send_base = hdr->th_ack;
                  cumulative_ack(&s_queue, hdr->th_ack);
                  retransmit_ack(sd, &s_queue, hdr->th_ack);
                  break;
                case 'c':
                  ctx->done = true;
                  f = true;
                  break;
              }
              if(f){
                continue;
              }
            }
            else if (hdr->th_seq < (ctx->th_remote+window-1)) {
                if (hdr->th_seq >= ctx->th_remote){
                  packet_t *pack = record(hdr->th_seq, rcvd, data, r_buf);
                  insert(&r_buf, pack);
                }
                if (hdr->th_flags == TH_FIN) {
                    if (!ctx->l_fin) {
                        hdr->th_ack = hdr->th_seq + 1;
                        stcp_network_send(sd, (void *)convert_to_network(hdr), sizeof(struct tcphdr), NULL);
                        current_state = CSTATE_CLOSE_WAIT;

                        hdr->th_ack = hdr->th_ack+1;
                        hdr->th_seq = hdr->th_seq+1;

                        stcp_network_send(sd, (void *)convert_to_network(hdr), sizeof(struct tcphdr), NULL);
                        current_state = CSTATE_LAST_ACK;
                    }
                    ctx->r_fin = true;
                }
                else if (ctx->th_remote == hdr->th_seq) {
                    hdr->th_flags = TH_ACK;
                    stcp_app_send(sd, data, rcvd);
                    int newack = topinorder(sd, &r_buf, hdr->th_seq+rcvd);
                    if( newack == -2){
                      newack = hdr->th_seq+rcvd;
                      ctx->th_remote = newack;
                    }else{
                      ctx->th_remote = newack;
                    }
                    hdr->th_ack = ctx->th_remote;
                    stcp_network_send(sd,convert_to_network(hdr), HEADER_SIZE, NULL);
                    if (ctx->l_fin){
                      if(ctx->r_fin)
                        ctx->done = true;
                    }
                }
                else if (hdr->th_seq < ctx->th_remote+window-1) {
                  send_ack(hdr, sd, ctx->th_remote);
                }
            }
            clear_hdr(hdr);
        }

        if (event & APP_CLOSE_REQUESTED) {
            char x[] = "";

            if(ctx->is_active){
              current_state = CSTATE_FIN_WAIT1;
              hdr->th_seq = ctx->th_local;
              hdr->th_flags = TH_FIN;
              enqueue(&s_queue, convert_to_network(hdr), x, 0);
              stcp_network_send(sd, convert_to_network(hdr), HEADER_SIZE, NULL);
            }
            else{
              current_state = CSTATE_CLOSE_WAIT;
              hdr->th_seq = ctx->th_local;
              hdr->th_flags = TH_FIN;
              enqueue(&s_queue, convert_to_network(hdr), x, 0);
              stcp_network_send(sd, convert_to_network(hdr), HEADER_SIZE, NULL);
            }
            ctx->l_fin = true;

        }
        int tout = check_timeout(&s_queue);
        if (tout == -2){
          hdr->th_flags = TH_FIN;
          hdr->th_seq = ctx->th_local;
          ctx->l_fin = true;
          char x[] = "";
          enqueue(&s_queue, convert_to_network(hdr), x, 0);
          stcp_network_send(sd, convert_to_network(hdr), HEADER_SIZE, NULL);
          ctx->done = true;
        }
        else if (tout != -1){
          gettimeofday(&(s_queue.buffer[tout].sent), NULL);
          s_queue.buffer[tout].tries += 1;
          stcp_network_send(sd, s_queue.buffer[tout].payload,HEADER_SIZE + s_queue.buffer[tout].len, NULL);
        }
        if (ctx->r_fin) {
          if(ctx->l_fin)
            ctx->done = true;
        }
    }
    if(ctx->is_active){
      stcp_fin_received(sd);
    }
    printf("\nWe are finished!\n\n");
    free(hdr);
}
/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...) {
    printf("our_dprintf\n");
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

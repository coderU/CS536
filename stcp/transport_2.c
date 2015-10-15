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
#define TIMEOUT 500
#endif
enum { CSTATE_ESTABLISHED };    /* obviously you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct {
    bool_t done;    /* TRUE once connection is closed */
    bool_t r_fin, l_fin, is_active;
    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    /* any other connection-wide global variables go here */
    tcp_seq th_local, th_remote, send_base;
} context_t;

/********************** MY GLOBAL ADDITIONS **************************/
int length=-1;
double transmitted=0.0, current=0.0;
bool_t isctrl = true;
uint16_t window;
tcp_seq last_ack;
typedef struct packet_t {
    struct timeval sent;
    uint32_t tries;
    tcp_seq seq;
    char *payload;
    packet_t *next, *prev;
    size_t len;
} Packet;

typedef struct ooorder {
    packet_t *head, *tail;
} OOOrder;

typedef struct wqueue {
    uint32_t front, back, size, max;
    packet_t *buffer;
} Queue;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static void clear_hdr(tcphdr *);
static int enqueue(wqueue *, tcphdr *, char *, size_t);
static packet_t *dequeue(wqueue *);
static void print_packet(char *);
static void print_queue(wqueue *);
void cumulative_ack(wqueue *, tcp_seq);
int check_timeout(wqueue *);
unsigned long int tv2ms(struct timeval *);
void retransmit_ack(mysocket_t, wqueue *, tcp_seq);
uint32_t scanbuffer(wqueue *);
void insert(ooorder *, packet_t *);
void remove(ooorder *r_buf, tcp_seq);
void print_ooorder(ooorder *);
int topinorder(mysocket_t, ooorder *, tcp_seq);
void get_fsize(char *line);
void print_progress(double);


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

        //Hand Shake successful, send back acknowledgement
        //ack = rcv_header seq +1
        //seq = rcv_header ack
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
        printf("aaaa\n" );

        stcp_network_recv(sd, (void *)rcv_header, sizeof(struct tcphdr));
        rcv_header = convert_to_host(rcv_header);
        ctx->th_remote = rcv_header->th_seq+1;
        window = rcv_header->th_win;
        // snd_header = rcv_header;
        if (rcv_header->th_flags != TH_SYN || rcv_header->th_seq > 255) {
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

/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx) {
    assert(ctx);

    // use this header when parsing the incoming TCP header, or for
    // constructing an
    // outgoing SEGMENT
    tcphdr *hdr;
    hdr = (tcphdr *) calloc(1, sizeof(tcphdr));

    // this is the queue of outgoing segments from the sender
    wqueue s_queue;
    s_queue.front = ctx->th_local;
    s_queue.back = ctx->th_local;
    s_queue.size = 0;
    s_queue.max = window;
    s_queue.buffer = (struct packet_t *) calloc(window, sizeof(struct packet_t));

    // a linked list of out of order segments received by receiver
    ooorder r_buf;
    r_buf.head = NULL;
    r_buf.tail = NULL;

    // timeout for event
    timespec to;
    while (!ctx->done)
    {
        unsigned int event = 0;

        // set up timeout values and call wait_for_event()
        to.tv_sec = time(NULL) + 2;
        to.tv_nsec = 0;
        event = stcp_wait_for_event(sd, APP_DATA | NETWORK_DATA, &to);

        // received data from network layer
        if (event & NETWORK_DATA) {
            // read the segment into this buffer (SHOULDNT be larger than
            // PACKET_SIZE)
            char buf[PACKET_SIZE] = {0};
            // payload from segment
            char data[PACKET_SIZE - HEADER_SIZE] = {0};
            size_t rcvd = stcp_network_recv(sd, buf, PACKET_SIZE)-HEADER_SIZE;

            // copy into appropriate locations
            memcpy(hdr, buf, HEADER_SIZE);
            memcpy(data, &(buf[HEADER_SIZE]), rcvd);
            if( ctx->is_active && ntohs(hdr->th_sum) != checksum(data,rcvd)){
              // printf("%d %d\n",ntohs(hdr->th_sum),checksum(data,rcvd) );
              hdr->th_flags = TH_ACK;
              hdr->th_ack = ctx->th_remote;
              // printf("ACK: %d\n", hdr->th_ack);

              stcp_network_send(sd, hdr, HEADER_SIZE, NULL);
              continue;
            }
            /* ACK received */
            if (hdr->th_flags == TH_ACK && hdr->th_ack < (ctx->th_local+window-1) ) {
                if (ctx->l_fin && ctx->r_fin) {  // last ACK from 4 way term
                    ctx->done = true;
                    continue;
                }

                // received an ack larger than the sendbase, receiver is ahead
                if (ctx->send_base < hdr->th_ack) {
                    ctx->send_base = hdr->th_ack;
                    // remove everything up to this ACK from sender buffer and
                    // retransmit
                    cumulative_ack(&s_queue, hdr->th_ack);
                    retransmit_ack(sd, &s_queue, hdr->th_ack);
                }
            }
            // data received inside window, send ACK, buffer if out of order
            else if (hdr->th_seq < (ctx->th_remote+window-1)) {
                if (isctrl && ctx->is_active) {
                    isctrl = false;
                    char *copy = strdup(data);
                    get_fsize(copy);
                    free(copy);
                    if (length == -1) {
                        mysock_context_t *ctx_s = _mysock_get_context(sd);
                        ctx_s->close_requested = true;
                        continue;
                    }
                    else
                        transmitted -= strlen(data);

                }
                // printf("%d %d\n", hdr->th_seq, ctx->th_remote);
                // insert this segment into out of order buffer
                if (hdr->th_seq >= ctx->th_remote){
                  packet_t *pack = (packet_t *) calloc(1, sizeof(packet_t));
                  pack->seq = hdr->th_seq;
                  pack->len = rcvd;
                  pack->payload = (char *) malloc(rcvd);
                  memcpy(pack->payload, data, rcvd);
                  insert(&r_buf, pack);
                }
                // received FIN
                if (hdr->th_flags == TH_FIN) {
                    if (!ctx->l_fin) {
                        mysock_context_t *ctx_s = _mysock_get_context(sd);
                        ctx_s->close_requested = true;
                    }
                    ctx->r_fin = true;
                }
                // correct next packet
                else if (ctx->th_remote == hdr->th_seq) {
                    hdr->th_flags = TH_ACK;
                    // send data to app
                    transmitted += rcvd;
                    print_progress(transmitted);

                    stcp_app_send(sd, data, rcvd);
                    // obtain the proper ACK (if there are more packets that
                    // were received out of order
                    int newack = topinorder(sd, &r_buf,
                                            hdr->th_seq+rcvd);
                    newack = newack == -2 ?
                        hdr->th_seq+rcvd : newack;


                    ctx->th_remote = newack;
                    hdr->th_ack = ctx->th_remote;
                    // printf("ACK: %d\n", hdr->th_ack);
                    stcp_network_send(sd,hdr, HEADER_SIZE, NULL);
                    if (ctx->l_fin){
                      if(ctx->r_fin)
                        ctx->done = true;
                    }
                }
                // if this segment has already been ACK'd send another

                // else if (hdr->th_seq < ctx->th_remote) {
                else if (hdr->th_seq < ctx->th_remote+window-1) {
                    hdr->th_flags = TH_ACK;
                    hdr->th_ack = ctx->th_remote;
                    // printf("ACK: %d\n", hdr->th_ack);

                    stcp_network_send(sd, hdr, HEADER_SIZE, NULL);
                }
            }
            clear_hdr(hdr);
        } // if (NETWORK_DATA)

        // APP sending data
        if (event & APP_DATA) {
            /* the application has requested that data be sent */
            if (ctx->th_local < ctx->send_base + window) {
                // get data for this packet
                char data[PACKET_SIZE - HEADER_SIZE] = {0};
                size_t len = stcp_app_recv(sd, data,
                                            (PACKET_SIZE - HEADER_SIZE));

                // construct header for this packet
                hdr->th_seq = ctx->th_local;
                hdr->th_win = window;
                hdr->th_sum = htons( checksum(data, len) );
                size_t sent = stcp_network_send(sd, hdr, HEADER_SIZE, data, len, NULL)-HEADER_SIZE;
                printf("Send: %d\n",hdr->th_seq );
                last_ack = hdr->th_seq;
                enqueue(&s_queue, hdr, data, sent);
                ctx->th_local += sent;

                clear_hdr(hdr);
            }
        } // if (APP_DATA)

        // APP_CLOSE
        if (event & APP_CLOSE_REQUESTED) {
            hdr->th_flags = TH_FIN;
            hdr->th_seq = ctx->th_local;
            ctx->l_fin = true;
            char x[] = "";
            enqueue(&s_queue, hdr, x, 0);
            stcp_network_send(sd, hdr, HEADER_SIZE, NULL);
            ctx->done = true;
        } // if (APP_CLOSE_REQUESTED)

        // check for timeouts, retransmit
        int tout = check_timeout(&s_queue);
        if (tout == -2){
          hdr->th_flags = TH_FIN;
          hdr->th_seq = ctx->th_local;
          ctx->l_fin = true;
          char x[] = "";
          enqueue(&s_queue, hdr, x, 0);
          stcp_network_send(sd, hdr, HEADER_SIZE, NULL);
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
    printf("\nDONE!\n\n");
    free(hdr);
} // control_loop()



// insert a segment into the receiver out of order buffer
void insert(ooorder *r_buf,  packet_t *pack) {
    if (r_buf->head == NULL) {
        pack->next = NULL;
        pack->prev = NULL;
        r_buf->head = pack;
        r_buf->tail = pack;
    }
    else {
        pack->next = NULL;
        pack->prev = r_buf->tail;
        pack->prev->next = pack;
        r_buf->tail = pack;
    }
}

// remove element from receiver out of order linked list
// also removes any duplicates
void remove(ooorder *r_buf, tcp_seq seq) {
    packet_t *start = r_buf->head;
    while (start != NULL) {
        if (start->seq == seq) {
            if (start->prev == NULL) {
                r_buf->head = start->next;
                if (r_buf->head != NULL) r_buf->head->prev = NULL;
            }
            else start->prev->next = start->next;

            if (start->next == NULL) {
                r_buf->tail = start->prev;
                if (r_buf->tail != NULL) r_buf->tail->next = NULL;
            }
            else start->next->prev = start->prev;
        }
        start = start->next;
    }
} // remove()

// check for in order packets past the newest receieved
int topinorder(mysocket_t sd, ooorder *r_buf, tcp_seq seq) {
    // uhhhh........
    int newack = -2;
    packet_t *start;
    do {
        start = r_buf->head;
        while (start != NULL) {
            if (start->seq < seq)
                remove(r_buf, start->seq);

            else if (start->seq == seq) {
                char data[PACKET_SIZE-HEADER_SIZE] = {0};
                memcpy(data, start->payload, start->len);

                transmitted += start->len;
                print_progress(transmitted);

                stcp_app_send(sd, data, start->len);

                newack = start->seq + start->len;
                remove(r_buf, seq);
                seq += start->len;
            }
            start = start->next;
        }
    } while(start != NULL);

    return newack;
} // topinorder()

// retransmits all packets in the senders buffer less than ack
void retransmit_ack(mysocket_t sd, wqueue *queue, tcp_seq ack) {
    uint i = queue->front;
    for (; i<queue->back; i++)
        if (queue->buffer[i].seq < ack)
            stcp_network_send(sd, queue->buffer[i].payload, PACKET_SIZE, NULL);
} // retransmit_ack()

// print the receiver buffer (DEBUG)
void print_ooorder(ooorder *r_buf) {
    packet_t *start = r_buf->head;
    while (start != NULL) {
        printf("SEQ: %d\n", start->seq);
        start = start->next;
    }

} // print_ooorder()

// resets a header to all 0's
void clear_hdr(tcphdr *hdr) {
    hdr->th_flags = 0;
    hdr->th_ack = 0;
    hdr->th_seq = 0;
    hdr->th_win = 0;
} // clear_hdr()

// find the first segment to have timed out and returns its index
int check_timeout(wqueue *queue) {
    struct timeval now;
    uint32_t i = queue->front;
    uint32_t end = queue->back;
    gettimeofday(&now, NULL);
    while ( i < end ) {
        if (queue->buffer[i].tries == 20) return -2;
        if ( ( tv2ms(&now) - tv2ms(&queue->buffer[i].sent) ) > TIMEOUT )
            return i;
        i++;
    }
    return -1;
} // check_timeout()

// constructs and places an element in the sender queue
int enqueue(wqueue *queue, tcphdr *hdr, char *data, size_t length) {
    ssize_t len = length+HEADER_SIZE;
    char *packet = (char *) calloc(1, len);
    memcpy(packet, hdr, sizeof(tcphdr));
    memcpy(&packet[HEADER_SIZE], data, len-HEADER_SIZE);

    packet_t pack;
    pack.seq = hdr->th_seq;
    pack.payload = (char *) malloc(len);
    gettimeofday(&pack.sent, NULL);
    pack.tries = 1;
    pack.len = length;
    memcpy(pack.payload, packet, len);

    queue->buffer[queue->back] = pack;
    queue->back = (queue->back+1) % queue->max;
    queue->size += len-HEADER_SIZE;

    return len;
} // enqueue()

// removes an elements from the sender queue
packet_t *dequeue(wqueue *queue) {
    if (queue->size == 0)
      return NULL;

    packet_t *p = &(queue->buffer[queue->front]);
    queue->front = (queue->front+1) % queue->max;
    queue->size -= p->len;

    return p;
} // dequeue()


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


// print the sender queue (DEBUG)
void print_queue(wqueue *queue) {
    printf("QUEUE front: %u size: %u\n", queue->front, queue->size);
    uint32_t i=queue->front;
    struct timeval now;
    gettimeofday(&now, NULL);
    for (; i<queue->back; i++) {
        packet_t p = queue->buffer[i];
        printf("______index: %d_______\n", i);
        printf("TIME LEFT: %lu SEQ: %d TRIES: %d\n",tv2ms(&now)-tv2ms(&p.sent), p.seq, p.tries);
    }
} // print_queue()

// prints a packet (DEBUG)
void print_packet(char *packet) {
    tcp_seq seq, ack;
    uint8_t off, flags;
    uint16_t win;

    tcphdr *hdr;
    hdr = (tcphdr *)calloc(1, sizeof(tcphdr));
    memcpy(hdr, packet, HEADER_SIZE);

    char data[PACKET_SIZE-HEADER_SIZE];
    memcpy(data, packet+HEADER_SIZE, strlen(packet+HEADER_SIZE)+1);

    seq=hdr->th_seq;ack=hdr->th_ack;off=hdr->th_off;
    flags=hdr->th_flags;win=hdr->th_win;
    printf("*****************PACKET******************\n");
    printf("SEQ: %u ACK: %u OFF: %d FLAGS: %d WIN: %d\n",
           seq,ack,off,flags,win);
    /* printf("DATA: [%s]", data); */
    printf("\n*****************************************\n");

    free(hdr);
} // print_packet()

/* convert struct timeval to ms(milliseconds) */
/* FROM: http://enl.usc.edu/enl/trunk/peg/testPlayer/timeval.c */
unsigned long int tv2ms(struct timeval *a) {
    return ((a->tv_sec * 1000) + (a->tv_usec / 1000));
} // tv2ms()

void get_fsize(char *line)  {
    char *resp;

    if (NULL == (resp = strrchr(line, ','))) {
        fprintf(stderr, "Malformed response from server.\n");
        length = -1;
    }
    *resp++ = '\0';

    if (NULL == (resp = strrchr(line, ','))) {
        fprintf(stderr, "Malformed response from server.\n");
        length = -1;
    }
    *resp++ = '\0';

    sscanf(resp, "%d", &length);}

void print_progress(double transmitted) {
    if ((transmitted - current) >= 2000 || transmitted == length) {
        current = transmitted;
        printf("%.0f bytes out of %d bytes -- %.0f%%\n",
               transmitted, length, transmitted/length*100);
    }
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

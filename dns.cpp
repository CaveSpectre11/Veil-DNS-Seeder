// Copyright (c) 2009-2018 The Bitcoin Core developers
// Copyright (c) 2009-2018 Bitcoin Developers
// Copyright (c) 2019 The Veil Developers
/*
** Permission is hereby granted, free of charge, to any person obtaining a copy
** of this software and associated documentation files (the "Software"), to deal
** in the Software without restriction, including without limitation the rights
** to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
** copies of the Software, and to permit persons to whom the Software is
** furnished to do so, subject to the following conditions:
**
** The above copyright notice and this permission notice shall be included in
** all copies or substantial portions of the Software.
**
** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
** IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
** FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
** AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
** LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
** OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
** THE SOFTWARE.
*/
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <iostream>

#include "dns.h"

#define BUFLEN 512

#if defined(IP_RECVDSTADDR)
# define DSTADDR_SOCKOPT IP_RECVDSTADDR
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in_addr)))
# define dstaddr(x) (CMSG_DATA(x))
#elif defined(IPV6_PKTINFO)
# define DSTADDR_SOCKOPT IPV6_PKTINFO
# define DSTADDR_DATASIZE (CMSG_SPACE(sizeof(struct in6_pktinfo)))
# define dstaddr(x) (&(((struct in6_pktinfo *)(CMSG_DATA(x)))->ipi6_addr))
#else
# error "can't determine socket option"
#endif

typedef enum {
  CLASS_IN = 1,
  QCLASS_ANY = 255
} dns_class;

typedef enum {
  TYPE_A = 1,
  TYPE_NS = 2,
  TYPE_CNAME = 5,
  TYPE_SOA = 6,
  TYPE_MX = 15,
  TYPE_AAAA = 28,
  TYPE_SRV = 33,
  QTYPE_ANY = 255
} dns_type;


//  0: ok
// -1: premature end of input, forward reference, component > 63 char, invalid character
// -2: insufficient space in output
int static parse_name(const unsigned char **inpos, const unsigned char *inend, const unsigned char *inbuf, char *buf, size_t bufsize) {
  size_t bufused = 0;
  int init = 1;
  do {
    if (*inpos == inend)
      return -1;
    // read length of next component
    int octet = *((*inpos)++);
    if (octet == 0) {
      buf[bufused] = 0;
      return 0;
    }
    // add dot in output
    if (!init) {
      if (bufused == bufsize-1)
        return -2;
      buf[bufused++] = '.';
    } else
      init = 0;
    // handle references
    if ((octet & 0xC0) == 0xC0) {
      if (*inpos == inend)
        return -1;
      int ref = ((octet - 0xC0) << 8) + *((*inpos)++);
      if (ref < 0 || ref >= (*inpos)-inbuf-2) return -1;
      const unsigned char *newbuf = inbuf + ref;
      return parse_name(&newbuf, (*inpos) - 2, inbuf, buf+bufused, bufsize-bufused);
    }
    if (octet > 63) return -1;
    // copy label
    while (octet) {
      if (*inpos == inend)
        return -1;
      if (bufused == bufsize-1)
        return -2;
      int c = *((*inpos)++);
      if (c == '.')
        return -1;
      octet--;
      buf[bufused++] = c;
    }
  } while(1);
}

//  0: k
// -1: component > 63 characters
// -2: insufficent space in output
// -3: two subsequent dots
int static write_name(unsigned char** outpos, const unsigned char *outend, const char *name, int offset) {
  while (*name != 0) {
    const char *dot = strchr(name, '.');
    const char *fin = dot;
    if (!dot) fin = name + strlen(name);
    if (fin - name > 63) return -1;
    if (fin == name) return -3;
    if (outend - *outpos < fin - name + 2) return -2;
    *((*outpos)++) = fin - name;
    memcpy(*outpos, name, fin - name);
    *outpos += fin - name;
    if (!dot) break;
    name = dot + 1;
  }
  if (offset < 0) {
    // no reference
    if (outend == *outpos) return -2;
    *((*outpos)++) = 0;
  } else {
    if (outend - *outpos < 2) return -2;
    *((*outpos)++) = (offset >> 8) | 0xC0;
    *((*outpos)++) = offset & 0xFF;
  }
  return 0;
}

int static write_record(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_type typ, dns_class cls, int ttl) {
  unsigned char *oldpos = *outpos;
  int error = 0;
  // name
  int ret = write_name(outpos, outend, name, offset);
  if (ret) {
    error = ret;
  } else {
    if (outend - *outpos < 8) {
      error = -4;
    } else {
      // type
      *((*outpos)++) = typ >> 8; *((*outpos)++) = typ & 0xFF;
      // class
      *((*outpos)++) = cls >> 8; *((*outpos)++) = cls & 0xFF;
      // ttl
      *((*outpos)++) = (ttl >> 24) & 0xFF; *((*outpos)++) = (ttl >> 16) & 0xFF; *((*outpos)++) = (ttl >> 8) & 0xFF; *((*outpos)++) = ttl & 0xFF;
      return 0;
    }
  }
  *outpos = oldpos;
  return error;
}


int static write_record_a(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_class cls, int ttl, const addr_t *ip) {
  if (ip->v != 4)
     return -6;
  unsigned char *oldpos = *outpos;
  int error = 0;
  int ret = write_record(outpos, outend, name, offset, TYPE_A, cls, ttl);
  if (ret) return ret;
  if (outend - *outpos < 6) {
    error = -5;
  } else {
    // rdlength
    *((*outpos)++) = 0; *((*outpos)++) = 4;
    // rdata
    for (int i=0; i<4; i++)
      *((*outpos)++) = ip->data.v4[i];
    return 0;
  }
  *outpos = oldpos;
  return error;
}

int static write_record_aaaa(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_class cls, int ttl, const addr_t *ip) {
  if (ip->v != 6)
     return -6;
  unsigned char *oldpos = *outpos;
  int error = 0;
  int ret = write_record(outpos, outend, name, offset, TYPE_AAAA, cls, ttl);
  if (ret) return ret;
  if (outend - *outpos < 6) {
    error = -5;
  } else {
    // rdlength
    *((*outpos)++) = 0; *((*outpos)++) = 16;
    // rdata
    for (int i=0; i<16; i++)
      *((*outpos)++) = ip->data.v6[i];
    return 0;
  }
  *outpos = oldpos;
  return error;
}

int static write_record_ns(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_class cls, int ttl, const char *ns) {
  unsigned char *oldpos = *outpos;
  int ret = write_record(outpos, outend, name, offset, TYPE_NS, cls, ttl);
  if (ret) return ret;
  int error = 0;
  if (outend - *outpos < 2) {
    error = -5;
  } else {
    (*outpos) += 2;
    unsigned char *curpos = *outpos;
    ret = write_name(outpos, outend, ns, -1);
    if (ret) {
      error = ret;
    } else {
      curpos[-2] = (*outpos - curpos) >> 8;
      curpos[-1] = (*outpos - curpos) & 0xFF;
      return 0;
    }
  }
  *outpos = oldpos;
  return error;
}

int static write_record_soa(unsigned char** outpos, const unsigned char *outend, const char *name, int offset, dns_class cls, int ttl, const char* mname, const char *rname,
                     uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum) {
  unsigned char *oldpos = *outpos;
  int ret = write_record(outpos, outend, name, offset, TYPE_SOA, cls, ttl);
  if (ret) return ret;
  int error = 0;
  if (outend - *outpos < 2) {
    error = -5;
  } else {
    (*outpos) += 2;
    unsigned char *curpos = *outpos;
    ret = write_name(outpos, outend, mname, -1);
    if (ret) {
      error = ret;
    } else {
      ret = write_name(outpos, outend, rname, -1);
      if (ret) {
        error = ret;
      } else {
        if (outend - *outpos < 20) {
          error = -5;
        } else {
          *((*outpos)++) = (serial  >> 24) & 0xFF; *((*outpos)++) = (serial  >> 16) & 0xFF; *((*outpos)++) = (serial  >> 8) & 0xFF; *((*outpos)++) = serial  & 0xFF;
          *((*outpos)++) = (refresh >> 24) & 0xFF; *((*outpos)++) = (refresh >> 16) & 0xFF; *((*outpos)++) = (refresh >> 8) & 0xFF; *((*outpos)++) = refresh & 0xFF;
          *((*outpos)++) = (retry   >> 24) & 0xFF; *((*outpos)++) = (retry   >> 16) & 0xFF; *((*outpos)++) = (retry   >> 8) & 0xFF; *((*outpos)++) = retry   & 0xFF;
          *((*outpos)++) = (expire  >> 24) & 0xFF; *((*outpos)++) = (expire  >> 16) & 0xFF; *((*outpos)++) = (expire  >> 8) & 0xFF; *((*outpos)++) = expire  & 0xFF;
          *((*outpos)++) = (minimum >> 24) & 0xFF; *((*outpos)++) = (minimum >> 16) & 0xFF; *((*outpos)++) = (minimum >> 8) & 0xFF; *((*outpos)++) = minimum & 0xFF;
          curpos[-2] = (*outpos - curpos) >> 8;
          curpos[-1] = (*outpos - curpos) & 0xFF;
          return 0;
        }
      }
    }
  }
  *outpos = oldpos;
  return error;
}

static ssize_t set_error(unsigned char* outbuf, int error) {
  // set error
  outbuf[3] |= error & 0xF;
  // set counts
  outbuf[4] = 0;  outbuf[5] = 0;
  outbuf[6] = 0;  outbuf[7] = 0;
  outbuf[8] = 0;  outbuf[9] = 0;
  outbuf[10] = 0; outbuf[11] = 0;
  return 12;
}

ssize_t static dnshandle(dns_opt_t *opt, const unsigned char *inbuf, size_t insize, unsigned char* outbuf) {
  int error = 0;
  if (insize < 12) // DNS header
    return -1;
  // copy id
  outbuf[0] = inbuf[0];
  outbuf[1] = inbuf[1];
  // copy flags;
  outbuf[2] = inbuf[2];
  outbuf[3] = inbuf[3];
  // clear error
  outbuf[3] &= ~15;
  // check qr
  if (inbuf[2] & 128) return set_error(outbuf, 1); /* printf("Got response?\n"); */
  // check opcode
  if (((inbuf[2] & 120) >> 3) != 0) return set_error(outbuf, 1); /* printf("Opcode nonzero?\n"); */
  // unset TC
  outbuf[2] &= ~2;
  // unset RA
  outbuf[3] &= ~128;
  // check questions
  int nquestion = (inbuf[4] << 8) + inbuf[5];
  if (nquestion == 0) return set_error(outbuf, 0); /* printf("No questions?\n"); */
  if (nquestion > 1) return set_error(outbuf, 4); /* printf("Multiple questions %i?\n", nquestion); */
  const unsigned char *inpos = inbuf + 12;
  const unsigned char *inend = inbuf + insize;
  char name[256];
  int offset = inpos - inbuf;
  int ret = parse_name(&inpos, inend, inbuf, name, 256);
  if (ret == -1) return set_error(outbuf, 1);
  if (ret == -2) return set_error(outbuf, 5);
  int namel = strlen(name), hostl = strlen(opt->host);
  if (strcasecmp(name, opt->host) && (namel<hostl+2 || name[namel-hostl-1]!='.' || strcasecmp(name+namel-hostl,opt->host))) return set_error(outbuf, 5);
  if (inend - inpos < 4) return set_error(outbuf, 1);
  // copy question to output
  memcpy(outbuf+12, inbuf+12, inpos+4 - (inbuf+12));
  // set counts
  outbuf[4] = 0;  outbuf[5] = 1;
  outbuf[6] = 0;  outbuf[7] = 0;
  outbuf[8] = 0;  outbuf[9] = 0;
  outbuf[10] = 0; outbuf[11] = 0;
  // set qr
  outbuf[2] |= 128;
  
  int typ = (inpos[0] << 8) + inpos[1];
  int cls = (inpos[2] << 8) + inpos[3];
  inpos += 4;
  
  unsigned char *outpos = outbuf+(inpos-inbuf);
  unsigned char *outend = outbuf + BUFLEN;
  
//  printf("DNS: Request host='%s' type=%i class=%i\n", name, typ, cls);
  
  // calculate max size of authority section
  
  int max_auth_size = 0;
  
  if (!((typ == TYPE_NS || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY))) {
    // authority section will be necessary, either NS or SOA
    unsigned char *newpos = outpos;
    write_record_ns(&newpos, outend, "", offset, CLASS_IN, 0, opt->ns);
    max_auth_size = newpos - outpos;

    newpos = outpos;
    write_record_soa(&newpos, outend, "", offset, CLASS_IN, opt->nsttl, opt->ns, opt->mbox, time(NULL), 604800, 86400, 2592000, 604800);
    if (max_auth_size < newpos - outpos)
        max_auth_size = newpos - outpos;
//    printf("Authority section will claim %i bytes max\n", max_auth_size);
  }
  
  // Answer section

  int have_ns = 0;

  // NS records
  if ((typ == TYPE_NS || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY)) {
    int ret2 = write_record_ns(&outpos, outend - max_auth_size, "", offset, CLASS_IN, opt->nsttl, opt->ns);
//    printf("wrote NS record: %i\n", ret2);
    if (!ret2) { outbuf[7]++; have_ns++; }
  }

  // SOA records
  if ((typ == TYPE_SOA || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY) && opt->mbox) {
    int ret2 = write_record_soa(&outpos, outend - max_auth_size, "", offset, CLASS_IN, opt->nsttl, opt->ns, opt->mbox, time(NULL), 604800, 86400, 2592000, 604800);
//    printf("wrote SOA record: %i\n", ret2);
    if (!ret2) { outbuf[7]++; }
  }
  
  // A/AAAA records
  if ((typ == TYPE_A || typ == TYPE_AAAA || typ == QTYPE_ANY) && (cls == CLASS_IN || cls == QCLASS_ANY)) {
    addr_t addr[32];
    int naddr = opt->cb((void*)opt, name, addr, 32, typ == TYPE_A || typ == QTYPE_ANY, typ == TYPE_AAAA || typ == QTYPE_ANY);
    int n = 0;
    while (n < naddr) {
      int ret = 1;
      if (addr[n].v == 4)
         ret = write_record_a(&outpos, outend - max_auth_size, "", offset, CLASS_IN, opt->datattl, &addr[n]);
      else if (addr[n].v == 6)
         ret = write_record_aaaa(&outpos, outend - max_auth_size, "", offset, CLASS_IN, opt->datattl, &addr[n]);
//      printf("wrote A record: %i\n", ret);
      if (!ret) {
        n++;
        outbuf[7]++;
      } else
        break;
    }
  }
  
  // Authority section
  if (!have_ns && outbuf[7]) {
    int ret2 = write_record_ns(&outpos, outend, "", offset, CLASS_IN, opt->nsttl, opt->ns);
//    printf("wrote NS record: %i\n", ret2);
    if (!ret2) {
      outbuf[9]++;
    }
  }
  else if (!outbuf[7]) {
    // Didn't include any answers, so reply with SOA as this is a negative
    // response. If we replied with NS above we'd create a bad horizontal
    // referral loop, as the NS response indicates where the resolver should
    // try next.
    int ret2 = write_record_soa(&outpos, outend, "", offset, CLASS_IN, opt->nsttl, opt->ns, opt->mbox, time(NULL), 604800, 86400, 2592000, 604800);
//    printf("wrote SOA record: %i\n", ret2);
    if (!ret2) { outbuf[9]++; }
  }
  
  // set AA
  outbuf[2] |= 4;
  
  return outpos - outbuf;
}

int dnsserver(dns_opt_t *opt) {

    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < -1) {
        printf("socket() failed: %s\n", strerror(errno));
        return -1;
    }

    int sockopt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) < 0) {
        printf("setsockopt() failed: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    struct sockaddr_in serveraddr;
    memset((char *) &serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(opt->port);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        printf("Bind failed: %s\n", strerror(errno));
        close(sockfd);
        return -2;
    }

    char buffer[128];
    inet_ntop (AF_INET, &serveraddr.sin_addr, buffer, sizeof(buffer));
//  printf("Binding to %s %d\n", buffer, ntohs(serveraddr.sin_port));
  
    unsigned char inbuf[BUFLEN], outbuf[BUFLEN];
    struct iovec iov[1];
    struct sockaddr_in src_addr;
    struct msghdr message;

    message.msg_name       = &src_addr;
    message.msg_namelen    = sizeof(src_addr);
    message.msg_iov        = iov;
    message.msg_iovlen     = 1;
    message.msg_control    = 0;
    message.msg_controllen = 0;

    while (1) {
        opt->nRequests++;
        message.msg_iov[0].iov_base = inbuf;
        message.msg_iov[0].iov_len  = sizeof(inbuf);

        ssize_t nBytes = recvmsg(sockfd, &message, 0);
        if (-1 == nBytes) {
            printf("Error: recvmsg failed: %s\n", strerror(errno));
            continue;
        }

        unsigned char *addr = (unsigned char*)&src_addr.sin_addr.s_addr;
        inet_ntop(AF_INET, &src_addr.sin_addr, buffer, sizeof(buffer));
  //      printf("DNS: Request %llu from %s:%i of %i bytes\n", (unsigned long long)(opt->nRequests),
  //             buffer, ntohs(src_addr.sin_port), (int)nBytes);

        ssize_t ret = dnshandle(opt, inbuf, nBytes, outbuf);
        if (ret <= 0) {
            printf("Error: DNS Processing failed: %s\n", strerror(errno));
            continue;
        }

        bool handled = false;
        for (struct cmsghdr*hdr = CMSG_FIRSTHDR(&message); hdr; hdr = CMSG_NXTHDR(&message, hdr)) {
            if (hdr->cmsg_level == IPPROTO_IP && hdr->cmsg_type == DSTADDR_SOCKOPT) {
                message.msg_iov[0].iov_base = outbuf;
                message.msg_iov[0].iov_len = ret;

                nBytes = sendmsg(sockfd, &message, 0);
                if (-1 == nBytes) {
                    printf("Error: sendmsg failed: %s\n", strerror(errno));
                    continue;
                } else {
                  handled = true;
                }
            }
        }
        if (!handled)
            sendto(sockfd, outbuf, ret, 0, (struct sockaddr*)&src_addr, sizeof(src_addr));
    }
    return 0;
}

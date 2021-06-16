#include <qtpcap.h>
#include <pcap.h>

//////////////////////////////////////////////////////////////////////////////

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet                 {
  u_char  ether_dhost[ETHER_ADDR_LEN] ; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN] ; /* source host address */
  u_short ether_type                  ; /* IP? ARP? RARP? etc */
}                                     ;

/* IP header */
struct sniff_ip             {
  u_char  ip_vhl            ; /* version << 4 | header length >> 2 */
  u_char  ip_tos            ; /* type of service */
  u_short ip_len            ; /* total length */
  u_short ip_id             ; /* identification */
  u_short ip_off            ; /* fragment offset field */
  #define IP_RF 0x8000        /* reserved fragment flag */
  #define IP_DF 0x4000        /* dont fragment flag */
  #define IP_MF 0x2000        /* more fragments flag */
  #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
  u_char  ip_ttl            ; /* time to live */
  u_char  ip_p              ; /* protocol */
  u_short ip_sum            ; /* checksum */
  struct  in_addr ip_src    ;
  struct  in_addr ip_dst    ; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

typedef struct                  {
  unsigned char  hdr_len :4     ;
  unsigned char  version :4     ;
  unsigned char  tos            ;
  unsigned short total_len      ;
  unsigned short identifier     ;
  unsigned short frag_and_flags ;
  unsigned char  ttl            ;
  unsigned char  protocol       ;
  unsigned short checksum       ;
  unsigned long  sourceIP       ;
  unsigned long  destIP         ;
} IP_HEADER                     ;

typedef struct         {
  unsigned char  type  ;
  unsigned char  code  ;
  unsigned short cksum ;
  unsigned short id    ;
  unsigned short seq   ;
} ICMP_HEADER          ;

typedef struct                   {
  unsigned short usSeqNo         ;
  DWORD          dwRoundTripTime ;
  in_addr        dwIPaddr        ;
} DECODE_RESULT                  ;

#define ICMP_ECHO_REQUEST    8
#define ICMP_ECHO_REPLY      0
#define ICMP_TIMEOUT         11
#define DEF_ICMP_TIMEOUT     3000
#define DEF_ICMP_DATA_SIZE   32
#define MAX_ICMP_PACKET_SIZE 1024
#define MAX_EMPTY_ICMP       5
#define DEFAULT_MAX_HOP      60

//////////////////////////////////////////////////////////////////////////////

static unsigned long toIpAddress(QString ip)
{
  QStringList   R                                  ;
  unsigned long z = INADDR_NONE                    ;
  QString       A                                  ;
  //////////////////////////////////////////////////
  if ( ip . length ( ) <= 0 ) return 0             ;
  R = ip . split ( ':' )                           ;
  if ( R . count   ( ) <= 0 ) return 0             ;
  A = R [ 0 ]                                      ;
  //////////////////////////////////////////////////
  char IP [ 1024 ]                                 ;
  ::memset ( IP , 0 , 1024                       ) ;
  ::strcpy ( IP , A . toUtf8 ( ) . constData ( ) ) ;
  z = inet_addr ( IP )                             ;
  if ( z != INADDR_NONE ) return z                 ;
  hostent * pHostent = ::gethostbyname ( IP )      ;
  if ( NULL == pHostent ) return z                 ;
  z = (*(in_addr*)pHostent->h_addr) . s_addr       ;
  //////////////////////////////////////////////////
  return z                                         ;
}

static QString saString(sockaddr * sa)
{
  QString v                                                            ;
  if ( NULL == sa ) return v                                           ;
  if ( AF_INET  == sa -> sa_family )                                   {
    sockaddr_in  * ipv4 = (sockaddr_in  *) sa                          ;
    char    buff [ 128 ]                                               ;
    char *  iaddr = NULL                                               ;
    #if defined(Q_OS_WIN)
    iaddr = (char *) InetNtop  ( AF_INET                               ,
                                 & ( ipv4 -> sin_addr )                ,
                                 (PTSTR) buff                          ,
                                 120                                 ) ;
    #if defined(UNICODE)
    if ( NULL != iaddr ) v = QString::fromUtf16((const ushort *)iaddr) ;
    #else
    if ( NULL != iaddr ) v = QString::fromUtf8(iaddr)                  ;
    #endif
    #else
    iaddr = (char *) inet_ntop ( AF_INET                               ,
                                 & ( ipv4 -> sin_addr )                ,
                                 buff                                  ,
                                 120                                 ) ;
    if ( NULL != iaddr ) v = QString::fromUtf8(iaddr)                  ;
    #endif
  } else
  if ( AF_INET6 == sa -> sa_family )                                   {
    sockaddr_in6  * ipv6 = (sockaddr_in6 *) sa                         ;
    QStringList     l                                                  ;
    unsigned char * ipf                                                ;
    ipf = (unsigned char *) & ( ipv6 -> sin6_addr )                    ;
    for (int i=0;i<8;i++)                                              {
      unsigned short v                                                 ;
      v   = ipf [       i * 2   ]                                      ;
      v <<= 8                                                          ;
      v  += ipf [ 1 + ( i * 2 ) ]                                      ;
      l << QString::number ( (unsigned int) v , 16 )                   ;
    }                                                                  ;
    v = l . join ( ":" )                                               ;
  }                                                                    ;
  return v                                                             ;
}

QtPCAP:: QtPCAP (void)
{
}

QtPCAP::~QtPCAP(void)
{
}

QString QtPCAP::Version(void)
{
  QTextCodec * codec = QTextCodec::codecForLocale ( ) ;
  QString      v                                      ;
  const char * ver                                    ;
  ver = ::pcap_lib_version (     )                    ;
  if ( NULL != ver )                                  {
    v = codec -> toUnicode ( ver )                    ;
  }                                                   ;
  return v                                            ;
}

QString QtPCAP::Lookup(QString & error)
{
  QTextCodec * codec = QTextCodec::codecForLocale ( )   ;
  QString      s                                        ;
  char       * dev                                      ;
  char         err [ PCAP_ERRBUF_SIZE ]                 ;
  ///////////////////////////////////////////////////////
  ::memset ( err , 0 , PCAP_ERRBUF_SIZE )               ;
  dev = ::pcap_lookupdev ( err )                        ;
  ///////////////////////////////////////////////////////
  #ifdef Q_OS_WIN
  if ( NULL == dev )                                    {
    error = codec -> toUnicode ( err                  ) ;
  } else                                                {
    s     = QString::fromUtf16 ( (const ushort *) dev ) ;
  }                                                     ;
  #endif
  ///////////////////////////////////////////////////////
  return s                                              ;
}

bool QtPCAP::Probe(void)
{
  QTextCodec * codec = QTextCodec::codecForLocale ( )    ;
  char         err [ PCAP_ERRBUF_SIZE ]                  ;
  pcap_if_t  * ifs = NULL                                ;
  pcap_if_t  * afs = NULL                                ;
  ////////////////////////////////////////////////////////
  Interfaces   . clear ( )                               ;
  ErrorMessage = ""                                      ;
  ////////////////////////////////////////////////////////
  ::memset ( err ,0,PCAP_ERRBUF_SIZE)                    ;
  if ( 0 != ::pcap_findalldevs ( &ifs , err ) )          {
    ErrorMessage  = codec -> toUnicode ( err )           ;
    return false                                         ;
  }                                                      ;
  ////////////////////////////////////////////////////////
  afs = ifs                                              ;
  while ( NULL != afs )                                  {
    PcapIf        pif                                    ;
    QString       n                                      ;
    QString       d                                      ;
    pcap_addr_t * addr                                   ;
    if ( NULL != afs -> name )                           {
      n = codec -> toUnicode ( afs -> name        )      ;
    }                                                    ;
    if ( NULL != afs -> description )                    {
      d = codec -> toUnicode ( afs -> description )      ;
    }                                                    ;
    addr                = afs  -> addresses              ;
    pif . Name          = n                              ;
    pif . Description   = d                              ;
    pif . Flags         = afs  -> flags                  ;
    pif . Address       . clear ( )                      ;
    while ( NULL != addr )                               {
      PcapAddress pa                                     ;
      pa  . address     = saString ( addr -> addr      ) ;
      pa  . netmask     = saString ( addr -> netmask   ) ;
      pa  . broadcast   = saString ( addr -> broadaddr ) ;
      pa  . destination = saString ( addr -> dstaddr   ) ;
      pif . Address    << pa                             ;
      addr              = addr -> next                   ;
    }                                                    ;
    afs                 = afs  -> next                   ;
    Interfaces << pif                                    ;
  }                                                      ;
  ////////////////////////////////////////////////////////
  if ( NULL != ifs ) ::pcap_freealldevs ( ifs )          ;
  ////////////////////////////////////////////////////////
  return ( Interfaces . count ( ) > 0 )                  ;
}

int QtPCAP::indexOf(QString device)
{
  int total = Interfaces . count ( )         ;
  for (int i=0;i<total;i++)                  {
    if ( Interfaces [ i ] . Name == device ) {
      return  i                              ;
    }                                        ;
  }                                          ;
  return -1                                  ;
}

bool QtPCAP::SniffTCP(int Interface,bool & keep)
{
  if ( Interface < 0                       ) return false ;
  if ( Interfaces . count ( ) <= Interface ) return false ;
  return SniffTCP ( Interfaces [ Interface ] , keep )     ;
}

bool QtPCAP::SniffTCP(QString Interface,bool & keep)
{
  int index = indexOf ( Interface )               ;
  if ( index < 0 ) return false                   ;
  return SniffTCP ( Interfaces [ index ] , keep ) ;
}

bool QtPCAP::SniffTCP (PcapIf & If,bool & keep)
{
  const ushort * dex = If . Name . utf16 ( )                                 ;
  if ( NULL == dex ) return false                                            ;
  ////////////////////////////////////////////////////////////////////////////
  pcap_t          *  handle                                                  ;
  char               errbuf [ PCAP_ERRBUF_SIZE ]                             ;
  struct bpf_program fp                                                      ;
  bpf_u_int32        mask                                                    ;
  bpf_u_int32        net                                                     ;
  struct pcap_pkthdr header                                                  ;
  const u_char    *  packet                                                  ;
  char               filter_exp [ 1024 ]                                     ;
  ////////////////////////////////////////////////////////////////////////////
  ::memset   ( filter_exp , 0 , 1024 )                                       ;
  ::strcpy   ( filter_exp , "ip"     )                                       ;
  if ( Variables . contains ( "SniffProtocol" ) )                            {
    QString fe = Variables [ "SniffProtocol" ] . toString ( )                ;
    ::strcpy ( filter_exp , fe . toUtf8 ( ) . constData ( ) )                ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  if ( -1 == ::pcap_lookupnet((const char *)dex, &net, &mask, errbuf) )      {
    net  = 0                                                                 ;
    mask = 0                                                                 ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  handle = ::pcap_open_live( (const char *)dex,BUFSIZ,1,1000,errbuf )        ;
  if ( NULL == handle                                      ) return false    ;
  if ( -1   == ::pcap_compile(handle,&fp,filter_exp,0,net) ) return false    ;
  if ( -1   == ::pcap_setfilter(handle,&fp)                ) return false    ;
  ////////////////////////////////////////////////////////////////////////////
  while ( keep )                                                             {
    packet = pcap_next                ( handle , &header          )          ;
    if ( NULL != packet ) Interpreter ( (unsigned char * ) packet )          ;
  }                                                                          ;
  ::pcap_close ( handle )                                                    ;
  ////////////////////////////////////////////////////////////////////////////
  return true                                                                ;
}

bool QtPCAP::Interpreter(unsigned char * p)
{
  /* declare pointers to packet headers */
  const struct sniff_ethernet * ethernet     ; /* The ethernet header [1] */
  const struct sniff_ip       * ip           ; /* The IP header */
  const struct sniff_tcp      * tcp          ; /* The TCP header */
  unsigned char               * payload      ; /* Packet payload */
  int                           size_ip                                      ;
  int                           size_tcp                                     ;
  int                           size_payload                                 ;
  ////////////////////////////////////////////////////////////////////////////
  ethernet = (struct sniff_ethernet *) p                                     ;
  ////////////////////////////////////////////////////////////////////////////
  ip      = (struct sniff_ip *) ( p + SIZE_ETHERNET )                        ;
  size_ip = IP_HL ( ip ) * 4                                                 ;
  if ( size_ip < 20 ) return false                                           ;
  ////////////////////////////////////////////////////////////////////////////
  switch ( ip -> ip_p )                                                      {
    case IPPROTO_TCP                                                         :
    break                                                                    ;
    case IPPROTO_UDP                                                         :
    return false                                                             ;
    case IPPROTO_ICMP                                                        :
    return false                                                             ;
    case IPPROTO_IP                                                          :
    return false                                                             ;
    default                                                                  :
    return false                                                             ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  /* define/compute tcp header offset                                       */
  tcp      = (struct sniff_tcp *) ( p + SIZE_ETHERNET + size_ip )            ;
  size_tcp = TH_OFF ( tcp ) * 4                                              ;
  if ( size_tcp < 20 ) return false                                          ;
  ////////////////////////////////////////////////////////////////////////////
  QString from = QString::fromUtf8 ( inet_ntoa ( ip -> ip_src ) )            ;
  QString toip = QString::fromUtf8 ( inet_ntoa ( ip -> ip_dst ) )            ;
  from . append ( QString(":%1") . arg ( ntohs(tcp->th_sport) ) )            ;
  toip . append ( QString(":%1") . arg ( ntohs(tcp->th_dport) ) )            ;
  /* define/compute tcp payload (segment) offset                            */
  payload = (unsigned char *) ( p + SIZE_ETHERNET + size_ip + size_tcp )     ;
  /* compute tcp payload (segment) size                                     */
  size_payload = ntohs ( ip -> ip_len ) - ( size_ip + size_tcp )             ;
  ////////////////////////////////////////////////////////////////////////////
  Sniff     ( from    , toip                          )                      ;
  if ( size_payload > 0 )                                                    {
    Payload (                  payload , size_payload )                      ;
    Payload ( from    , toip , payload , size_payload )                      ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  return true                                                                ;
}

bool QtPCAP::Sniff(QString s,QString d)
{
  return true ;
}

bool QtPCAP::Payload(unsigned char * payload,int size)
{
  return true ;
}

bool QtPCAP::Payload(QString s,QString d,unsigned char * payload,int size)
{
  return true ;
}

bool QtPCAP::Traceroute(QString destination)
{
  unsigned long ip = toIpAddress ( destination )                             ;
  ////////////////////////////////////////////////////////////////////////////
  if ( INADDR_NONE == ip ) return false                                      ;
  ////////////////////////////////////////////////////////////////////////////
#ifdef Q_OS_WIN
  sockaddr_in destSockAddr                                                   ;
  ZeroMemory ( &destSockAddr , sizeof(sockaddr_in) )                         ;
  destSockAddr . sin_family        = AF_INET                                 ;
  destSockAddr . sin_addr . s_addr = ip                                      ;
  ////////////////////////////////////////////////////////////////////////////
  SOCKET sockRaw                                                             ;
  sockRaw = WSASocket ( AF_INET                                              ,
                        SOCK_RAW                                             ,
                        IPPROTO_ICMP                                         ,
                        NULL                                                 ,
                        0                                                    ,
                        WSA_FLAG_OVERLAPPED                                ) ;
  if ( INVALID_SOCKET == sockRaw )                                           {
    Variables [ "TracerouteError" ] = WSAGetLastError ( )                    ;
    return false                                                             ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  int iTimeout = DEF_ICMP_TIMEOUT                                            ;
  int r                                                                      ;
  if ( Variables . contains ( "DEF_ICMP_TIMEOUT" ) )                         {
    iTimeout = Variables [ "DEF_ICMP_TIMEOUT" ] . toInt ( )                  ;
  }                                                                          ;
  r = ::setsockopt ( sockRaw                                                 ,
                     SOL_SOCKET                                              ,
                     SO_RCVTIMEO                                             ,
                     (char*)&iTimeout                                        ,
                     sizeof(iTimeout)                                      ) ;
  if ( SOCKET_ERROR == r )                                                   {
    ::closesocket ( sockRaw )                                                ;
    return false                                                             ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  char          IcmpSendBuf [ sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE ]     ;
  char          IcmpRecvBuf [ MAX_ICMP_PACKET_SIZE                     ]     ;
  ICMP_HEADER * pIcmpHeader = (ICMP_HEADER *) IcmpSendBuf                    ;
  ////////////////////////////////////////////////////////////////////////////
  ::memset ( IcmpSendBuf , 0 , sizeof(IcmpSendBuf) )                         ;
  ::memset ( IcmpRecvBuf , 0 , sizeof(IcmpRecvBuf) )                         ;
  ////////////////////////////////////////////////////////////////////////////
  pIcmpHeader -> type = ICMP_ECHO_REQUEST                                    ;
  pIcmpHeader -> code = 0                                                    ;
  pIcmpHeader -> id   = (unsigned short) ::GetCurrentProcessId ( )           ;
  ::memset ( IcmpSendBuf + sizeof(ICMP_HEADER) , 'E' , DEF_ICMP_DATA_SIZE )  ;
  ////////////////////////////////////////////////////////////////////////////
  DECODE_RESULT  dr                                                          ;
  bool           bReachDestHost = false                                      ;
  unsigned short usSeqNo        = 0                                          ;
  unsigned short chksum         = 0                                          ;
  int            iTTL           = 1                                          ;
  int            iMaxHop        = DEFAULT_MAX_HOP                            ;
  int            iMaxEmpty      = MAX_EMPTY_ICMP                             ;
  int            iEmpty         = 0                                          ;
  ////////////////////////////////////////////////////////////////////////////
  if ( Variables . contains ( "DEFAULT_MAX_HOP" ) )                          {
    iMaxHop   = Variables [ "DEFAULT_MAX_HOP" ] . toInt ( )                  ;
  }                                                                          ;
  if ( Variables . contains ( "MAX_EMPTY_ICMP"  ) )                          {
    iMaxEmpty = Variables [ "MAX_EMPTY_ICMP"  ] . toInt ( )                  ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  while ( ( ! bReachDestHost ) && ( ( iMaxHop-- ) > 0 ) )                    {
    //////////////////////////////////////////////////////////////////////////
    ::setsockopt ( sockRaw                                                   ,
                   IPPROTO_IP                                                ,
                   IP_TTL                                                    ,
                   (char*)&iTTL                                              ,
                   sizeof(iTTL)                                            ) ;
    //////////////////////////////////////////////////////////////////////////
    ((ICMP_HEADER *)IcmpSendBuf) -> cksum = 0                                ;
    ((ICMP_HEADER *)IcmpSendBuf) -> seq   = htons ( usSeqNo++ )              ;
    chksum = Checksum ( (unsigned short *) IcmpSendBuf                       ,
                        sizeof(ICMP_HEADER) + DEF_ICMP_DATA_SIZE           ) ;
    ((ICMP_HEADER *)IcmpSendBuf) -> cksum = chksum                           ;
    dr . usSeqNo         = ( (ICMP_HEADER *) IcmpSendBuf ) -> seq            ;
    dr . dwRoundTripTime = ::GetTickCount ( )                                ;
    //////////////////////////////////////////////////////////////////////////
    r = ::sendto ( sockRaw                                                   ,
                   IcmpSendBuf                                               ,
                   sizeof(IcmpSendBuf)                                       ,
                   0                                                         ,
                   (sockaddr *) &destSockAddr                                ,
                   sizeof(destSockAddr)                                    ) ;
    if ( SOCKET_ERROR == r )                                                 {
      ::closesocket ( sockRaw )                                              ;
      return false                                                           ;
    }                                                                        ;
    //////////////////////////////////////////////////////////////////////////
    sockaddr_in from                                                         ;
    int         iFromLen = sizeof(from)                                      ;
    int         iReadDataLen                                                 ;
    while ( true )                                                           {
      iReadDataLen = ::recvfrom ( sockRaw                                    ,
                                  IcmpRecvBuf                                ,
                                  MAX_ICMP_PACKET_SIZE                       ,
                                  0                                          ,
                                  (sockaddr*)&from                           ,
                                  &iFromLen                                ) ;
      if ( iReadDataLen != SOCKET_ERROR )                                    {
        if ( DecodeICMP ( IcmpRecvBuf , iReadDataLen , &dr ) )               {
          if ( dr . dwIPaddr . s_addr == destSockAddr . sin_addr . s_addr )  {
            bReachDestHost = true                                            ;
          }                                                                  ;
          QString IPX = QString::fromUtf8 ( inet_ntoa ( dr.dwIPaddr ) )      ;
          if ( IPX == destination )                                          {
            ::closesocket ( sockRaw )                                        ;
            RoutePath ( destination , ""  , iTTL , (int)dr.dwRoundTripTime ) ;
            return true                                                      ;
          } else                                                             {
            RoutePath ( destination , IPX , iTTL , (int)dr.dwRoundTripTime ) ;
            iEmpty = 0                                                       ;
          }                                                                  ;
          break                                                              ;
        }                                                                    ;
      } else
      if ( WSAETIMEDOUT == ::WSAGetLastError ( ) )                           {
        RoutePath ( destination , "*" , iTTL , -1 )                          ;
        iEmpty ++                                                            ;
        if ( iEmpty >= iMaxEmpty ) return false                              ;
        break                                                                ;
      } else                                                                 {
        ::closesocket ( sockRaw )                                            ;
        RoutePath ( destination , "" , 0 , 0 )                               ;
        return false                                                         ;
      }                                                                      ;
    }                                                                        ;
    iTTL++                                                                   ;
  }                                                                          ;
  ////////////////////////////////////////////////////////////////////////////
  ::closesocket ( sockRaw )                                                  ;
  RoutePath ( destination , "" , 0 , 0 )                                     ;
#endif
  return true                                                                ;
}

unsigned short QtPCAP::Checksum(unsigned short * buffer,int size)
{
  unsigned long cksum = 0                             ;
  while ( size > 1 )                                  {
    cksum += * buffer ++                              ;
    size  -= sizeof(unsigned short)                   ;
  }                                                   ;
  if ( size != 0 ) cksum += *(unsigned char *) buffer ;
  cksum  = (cksum >> 16) + (cksum & 0xffff)           ;
  cksum += (cksum >> 16)                              ;
  return (unsigned short)(~cksum)                     ;
}

bool QtPCAP::DecodeICMP(char * buffer,int size,void * result)
{
  DECODE_RESULT * dr        = (DECODE_RESULT *) result                       ;
  IP_HEADER     * pIpHdr    = (IP_HEADER     *) buffer                       ;
  int             iIpHdrLen = pIpHdr -> hdr_len * 4                          ;
  ////////////////////////////////////////////////////////////////////////////
  if ( size < (int) ( iIpHdrLen + sizeof(ICMP_HEADER) ) ) return false       ;
  ////////////////////////////////////////////////////////////////////////////
  ICMP_HEADER  * pIcmpHdr = (ICMP_HEADER *) ( buffer + iIpHdrLen )           ;
  unsigned short usID                                                        ;
  unsigned short usSquNo                                                     ;
  ////////////////////////////////////////////////////////////////////////////
  if ( pIcmpHdr -> type == ICMP_ECHO_REPLY )                                 {
    usID    = pIcmpHdr -> id                                                 ;
    usSquNo = pIcmpHdr -> seq                                                ;
  } else
  if ( pIcmpHdr -> type == ICMP_TIMEOUT )                                    {
    char        * pInnerIpHdr                                                ;
    int           iInnerIPHdrLen                                             ;
    ICMP_HEADER * pInnerIcmpHdr                                              ;
    //////////////////////////////////////////////////////////////////////////
    pInnerIpHdr    = buffer + iIpHdrLen + sizeof(ICMP_HEADER)                ;
    iInnerIPHdrLen = ( (IP_HEADER  *)pInnerIpHdr ) -> hdr_len * 4            ;
    pInnerIcmpHdr  = (ICMP_HEADER *)(pInnerIpHdr+iInnerIPHdrLen)             ;
    usID    = pInnerIcmpHdr -> id                                            ;
    usSquNo = pInnerIcmpHdr -> seq                                           ;
  } else return false                                                        ;
  ////////////////////////////////////////////////////////////////////////////
  if ( usSquNo != dr -> usSeqNo ) return false                               ;
  unsigned short cpi = ::GetCurrentProcessId ( )                             ;
  if ( usID    != cpi           ) return false                               ;
  ////////////////////////////////////////////////////////////////////////////
  dr -> dwIPaddr . s_addr = pIpHdr -> sourceIP                               ;
  dr -> dwRoundTripTime   = ::GetTickCount ( ) - dr -> dwRoundTripTime       ;
  ////////////////////////////////////////////////////////////////////////////
  return true                                                                ;
}

bool QtPCAP::RoutePath(QString destination,QString StopSite,int hop,int RTT)
{
  if ( RTT < 0 ) return false ;
  return true                 ;
}

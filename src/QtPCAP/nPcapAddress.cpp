#include <qtpcap.h>
#include <pcap.h>

PcapAddress:: PcapAddress ( void )
            : address     ( ""   )
            , netmask     ( ""   )
            , broadcast   ( ""   )
            , destination ( ""   )
{
}

PcapAddress::~PcapAddress(void)
{
}

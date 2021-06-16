/****************************************************************************
 *                                                                          *
 * Copyright (C) 2015 Neutrino International Inc.                           *
 *                                                                          *
 * Author : Brian Lin <lin.foxman@gmail.com>, Skype: wolfram_lin            *
 *                                                                          *
 ****************************************************************************/

#ifndef QT_PCAP_H
#define QT_PCAP_H

#include <QtCore>
#ifndef QT_STATIC
#include <QtScript>
#endif
#include <QtNetwork>
#include <QtSql>

QT_BEGIN_NAMESPACE

#ifndef QT_STATIC
#  if defined(QT_BUILD_QTPCAP_LIB)
#    define Q_PCAP_EXPORT Q_DECL_EXPORT
#  else
#    define Q_PCAP_EXPORT Q_DECL_IMPORT
#  endif
#else
#    define Q_PCAP_EXPORT
#endif

class Q_PCAP_EXPORT PcapAddress ;
class Q_PCAP_EXPORT PcapIf      ;
class Q_PCAP_EXPORT QtPCAP      ;

class Q_PCAP_EXPORT PcapAddress
{
  public:

    QString address     ;
    QString netmask     ;
    QString broadcast   ;
    QString destination ;

    explicit PcapAddress (void) ;
    virtual ~PcapAddress (void) ;

  protected:

  private:

};

class Q_PCAP_EXPORT PcapIf
{
  public:

    enum             {
      LOOPBACK = 1   ,
      UP       = 2   ,
      RUNNING  = 4 } ;

    QString            Name        ;
    QString            Description ;
    int                Flags       ;
    QList<PcapAddress> Address     ;

    explicit PcapIf (void) ;
    virtual ~PcapIf (void) ;

  protected:

  private:

};

class Q_PCAP_EXPORT QtPCAP
{
  public:

    QMap<QString,QVariant> Variables    ;
    QList<PcapIf>          Interfaces   ;
    QString                ErrorMessage ;

    explicit       QtPCAP      (void) ;
    virtual       ~QtPCAP      (void) ;

    static QString Version     (void) ;
    static QString Lookup      (QString & error) ;

    virtual bool   Probe       (void) ;
    virtual int    indexOf     (QString device) ;

    virtual bool   SniffTCP    (int      Interface,bool & keep) ;
    virtual bool   SniffTCP    (QString  Interface,bool & keep) ;
    virtual bool   SniffTCP    (PcapIf & Interface,bool & keep) ;
    virtual bool   Interpreter (unsigned char * packet) ;
    virtual bool   Sniff       (QString source,QString destination) ;
    virtual bool   Payload     (unsigned char * payload,int size) ;
    virtual bool   Payload     (QString         source      ,
                                QString         destination ,
                                unsigned char * payload     ,
                                int             size      ) ;

    virtual bool   Traceroute  (QString destination) ;
    virtual bool   RoutePath   (QString destination,QString StopSite,int hop,int RTT) ;

  protected:

    unsigned short Checksum    (unsigned short * buffer,int size) ;
    bool           DecodeICMP  (char * buffer,int size,void * result) ;

  private:

};

QT_END_NAMESPACE

#endif

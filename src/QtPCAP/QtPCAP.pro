NAME         = QtPCAP
TARGET       = $${NAME}
QT           = core
QT          -= gui
QT          += network
QT          += sql
CONFIG(static,static|shared) {
# static version does not support Qt Script now
QT          -= script
} else {
QT          += script
}

load(qt_build_config)
load(qt_module)

INCLUDEPATH += $${PWD}/../../include/QtPCAP
INCLUDEPATH += $${PWD}/../../include/QtPCAP/libpcap

HEADERS     += $${PWD}/../../include/QtPCAP/qtpcap.h

SOURCES     += $${PWD}/nPCAP.cpp
SOURCES     += $${PWD}/nPcapIf.cpp
SOURCES     += $${PWD}/nPcapAddress.cpp

OTHER_FILES += $${PWD}/../../include/$${NAME}/headers.pri

include ($${PWD}/../../doc/Qt/Qt.pri)

win32 {

LIBS        += -luser32
LIBS        += -lshell32
LIBS        += -lws2_32
LIBS        += -lAdvapi32

CONFIG(release,debug|release) {
LIBS        += -lairpcap
LIBS        += -lnpptools
LIBS        += -lPacket
LIBS        += -lwpcap
} else {
LIBS        += -lairpcapd
LIBS        += -lnpptoolsd
LIBS        += -lPacketd
LIBS        += -lwpcapd
}

}

TRNAME       = QtPCAP
include ($${PWD}/../../Translations.pri)

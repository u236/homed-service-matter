include(../homed-common/homed-common.pri)
include(../homed-common/homed-endpoint.pri)
include(../homed-common/homed-parser.pri)

HEADERS += \
    clusters.h \
    controller.h \
    crypto.h \
    device.h \
    interaction.h \
    mdns.h \
    message.h \
    mrp.h \
    pase.h \
    session.h \
    matter.h \

    tlv.h

SOURCES += \
    controller.cpp \
    crypto.cpp \
    device.cpp \
    interaction.cpp \
    mdns.cpp \
    message.cpp \
    mrp.cpp \
    pase.cpp \
    session.cpp \
    matter.cpp \
    tlv.cpp

QT += network

linux-arm-gnueabihf-g++
{
    INCLUDEPATH += /opt/arm-libs/include/
    LIBS += -L/opt/arm-libs/lib/
}

mac-linux-arm-gnueabihf-g++
{
    INCLUDEPATH += /Volumes/Storage/Toolchain/arm-libs/include/
    LIBS += -L/Volumes/Storage/Toolchain/arm-libs/lib/
}

LIBS += -lssl -lcrypto

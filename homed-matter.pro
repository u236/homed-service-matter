include(../homed-common/homed-color.pri)
include(../homed-common/homed-common.pri)
include(../homed-common/homed-endpoint.pri)
include(../homed-common/homed-parser.pri)

HEADERS += \
    action.h \
    ble.h \
    case.h \
    clusters.h \
    controller.h \
    crypto.h \
    device.h \
    interaction.h \
    mdns.h \
    message.h \
    mrp.h \
    pase.h \
    matter.h \
    property.h \
    tlv.h

SOURCES += \
    action.cpp \
    ble.cpp \
    case.cpp \
    controller.cpp \
    crypto.cpp \
    device.cpp \
    interaction.cpp \
    mdns.cpp \
    message.cpp \
    mrp.cpp \
    pase.cpp \
    matter.cpp \
    property.cpp \
    tlv.cpp

QT += dbus

QMAKE_CXXFLAGS += -Wno-deprecated-declarations
LIBS += -lcrypto -ldl -lpthread -lssl

mac-linux-arm-gnueabihf-g++
{
    INCLUDEPATH += /Volumes/Storage/Toolchain/arm-libs/include/
    LIBS += -L/Volumes/Storage/Toolchain/arm-libs/lib/
}

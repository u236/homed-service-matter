include(../homed-common/homed-color.pri)
include(../homed-common/homed-common.pri)
include(../homed-common/homed-endpoint.pri)
include(../homed-common/homed-parser.pri)

HEADERS += \
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
    session.h \
    matter.h \
    tlv.h

SOURCES += \
    case.cpp \
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

QMAKE_CXXFLAGS += -Wno-deprecated-declarations
LIBS += -lcrypto -ldl -lpthread -lssl

#ifndef BTP_H
#define BTP_H

#include <QObject>
#include <QByteArray>
#include <QTimer>

/*
    BLE Transport Protocol (BTP) — Matter spec section 4.18

    Provides reliable, segmented delivery over BLE GATT:
    - Handshake to negotiate MTU and window size
    - Segmentation for messages larger than MTU
    - ACK-based flow control
    - Sequence numbers for ordering

    Packet format:
    - Flags (1 byte): H=handshake, M=management, A=has ACK, E=end, B=beginning
    - ACK number (1 byte, if A flag)
    - Sequence number (1 byte, if not handshake)
    - Message length (2 bytes, if B flag, little-endian)
    - Payload (remaining bytes)

    Handshake request (opcode 0x6C):
    - Flags: 0x65 (H=1, M=1, B=1, E=1)
    - Versions bitmap (4 bytes)
    - Client MTU (2 bytes, LE)
    - Client window size (1 byte)

    Handshake response (opcode 0x6D):
    - Flags: 0x65
    - Selected version (1 byte)
    - Server MTU (2 bytes, LE)
    - Server window size (1 byte)
*/

#define BTP_FLAG_HANDSHAKE      0x40
#define BTP_FLAG_MANAGEMENT     0x20
#define BTP_FLAG_ACK            0x08
#define BTP_FLAG_END            0x04
#define BTP_FLAG_BEGINNING      0x01

#define BTP_HANDSHAKE_REQUEST   0x6C
#define BTP_HANDSHAKE_RESPONSE  0x6D

#define BTP_DEFAULT_MTU         256
#define BTP_DEFAULT_WINDOW      6
#define BTP_VERSION             4

class BTP : public QObject
{
    Q_OBJECT

public:

    BTP(QObject *parent);

    void startHandshake(void);
    void handleData(const QByteArray &data);
    void sendMessage(const QByteArray &message);

    inline bool ready(void) { return m_ready; }

private:

    bool m_ready;
    quint16 m_mtu;
    quint8 m_windowSize;

    quint8 m_txSequence;
    quint8 m_rxSequence;
    quint8 m_lastAck;

    QByteArray m_rxBuffer;
    quint16 m_rxExpectedLength;

    QList <QByteArray> m_txQueue;

    void sendSegments(const QByteArray &message);
    void sendAck(void);

signals:

    void handshakeComplete(void);
    void messageReceived(const QByteArray &message);
    void writeData(const QByteArray &data);

};

#endif

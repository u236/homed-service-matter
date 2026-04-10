// NOT REWIEWED

#ifndef BLE_H
#define BLE_H

#include <QDBusInterface>
#include <QTimer>

#define MATTER_BLE_SERVICE_UUID     "0000fff6-0000-1000-8000-00805f9b34fb"
#define MATTER_BLE_C1_UUID          "18ee2ef5-263d-4559-959f-4f9c429f9d11"
#define MATTER_BLE_C2_UUID          "18ee2ef5-263d-4559-959f-4f9c429f9d12"

struct BLEDevice
{
    QString path;
    QString address;
    QString name;
    quint16 discriminator;
    quint16 vendorId;
    quint16 productId;

    BLEDevice(void) : discriminator(0), vendorId(0), productId(0) {}
};

class BLE : public QObject
{
    Q_OBJECT

public:

    BLE(QObject *parent);

    void scan(void);
    void stopScan(void);
    void connectDevice(const QString &path);
    void disconnectDevice(void);

    void write(const QByteArray &data);
    void subscribe(void);

    inline bool available(void) { return m_available; }

private:

    QDBusConnection m_bus;
    bool m_available;
    bool m_scanning;
    bool m_connected;
    QTimer *m_scanTimer;

    QString m_adapterPath;
    QString m_devicePath;
    QString m_c1Path;
    QString m_c2Path;

    QMap <QString, BLEDevice> m_discovered;

    void findAdapter(void);
    void parseServiceData(const QByteArray &data, BLEDevice &device);
    void discoverCharacteristics(void);

private slots:

    void interfacesAdded(const QDBusMessage &message);
    void propertiesChanged(const QString &interface, const QMap <QString, QVariant> &changed, const QStringList &invalidated);
    void scanTimeout(void);

signals:

    void deviceFound(const BLEDevice &device);
    void connected(void);
    void disconnected(void);
    void dataReceived(const QByteArray &data);

};

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

    BTP(QObject *parent) : QObject(parent), m_ready(false), m_ackPending(false), m_mtu(BTP_DEFAULT_MTU), m_windowSize(BTP_DEFAULT_WINDOW), m_txSequence(0), m_rxSequence(0), m_lastAck(0), m_rxExpectedLength(0) {}

    void startHandshake(void);
    void handleData(const QByteArray &data);
    void sendMessage(const QByteArray &message);

    inline bool ready(void) { return m_ready; }

private:

    bool m_ready;
    bool m_ackPending;
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

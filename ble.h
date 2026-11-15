// NOT REWIEWED

#ifndef BLE_H
#define BLE_H

#define BLE_SERVICE_UUID            "0000fff6-0000-1000-8000-00805f9b34fb"
#define BLE_C1_UUID                 "18ee2ef5-263d-4559-959f-4f9c429f9d11"
#define BLE_C2_UUID                 "18ee2ef5-263d-4559-959f-4f9c429f9d12"
#define BLE_SCAN_TIMEOUT            30000

#define BTP_FLAG_HANDSHAKE          0x40
#define BTP_FLAG_MANAGEMENT         0x20
#define BTP_FLAG_ACK                0x08
#define BTP_FLAG_END                0x04
#define BTP_FLAG_BEGINNING          0x01

#define BTP_HANDSHAKE_REQUEST       0x6C
#define BTP_HANDSHAKE_RESPONSE      0x6D

#define BTP_DEFAULT_MTU             256
#define BTP_DEFAULT_WINDOW          6
#define BTP_VERSION                 4

#include <QDBusInterface>
#include <QTimer>

#pragma pack(push, 1)

struct bleServiceDataStruct
{
    quint8  flags;
    quint16 discriminator;
    quint16 vendorId;
    quint16 productId;
    quint8  additionalData;
};

struct btpHandshakeRequestStruct
{
    quint8  flags;
    quint8  opcode;
    quint32 versions;
    quint16 mtu;
    quint8  window;
};

struct btpHandshakeResponseStruct
{
    quint8  flags;
    quint8  opcode;
    quint8  version;
    quint16 mtu;
    quint8  window;
};

#pragma pack(pop)

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

    inline bool available(void) { return m_available; }

    void scan(void);
    void stopScan(void);

    void connectDevice(const QString &path);
    void disconnectDevice(void);

    void write(const QByteArray &data);
    void subscribe(void);

private:

    QTimer *m_timer;
    QDBusConnection m_bus;

    QString m_adapterPath, m_devicePath, m_c1Path, m_c2Path;
    bool m_available, m_scanning, m_connected;

    void findAdapter(void);
    void findCharacteristics(void);
    void clearDevice(void);

private slots:

    void interfacesAdded(const QDBusMessage &message);
    void propertiesChanged(const QString &interface, const QMap <QString, QVariant> &changed, const QStringList &);
    void scanTimeout(void);

signals:

    void deviceFound(const BLEDevice &device);
    void connected(void);
    void disconnected(void);
    void dataReceived(const QByteArray &data);

};

class BTP : public QObject
{
    Q_OBJECT

public:

    BTP(QObject *parent) : QObject(parent), m_ready(false), m_mtu(BTP_DEFAULT_MTU), m_window(BTP_DEFAULT_WINDOW), m_txSequence(0), m_rxSequence(0) {}

    void startHandshake(void);
    void parseData(const QByteArray &data);
    void sendMessage(const QByteArray &message);

private:

    bool m_ready;
    quint16 m_mtu;
    quint8 m_window, m_txSequence, m_rxSequence;
    QByteArray m_buffer;

signals:

    void handshakeFinished(void);
    void messageReceived(const QByteArray &message);
    void writeData(const QByteArray &data);

};

#endif

#ifndef BLE_H
#define BLE_H

#include <QObject>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusObjectPath>
#include <QMap>
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

#endif

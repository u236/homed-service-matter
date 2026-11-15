// NOT REWIEWED

#include <QProcess>
#include <QtEndian>
#include <QRandomGenerator>
#include "logger.h"
#include "matter.h"

using namespace MatterProtocol;

static const char base38Alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

static const int verhoeffD[10][10] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5}, {2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7}, {4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1}, {6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3}, {8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0}};
static const int verhoeffP[8][10] = {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4}, {5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7}, {9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1}, {2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8}};
static const int verhoeffInv[10] = {0, 4, 3, 2, 1, 5, 6, 7, 8, 9};

static QByteArray base38Decode(const QString &string)
{
    QByteArray data;

    for (int i = 0; i < string.length(); i += 5)
    {
        int length = qMin(string.length() - i, 5);
        quint32 value = 0, base = 1;

        for (int j = 0; j < length; j++)
        {
            const char *pointer = strchr(base38Alphabet, string.at(i + j).toLatin1());

            if (!pointer)
                return QByteArray();

            value += static_cast <quint32> (pointer - base38Alphabet) * base;
            base *= 38;
        }

        for (int j = 0; j < (length == 5 ? 3 : length == 4 ? 2 : 1); j++)
        {
            data.append(static_cast <char> (value & 0xFF));
            value >>= 8;
        }
    }

    return data;
}

static QString base38Encode(const QByteArray &data)
{
    QString string;

    for (int i = 0; i < data.length(); i += 3)
    {
        int length = qMin(data.length() - i, 3);
        quint32 value = 0;

        for (int j = length - 1; j >= 0; j--)
            value = (value << 8) | static_cast <quint8> (data.at(i + j));

        for (int j = 0; j < (length == 3 ? 5 : length == 2 ? 4 : 2); j++)
        {
            string.append(QLatin1Char(base38Alphabet[value % 38]));
            value /= 38;
        }
    }

    return string;
}

static int verhoeffChecksum(const QString &digits)
{
    int value = 0;

    for (int i = digits.length() - 1; i >= 0; i--)
        value = verhoeffD[value][verhoeffP[(digits.length() - i) % 8][digits.at(i).digitValue()]];

    return verhoeffInv[value];
}

static bool parseQrCode(const QString &code, quint32 &passcode, quint16 &discriminator)
{
    QByteArray data = base38Decode(code.mid(3));
    quint64 low;
    quint32 high = 0;

    if (!code.startsWith("MT:") || data.length() < 11)
        return false;

    // 88-bit payload: version (3), vendor id (16), product id (16), commissioning flow (2), rendezvous flags (8), discriminator (12), passcode (27), padding (4)
    memcpy(&low, data.constData(), sizeof(low));
    memcpy(&high, data.constData() + 8, 3);

    low = qFromLittleEndian(low);
    high = qFromLittleEndian(high);

    discriminator = static_cast <quint16> ((low >> 45) & 0xFFF);
    passcode = static_cast <quint32> (((low >> 57) | (static_cast <quint64> (high) << 7)) & 0x7FFFFFF);

    return passcode && passcode <= 99999998;
}

static bool parseManualCode(const QString &code, quint32 &passcode, quint16 &discriminator)
{
    QString digits;
    quint32 chunk1, chunk2, chunk3;

    for (int i = 0; i < code.length(); i++)
    {
        if (!code.at(i).isDigit())
            continue;

        digits.append(code.at(i));
    }

    if (digits.length() != 11 && digits.length() != 21)
        return false;

    chunk1 = digits.mid(0, 1).toUInt();
    chunk2 = digits.mid(1, 5).toUInt();
    chunk3 = digits.mid(6, 4).toUInt();

    // 4-bit short discriminator and 27-bit passcode
    discriminator = static_cast <quint16> (((chunk1 & 0x03) << 2) | ((chunk2 >> 14) & 0x03));
    passcode = (chunk2 & 0x3FFF) | (chunk3 << 14);

    return passcode && passcode <= 99999998;
}

static QString generateManualCode(quint32 passcode, quint16 discriminator)
{
    quint8 shortDiscriminator = (discriminator >> 8) & 0x0F;
    quint32 chunk1 = (shortDiscriminator >> 2) & 0x03, chunk2 = ((shortDiscriminator & 0x03) << 14) | (passcode & 0x3FFF), chunk3 = (passcode >> 14) & 0x1FFF;
    QString digits = QString("%1%2%3").arg(chunk1, 1, 10, QLatin1Char('0')).arg(chunk2, 5, 10, QLatin1Char('0')).arg(chunk3, 4, 10, QLatin1Char('0'));

    return digits.append(QString::number(verhoeffChecksum(digits)));
}

static QString generateQrCode(quint32 passcode, quint16 discriminator)
{
    quint64 low = static_cast <quint64> (2) << 35 | static_cast <quint64> (4) << 37 | static_cast <quint64> (discriminator & 0xFFF) << 45 | static_cast <quint64> (passcode & 0x7F) << 57;
    quint32 high = qToLittleEndian <quint32> ((passcode >> 7) & 0xFFFFF);

    // version, vendor id and product id are zero, commissioning flow is enhanced, rendezvous is BLE
    low = qToLittleEndian(low);
    return QString("MT:").append(base38Encode(QByteArray(reinterpret_cast <char*> (&low), sizeof(low)).append(reinterpret_cast <char*> (&high), 3)));
}

static QByteArray threadExtendedPanId(const QByteArray &dataset)
{
    int offset = 0;

    // MeshCoP TLV, type 2 is extended PAN ID
    while (offset + 1 < dataset.length())
    {
        quint8 type = static_cast <quint8> (dataset.at(offset++));
        quint16 length = static_cast <quint8> (dataset.at(offset++));

        if (length == 0xFF)
        {
            if (offset + 2 > dataset.length())
                return QByteArray();

            length = static_cast <quint16> (static_cast <quint8> (dataset.at(offset)) << 8 | static_cast <quint8> (dataset.at(offset + 1)));
            offset += 2;
        }

        if (offset + length > dataset.length())
            return QByteArray();

        if (type == 2 && length == 8)
            return dataset.mid(offset, 8);

        offset += length;
    }

    return QByteArray();
}

static QByteArray otbrRequest(const QString &url, const QString &path)
{
    QProcess process;

    process.start("curl", {"-fsS", "-H", "Accept: text/plain", "--max-time", "5", QString("http://%1%2").arg(url, path)});
    process.waitForFinished(THREAD_DATASET_TIMEOUT);

    if (process.exitStatus() != QProcess::NormalExit || process.exitCode())
        return QByteArray();

    return process.readAllStandardOutput().trimmed();
}

Matter::Matter(QSettings *config, QObject *parent) : QObject(parent), m_searchTimer(new QTimer(this)), m_reconnectTimer(new QTimer(this)), m_pingTimer(new QTimer(this)), m_threadTimer(new QTimer(this)), m_socket(new QUdpSocket(this)), m_mrp(new MRP(this)), m_mdns(new MDNS(this)), m_ble(new BLE(this)), m_btp(new BTP(this)), m_sessions(new SessionManager(this)), m_devices(new DeviceList(config, parent)), m_events(QMetaEnum::fromType <Event> ()), m_threadReady(false), m_fabricId(1), m_nodeId(1), m_rootCaId(0), m_exchangeCounter(0), m_sessionCounter(1), m_searching(false), m_shortDiscriminator(false), m_bleCommissioning(false), m_commissioning(false), m_passcode(0), m_discriminator(0), m_searchNodeId(0), m_commissionDevice(nullptr), m_removeDevice(nullptr)
{
    QByteArray data = Crypto::randomData(sizeof(m_messageCounter));

    // random message counter avoids replay detection after restart
    memcpy(&m_messageCounter, data.constData(), sizeof(m_messageCounter));

    m_debug = config->value("debug/matter", false).toBool();
    m_wifiSsid = config->value("wifi/ssid").toString();
    m_wifiPassword = config->value("wifi/password").toString();
    m_otbrUrl = config->value("thread/otbr").toString();

    m_mrp->setDebug(m_debug); // TODO: separate config parameters

    connect(m_searchTimer, &QTimer::timeout, this, &Matter::searchTimeout);
    connect(m_reconnectTimer, &QTimer::timeout, this, &Matter::reconnectTimeout);
    connect(m_pingTimer, &QTimer::timeout, this, &Matter::pingTimeout);
    connect(m_threadTimer, &QTimer::timeout, this, &Matter::threadTimeout);
    connect(m_socket, &QUdpSocket::readyRead, this, &Matter::readyRead);

    connect(m_mrp, &MRP::retransmit, this, &Matter::retransmit);
    connect(m_mrp, &MRP::retransmitFailed, this, &Matter::retransmitFailed);
    connect(m_mrp, &MRP::sendStandaloneAck, this, &Matter::sendStandaloneAck);
    connect(m_mdns, &MDNS::serviceFound, this, &Matter::serviceFound);

    connect(m_ble, &BLE::deviceFound, this, &Matter::bleDeviceFound);
    connect(m_ble, &BLE::connected, this, &Matter::bleConnected);
    connect(m_ble, &BLE::disconnected, this, &Matter::bleDisconnected);
    connect(m_ble, &BLE::dataReceived, this, &Matter::bleDataReceived);

    connect(m_btp, &BTP::handshakeFinished, this, &Matter::btpHandshakeFinished);
    connect(m_btp, &BTP::messageReceived, this, &Matter::btpMessageReceived);
    connect(m_btp, &BTP::writeData, this, &Matter::btpWriteData);

    m_searchTimer->setSingleShot(true);
    m_reconnectTimer->setSingleShot(true);
    m_pingTimer->start(PING_INTERVAL);

    // OTBR may start later than this service, Thread peers are not reachable until it's ready
    if (!m_otbrUrl.isEmpty() && !fetchThreadDataset())
        m_threadTimer->start(THREAD_DATASET_INTERVAL);

    if (!m_socket->bind(QHostAddress::Any, MATTER_PORT))
    {
        logWarning << "Matter UDP port" << MATTER_PORT << "bind failed";
        return;
    }

    logInfo << "Matter controller listening on port" << MATTER_PORT;
    m_devices->init();

    for (int i = 0; i < m_devices->count(); i++)
    {
        const Device &device = m_devices->at(i);
        SessionInfo session;

        connect(device.data(), &DeviceObject::deviceUpdated, this, &Matter::deviceUpdated, Qt::UniqueConnection);
        connect(device.data(), &DeviceObject::endpointUpdated, this, &Matter::endpointUpdated, Qt::UniqueConnection);

        // sessions are restored for battery powered devices only, CASE handshake wakes up their radio and takes long time
        if (!device->sessionStored() || !device->batteryPowered())
            continue;

        device->restoreSession(session);
        session.localMessageCounter += SESSION_COUNTER_MARGIN; // message counter must be strictly monotonic across restarts
        m_sessions->addSession(session);

        if (m_sessionCounter <= session.localSessionId)
            m_sessionCounter = session.localSessionId + 1;

        logInfo << device << "secure session" << session.localSessionId << "restored, peer session" << session.peerSessionId << "message counter" << session.localMessageCounter;

        if (device->endpoints().isEmpty())
            continue;

        // Thread peers stay offline until OTBR is ready, otherwise MRP retransmits storm out when route appears
        if (device->thread() && !m_threadReady)
        {
            device->setAvailability(Availability::Offline);
            continue;
        }

        // peer subscription may expire while service is down
        subscribeDevice(device.data(), m_sessions->byLocalId(session.localSessionId));
    }

    if (m_devices->fabricKey().isEmpty())
    {
        QByteArray fabricKey = Crypto::randomData(32), ipk = Crypto::randomData(16), operationalKey = Crypto::randomData(32), id = Crypto::randomData(8);
        quint64 rootCaId;

        logInfo << "New fabric credentials generated";
        memcpy(&rootCaId, id.constData(), sizeof(rootCaId));

        setFabricCredentials(fabricKey, ipk, operationalKey, QByteArray(), QByteArray(), rootCaId);
        m_devices->setFabricCredentials(m_fabricKey, m_ipk, m_operationalKey, m_controllerNoc, m_controllerRcac, m_rootCaId);
        m_devices->storeDatabase(true);
        return;
    }

    setFabricCredentials(m_devices->fabricKey(), m_devices->ipk(), m_devices->operationalKey(), m_devices->controllerNoc(), m_devices->controllerRcac(), m_devices->rootCaId());
}

Matter::~Matter(void)
{
    delete m_devices;
}

void Matter::connectDevice(const QString &code)
{
    bool qrCode = code.startsWith("MT:");
    quint32 passcode;
    quint16 discriminator;
    quint64 nodeId;

    if (qrCode ? !parseQrCode(code, passcode, discriminator) : !parseManualCode(code, passcode, discriminator))
    {
        logWarning << "Invalid" << (qrCode ? "QR" : "manual") << "code" << code;
        return;
    }

    nodeId = m_devices->generateNodeId();

    logInfo << "Adding device with passcode" << passcode << "and" << (qrCode ? "full" : "short") << "discriminator" << discriminator << "as node" << QString::number(nodeId, 16) << "...";
    searchDevice(passcode, discriminator, !qrCode, nodeId);
}

void Matter::connectDevice(DeviceObject *device)
{
    PendingCase pending;

    // Thread peers are not reachable until OTBR is ready, resumeThreadDevices will retry later
    if (device->thread() && !m_threadReady)
    {
        logDebug(m_debug) << device << "CASE deferred, Thread network is not ready";
        return;
    }

    if (m_sessions->byPeerNodeId(device->nodeId()))
    {
        logDebug(m_debug) << device << "already has active session";
        return;
    }

    if (caseInProgress(device))
    {
        logDebug(m_debug) << device << "CASE already in progress";
        return;
    }

    if (device->networkAddress().isNull())
    {
        logWarning << device << "network address is unknown";
        return;
    }

    pending.session = new CASESession(this);
    pending.device = device;
    pending.address = device->networkAddress();
    pending.port = device->networkPort();
    pending.exchangeId = m_exchangeCounter++;
    pending.commissioning = m_commissioning;

    connect(pending.session, &CASESession::sendSigma1, this, &Matter::caseSendSigma1);
    connect(pending.session, &CASESession::sendSigma3, this, &Matter::caseSendSigma3);
    connect(pending.session, &CASESession::established, this, &Matter::caseEstablished);
    connect(pending.session, &CASESession::failed, this, &Matter::caseFailed);

    m_pendingCases.insert(pending.exchangeId, pending);
    m_commissioning = false;

    logInfo << device << "starting CASE with" << pending.address.toString() << "port" << pending.port << "...";
    pending.session->start(m_sessionCounter++, device->nodeId(), m_fabricId, m_fabricPublicKey, m_operationalKey, m_ipk, m_controllerNoc, device->resumptionId(), device->resumptionSecret());
}

void Matter::discoverDevice(const QString &deviceName)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull())
    {
        logWarning << "Device" << deviceName << "discovery failed, device not found";
        return;
    }

    emit deviceEvent(device.data(), Event::aboutToUpdate);

    device->endpoints().clear();
    m_devices->storeDatabase(true);

    discoverDevice(device.data());
}

void Matter::shareDevice(const QString &deviceName, quint16 timeout)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull() || !device->active())
    {
        logWarning << "Device" << deviceName << "share failed, device not found or inactive";
        return;
    }

    shareDevice(device.data(), timeout < SHARE_TIMEOUT_MIN ? SHARE_TIMEOUT_MIN : timeout > SHARE_TIMEOUT_MAX ? SHARE_TIMEOUT_MAX : timeout);
}

void Matter::updateDevice(const QString &deviceName, const QString &name, const QString &note, bool active, bool discovery, bool cloud)
{
    const Device &device = m_devices->byName(deviceName), &other = m_devices->byName(name);

    if (device.isNull())
    {
        logWarning << "Device" << deviceName << "update failed, device not found";
        return;
    }

    if (!name.isEmpty() && device != other && !other.isNull())
    {
        logWarning << device << "rename failed, name already in use";
        emit deviceEvent(device.data(), Event::nameDuplicate);
        return;
    }

    if (!name.isEmpty() && device->name() != name)
    {
        emit deviceEvent(device.data(), Event::aboutToUpdate);
        device->setName(name);
    }

    // TODO: inactive device must not run at all: no session restore, subscription or reconnect, status always offline.
    // Now it keeps working and any incoming packet sets it online. Also decide how to remove inactive device, without a session it stays in our fabric
    device->setActive(active);
    device->setDiscovery(discovery);
    device->setCloud(cloud);
    device->setNote(note);

    logInfo << device << "successfully updated";
    emit deviceEvent(device.data(), Event::updated);
    m_devices->storeDatabase(true);
}

void Matter::removeDevice(const QString &deviceName)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull())
    {
        logWarning << "Device" << deviceName << "remove failed, device not found";
        return;
    }

    removeDevice(device.data());
}

void Matter::getProperties(const QString &deviceName)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull() || !device->active())
        return;

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        if (it.value()->properties().isEmpty())
            continue;

        emit endpointUpdated(device.data(), it.key());
    }
}

void Matter::deviceAction(const QString &deviceName, quint8 endpointId, const QString &name, const QVariant &value)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull() || !device->active())
        return;

    if (endpointId)
    {
        deviceCommand(device.data(), endpointId, name, value);
        return;
    }

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
        deviceCommand(device.data(), it.key(), name, value);
}

void Matter::setFabricCredentials(const QByteArray &fabricKey, const QByteArray &ipk, const QByteArray &operationalKey, const QByteArray &controllerNoc, const QByteArray &controllerRcac, quint64 rootCaId)
{
    m_fabricKey = fabricKey;
    m_ipk = ipk;
    m_operationalKey = operationalKey;
    m_rootCaId = rootCaId;

    m_fabricPublicKey = ECPoint::multiply(ECPoint::generator(), BigNum(m_fabricKey).bn()).toData();
    m_operationalPublicKey = ECPoint::multiply(ECPoint::generator(), BigNum(m_operationalKey).bn()).toData();

    if (!controllerNoc.isEmpty() && !controllerRcac.isEmpty())
    {
        m_controllerNoc = controllerNoc;
        m_controllerRcac = controllerRcac;
    }
    else
    {
        m_controllerRcac = generateCertificate(0, m_fabricPublicKey, true);
        m_controllerNoc = generateCertificate(m_nodeId, m_operationalPublicKey, false);
    }

    logInfo << "Fabric credentials loaded, root CA id" << QString::number(m_rootCaId, 16);
}

QByteArray Matter::generateCertificate(quint64 nodeId, const QByteArray &publicKey, bool root)
{
    QByteArray certificate = Crypto::generateCertificate(m_rootCaId, m_fabricId, nodeId, publicKey, m_fabricKey, m_fabricPublicKey, root), data;

    if (certificate.isEmpty())
    {
        logWarning << "X.509 certificate generation failed";
        return QByteArray();
    }

    data = Crypto::convertCertificate(certificate);
    logDebug(m_debug) << (root ? "RCAC" : "NOC") << "certificate generated, DER length" << certificate.length() << "and TLV length" << data.length();

    return data;
}

bool Matter::fetchThreadDataset(void)
{
    QByteArray state = otbrRequest(m_otbrUrl, "/node/state"), dataset, extendedPanId;

    // dataset is available before radio joins the mesh, so Thread state must be checked first
    if (state.isEmpty())
        return false;

    if (state.startsWith('"') && state.endsWith('"'))
        state = state.mid(1, state.length() - 2);

    if (!QList <QByteArray> {"child", "router", "leader"}.contains(state))
    {
        logDebug(m_debug) << "Thread state" << state << "is not ready";
        return false;
    }

    dataset = QByteArray::fromHex(otbrRequest(m_otbrUrl, "/node/dataset/active"));
    extendedPanId = threadExtendedPanId(dataset);

    if (extendedPanId.isEmpty())
        return false;

    m_threadDataset = dataset;
    m_threadExtendedPanId = extendedPanId;
    m_threadReady = true;

    logInfo << "Thread dataset received from" << m_otbrUrl << "with state" << state << "and extended PAN ID" << m_threadExtendedPanId.toHex();
    return true;
}

void Matter::resumeThreadDevices(void)
{
    bool reconnect = false;

    for (int i = 0; i < m_devices->count(); i++)
    {
        const Device &device = m_devices->at(i);
        SessionInfo *session;

        if (!device->thread() || device->endpoints().isEmpty())
            continue;

        session = m_sessions->byPeerNodeId(device->nodeId());

        if (session)
        {
            subscribeDevice(device.data(), session);
            continue;
        }

        device->setReconnectTime(0);
        reconnect = true;
    }

    if (!reconnect)
        return;

    scheduleReconnect();
}

void Matter::searchDevice(quint32 passcode, quint16 discriminator, bool shortDiscriminator, quint64 nodeId)
{
    m_searching = true;
    m_passcode = passcode;
    m_discriminator = discriminator;
    m_shortDiscriminator = shortDiscriminator;
    m_searchNodeId = nodeId;
    m_bleCommissioning = false;

    m_searchTimer->start(SEARCH_TIMEOUT);
    m_mdns->browse();

    logInfo << "Searching for commissionable device with" << (shortDiscriminator ? "short" : "full") << "discriminator" << discriminator << "...";

    if (!m_ble->available() || m_wifiSsid.isEmpty())
        return;

    logInfo << "BLE and mDNS scanning in parallel...";
    m_ble->scan();
}

void Matter::discoverDevice(DeviceObject *device)
{
    SessionInfo *session = m_sessions->byPeerNodeId(device->nodeId());

    if (!session)
        return;

    logInfo << device << "discovering endpoints...";
    sendRequest(session, InteractionModelOpcode::ReadRequest, InteractionModel::readRequest(QList <AttributePath> {AttributePath(0, Clusters::Descriptor::Id, Clusters::Descriptor::Attributes::PartsList)}));
}

void Matter::removeDevice(DeviceObject *device)
{
    SessionInfo *session = m_sessions->byPeerNodeId(device->nodeId());
    MatterTLV::Encoder fields;

    if (!session)
    {
        logWarning << device << "has no active session, removing forcefully";
        releaseDevice(device, false);
        return;
    }

    logInfo << device << "sending RemoveFabric request with fabric index" << device->fabricIndex() << "...";
    m_removeDevice = device;

    fields.openStructure();
    fields.encodeUnsignedInt(0, device->fabricIndex());
    fields.closeContainer();

    sendRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::RemoveFabric), fields));
    session->active = false;
}

void Matter::releaseDevice(DeviceObject *device, bool success)
{
    SessionInfo *session = m_sessions->byPeerNodeId(device->nodeId());
    int index = -1;

    m_devices->byName(device->name(), &index);
    emit deviceEvent(device, Event::removed, {{"success", success}});

    // pending CASE keeps raw device pointer, so it must be dropped before device removal
    for (auto it = m_pendingCases.begin(); it != m_pendingCases.end(); )
    {
        if (it.value().device != device)
        {
            it++;
            continue;
        }

        it.value().session->deleteLater();
        it = m_pendingCases.erase(it);
    }

    if (session)
        m_sessions->removeSession(session->localSessionId);

    // some peers (e.g. Shelly 1PM) keep advertising themselves after removal from the fabric
    m_mdns->purgeOperational(device->networkAddress());

    if (index < 0)
        return;

    m_devices->removeAt(index);
    m_devices->storeDatabase(true);
}

void Matter::shareDevice(DeviceObject *device, quint16 timeout)
{
    SessionInfo *session = m_sessions->byPeerNodeId(device->nodeId());
    QList <quint32> invalid = {11111111, 22222222, 33333333, 44444444, 55555555, 66666666, 77777777, 88888888, 12345678, 87654321};
    PendingShare share;
    QByteArray data;

    if (!session)
    {
        logWarning << device << "has no active session to share";
        return;
    }

    if (m_pendingShares.contains(device->nodeId()))
    {
        logWarning << device << "sharing already in progress";
        return;
    }

    while (true)
    {
        data = Crypto::randomData(sizeof(share.passcode));
        memcpy(&share.passcode, data.constData(), sizeof(share.passcode));
        share.passcode = share.passcode % 99999998 + 1;

        if (!invalid.contains(share.passcode))
            break;
    }

    data = Crypto::randomData(2);

    share.device = device;
    share.exchangeId = m_exchangeCounter++;
    share.discriminator = (static_cast <quint8> (data.at(0)) | static_cast <quint8> (data.at(1)) << 8) & 0xFFF;
    share.timeout = timeout;
    share.salt = Crypto::randomData(32);
    share.verifier = PASESession::verifier(share.passcode, share.salt, SHARE_ITERATIONS);
    share.timedRequest = true;

    logInfo << device << "sharing with passcode" << share.passcode << "discriminator" << share.discriminator << "and timeout" << timeout << "...";
    m_pendingShares.insert(device->nodeId(), share);

    // OpenCommissioningWindow is sent after timed request acknowledgement
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::TimedRequest), static_cast <quint16> (ProtocolId::InteractionModel), InteractionModel::timedRequest(TIMED_REQUEST_TIMEOUT), share.exchangeId, true);
}

void Matter::deviceCommand(DeviceObject *device, quint8 endpointId, const QString &name, const QVariant &value)
{
    SessionInfo *session = m_sessions->byPeerNodeId(device->nodeId());
    const Endpoint &endpoint = device->endpoints().value(endpointId);

    if (!session)
    {
        logWarning << device << "has no active session, starting CASE...";
        connectDevice(device);
        return;
    }

    if (endpoint.isNull())
        return;

    // endpoints without matching action are skipped, so broadcast request is sent to suitable endpoints only
    for (int i = 0; i < endpoint->actions().count(); i++)
    {
        const Action &action = endpoint->actions().at(i);
        QByteArray payload;

        if (action->name() != name || !endpoint->clusters().contains(action->clusterId()))
            continue;

        payload = action->request(endpointId, value);

        if (payload.isEmpty())
            continue;

        logInfo << device << "endpoint" << endpointId << "command" << name << "sent";
        sendEncrypted(session, static_cast <quint8> (action->opcode()), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
        return;
    }
}

bool Matter::subscribeDevice(DeviceObject *device, SessionInfo *session)
{
    QList <AttributePath> attributes;
    QList <EventPath> events;

    if (!session)
        return false;

    attributes = subscriptionAttributes(device);
    events = subscriptionEvents(device);

    if (attributes.isEmpty() && events.isEmpty())
        return false;

    // priming report contains buffered event history, events are ignored until subscribe response is received
    device->setSubscriptionPrimed(false);

    logInfo << device << "subscribing to" << attributes.count() << "attributes and" << events.count() << "events...";
    sendRequest(session, InteractionModelOpcode::SubscribeRequest, InteractionModel::subscribeRequest(attributes, events, 0, SUBSCRIPTION_MAX_INTERVAL));
    return true;
}

QList <AttributePath> Matter::subscriptionAttributes(DeviceObject *device)
{
    QList <AttributePath> list;

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        const Endpoint &endpoint = it.value();
        quint32 capabilities = static_cast <quint16> (endpoint->meta().value("colorCapabilities").toInt());
        bool hueSaturation = capabilities & Clusters::ColorControl::Capabilities::HueSaturation, colorTemperature = capabilities & Clusters::ColorControl::Capabilities::ColorTemperature;

        if (endpoint->clusters().contains(Clusters::OnOff::Id))
        {
            list.append(AttributePath(it.key(), Clusters::OnOff::Id, Clusters::OnOff::Attributes::OnOff));

            // StartUpOnOff attribute is optional without lighting feature, unsupported attribute may break the whole subscription
            if (endpoint->meta().value("onOffFeatures").toUInt() & Clusters::OnOff::Features::LT)
                list.append(AttributePath(it.key(), Clusters::OnOff::Id, Clusters::OnOff::Attributes::StartUpOnOff));
        }

        if (endpoint->clusters().contains(Clusters::LevelControl::Id))
            list.append(AttributePath(it.key(), Clusters::LevelControl::Id, Clusters::LevelControl::Attributes::CurrentLevel));

        if (endpoint->clusters().contains(Clusters::ColorControl::Id))
        {
            if (hueSaturation)
            {
                list.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::CurrentHue));
                list.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::CurrentSaturation));
            }

            if (colorTemperature)
                list.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorTemperatureMireds));

            if (hueSaturation && colorTemperature)
                list.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorMode));
        }

        if (endpoint->clusters().contains(Clusters::PowerSource::Id))
            list.append(AttributePath(it.key(), Clusters::PowerSource::Id, Clusters::PowerSource::Attributes::BatPercentRemaining));

        if (endpoint->clusters().contains(Clusters::BooleanState::Id))
            list.append(AttributePath(it.key(), Clusters::BooleanState::Id, Clusters::BooleanState::Attributes::StateValue));

        if (endpoint->clusters().contains(Clusters::OccupancySensing::Id))
            list.append(AttributePath(it.key(), Clusters::OccupancySensing::Id, Clusters::OccupancySensing::Attributes::Occupancy));

        if (endpoint->clusters().contains(Clusters::TemperatureMeasurement::Id))
            list.append(AttributePath(it.key(), Clusters::TemperatureMeasurement::Id, Clusters::TemperatureMeasurement::Attributes::MeasuredValue));

        if (endpoint->clusters().contains(Clusters::RelativeHumidityMeasurement::Id))
            list.append(AttributePath(it.key(), Clusters::RelativeHumidityMeasurement::Id, Clusters::RelativeHumidityMeasurement::Attributes::MeasuredValue));

        if (endpoint->clusters().contains(Clusters::ElectricalPowerMeasurement::Id))
        {
            quint32 features = endpoint->meta().value("powerFeatures").toUInt();

            // AC peers report RMS values, DC peers report generic ones
            if (features & Clusters::ElectricalPowerMeasurement::Features::ALTC)
            {
                list.append(AttributePath(it.key(), Clusters::ElectricalPowerMeasurement::Id, Clusters::ElectricalPowerMeasurement::Attributes::RMSVoltage));
                list.append(AttributePath(it.key(), Clusters::ElectricalPowerMeasurement::Id, Clusters::ElectricalPowerMeasurement::Attributes::RMSCurrent));
                list.append(AttributePath(it.key(), Clusters::ElectricalPowerMeasurement::Id, Clusters::ElectricalPowerMeasurement::Attributes::Frequency));
            }
            else if (features & Clusters::ElectricalPowerMeasurement::Features::DIRC)
            {
                list.append(AttributePath(it.key(), Clusters::ElectricalPowerMeasurement::Id, Clusters::ElectricalPowerMeasurement::Attributes::Voltage));
                list.append(AttributePath(it.key(), Clusters::ElectricalPowerMeasurement::Id, Clusters::ElectricalPowerMeasurement::Attributes::ActiveCurrent));
            }

            list.append(AttributePath(it.key(), Clusters::ElectricalPowerMeasurement::Id, Clusters::ElectricalPowerMeasurement::Attributes::ActivePower));
        }

        if (endpoint->clusters().contains(Clusters::ElectricalEnergyMeasurement::Id))
            list.append(AttributePath(it.key(), Clusters::ElectricalEnergyMeasurement::Id, Clusters::ElectricalEnergyMeasurement::Attributes::CumulativeEnergyImported));
    }

    return list;
}

QList <EventPath> Matter::subscriptionEvents(DeviceObject *device)
{
    QList <EventPath> list;

    // only consumed events are subscribed, too many paths are rejected (e.g. IKEA BILRESA with 9 switch endpoints)
    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        const Endpoint &endpoint = it.value();
        quint32 features = endpoint->meta().value("switchFeatures").toUInt();
        bool encoder = (features & Clusters::Switch::Features::MSM) && !(features & Clusters::Switch::Features::MSL) && static_cast <quint8> (endpoint->meta().value("switchMultiPressMax").toUInt()) > 5;

        if (!endpoint->clusters().contains(Clusters::Switch::Id))
            continue;

        if (features & Clusters::Switch::Features::LS)
            list.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::SwitchLatched, true));

        // initial press is used by encoders only to report rotation start
        if (encoder)
            list.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::InitialPress, true));

        // short release is not reported with MSM feature, multi press complete is used instead
        if ((features & Clusters::Switch::Features::MSR) && !(features & Clusters::Switch::Features::MSM))
            list.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::ShortRelease, true));

        if (features & Clusters::Switch::Features::MSL)
        {
            list.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::LongPress, true));
            list.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::LongRelease, true));
        }

        if (features & Clusters::Switch::Features::MSM)
            list.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::MultiPressComplete, true));
    }

    return list;
}

void Matter::deviceUnreachable(DeviceObject *device)
{
    SessionInfo *session = m_sessions->byPeerNodeId(device->nodeId());
    qint64 time = QDateTime::currentMSecsSinceEpoch();

    if (session)
        m_sessions->removeSession(session->localSessionId);

    if (device->availability() == Availability::Online)
    {
        logWarning << device << "is unreachable";
        device->setAvailability(Availability::Offline);
        emit availabilityUpdated(device);
    }

    // first failure leads to immediate CASE, next ones are spaced to avoid spamming sleeping peer
    if (!device->reconnectTime())
        device->setReconnectTime(time);
    else if (device->reconnectTime() < time)
        device->setReconnectTime(time + RECONNECT_DELAY + QRandomGenerator::global()->bounded(RECONNECT_JITTER));

    scheduleReconnect();
}

void Matter::retryConnection(DeviceObject *device)
{
    device->setReconnectTime(QDateTime::currentMSecsSinceEpoch() + RECONNECT_DELAY + QRandomGenerator::global()->bounded(RECONNECT_JITTER));
    scheduleReconnect();
}

void Matter::scheduleReconnect(void)
{
    qint64 time = QDateTime::currentMSecsSinceEpoch(), nearest = -1;

    for (int i = 0; i < m_devices->count(); i++)
    {
        const Device &device = m_devices->at(i);
        qint64 value = device->reconnectTime() ? device->reconnectTime() : time;

        // devices with restored session or with CASE in progress are skipped, MRP or CASE failure will schedule reconnect
        if (device->availability() == Availability::Online || device->networkAddress().isNull() || m_sessions->byPeerNodeId(device->nodeId()) || caseInProgress(device.data()))
            continue;

        if (nearest < 0 || value < nearest)
            nearest = value;
    }

    if (nearest < 0)
    {
        logDebug(m_debug) << "No offline devices to reconnect";
        return;
    }

    logDebug(m_debug) << "Reconnect scheduled in" << qMax <qint64> (0, nearest - time) << "ms";
    m_reconnectTimer->start(static_cast <int> (qMax <qint64> (0, nearest - time)));
}

bool Matter::caseInProgress(DeviceObject *device)
{
    for (auto it = m_pendingCases.begin(); it != m_pendingCases.end(); it++)
    {
        if (it.value().device != device)
            continue;

        return true;
    }

    return false;
}

PendingCase *Matter::pendingCase(CASESession *session)
{
    for (auto it = m_pendingCases.begin(); it != m_pendingCases.end(); it++)
    {
        if (it.value().session != session)
            continue;

        return &it.value();
    }

    return nullptr;
}

PASESession *Matter::createPase(void)
{
    PASESession *pase = new PASESession(this);

    connect(pase, &PASESession::sendPBKDFParamRequest, this, &Matter::paseSendPBKDFParamRequest);
    connect(pase, &PASESession::sendPake1, this, &Matter::paseSendPake1);
    connect(pase, &PASESession::sendPake3, this, &Matter::paseSendPake3);
    connect(pase, &PASESession::established, this, &Matter::paseEstablished);
    connect(pase, &PASESession::failed, this, &Matter::paseFailed);

    return pase;
}

void Matter::parseSecureChannel(const MessageHeader &messageHeader, const ProtocolHeader &protocolHeader, const QByteArray &payload)
{
    SecureChannelOpcode opcode = static_cast <SecureChannelOpcode> (protocolHeader.opcode);

    switch (opcode)
    {
        case SecureChannelOpcode::PBKDFParamResponse:
        case SecureChannelOpcode::PASEPake2:
        {
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                PASESession *pase = it.value().pase;

                if (it.value().exchangeId != protocolHeader.exchangeId)
                    continue;

                pase->setPeerMessageCounter(messageHeader.messageCounter);

                if (opcode == SecureChannelOpcode::PBKDFParamResponse)
                    pase->parsePBKDFParamResponse(payload);
                else
                    pase->parsePake2(payload);

                break;
            }

            break;
        }

        case SecureChannelOpcode::StatusReport:
        {
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().exchangeId != protocolHeader.exchangeId || it.value().state != CommissioningState::PASE)
                    continue;

                it.value().pase->parseStatusReport(payload);
                return;
            }

            if (m_pendingCases.contains(protocolHeader.exchangeId))
            {
                m_pendingCases.value(protocolHeader.exchangeId).session->parseStatusReport(payload);
                return;
            }

            logDebug(m_debug) << "Session" << messageHeader.sessionId << "StatusReport received";
            break;
        }

        case SecureChannelOpcode::CASESigma1:
            logDebug(m_debug) << "CASE Sigma1 received from node" << QString::number(messageHeader.sourceNodeId, 16);
            break;

        case SecureChannelOpcode::CASESigma2:
        case SecureChannelOpcode::CASESigma2Resume:
        {
            CASESession *session;

            if (!m_pendingCases.contains(protocolHeader.exchangeId))
            {
                logDebug(m_debug) << (opcode == SecureChannelOpcode::CASESigma2 ? "Sigma2" : "Sigma2_Resume") << "received for unknown exchange" << protocolHeader.exchangeId;
                break;
            }

            session = m_pendingCases.value(protocolHeader.exchangeId).session;
            session->setPeerMessageCounter(messageHeader.messageCounter);

            if (opcode == SecureChannelOpcode::CASESigma2)
                session->parseSigma2(payload);
            else
                session->parseSigma2Resume(payload);

            break;
        }

        case SecureChannelOpcode::MRPStandaloneAck:
            break;

        default:
            logWarning << "Unrecognized secure channel opcode" << QString::asprintf("0x%02x", protocolHeader.opcode);
            break;
    }
}

void Matter::parseInteractionModel(const MessageHeader &messageHeader, const ProtocolHeader &protocolHeader, const QByteArray &payload)
{
    switch (static_cast <InteractionModelOpcode> (protocolHeader.opcode))
    {
        case InteractionModelOpcode::ReportData:
            parseReportData(messageHeader, protocolHeader, payload);
            break;

        case InteractionModelOpcode::WriteResponse:
            logDebug(m_debug) << "WriteResponse received, payload length" << payload.length();
            break;

        case InteractionModelOpcode::StatusResponse:
            parseStatusResponse(messageHeader, payload);
            break;

        case InteractionModelOpcode::SubscribeResponse:
            parseSubscribeResponse(messageHeader, payload);
            break;

        case InteractionModelOpcode::InvokeResponse:
            parseInvokeResponse(messageHeader, payload);
            break;

        default:
            logWarning << "Unrecognized interaction model opcode" << QString::asprintf("0x%02x", protocolHeader.opcode);
            break;
    }
}

void Matter::parseReportData(const MessageHeader &messageHeader, const ProtocolHeader &protocolHeader, const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();
    QList <AttributeReport> reports = InteractionModel::attributeReports(payload);
    SessionInfo *session = m_sessions->byLocalId(messageHeader.sessionId);
    Device device = session ? m_devices->byNodeId(session->peerNodeId) : Device();
    bool subscription = false, suppressResponse = false, subscribe = false;

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &item = root.children.at(i);

        switch (item.tag)
        {
            case 0:
                subscription = true;
                logDebug(m_debug) << "ReportData subscription id" << item.value.toUInt();
                break;

            case 3:
                suppressResponse = item.value.toBool();
                logDebug(m_debug) << "ReportData suppress response" << suppressResponse;
                break;
        }
    }

    for (int i = 0; i < reports.count(); i++)
    {
        const AttributeReport &report = reports.at(i);

        if (report.error)
        {
            logWarning << "Cluster" << QString::asprintf("0x%04x", report.path.clusterId) << "attribute" << QString::asprintf("0x%04x", report.path.attributeId) << "report failed with status" << report.status;
            continue;
        }

        logDebug(m_debug) << "Endpoint" << report.path.endpointId << "cluster" << QString::asprintf("0x%04x", report.path.clusterId) << "attribute" << QString::asprintf("0x%04x", report.path.attributeId) << "value" << report.value;

        if (!device.isNull())
        {
            const Endpoint &endpoint = device->endpoints().value(static_cast <quint8> (report.path.endpointId));

            if (!endpoint.isNull())
            {
                for (int j = 0; j < endpoint->properties().count(); j++)
                {
                    const Property &property = endpoint->properties().at(j);

                    if (property->clusterId() != report.path.clusterId)
                        continue;

                    property->parseAttribute(report.path.attributeId, report.data);
                }

                device->updateEndpoint(static_cast <quint8> (report.path.endpointId));
            }
        }

        for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
        {
            PendingCommission &commission = it.value();

            if (commission.state == CommissioningState::ReadBasicInfo && commission.device && report.path.clusterId == Clusters::BasicInformation::Id)
            {
                switch (report.path.attributeId)
                {
                    case Clusters::BasicInformation::Attributes::VendorName:  commission.device->setManufacturerName(report.value.toString()); break;
                    case Clusters::BasicInformation::Attributes::ProductName: commission.device->setModelName(report.value.toString()); break;
                    case Clusters::BasicInformation::Attributes::VendorID:    commission.device->setVendorId(static_cast <quint16> (report.value.toUInt())); break;
                    case Clusters::BasicInformation::Attributes::ProductID:   commission.device->setProductId(static_cast <quint16> (report.value.toUInt())); break;
                }
            }

            if (commission.state == CommissioningState::ReadNetworkType && report.path.clusterId == Clusters::NetworkCommissioning::Id && report.path.attributeId == Clusters::NetworkCommissioning::Attributes::FeatureMap)
                commission.networkFeatures = report.value.toUInt();
        }
    }

    if (!device.isNull())
    {
        QList <EventReport> events = InteractionModel::eventReports(payload);

        for (int i = 0; i < events.count(); i++)
        {
            const EventReport &event = events.at(i);
            const Endpoint &endpoint = device->endpoints().value(static_cast <quint8> (event.path.endpointId));

            logDebug(m_debug) << "Endpoint" << event.path.endpointId << "cluster" << QString::asprintf("0x%04x", event.path.clusterId) << "event" << QString::asprintf("0x%02x", event.path.eventId) << "number" << event.eventNumber;

            // events from priming report are buffered history, they must not trigger anything
            if (!device->subscriptionPrimed() || endpoint.isNull())
                continue;

            for (int j = 0; j < endpoint->properties().count(); j++)
            {
                const Property &property = endpoint->properties().at(j);

                if (property->clusterId() != event.path.clusterId)
                    continue;

                property->parseEvent(event.path.eventId, event.data);
            }

            device->updateEndpoint(static_cast <quint8> (event.path.endpointId));
        }

        subscribe = parseDiscovery(device.data(), session, reports);
    }

    if (session && !suppressResponse && !m_bleCommissioning && (!reports.isEmpty() || subscription))
    {
        logDebug(m_debug) << "ReportData exchange" << protocolHeader.exchangeId << "acknowledged with StatusResponse";
        sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::StatusResponse), static_cast <quint16> (ProtocolId::InteractionModel), InteractionModel::statusResponse(0), protocolHeader.exchangeId, !(protocolHeader.exchangeFlags & static_cast <quint8> (ExchangeFlag::Initiator)), messageHeader.messageCounter);
    }

    // subscribe request is sent after status response
    if (subscribe && subscribeDevice(device.data(), session))
        emit device->deviceUpdated(device.data());

    for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
    {
        PendingCommission &commission = it.value();

        if (commission.state == CommissioningState::ReadBasicInfo)
        {
            commission.state = CommissioningState::RequestPAI;
            continueCommissioning(commission);
            break;
        }

        if (commission.state == CommissioningState::ReadNetworkType)
        {
            bool wifi = commission.networkFeatures & Clusters::NetworkCommissioning::Features::WiFi, thread = commission.networkFeatures & Clusters::NetworkCommissioning::Features::Thread, ethernet = commission.networkFeatures & Clusters::NetworkCommissioning::Features::Ethernet;

            logInfo << "Device network commissioning features:" << QString("WiFi=%1 Thread=%2 Ethernet=%3").arg(wifi).arg(thread).arg(ethernet);

            if (thread && !m_threadDataset.isEmpty())
            {
                logInfo << "Sending Thread operational dataset over BLE...";
                commission.thread = true;
                commission.state = CommissioningState::AddThreadNetwork;
            }
            else if (wifi && !m_wifiSsid.isEmpty())
            {
                logInfo << "Sending WiFi credentials over BLE...";
                commission.thread = false;
                commission.state = CommissioningState::AddWiFiNetwork;
            }
            else
            {
                logWarning << "No matching network credentials for device, commissioning will fail";
                break;
            }

            continueCommissioning(commission);
            break;
        }
    }
}

bool Matter::parseDiscovery(DeviceObject *device, SessionInfo *session, const QList <AttributeReport> &reports)
{
    QList <quint8> endpoints;
    QMap <quint8, QList <quint32>> clusters;
    bool meta = false, finalize = false;

    for (int i = 0; i < reports.count(); i++)
    {
        const AttributeReport &report = reports.at(i);

        if (report.error || report.path.clusterId != Clusters::Descriptor::Id || report.path.attributeId != Clusters::Descriptor::Attributes::PartsList || report.path.endpointId)
            continue;

        // complete array or single list item
        for (int j = 0; j < report.data.children.count(); j++)
            endpoints.append(static_cast <quint8> (report.data.children.at(j).value.toUInt()));

        if (report.value.isValid() && report.value.canConvert <uint> ())
            endpoints.append(static_cast <quint8> (report.value.toUInt()));
    }

    if (!endpoints.isEmpty() && device->endpoints().isEmpty())
    {
        QList <AttributePath> attributes;

        logInfo << device << "has" << endpoints.count() << "endpoints";

        // root endpoint is added because PowerSource cluster may be there
        endpoints.prepend(0);

        for (int i = 0; i < endpoints.count(); i++)
            attributes.append(AttributePath(endpoints.at(i), Clusters::Descriptor::Id, Clusters::Descriptor::Attributes::ServerList));

        sendRequest(session, InteractionModelOpcode::ReadRequest, InteractionModel::readRequest(attributes));
    }

    // discovery is split into several reads to keep path count small for multi-endpoint peers (e.g. Aqara W100), exposes are created after all reads
    for (int i = 0; i < reports.count(); i++)
    {
        const AttributeReport &report = reports.at(i);
        quint8 endpointId = static_cast <quint8> (report.path.endpointId);
        Endpoint endpoint;
        QVariant value;
        QString key;

        if (report.error)
            continue;

        if (report.path.clusterId == Clusters::Descriptor::Id && report.path.attributeId == Clusters::Descriptor::Attributes::ServerList)
        {
            for (int j = 0; j < report.data.children.count(); j++)
                clusters[endpointId].append(report.data.children.at(j).value.toUInt());

            if (report.value.isValid() && report.value.canConvert <uint> ())
                clusters[endpointId].append(report.value.toUInt());

            continue;
        }

        switch (report.path.clusterId)
        {
            case Clusters::Descriptor::Id:

                if (report.path.attributeId == Clusters::Descriptor::Attributes::DeviceTypeList)
                    key = "deviceType";

                break;

            case Clusters::OnOff::Id:

                if (report.path.attributeId == Clusters::OnOff::Attributes::FeatureMap)
                    key = "onOffFeatures";

                break;

            case Clusters::ColorControl::Id:

                switch (report.path.attributeId)
                {
                    case Clusters::ColorControl::Attributes::ColorCapabilities:          key = "colorCapabilities"; break;
                    case Clusters::ColorControl::Attributes::ColorTempPhysicalMinMireds: key = "colorTempMin"; break;
                    case Clusters::ColorControl::Attributes::ColorTempPhysicalMaxMireds: key = "colorTempMax"; break;
                }

                break;

            case Clusters::Switch::Id:

                switch (report.path.attributeId)
                {
                    case Clusters::Switch::Attributes::FeatureMap:    key = "switchFeatures"; break;
                    case Clusters::Switch::Attributes::MultiPressMax: key = "switchMultiPressMax"; break;
                }

                break;

            case Clusters::ElectricalPowerMeasurement::Id:

                if (report.path.attributeId == Clusters::ElectricalPowerMeasurement::Attributes::FeatureMap)
                    key = "powerFeatures";

                break;
        }

        endpoint = device->endpoints().value(endpointId);

        if (key.isEmpty() || endpoint.isNull())
            continue;

        if (key == "deviceType")
        {
            // device type list contains structures, first entry device type is used
            for (int j = 0; j < report.data.children.count() && !value.isValid(); j++)
            {
                const MatterTLV::Element &item = report.data.children.at(j);

                for (int k = 0; k < item.children.count(); k++)
                {
                    if (item.children.at(k).tag)
                        continue;

                    value = item.children.at(k).value.toUInt();
                    break;
                }
            }

            if (!value.isValid())
                continue;
        }
        else
            value = report.value.toUInt();

        endpoint->meta().insert(key, value);
        meta = true;
    }

    if (!clusters.isEmpty())
    {
        QList <AttributePath> attributes;

        for (auto it = clusters.begin(); it != clusters.end(); it++)
            m_devices->addEndpoint(device, it.key(), it.value());

        for (auto it = clusters.begin(); it != clusters.end(); it++)
        {
            if (it.value().contains(Clusters::OnOff::Id))
                attributes.append(AttributePath(it.key(), Clusters::OnOff::Id, Clusters::OnOff::Attributes::FeatureMap));

            if (it.value().contains(Clusters::ColorControl::Id))
            {
                attributes.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorCapabilities));
                attributes.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorTempPhysicalMinMireds));
                attributes.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorTempPhysicalMaxMireds));
            }

            if (it.value().contains(Clusters::Switch::Id))
            {
                attributes.append(AttributePath(it.key(), Clusters::Switch::Id, Clusters::Switch::Attributes::FeatureMap));
                attributes.append(AttributePath(it.key(), Clusters::Switch::Id, Clusters::Switch::Attributes::MultiPressMax));
            }

            if (it.value().contains(Clusters::ElectricalPowerMeasurement::Id))
                attributes.append(AttributePath(it.key(), Clusters::ElectricalPowerMeasurement::Id, Clusters::ElectricalPowerMeasurement::Attributes::FeatureMap));

            // BooleanState cluster meaning depends on endpoint device type (contact, water leak, etc.)
            if (it.value().contains(Clusters::BooleanState::Id))
                attributes.append(AttributePath(it.key(), Clusters::Descriptor::Id, Clusters::Descriptor::Attributes::DeviceTypeList));
        }

        if (!attributes.isEmpty())
            sendRequest(session, InteractionModelOpcode::ReadRequest, InteractionModel::readRequest(attributes));
        else
            finalize = true;
    }

    if (!finalize && !meta)
        return false;

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
        m_devices->setupEndpoint(device, it.key());

    m_devices->updateMultiple(device);

    // battery powered flag is known only after discovery, so session of freshly commissioned device is stored here
    if (device->batteryPowered() && !device->sessionStored())
    {
        SessionInfo *active = m_sessions->byPeerNodeId(device->nodeId());

        if (active)
            device->storeSession(active);
    }

    m_devices->storeDatabase(true);
    return true;
}

void Matter::parseStatusResponse(const MessageHeader &messageHeader, const QByteArray &payload)
{
    SessionInfo *session = m_sessions->byLocalId(messageHeader.sessionId);
    quint8 status = InteractionModel::status(payload);
    MatterTLV::Encoder fields;
    PendingShare *share;

    logDebug(m_debug) << "StatusResponse received with status" << status;

    // successful status response acknowledges timed request, so OpenCommissioningWindow can be sent now
    if (status || !session || !m_pendingShares.contains(session->peerNodeId))
        return;

    share = &m_pendingShares[session->peerNodeId];

    if (!share->timedRequest)
        return;

    share->timedRequest = false;

    fields.openStructure();
    fields.encodeUnsignedInt(0, share->timeout);
    fields.encodeByteString(1, share->verifier);
    fields.encodeUnsignedInt(2, share->discriminator);
    fields.encodeUnsignedInt(3, SHARE_ITERATIONS);
    fields.encodeByteString(4, share->salt);
    fields.closeContainer();

    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), InteractionModel::invokeRequest(CommandPath(0, Clusters::AdministratorCommissioning::Id, Clusters::AdministratorCommissioning::Commands::OpenCommissioningWindow), fields, true), share->exchangeId, true, messageHeader.messageCounter);
    logInfo << share->device << "OpenCommissioningWindow request sent";
}

void Matter::parseSubscribeResponse(const MessageHeader &messageHeader, const QByteArray &payload)
{
    MatterTLV::Element root = MatterTLV::Decoder(payload).decode();
    SessionInfo *session = m_sessions->byLocalId(messageHeader.sessionId);
    Device device = session ? m_devices->byNodeId(session->peerNodeId) : Device();
    quint32 subscriptionId = 0;
    quint16 maxInterval = 0;

    for (int i = 0; i < root.children.count(); i++)
    {
        const MatterTLV::Element &item = root.children.at(i);

        switch (item.tag)
        {
            case 0: subscriptionId = item.value.toUInt(); break;
            case 2: maxInterval = static_cast <quint16> (item.value.toUInt()); break;
        }
    }

    logInfo << "Subscription" << subscriptionId << "established with max interval" << maxInterval;

    if (device.isNull())
        return;

    // priming reports are received before subscribe response, so further events are real-time
    device->setSubscriptionInterval(maxInterval);
    device->setSubscriptionPrimed(true);
}

void Matter::parseInvokeResponse(const MessageHeader &messageHeader, const QByteArray &payload)
{
    QList <CommandResponse> responses = InteractionModel::commandResponses(payload);
    SessionInfo *session;

    logDebug(m_debug) << "InvokeResponse received with" << responses.count() << "responses, payload length" << payload.length();

    for (int i = 0; i < responses.count(); i++)
    {
        const CommandResponse &response = responses.at(i);

        logDebug(m_debug) << "Cluster" << QString::asprintf("0x%04x", response.path.clusterId) << "command" << QString::asprintf("0x%02x", response.path.commandId) << "response status" << response.status;

        for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
        {
            if (!commissioningResponse(it.value(), response))
                continue;

            break;
        }
    }

    for (int i = 0; i < responses.count() && m_removeDevice; i++)
    {
        const CommandResponse &response = responses.at(i);
        quint8 status = 0xFF;

        if (response.path.clusterId != Clusters::OperationalCredentials::Id || response.path.commandId != Clusters::OperationalCredentials::Commands::NOCResponse)
            continue;

        for (int j = 0; j < response.data.children.count(); j++)
        {
            if (response.data.children.at(j).tag)
                continue;

            status = static_cast <quint8> (response.data.children.at(j).value.toUInt());
        }

        releaseDevice(m_removeDevice, !status);
        m_removeDevice = nullptr;
    }

    session = m_sessions->byLocalId(messageHeader.sessionId);

    if (session && m_pendingShares.contains(session->peerNodeId))
    {
        PendingShare share = m_pendingShares.value(session->peerNodeId);
        quint64 nodeId = session->peerNodeId;

        for (int i = 0; i < responses.count(); i++)
        {
            const CommandResponse &response = responses.at(i);

            if (response.path.clusterId != Clusters::AdministratorCommissioning::Id)
                continue;

            if (!response.status)
            {
                QString manualCode = generateManualCode(share.passcode, share.discriminator);
                logInfo << share.device << "sharing window opened with manual code" << manualCode;
                emit deviceShared(share.device, manualCode, generateQrCode(share.passcode, share.discriminator), share.timeout);
            }
            else
                logWarning << share.device << "OpenCommissioningWindow request failed with status" << response.status;

            m_pendingShares.remove(nodeId);
            break;
        }
    }

    for (int i = 0; i < responses.count() && m_commissionDevice; i++)
    {
        const CommandResponse &response = responses.at(i);

        if (response.path.clusterId != Clusters::GeneralCommissioning::Id || response.path.commandId != Clusters::GeneralCommissioning::Commands::CommissioningCompleteResponse)
            continue;

        finishCommissioning(m_commissionDevice);
        discoverDevice(m_commissionDevice);
        m_commissionDevice = nullptr;
    }
}

void Matter::startCommissioning(const MatterService &service)
{
    PendingCommission commission;

    commission.pase = createPase();
    commission.state = CommissioningState::PASE;
    commission.service = service;
    commission.address = service.address;
    commission.port = service.port;
    commission.exchangeId = m_exchangeCounter++;
    commission.localSessionId = m_sessionCounter++;
    commission.passcode = m_passcode;
    commission.nodeId = m_searchNodeId;

    m_pendingCommissions.insert(commission.localSessionId, commission);

    logInfo << "Commissioning started with" << service.address.toString() << "port" << service.port;
    emit deviceEvent(nullptr, Event::deviceConnecting, {{"nodeId", QString::number(m_searchNodeId, 16)}});

    commission.pase->start(commission.passcode, commission.localSessionId);
}

void Matter::continueCommissioning(PendingCommission &commission)
{
    SessionInfo *session = m_sessions->byLocalId(commission.localSessionId);
    MatterTLV::Encoder fields;

    if (!session)
    {
        logWarning << "Commissioning session" << commission.localSessionId << "not found";
        return;
    }

    switch (commission.state)
    {
        case CommissioningState::ReadNetworkType:
            logInfo << "Reading network commissioning features...";
            sendCommissioningRequest(session, InteractionModelOpcode::ReadRequest, InteractionModel::readRequest(QList <AttributePath> {AttributePath(0, Clusters::NetworkCommissioning::Id, Clusters::NetworkCommissioning::Attributes::FeatureMap)}), m_exchangeCounter++, true);
            break;

        case CommissioningState::AddWiFiNetwork:
            logInfo << "Sending AddOrUpdateWiFiNetwork request...";
            fields.openStructure();
            fields.encodeByteString(0, m_wifiSsid.toUtf8());
            fields.encodeByteString(1, m_wifiPassword.toUtf8());
            fields.encodeUnsignedInt(2, 1); // breadcrumb
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::NetworkCommissioning::Id, Clusters::NetworkCommissioning::Commands::AddOrUpdateWiFiNetwork), fields), m_exchangeCounter++, true);
            break;

        case CommissioningState::AddThreadNetwork:
            logInfo << "Sending AddOrUpdateThreadNetwork request...";
            fields.openStructure();
            fields.encodeByteString(0, m_threadDataset);
            fields.encodeUnsignedInt(1, 1); // breadcrumb
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::NetworkCommissioning::Id, Clusters::NetworkCommissioning::Commands::AddOrUpdateThreadNetwork), fields), m_exchangeCounter++, true);
            break;

        case CommissioningState::ConnectNetwork:
            logInfo << "Sending ConnectNetwork request...";
            fields.openStructure();
            fields.encodeByteString(0, commission.thread ? m_threadExtendedPanId : m_wifiSsid.toUtf8());
            fields.encodeUnsignedInt(1, 1); // breadcrumb
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::NetworkCommissioning::Id, Clusters::NetworkCommissioning::Commands::ConnectNetwork), fields), m_exchangeCounter++, true);
            break;

        case CommissioningState::ArmFailSafe:
            logDebug(m_debug) << "Sending ArmFailSafe request...";
            fields.openStructure();
            fields.encodeUnsignedInt(0, FAIL_SAFE_TIMEOUT);
            fields.encodeUnsignedInt(1, 1); // breadcrumb
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::ArmFailSafe), fields), m_exchangeCounter++, m_bleCommissioning);
            break;

        case CommissioningState::SetRegulatoryConfig:
            logDebug(m_debug) << "Sending SetRegulatoryConfig request...";
            fields.openStructure();
            fields.encodeUnsignedInt(0, 0); // indoor
            fields.encodeUTF8String(1, "XX"); // country code
            fields.encodeUnsignedInt(2, 0); // breadcrumb
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::SetRegulatoryConfig), fields), m_exchangeCounter++, m_bleCommissioning);
            break;

        case CommissioningState::ReadBasicInfo:
        {
            QList <quint32> list = {Clusters::BasicInformation::Attributes::VendorName, Clusters::BasicInformation::Attributes::VendorID, Clusters::BasicInformation::Attributes::ProductName, Clusters::BasicInformation::Attributes::ProductID, Clusters::BasicInformation::Attributes::SoftwareVersionString};
            QList <AttributePath> attributes;

            for (int i = 0; i < list.count(); i++)
                attributes.append(AttributePath(0, Clusters::BasicInformation::Id, list.at(i)));

            logDebug(m_debug) << "Reading basic information...";
            sendCommissioningRequest(session, InteractionModelOpcode::ReadRequest, InteractionModel::readRequest(attributes), m_exchangeCounter++, m_bleCommissioning);
            break;
        }

        case CommissioningState::RequestPAI:
        case CommissioningState::RequestDAC:
            logDebug(m_debug) << "Requesting" << (commission.state == CommissioningState::RequestPAI ? "PAI" : "DAC") << "certificate...";
            fields.openStructure();
            fields.encodeUnsignedInt(0, commission.state == CommissioningState::RequestPAI ? 2 : 1); // certificate type
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CertificateChainRequest), fields), m_exchangeCounter++, m_bleCommissioning);
            break;

        case CommissioningState::RequestAttestation:
            logDebug(m_debug) << "Sending AttestationRequest...";
            fields.openStructure();
            fields.encodeByteString(0, Crypto::randomData(32)); // nonce
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AttestationRequest), fields), m_exchangeCounter++, m_bleCommissioning);
            break;

        case CommissioningState::CSRRequest:
            logDebug(m_debug) << "Sending CSRRequest...";
            fields.openStructure();
            fields.encodeByteString(0, Crypto::randomData(32)); // nonce
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CSRRequest), fields), m_exchangeCounter++, m_bleCommissioning);
            break;

        case CommissioningState::AddTrustedRootCert:
            logDebug(m_debug) << "Sending AddTrustedRootCertificate request...";
            fields.openStructure();
            fields.encodeByteString(0, commission.rcac);
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AddTrustedRootCertificate), fields), m_exchangeCounter++, m_bleCommissioning);
            break;

        case CommissioningState::AddNOC:
            logDebug(m_debug) << "Sending AddNOC request...";
            fields.openStructure();
            fields.encodeByteString(0, commission.noc);
            fields.encodeByteString(2, m_ipk); // there is no intermediate certificate
            fields.encodeUnsignedInt(3, m_nodeId); // CASE admin subject
            fields.encodeUnsignedInt(4, ADMIN_VENDOR_ID);
            fields.closeContainer();
            sendCommissioningRequest(session, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AddNOC), fields), m_exchangeCounter++, m_bleCommissioning);
            break;

        default:
            break;
    }
}

bool Matter::commissioningResponse(PendingCommission &commission, const CommandResponse &response)
{
    PASESession *pase = commission.pase;
    DeviceObject *device = commission.device;
    quint16 localSessionId = commission.localSessionId;

    switch (commission.state)
    {
        case CommissioningState::AddWiFiNetwork:
        case CommissioningState::AddThreadNetwork:

            if (response.path.clusterId != Clusters::NetworkCommissioning::Id || response.path.commandId != Clusters::NetworkCommissioning::Commands::NetworkConfigResponse)
                return false;

            logInfo << "Network credentials added, connecting...";
            commission.state = CommissioningState::ConnectNetwork;
            continueCommissioning(commission);
            return true;

        case CommissioningState::ConnectNetwork:
        {
            quint8 status = 0xFF;

            if (response.path.clusterId != Clusters::NetworkCommissioning::Id || response.path.commandId != Clusters::NetworkCommissioning::Commands::ConnectNetworkResponse)
                return false;

            for (int i = 0; i < response.data.children.count(); i++)
            {
                if (response.data.children.at(i).tag)
                    continue;

                status = static_cast <quint8> (response.data.children.at(i).value.toUInt());
            }

            if (status)
            {
                logWarning << "ConnectNetwork request failed with status" << status;
                return true;
            }

            logInfo << device << (commission.thread ? "joined Thread network" : "connected to WiFi network") << ", starting CASE...";

            m_bleCommissioning = false;
            m_ble->disconnectDevice();

            m_commissioning = true;
            m_commissionDevice = device;

            device->setThread(commission.thread);
            device->setNetworkPort(MATTER_PORT);

            m_sessions->removeSession(localSessionId);
            m_pendingCommissions.remove(localSessionId);

            if (pase)
                pase->deleteLater();

            m_searching = true;
            m_searchTimer->start(SEARCH_TIMEOUT);
            m_mdns->browse();
            return true;
        }

        case CommissioningState::ArmFailSafe:

            if (response.path.clusterId != Clusters::GeneralCommissioning::Id || response.path.commandId != Clusters::GeneralCommissioning::Commands::ArmFailSafeResponse)
                return false;

            logDebug(m_debug) << "ArmFailSafe response received";
            commission.state = CommissioningState::SetRegulatoryConfig;
            continueCommissioning(commission);
            return true;

        case CommissioningState::SetRegulatoryConfig:

            if (response.path.clusterId != Clusters::GeneralCommissioning::Id || response.path.commandId != Clusters::GeneralCommissioning::Commands::SetRegulatoryConfigResponse)
                return false;

            logDebug(m_debug) << "SetRegulatoryConfig response received";
            commission.state = CommissioningState::ReadBasicInfo;
            continueCommissioning(commission);
            return true;

        case CommissioningState::RequestPAI:
        case CommissioningState::RequestDAC:

            if (response.path.clusterId != Clusters::OperationalCredentials::Id || response.path.commandId != Clusters::OperationalCredentials::Commands::CertificateChainResponse)
                return false;

            logDebug(m_debug) << (commission.state == CommissioningState::RequestPAI ? "PAI" : "DAC") << "certificate received";
            commission.state = commission.state == CommissioningState::RequestPAI ? CommissioningState::RequestDAC : CommissioningState::RequestAttestation;
            continueCommissioning(commission);
            return true;

        case CommissioningState::RequestAttestation:

            if (response.path.clusterId != Clusters::OperationalCredentials::Id || response.path.commandId != Clusters::OperationalCredentials::Commands::AttestationResponse)
                return false;

            logDebug(m_debug) << "AttestationResponse received";
            commission.state = CommissioningState::CSRRequest;
            continueCommissioning(commission);
            return true;

        case CommissioningState::CSRRequest:

            if (response.path.clusterId != Clusters::OperationalCredentials::Id || response.path.commandId != Clusters::OperationalCredentials::Commands::CSRResponse)
                return false;

            for (int i = 0; i < response.data.children.count(); i++)
            {
                const MatterTLV::Element &item = response.data.children.at(i);
                MatterTLV::Element elements;

                if (item.tag || item.type != MatterTLV::Type::ByteString)
                    continue;

                elements = MatterTLV::Decoder(item.value.toByteArray()).decode();

                for (int j = 0; j < elements.children.count(); j++)
                {
                    const MatterTLV::Element &element = elements.children.at(j);

                    if (element.tag != 1 || element.type != MatterTLV::Type::ByteString)
                        continue;

                    commission.publicKey = Crypto::csrPublicKey(element.value.toByteArray());
                }
            }

            if (commission.publicKey.isEmpty())
            {
                logWarning << "Device public key not found in CSRResponse";
                return true;
            }

            commission.rcac = generateCertificate(0, m_fabricPublicKey, true);
            commission.noc = generateCertificate(device->nodeId(), commission.publicKey, false);
            commission.state = CommissioningState::AddTrustedRootCert;

            logDebug(m_debug) << "CSRResponse received, RCAC length" << commission.rcac.length() << "and NOC length" << commission.noc.length();
            continueCommissioning(commission);
            return true;

        case CommissioningState::AddTrustedRootCert:

            if (response.path.clusterId != Clusters::OperationalCredentials::Id || response.path.commandId != Clusters::OperationalCredentials::Commands::AddTrustedRootCertificate)
                return false;

            if (response.status)
            {
                logWarning << "AddTrustedRootCertificate request failed with status" << response.status;
                return true;
            }

            logDebug(m_debug) << "AddTrustedRootCertificate request accepted";
            commission.state = CommissioningState::AddNOC;
            continueCommissioning(commission);
            return true;

        case CommissioningState::AddNOC:
        {
            quint8 status = 0xFF;

            if (response.path.clusterId != Clusters::OperationalCredentials::Id || response.path.commandId != Clusters::OperationalCredentials::Commands::NOCResponse)
                return false;

            for (int i = 0; i < response.data.children.count(); i++)
            {
                const MatterTLV::Element &item = response.data.children.at(i);

                switch (item.tag)
                {
                    case 0: status = static_cast <quint8> (item.value.toUInt()); break;
                    case 1: device->setFabricIndex(static_cast <quint8> (item.value.toUInt())); break;
                }
            }

            if (status)
            {
                logWarning << "AddNOC request failed with status" << status;
                return true;
            }

            logInfo << "AddNOC request accepted";

            // device supported network type is checked before sending credentials over BLE
            if (m_bleCommissioning)
            {
                emit deviceEvent(device, Event::networkSetup);
                commission.state = CommissioningState::ReadNetworkType;
                continueCommissioning(commission);
                return true;
            }

            device->setNetworkAddress(commission.address);
            device->setNetworkPort(commission.port);
            device->setThread(commission.address.protocol() == QAbstractSocket::IPv6Protocol);

            m_commissioning = true;
            QTimer::singleShot(COMMISSIONING_DELAY, this, [this, device] () { connectDevice(device); });

            m_sessions->removeSession(localSessionId);
            m_pendingCommissions.remove(localSessionId);

            if (pase)
                pase->deleteLater();

            return true;
        }

        default:
            return false;
    }
}

void Matter::finishCommissioning(DeviceObject *device)
{
    logInfo << device << "commissioned successfully";
    m_devices->append(Device(device));

    connect(device, &DeviceObject::deviceUpdated, this, &Matter::deviceUpdated, Qt::UniqueConnection);
    connect(device, &DeviceObject::endpointUpdated, this, &Matter::endpointUpdated, Qt::UniqueConnection);

    emit deviceEvent(device, Event::added);
}

ProtocolHeader Matter::protocolHeader(quint8 opcode, quint16 protocolId, quint16 exchangeId, bool initiator, bool reliable, quint32 ackCounter)
{
    ProtocolHeader header;

    header.exchangeFlags = reliable ? static_cast <quint8> (ExchangeFlag::Reliability) : 0;

    if (initiator)
        header.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);

    if (ackCounter)
    {
        header.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Acknowledgement);
        header.ackCounter = ackCounter;
    }

    header.opcode = opcode;
    header.exchangeId = exchangeId;
    header.protocolId = protocolId;

    return header;
}

QByteArray Matter::encryptMessage(SessionInfo *session, const ProtocolHeader &protocolHeader, const QByteArray &payload, quint64 sourceNodeId)
{
    MessageHeader messageHeader;
    QByteArray header;

    messageHeader.sessionId = session->peerSessionId;
    messageHeader.messageCounter = ++session->localMessageCounter;

    header = MessageCodec::encodeHeader(messageHeader);
    return header + Crypto::encrypt(session->i2rKey, SessionManager::nonce(messageHeader.securityFlags, messageHeader.messageCounter, sourceNodeId), header, MessageCodec::encodeProtocolHeader(protocolHeader).append(payload), SESSION_TAG_LENGTH);
}

QByteArray Matter::unencryptedMessage(const ProtocolHeader &protocolHeader, const QByteArray &payload)
{
    MessageHeader messageHeader;

    messageHeader.flags = MESSAGE_FLAG_SOURCE_NODE_ID;
    messageHeader.messageCounter = ++m_messageCounter;
    messageHeader.sourceNodeId = m_nodeId;

    return MessageCodec::encodeMessage(messageHeader, protocolHeader, payload);
}

void Matter::sendUnencrypted(quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, const QHostAddress &address, quint16 port, quint32 ackCounter)
{
    QByteArray data;

    if (ackCounter)
        m_mrp->cancelPendingAck(ackCounter);

    data = unencryptedMessage(protocolHeader(opcode, protocolId, exchangeId, true, true, ackCounter), payload);

    m_socket->writeDatagram(data, address, port);
    m_mrp->messageSent(data, address, port, m_messageCounter, exchangeId, true);
}

void Matter::sendEncrypted(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator, quint32 ackCounter)
{
    QByteArray data;

    if (ackCounter)
        m_mrp->cancelPendingAck(ackCounter);

    data = encryptMessage(session, protocolHeader(opcode, protocolId, exchangeId, initiator, true, ackCounter), payload, session->active ? m_nodeId : 0);

    m_socket->writeDatagram(data, session->peerAddress, session->peerPort);
    m_mrp->messageSent(data, session->peerAddress, session->peerPort, session->localMessageCounter, exchangeId, true, session->idleInterval);
}

void Matter::sendRequest(SessionInfo *session, InteractionModelOpcode opcode, const QByteArray &payload)
{
    sendEncrypted(session, static_cast <quint8> (opcode), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
}

void Matter::sendCommissioningRequest(SessionInfo *session, InteractionModelOpcode opcode, const QByteArray &payload, quint16 exchangeId, bool ble)
{
    if (!ble)
    {
        sendEncrypted(session, static_cast <quint8> (opcode), static_cast <quint16> (ProtocolId::InteractionModel), payload, exchangeId, true);
        return;
    }

    // BTP handles reliability itself, so MRP is not used over BLE
    m_btp->sendMessage(encryptMessage(session, protocolHeader(static_cast <quint8> (opcode), static_cast <quint16> (ProtocolId::InteractionModel), exchangeId, true, false), payload, 0));
}

void Matter::sendSecureChannel(const PendingCommission &commission, SecureChannelOpcode opcode, const QByteArray &payload, quint32 ackCounter)
{
    if (!m_bleCommissioning)
    {
        sendUnencrypted(static_cast <quint8> (opcode), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, commission.address, commission.port, ackCounter);
        return;
    }

    // BTP handles reliability itself, so MRP is not used over BLE
    m_btp->sendMessage(unencryptedMessage(protocolHeader(static_cast <quint8> (opcode), static_cast <quint16> (ProtocolId::SecureChannel), commission.exchangeId, true, false), payload));
}

void Matter::readyRead(void)
{
    while (m_socket->hasPendingDatagrams())
    {
        MessageHeader messageHeader;
        ProtocolHeader protocolHeader;
        QByteArray data, payload;
        QHostAddress address;
        quint32 ipv4, offset;
        quint16 port;
        bool check;

        data.resize(static_cast <int> (m_socket->pendingDatagramSize()));
        m_socket->readDatagram(data.data(), data.size(), &address, &port);

        ipv4 = address.toIPv4Address(&check);

        // IPv4-mapped IPv6 address is converted to plain IPv4
        if (check)
            address = QHostAddress(ipv4);

        if (!MessageCodec::decodeHeader(data, messageHeader, offset))
        {
            logDebug(m_debug) << "Invalid message header received from" << address.toString() << "with data" << data.left(16).toHex(':');
            continue;
        }

        if (m_mrp->duplicate(address, messageHeader.messageCounter))
            continue;

        if (messageHeader.sessionId)
        {
            SessionInfo *session = m_sessions->byLocalId(messageHeader.sessionId);
            Device device;

            if (!session)
                continue;

            payload = m_sessions->decrypt(session, messageHeader.securityFlags, messageHeader.messageCounter, data.left(offset), data.mid(offset));

            if (payload.isEmpty())
            {
                logDebug(m_debug) << "Session" << messageHeader.sessionId << "message" << messageHeader.messageCounter << "from" << address.toString() << "decryption failed";
                continue;
            }

            // successfully decrypted message proves that resumed CASE session is usable
            session->resumptionPending = false;
            logDebug(m_debug) << "Session" << messageHeader.sessionId << "message" << messageHeader.messageCounter << "decrypted, payload length" << payload.length();

            device = m_devices->byNodeId(session->peerNodeId);

            if (!device.isNull())
            {
                device->updateLastSeen();

                // covers both offline devices and devices with restored session and unknown availability
                if (device->availability() != Availability::Online)
                {
                    device->setAvailability(Availability::Online);
                    device->setReconnectTime(0);
                    emit availabilityUpdated(device.data());
                }
            }
        }
        else
            payload = data.mid(offset);

        if (!MessageCodec::decodeProtocolHeader(payload, protocolHeader, offset))
        {
            logDebug(m_debug) << "Invalid protocol header received from" << address.toString();
            continue;
        }

        m_mrp->messageReceived(messageHeader.messageCounter, protocolHeader.exchangeId, protocolHeader.exchangeFlags & static_cast <quint8> (ExchangeFlag::Acknowledgement), protocolHeader.ackCounter, address, port, messageHeader.sessionId, protocolHeader.exchangeFlags & static_cast <quint8> (ExchangeFlag::Reliability), protocolHeader.exchangeFlags & static_cast <quint8> (ExchangeFlag::Initiator));
        payload = payload.mid(offset);

        switch (static_cast <ProtocolId> (protocolHeader.protocolId))
        {
            case ProtocolId::SecureChannel:
                parseSecureChannel(messageHeader, protocolHeader, payload);
                break;

            case ProtocolId::InteractionModel:
                parseInteractionModel(messageHeader, protocolHeader, payload);
                break;

            default:
                logWarning << "Unrecognized protocol" << QString::asprintf("0x%04x", protocolHeader.protocolId);
                break;
        }
    }
}

void Matter::searchTimeout(void)
{
    m_searching = false;
    m_ble->stopScan();
    m_mdns->stop();

    logWarning << "Device search timeout, device not found";
    emit deviceEvent(nullptr, Event::deviceNotFound, {{"nodeId", QString::number(m_searchNodeId, 16)}});
}

void Matter::reconnectTimeout(void)
{
    qint64 time = QDateTime::currentMSecsSinceEpoch();
    bool offline = false;

    logDebug(m_debug) << "Reconnect timer fired";

    for (int i = 0; i < m_devices->count(); i++)
    {
        const Device &device = m_devices->at(i);

        if (device->availability() == Availability::Online || device->networkAddress().isNull())
            continue;

        // Thread peers are not reachable until OTBR is ready, resumeThreadDevices will reschedule them
        if (device->thread() && !m_threadReady)
            continue;

        // devices with restored session or with CASE in progress are skipped, MRP or CASE failure will schedule reconnect
        if (m_sessions->byPeerNodeId(device->nodeId()) || caseInProgress(device.data()))
            continue;

        offline = true;

        if (device->reconnectTime() > time)
            continue;

        connectDevice(device.data());
    }

    if (!offline)
        return;

    scheduleReconnect();
}

void Matter::pingTimeout(void)
{
    qint64 time = QDateTime::currentSecsSinceEpoch();

    for (int i = 0; i < m_devices->count(); i++)
    {
        const Device &device = m_devices->at(i);
        SessionInfo *session;

        if (device->availability() != Availability::Online)
            continue;

        session = m_sessions->byPeerNodeId(device->nodeId());

        if (!session)
        {
            deviceUnreachable(device.data());
            continue;
        }

        // actual counter is stored to be restored with margin after restart
        device->setSessionCounter(session->localMessageCounter);

        if (!device->lastSeen())
            continue;

        // battery powered devices are not pinged, subscription reports are used as keep alive
        if (device->batteryPowered())
        {
            if (device->subscriptionInterval() && time - device->lastSeen() > device->subscriptionInterval() + SUBSCRIPTION_TIMEOUT_MARGIN)
            {
                logWarning << device << "has no subscription reports for" << device->subscriptionInterval() + SUBSCRIPTION_TIMEOUT_MARGIN << "seconds";
                device->setAvailability(Availability::Offline);
                emit availabilityUpdated(device.data());
            }

            continue;
        }

        if (time - device->lastSeen() <= PING_TIMEOUT)
            continue;

        sendRequest(session, InteractionModelOpcode::ReadRequest, InteractionModel::readRequest(QList <AttributePath> {AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::DataModelRevision)}));
    }
}

void Matter::threadTimeout(void)
{
    if (!fetchThreadDataset())
        return;

    m_threadTimer->stop();
    resumeThreadDevices();
}

void Matter::retransmit(const QByteArray &data, const QHostAddress &address, quint16 port)
{
    m_socket->writeDatagram(data, address, port);
}

void Matter::retransmitFailed(quint32 messageCounter, quint16 exchangeId, const QHostAddress &address, quint16 port)
{
    SessionInfo *session;
    Device device;

    logWarning << "Message" << messageCounter << "delivery failed, exchange" << exchangeId;

    if (m_pendingCases.contains(exchangeId))
    {
        PendingCase pending = m_pendingCases.take(exchangeId);

        pending.session->deleteLater();

        logDebug(m_debug) << pending.device << "CASE message delivery failed, retry in 10-15 seconds";
        retryConnection(pending.device);
        return;
    }

    session = m_sessions->byPeerAddress(address, port);

    if (!session)
        return;

    device = m_devices->byNodeId(session->peerNodeId);

    if (device.isNull())
        return;

    // some peers accept Sigma2_Resume, but don't process first encrypted message, so stored resumption data must be dropped to avoid endless loop
    if (session->resumptionPending && !device->resumptionId().isEmpty())
    {
        logWarning << device << "resumed CASE session failed before first encrypted response, retrying with full handshake";
        device->setResumption(QByteArray(), QByteArray());
        m_devices->storeDatabase(true);
    }

    deviceUnreachable(device.data());
}

void Matter::sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port, bool initiator)
{
    SessionInfo *session = m_sessions->byLocalId(sessionId);
    ProtocolHeader header = protocolHeader(static_cast <quint8> (SecureChannelOpcode::MRPStandaloneAck), static_cast <quint16> (ProtocolId::SecureChannel), exchangeId, initiator, false);
    MessageHeader messageHeader;

    header.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Acknowledgement);
    header.ackCounter = ackCounter;

    if (session && session->active)
    {
        m_socket->writeDatagram(encryptMessage(session, header, QByteArray(), m_nodeId), session->peerAddress, session->peerPort);
        return;
    }

    messageHeader.sessionId = sessionId;
    messageHeader.messageCounter = ++m_messageCounter;

    m_socket->writeDatagram(MessageCodec::encodeMessage(messageHeader, header, QByteArray()), address, port);
}

void Matter::serviceFound(const MatterService &service)
{
    if (!m_searching)
        return;

    if (service.operational)
    {
        QString name = service.instanceName.split('.').first();
        int index = name.indexOf('-');

        if (!m_commissioning || !m_commissionDevice)
            return;

        // instance name is "<compressed fabric id>-<node id>", node id must match commissioned device
        if (index > 0)
        {
            quint64 nodeId;
            bool check;

            nodeId = name.mid(index + 1).toULongLong(&check, 16);

            if (!check || nodeId != m_commissionDevice->nodeId())
                return;
        }

        logInfo << "Operational device" << service.instanceName << "found at" << service.address.toString() << "port" << service.port;

        m_searching = false;
        m_searchTimer->stop();
        m_mdns->stop();
        m_ble->stopScan();

        m_commissionDevice->setNetworkAddress(service.address);
        m_commissionDevice->setNetworkPort(service.port);

        connectDevice(m_commissionDevice);
        return;
    }

    // only operational services are expected after BLE commissioning
    if (m_commissioning || (m_shortDiscriminator ? service.discriminator >> 8 : service.discriminator) != m_discriminator)
        return;

    for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
    {
        if (it.value().address != service.address || it.value().port != service.port)
            continue;

        return;
    }

    logInfo << "Commissionable device" << service.deviceName << "found at" << service.address.toString() << "port" << service.port << "with discriminator" << service.discriminator;
    emit deviceEvent(nullptr, Event::deviceFound, {{"nodeId", QString::number(m_searchNodeId, 16)}});

    m_searching = false;
    m_searchTimer->stop();
    m_mdns->stop();
    m_ble->stopScan();

    // PASE session may already be established over BLE
    for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
    {
        PendingCommission &commission = it.value();
        SessionInfo *session = m_sessions->byLocalId(it.key());

        if (commission.state != CommissioningState::ArmFailSafe)
            continue;

        logInfo << "Continuing commissioning with" << service.address.toString() << "port" << service.port << "over UDP...";

        if (session)
        {
            session->peerAddress = service.address;
            session->peerPort = service.port;
        }

        commission.address = service.address;
        commission.port = service.port;
        commission.service = service;
        commission.device->setNetworkAddress(service.address);
        commission.device->setNetworkPort(service.port);

        continueCommissioning(commission);
        return;
    }

    startCommissioning(service);
}

void Matter::bleDeviceFound(const BLEDevice &device)
{
    if (!m_searching || (m_shortDiscriminator ? device.discriminator >> 8 : device.discriminator) != m_discriminator)
        return;

    logInfo << "BLE device" << device.address << "matched, connecting...";
    emit deviceEvent(nullptr, Event::deviceFound, {{"nodeId", QString::number(m_searchNodeId, 16)}});

    m_searching = false;
    m_searchTimer->stop();
    m_mdns->stop();
    m_ble->stopScan();
    m_ble->connectDevice(device.path);
}

void Matter::bleConnected(void)
{
    logInfo << "BLE connected, starting BTP handshake...";
    m_btp->startHandshake();
    m_ble->subscribe();
}

void Matter::bleDisconnected(void)
{
    logInfo << "BLE disconnected";
    m_bleCommissioning = false;
}

void Matter::bleDataReceived(const QByteArray &data)
{
    logInfo << "BLE data received:" << data.toHex(':');
    m_btp->parseData(data);
}

void Matter::btpHandshakeFinished(void)
{
    PendingCommission commission;

    logInfo << "BTP handshake finished, starting PASE over BLE...";
    emit deviceEvent(nullptr, Event::deviceConnecting, {{"nodeId", QString::number(m_searchNodeId, 16)}});

    m_bleCommissioning = true;

    commission.pase = createPase();
    commission.state = CommissioningState::PASE;
    commission.localSessionId = m_sessionCounter++;
    commission.exchangeId = m_exchangeCounter++;
    commission.passcode = m_passcode;
    commission.nodeId = m_searchNodeId;

    m_pendingCommissions.insert(commission.localSessionId, commission);
    commission.pase->start(m_passcode, commission.localSessionId);
}

void Matter::btpMessageReceived(const QByteArray &message)
{
    MessageHeader messageHeader;
    ProtocolHeader protocolHeader;
    QByteArray payload;
    quint32 headerOffset, payloadOffset;

    if (!m_bleCommissioning)
        return;

    if (!MessageCodec::decodeHeader(message, messageHeader, headerOffset))
    {
        logWarning << "BLE message header decoding failed";
        return;
    }

    payload = message.mid(headerOffset);

    if (!MessageCodec::decodeProtocolHeader(payload, protocolHeader, payloadOffset))
    {
        logWarning << "BLE message protocol header decoding failed";
        return;
    }

    if (messageHeader.sessionId)
    {
        SessionInfo *session = m_sessions->byLocalId(messageHeader.sessionId);

        if (!session)
            return;

        payload = m_sessions->decrypt(session, messageHeader.securityFlags, messageHeader.messageCounter, message.left(headerOffset), message.mid(headerOffset));

        if (payload.isEmpty())
        {
            logWarning << "BLE message decryption failed";
            return;
        }

        if (!MessageCodec::decodeProtocolHeader(payload, protocolHeader, payloadOffset))
            return;
    }

    payload = payload.mid(payloadOffset);
    logInfo << "BLE message received, protocol" << QString::asprintf("0x%04x", protocolHeader.protocolId) << "opcode" << QString::asprintf("0x%02x", protocolHeader.opcode) << "exchange" << protocolHeader.exchangeId << "payload length" << payload.length();

    switch (static_cast <ProtocolId> (protocolHeader.protocolId))
    {
        case ProtocolId::SecureChannel:
            parseSecureChannel(messageHeader, protocolHeader, payload);
            break;

        case ProtocolId::InteractionModel:
            parseInteractionModel(messageHeader, protocolHeader, payload);
            break;
    }
}

void Matter::btpWriteData(const QByteArray &data)
{
    m_ble->write(data);
}

void Matter::paseSendPBKDFParamRequest(const QByteArray &payload, quint16 localSessionId)
{
    if (!m_pendingCommissions.contains(localSessionId))
        return;

    sendSecureChannel(m_pendingCommissions.value(localSessionId), SecureChannelOpcode::PBKDFParamRequest, payload);
}

void Matter::paseSendPake1(const QByteArray &payload)
{
    PASESession *pase = reinterpret_cast <PASESession*> (sender());

    if (!m_pendingCommissions.contains(pase->localSessionId()))
        return;

    sendSecureChannel(m_pendingCommissions.value(pase->localSessionId()), SecureChannelOpcode::PASEPake1, payload, pase->peerMessageCounter());
}

void Matter::paseSendPake3(const QByteArray &payload)
{
    PASESession *pase = reinterpret_cast <PASESession*> (sender());

    if (!m_pendingCommissions.contains(pase->localSessionId()))
        return;

    sendSecureChannel(m_pendingCommissions.value(pase->localSessionId()), SecureChannelOpcode::PASEPake3, payload, pase->peerMessageCounter());
}

void Matter::paseEstablished(quint16 localSessionId, quint16 peerSessionId)
{
    PendingCommission *commission;
    SessionInfo session;

    if (!m_pendingCommissions.contains(localSessionId))
        return;

    commission = &m_pendingCommissions[localSessionId];

    // PASE session is not operational, peer node id is unknown until commissioning finished
    session.localSessionId = localSessionId;
    session.peerSessionId = peerSessionId;
    session.i2rKey = commission->pase->encryptKey();
    session.r2iKey = commission->pase->decryptKey();
    session.attestationChallenge = commission->pase->attestationChallenge();
    session.peerAddress = commission->address;
    session.peerPort = commission->port;

    m_sessions->addSession(session);

    commission->device = new DeviceObject(commission->nodeId, QString("matter_%1").arg(commission->nodeId, 0, 16));
    commission->device->setVendorId(commission->service.vendorId);
    commission->device->setProductId(commission->service.productId);
    commission->device->setNetworkAddress(commission->address);
    commission->device->setNetworkPort(commission->port);

    commission->state = CommissioningState::ArmFailSafe;
    continueCommissioning(*commission);
}

void Matter::paseFailed(const QString &reason)
{
    PASESession *pase = reinterpret_cast <PASESession*> (sender());
    quint16 localSessionId = pase->localSessionId();

    logWarning << "PASE session failed:" << reason;
    emit deviceEvent(nullptr, Event::connectFailed, {{"nodeId", QString::number(m_pendingCommissions.value(localSessionId).nodeId, 16)}});

    if (m_bleCommissioning)
    {
        m_bleCommissioning = false;
        m_ble->disconnectDevice();
    }

    m_pendingCommissions.remove(localSessionId);
    pase->deleteLater();
}

void Matter::caseSendSigma1(const QByteArray &payload)
{
    PendingCase *pending = pendingCase(reinterpret_cast <CASESession*> (sender()));

    if (!pending)
        return;

    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::CASESigma1), static_cast <quint16> (ProtocolId::SecureChannel), payload, pending->exchangeId, pending->address, pending->port);
}

void Matter::caseSendSigma3(const QByteArray &payload)
{
    CASESession *session = reinterpret_cast <CASESession*> (sender());
    PendingCase *pending = pendingCase(session);

    if (!pending)
        return;

    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::CASESigma3), static_cast <quint16> (ProtocolId::SecureChannel), payload, pending->exchangeId, pending->address, pending->port, session->peerMessageCounter());
}

void Matter::caseEstablished(quint16 localSessionId, quint16 peerSessionId)
{
    CASESession *session = reinterpret_cast <CASESession*> (sender());
    PendingCase *pending = pendingCase(session);
    SessionInfo info, *current;
    DeviceObject *device;
    quint16 exchangeId;
    bool commissioning;

    if (!pending)
        return;

    device = pending->device;
    exchangeId = pending->exchangeId;
    commissioning = pending->commissioning;

    // resumed session must be acknowledged with status report, otherwise responder never finalizes it
    if (session->resumed())
        sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::StatusReport), static_cast <quint16> (ProtocolId::SecureChannel), QByteArray(8, 0), exchangeId, pending->address, pending->port, session->peerMessageCounter());

    info.localSessionId = localSessionId;
    info.peerSessionId = peerSessionId;
    info.i2rKey = session->encryptKey();
    info.r2iKey = session->decryptKey();
    info.attestationChallenge = session->attestationChallenge();
    info.peerAddress = device->networkAddress();
    info.peerPort = device->networkPort();
    info.peerNodeId = device->nodeId();
    info.active = true;
    info.resumptionPending = session->resumed();
    info.idleInterval = session->idleInterval();
    info.activeInterval = session->activeInterval();
    info.activeThreshold = session->activeThreshold();

    device->updateLastSeen();
    current = m_sessions->byPeerNodeId(device->nodeId());

    if (current)
        m_sessions->removeSession(current->localSessionId);

    m_sessions->addSession(info);
    current = m_sessions->byLocalId(localSessionId);

    logInfo << device << "CASE session established";

    // freshly commissioned device is discovered after CommissioningComplete response
    if (device->endpoints().isEmpty() && !commissioning)
        discoverDevice(device);

    if (current && commissioning)
    {
        MatterTLV::Encoder fields;

        logDebug(m_debug) << "Sending CommissioningComplete request...";
        m_commissionDevice = device;

        fields.openStructure();
        fields.closeContainer();

        sendRequest(current, InteractionModelOpcode::InvokeRequest, InteractionModel::invokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::CommissioningComplete), fields));
    }

    // new resumption data is stored to skip full handshake next time
    if (!session->resumptionId().isEmpty())
    {
        device->setResumption(session->resumptionId(), session->sharedSecret());
        logInfo << device << (session->resumed() ? "session resumed" : "full handshake finished") << ", new resumption id" << session->resumptionId().toHex();
    }

    // battery powered device session is stored to avoid slow CASE handshake after restart, battery powered flag of freshly commissioned device is unknown until discovery
    if (device->batteryPowered())
        device->storeSession(&info);

    m_devices->storeDatabase(true);

    device->setAvailability(Availability::Online);
    device->setReconnectTime(0);
    emit availabilityUpdated(device);

    if (!device->endpoints().isEmpty())
        subscribeDevice(device, current);

    session->deleteLater();
    m_pendingCases.remove(exchangeId);
}

void Matter::caseFailed(const QString &reason)
{
    CASESession *session = reinterpret_cast <CASESession*> (sender());
    PendingCase *pending = pendingCase(session);
    DeviceObject *device = pending ? pending->device : nullptr;
    quint16 exchangeId = pending ? pending->exchangeId : 0;

    logWarning << "CASE session failed:" << reason;
    session->deleteLater();

    if (pending)
        m_pendingCases.remove(exchangeId);

    if (!device)
        return;

    // only MIC verification failure proves that resumption data is invalid, other failures are transient
    if (!device->resumptionId().isEmpty() && reason.startsWith("Sigma2_Resume MIC"))
    {
        logInfo << device << "resumption data cleared, next attempt will be full handshake";
        device->setResumption(QByteArray(), QByteArray());
        m_devices->storeDatabase(true);
    }

    logDebug(m_debug) << device << "CASE retry in 10-15 seconds";
    retryConnection(device);
}

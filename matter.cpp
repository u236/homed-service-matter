// NOT REWIEWED

#include <QProcess>
#include <QRandomGenerator>
#include <QtEndian>
#include "matter.h"
#include "color.h"
#include "logger.h"
#include "clusters.h"

using namespace MatterProtocol;

Matter::Matter(QSettings *config, QObject *parent) : QObject(parent), m_udp(new QUdpSocket(this)), m_mrp(new MRP(this)), m_mdns(new MDNS(this)), m_ble(new BLE(this)), m_btp(new BTP(this)), m_sessions(new SessionManager(this)), m_searchTimer(new QTimer(this)), m_reconnectTimer(new QTimer(this)), m_pingTimer(new QTimer(this)), m_port(5540), m_debug(false), m_searching(false), m_searchShortDiscriminator(false), m_searchPasscode(0), m_searchDiscriminator(0), m_messageCounter(0), m_exchangeCounter(0), m_sessionCounter(1), m_fabricId(1), m_nodeId(1), m_devices(new DeviceList(config, parent)), m_events(QMetaEnum::fromType <Event> ()), m_bleCommissioning(false)
{
    QByteArray counterBytes = Crypto::randomBytes(sizeof(m_messageCounter));

    // start message counter from random value to avoid replay detection after restart
    memcpy(&m_messageCounter, counterBytes.constData(), sizeof(m_messageCounter));

    m_debug = config->value("debug/matter", false).toBool();
    m_mrp->setDebug(m_debug); // TODO: separate config parameters

    m_wifiSSID = config->value("wifi/ssid").toString();
    m_wifiPassword = config->value("wifi/password").toString();

    QString otbr = config->value("thread/otbr").toString();

    if (!otbr.isEmpty())
    {
        QString url = QString("http://%1/node/dataset/active").arg(otbr);
        QProcess curl;
        curl.start("curl", {"-fsS", "-H", "Accept: text/plain", "--max-time", "5", url});
        curl.waitForFinished(6000);

        if (curl.exitStatus() == QProcess::NormalExit && curl.exitCode() == 0)
        {
            m_threadDataset = QByteArray::fromHex(curl.readAllStandardOutput().trimmed());
            m_threadExtPanId = extractThreadExtPanId(m_threadDataset);

            if (m_threadExtPanId.isEmpty())
                logWarning << "Failed to extract Extended PAN ID from Thread dataset fetched from" << otbr;
            else
                logInfo << "Thread dataset fetched from" << otbr << ", ExtPanId:" << m_threadExtPanId.toHex();
        }
        else
            logWarning << "Failed to fetch Thread dataset from" << otbr << ":" << curl.readAllStandardError().trimmed();
    }

    connect(m_udp, &QUdpSocket::readyRead, this, &Matter::readyRead);
    connect(m_searchTimer, &QTimer::timeout, this, &Matter::searchTimeout);
    connect(m_reconnectTimer, &QTimer::timeout, this, &Matter::reconnectTimeout);
    connect(m_pingTimer, &QTimer::timeout, this, &Matter::pingTimeout);

    connect(m_mrp, &MRP::retransmit, this, &Matter::mrpRetransmit);
    connect(m_mrp, &MRP::retransmitFailed, this, &Matter::mrpRetransmitFailed);
    connect(m_mrp, &MRP::sendStandaloneAck, this, &Matter::mrpSendStandaloneAck);
    connect(m_mdns, &MDNS::serviceFound, this, &Matter::mdnsServiceFound);

    connect(m_ble, &BLE::deviceFound, this, &Matter::bleDeviceFound);
    connect(m_ble, &BLE::connected, this, &Matter::bleConnected);
    connect(m_ble, &BLE::disconnected, this, &Matter::bleDisconnected);
    connect(m_ble, &BLE::dataReceived, this, &Matter::bleDataReceived);
    connect(m_btp, &BTP::handshakeComplete, this, &Matter::btpHandshakeComplete);
    connect(m_btp, &BTP::messageReceived, this, &Matter::btpMessageReceived);
    connect(m_btp, &BTP::writeData, this, &Matter::btpWriteData);

    m_searchTimer->setSingleShot(true);
    m_reconnectTimer->setSingleShot(true);
    m_pingTimer->start(10000);

    m_caseNeedsCommissioningComplete = false;
    m_pendingCommissionDevice = nullptr;
    m_pendingRemoveDevice = nullptr;

    if (!m_udp->bind(QHostAddress::Any, m_port))
    {
        logWarning << "Failed to bind UDP port" << m_port;
        return;
    }

    logInfo << "Matter controller listening on port" << m_port;

    m_devices->init();

    for (int i = 0; i < m_devices->count(); i++)
        connectDeviceSignals(m_devices->at(i).data());

    // restore persisted secure sessions ONLY for battery-powered devices: for them CASE on restart wakes the radio
    // (battery hit) and waits tens of seconds on slow MRP intervals; mains devices fall through to normal CASE +
    // resumption which is ~200ms anyway, with no risk of stale-session MRP timeout
    for (int i = 0; i < m_devices->count(); i++)
    {
        DeviceObject *device = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

        if (!device->hasPersistedSession() || !device->batteryPowered())
            continue;

        SessionInfo session;
        session.localSessionId = device->sessionLocalId();
        session.peerSessionId = device->sessionPeerId();
        session.i2rKey = device->sessionI2RKey();
        session.r2iKey = device->sessionR2IKey();
        session.attestationChallenge = device->sessionAttestation();
        session.peerNodeId = device->nodeId();
        session.peerAddress = device->networkAddress();
        session.peerPort = device->networkPort();
        // safety margin: counter must be strictly monotonic across restarts; bump past anything that may have been used
        // since the last persist. 10000 is overkill for our tx rate but cheap (32-bit space ~4B values).
        session.localMessageCounter = device->sessionLocalCounter() + 10000;
        session.idleInterval = device->sessionIdleInterval();
        session.activeInterval = device->sessionActiveInterval();
        session.activeThreshold = device->sessionActiveThreshold();
        session.active = true;

        m_sessions->addSession(session);

        // bump counter so a new CASE (if needed later) won't collide with the restored localSessionId
        if (m_sessionCounter <= session.localSessionId)
            m_sessionCounter = session.localSessionId + 1;

        logInfo << device << "restored secure session, local:" << session.localSessionId << "peer:" << session.peerSessionId << "counter from:" << session.localMessageCounter;

        // peer's subscription state may have timed out while we were down (max interval passed without our acks),
        // re-subscribe to be safe — if the old subscription still exists peer will replace it
        if (!device->endpoints().isEmpty())
            subscribeDevice(device, m_sessions->findByLocalId(session.localSessionId));
    }

    if (m_devices->fabricKey().isEmpty())
    {
        QByteArray fabricKey = Crypto::randomBytes(32), ipk = Crypto::randomBytes(16), operationalKey = Crypto::randomBytes(32), rcacIdBytes = Crypto::randomBytes(8);
        quint64 rootCAId;

        logInfo << "Generated new fabric credentials";
        memcpy(&rootCAId, rcacIdBytes.constData(), 8);

        setFabricCredentials(fabricKey, rootCAId, ipk, operationalKey);
        m_devices->setFabricCredentials(fabricKey, rootCAId, ipk, operationalKey, m_controllerNOC, m_controllerRCAC);
        m_devices->store(true);
    }
    else
        setFabricCredentials(m_devices->fabricKey(), m_devices->rootCAId(), m_devices->ipk(), m_devices->operationalKey(), m_devices->controllerNOC(), m_devices->controllerRCAC());
}

Matter::~Matter(void)
{
    delete m_devices;
}

void Matter::setFabricCredentials(const QByteArray &fabricKey, quint64 rootCAId, const QByteArray &ipk, const QByteArray &operationalKey, const QByteArray &controllerNOC, const QByteArray &controllerRCAC)
{
    m_fabricKey = fabricKey;
    m_rootCAId = rootCAId;
    m_ipk = ipk;
    m_operationalKey = operationalKey;

    ECPoint fabricPub = ECPoint::fromMultiply(ECPoint::generator(), BigNum(m_fabricKey).bn());
    m_fabricPublicKey = fabricPub.toUncompressed();

    ECPoint opPub = ECPoint::fromMultiply(ECPoint::generator(), BigNum(m_operationalKey).bn());
    m_operationalPubKey = opPub.toUncompressed();

    if (!controllerNOC.isEmpty() && !controllerRCAC.isEmpty())
    {
        m_controllerNOC = controllerNOC;
        m_controllerRCAC = controllerRCAC;
    }
    else
    {
        m_controllerRCAC = generateFabricCert(m_fabricId, 0, m_fabricPublicKey, true);
        m_controllerNOC = generateFabricCert(m_fabricId, m_nodeId, m_operationalPubKey, false);
    }

    logInfo << "Fabric credentials loaded, rootCAId:" << QString::number(m_rootCAId, 16);
}

void Matter::connectDevice(DeviceObject *device)
{
    SessionInfo *existing = m_sessions->findByPeerNodeId(device->nodeId());

    if (existing && existing->active)
    {
        logDebug(m_debug) << device << "already have active session";
        return;
    }

    // already a CASE in flight for this device — don't pile up another
    for (auto it = m_pendingCASEs.begin(); it != m_pendingCASEs.end(); it++)
    {
        if (it.value().device == device)
        {
            logDebug(m_debug) << device << "CASE already in progress";
            return;
        }
    }

    QHostAddress address = device->networkAddress();
    quint16 port = device->networkPort();

    if (address.isNull())
    {
        logWarning << device << "no address known";
        return;
    }

    CASESession *session = new CASESession(this);

    connect(session, &CASESession::sendSigma1, this, &Matter::caseSendSigma1);
    connect(session, &CASESession::sendSigma3, this, &Matter::caseSendSigma3);
    connect(session, &CASESession::established, this, &Matter::caseEstablished);
    connect(session, &CASESession::failed, this, &Matter::caseFailed);

    PendingCASE pending;
    pending.session = session;
    pending.device = device;
    pending.exchangeId = m_exchangeCounter++;
    pending.address = address;
    pending.port = port;
    pending.needsCommissioningComplete = m_caseNeedsCommissioningComplete;
    m_pendingCASEs.insert(pending.exchangeId, pending);

    // global "post-commissioning CASE pending" flag is now consumed by this PendingCASE entry
    m_caseNeedsCommissioningComplete = false;

    quint16 sessionId = m_sessionCounter++;

    logInfo << device << "starting CASE at" << address.toString() << ":" << port;

    session->start(sessionId, device->nodeId(),
                   m_fabricKey, m_fabricPublicKey,
                   m_operationalKey, m_operationalPubKey,
                   m_fabricId, m_nodeId, m_rootCAId,
                   m_ipk, m_controllerNOC, m_controllerRCAC,
                   device->resumptionID(), device->resumptionSharedSecret());
}

void Matter::discoverDevice(DeviceObject *device)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session || !session->active)
        return;

    logInfo << device << "discovering endpoints";

    // step 1: read PartsList from endpoint 0
    QList <AttributePath> paths;
    paths.append(AttributePath(0, Clusters::Descriptor::Id, Clusters::Descriptor::Attributes::PartsList));

    QByteArray payload = InteractionModel::encodeReadRequest(paths);
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
}

QList <AttributePath> Matter::buildSubscribePaths(DeviceObject *device)
{
    QList <AttributePath> paths;

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        quint8 epId = it.key();
        EndpointObject *ep = reinterpret_cast <EndpointObject*> (it.value().data());
        const QList <quint32> &clusters = ep->clusters();
        quint16 caps = static_cast <quint16> (ep->meta().value("colorCapabilities").toInt());

        if (clusters.contains(Clusters::OnOff::Id))
            paths.append(AttributePath(epId, Clusters::OnOff::Id, Clusters::OnOff::Attributes::OnOff));

        if (clusters.contains(Clusters::LevelControl::Id))
            paths.append(AttributePath(epId, Clusters::LevelControl::Id, Clusters::LevelControl::Attributes::CurrentLevel));

        if (clusters.contains(Clusters::ColorControl::Id))
        {
            if (caps & 0x0009)
            {
                paths.append(AttributePath(epId, Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::CurrentHue));
                paths.append(AttributePath(epId, Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::CurrentSaturation));
            }

            if (caps & 0x0010)
                paths.append(AttributePath(epId, Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorTemperatureMireds));

            if ((caps & 0x0019) == 0x0019)
                paths.append(AttributePath(epId, Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorMode));
        }

        if (clusters.contains(Clusters::PowerSource::Id))
            paths.append(AttributePath(epId, Clusters::PowerSource::Id, Clusters::PowerSource::Attributes::BatPercentRemaining));

        if (clusters.contains(Clusters::TemperatureMeasurement::Id))
            paths.append(AttributePath(epId, Clusters::TemperatureMeasurement::Id, Clusters::TemperatureMeasurement::Attributes::MeasuredValue));

        if (clusters.contains(Clusters::RelativeHumidityMeasurement::Id))
            paths.append(AttributePath(epId, Clusters::RelativeHumidityMeasurement::Id, Clusters::RelativeHumidityMeasurement::Attributes::MeasuredValue));

        if (clusters.contains(Clusters::ElectricalPowerMeasurement::Id))
            paths.append(AttributePath(epId, Clusters::ElectricalPowerMeasurement::Id, Clusters::ElectricalPowerMeasurement::Attributes::ActivePower));

        if (clusters.contains(Clusters::ElectricalEnergyMeasurement::Id))
            paths.append(AttributePath(epId, Clusters::ElectricalEnergyMeasurement::Id, Clusters::ElectricalEnergyMeasurement::Attributes::CumulativeEnergyImported));
    }

    return paths;
}

QList <EventPath> Matter::buildSubscribeEvents(DeviceObject *device)
{
    QList <EventPath> events;

    // subscribe only to events the action handler actually consumes for the FeatureMap advertised by the
    // endpoint. over-subscribing inflates path count (IKEA BILRESA with 9 Switch endpoints rejects 9×7=63
    // paths with PathsExhausted) and we don't synthesize anything from the events we drop anyway.
    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
    {
        EndpointObject *ep = reinterpret_cast <EndpointObject*> (it.value().data());

        if (!ep->clusters().contains(Clusters::Switch::Id))
            continue;

        quint32 features = ep->meta().value("switchFeatures").toUInt();
        quint8 cap = static_cast <quint8> (ep->meta().value("switchMultiPressMax").toUInt());
        bool encoder = (features & Clusters::Switch::Features::MSM) && !(features & Clusters::Switch::Features::MSL) && cap > 5;

        if (features & Clusters::Switch::Features::LS)
            events.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::SwitchLatched, true));

        // encoder endpoints want a "start" indication when rotation begins (InitialPress fires once at the
        // beginning of a burst before MultiPressComplete reports the total). regular buttons don't need it —
        // we synthesize their action from ShortRelease/MultiPressComplete only.
        if (encoder)
            events.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::InitialPress, true));

        // ShortRelease is emitted only when MSM is absent (Matter §1.13.6.4); with MSM the peer reports
        // press counts via MultiPressComplete instead and we map each count to a click action there.
        if ((features & Clusters::Switch::Features::MSR) && !(features & Clusters::Switch::Features::MSM))
            events.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::ShortRelease, true));

        if (features & Clusters::Switch::Features::MSL)
        {
            events.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::LongPress, true));
            events.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::LongRelease, true));
        }

        if (features & Clusters::Switch::Features::MSM)
            events.append(EventPath(it.key(), Clusters::Switch::Id, Clusters::Switch::Events::MultiPressComplete, true));
    }

    return events;
}

void Matter::subscribeDevice(DeviceObject *device, SessionInfo *session)
{
    if (!session)
        return;

    QList <AttributePath> paths = buildSubscribePaths(device);
    QList <EventPath> events = buildSubscribeEvents(device);

    if (paths.isEmpty() && events.isEmpty())
        return;

    logInfo << device << "subscribing to" << paths.count() << "attributes," << events.count() << "events";
    // peer dumps its event history in the priming ReportData (Matter §8.5.7 — priming arrives before SubscribeResponse).
    // we don't want those replayed buffered clicks to fire automations on every restart, so flag the device as
    // "not yet primed" and drop event reports until SubscribeResponse confirms we're past the priming dump.
    device->setSubscriptionPrimed(false);
    QByteArray subPayload = InteractionModel::encodeSubscribeRequest(paths, events, 0, 60);
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::SubscribeRequest), static_cast <quint16> (ProtocolId::InteractionModel), subPayload, m_exchangeCounter++, true);
}

void Matter::connectDeviceSignals(DeviceObject *device)
{
    connect(device, &DeviceObject::deviceUpdated, this, &Matter::deviceUpdated, Qt::UniqueConnection);
    connect(device, &DeviceObject::endpointUpdated, this, &Matter::endpointUpdated, Qt::UniqueConnection);
}

void Matter::connectDevice(const QString &code)
{
    quint32 passcode;
    quint16 discriminator;
    bool shortDiscriminator;

    if (code.startsWith("MT:"))
    {
        if (!parseQRCode(code, passcode, discriminator))
        {
            logWarning << "Invalid QR code:" << code;
            return;
        }

        shortDiscriminator = false;
    }
    else
    {
        if (!parseManualCode(code, passcode, discriminator))
        {
            logWarning << "Invalid manual code:" << code;
            return;
        }

        shortDiscriminator = true;
    }

    quint64 nodeId = m_devices->generateNodeId();
    logInfo << "Adding device, passcode:" << passcode << "discriminator:" << discriminator << (shortDiscriminator ? "(short)" : "(full)") << "nodeId:" << QString::number(nodeId, 16);
    connectDevice(passcode, discriminator, shortDiscriminator, nodeId);
}

void Matter::discoverDevice(const QString &deviceName)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull())
    {
        logWarning << "Device" << deviceName << "discovery failed, device not found";
        return;
    }

    DeviceObject *obj = reinterpret_cast <DeviceObject*> (device.data());

    emit deviceEvent(obj, Event::aboutToUpdate);
    obj->endpoints().clear();
    m_devices->store(true);
    discoverDevice(obj);
}

void Matter::shareDevice(const QString &deviceName, quint16 timeout)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull() || !device->active())
    {
        logWarning << "Device" << deviceName << "share failed, not found or offline";
        return;
    }

    if (timeout < 180) timeout = 180;
    if (timeout > 900) timeout = 900;

    shareDevice(reinterpret_cast <DeviceObject*> (device.data()), timeout);
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

    device->setActive(active);
    device->setDiscovery(discovery);
    device->setCloud(cloud);
    device->setNote(note);

    logInfo << device << "successfully updated";
    emit deviceEvent(device.data(), Event::updated);
    m_devices->store(true);
}

void Matter::removeDevice(const QString &deviceName)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull())
    {
        logWarning << "Device" << deviceName << "remove failed, device not found";
        return;
    }

    removeDevice(reinterpret_cast <DeviceObject*> (device.data()));
}

void Matter::getProperties(const QString &deviceName)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull())
        return;

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
        emit endpointUpdated(reinterpret_cast <DeviceObject*> (device.data()), it.key());
}

void Matter::deviceAction(const QString &deviceName, quint8 endpointId, const QString &name, const QVariant &value)
{
    const Device &device = m_devices->byName(deviceName);

    if (device.isNull() || !device->active())
        return;

    DeviceObject *obj = reinterpret_cast <DeviceObject*> (device.data());

    if (endpointId)
    {
        sendCommand(obj, endpointId, name, value);
        return;
    }

    for (auto it = device->endpoints().begin(); it != device->endpoints().end(); it++)
        sendCommand(obj, it.key(), name, value);
}

void Matter::removeDevice(DeviceObject *device)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session || !session->active)
    {
        int index = -1;
        m_devices->byName(device->name(), &index);

        logWarning << device << "no active session, removing forcefully";
        emit deviceEvent(device, Event::removed, {{"success", false}});

        // tear down any in-flight CASE for this device before m_devices->removeAt drops the last shared pointer ref
        for (auto it = m_pendingCASEs.begin(); it != m_pendingCASEs.end(); )
        {
            if (it.value().device == device)
            {
                it.value().session->deleteLater();
                it = m_pendingCASEs.erase(it);
            }
            else
                it++;
        }

        if (index >= 0)
        {
            m_devices->removeAt(index);
            m_devices->store(true);
        }

        return;
    }

    logInfo << device << "sending RemoveFabric, fabricIndex:" << device->fabricIndex();

    m_pendingRemoveDevice = device;

    MatterTLV::Encoder fields;
    fields.openStructure();
    fields.encodeUnsignedInt(0, device->fabricIndex());
    fields.closeContainer();

    QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::RemoveFabric), fields);
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);

    session->active = false;
}

void Matter::connectDevice(quint32 passcode, quint16 discriminator, bool shortDiscriminator, quint64 nodeId)
{
    m_searching = true;
    m_searchPasscode = passcode;
    m_searchDiscriminator = discriminator;
    m_searchShortDiscriminator = shortDiscriminator;
    m_searchNodeId = nodeId;
    m_bleCommissioning = false;

    m_searchTimer->start(60000);
    logInfo << "Searching for commissionable device, discriminator:" << discriminator << (shortDiscriminator ? "(short)" : "(full)") << "nodeId:" << nodeId;

    m_mdns->browse();

    if (m_ble->available() && !m_wifiSSID.isEmpty())
    {
        logInfo << "Scanning BLE and mDNS in parallel...";
        m_ble->scan();
    }
}

// --- Send command to a commissioned device ---

void Matter::sendCommand(DeviceObject *device, quint8 endpointId, const QString &name, const QVariant &value)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session)
    {
        logWarning << device << "no active session, starting CASE";
        connectDevice(device);
        return;
    }

    QByteArray payload;

    if (name == "status")
    {
        QString status = value.toString();

        if (status == "toggle")
            payload = InteractionModel::encodeToggleCommand(endpointId);
        else
            payload = InteractionModel::encodeOnOffCommand(endpointId, status == "on");
    }
    else if (name == "level")
        payload = InteractionModel::encodeMoveToLevelCommand(endpointId, static_cast <quint8> (value.toUInt() * 0xFE / 0xFF));
    else if (name == "colorTemperature")
        payload = InteractionModel::encodeMoveToColorTemperatureCommand(endpointId, static_cast <quint16> (value.toUInt()));
    else if (name == "color")
    {
        QList <QVariant> list = value.toList();

        if (list.count() >= 3)
        {
            Color color(list.at(0).toDouble() / 0xFF, list.at(1).toDouble() / 0xFF, list.at(2).toDouble() / 0xFF);
            double h, s;
            color.toHS(&h, &s);
            payload = InteractionModel::encodeMoveToHueAndSaturationCommand(endpointId, static_cast <quint8> (h * 0xFE), static_cast <quint8> (s * 0xFE));
        }
    }
    else if (name == "lock")
        payload = InteractionModel::encodeLockCommand(endpointId, value.toString() == "lock");
    else if (name == "cover")
        payload = InteractionModel::encodeCoverCommand(endpointId, static_cast <quint8> (value.toUInt()));
    else if (name == "coverPosition")
        payload = InteractionModel::encodeCoverCommand(endpointId, 3, static_cast <quint16> (value.toUInt()));

    if (payload.isEmpty())
    {
        logWarning << "Unknown command:" << name;
        return;
    }

    logInfo << device << "sending command" << name << "to endpoint" << endpointId;
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
}

void Matter::readAttributes(DeviceObject *device, const QList <AttributePath> &paths)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session)
    {
        logWarning << device << "no active session, starting CASE";
        connectDevice(device);
        return;
    }

    QByteArray payload = InteractionModel::encodeReadRequest(paths);
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
}

// --- Low-level message sending ---

void Matter::sendRawDatagram(const QByteArray &data, const QHostAddress &address, quint16 port)
{
    m_udp->writeDatagram(data, address, port);
}

void Matter::sendUnencrypted(quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, const QHostAddress &address, quint16 port, bool initiator, quint32 ackCounter)
{
    MessageHeader msgHeader;
    msgHeader.flags = 0x04; // source node ID present
    msgHeader.securityFlags = 0x00;
    msgHeader.sessionId = 0;
    msgHeader.messageCounter = ++m_messageCounter;
    msgHeader.sourceNodeId = m_nodeId;

    ProtocolHeader protoHeader;
    protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Reliability);

    if (initiator)
        protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);

    if (ackCounter)
    {
        protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Acknowledgement);
        protoHeader.ackCounter = ackCounter;
        m_mrp->cancelPendingAck(ackCounter);
    }

    protoHeader.opcode = opcode;
    protoHeader.exchangeId = exchangeId;
    protoHeader.protocolId = protocolId;

    QByteArray data = MessageCodec::encodeMessage(msgHeader, protoHeader, payload);
    sendRawDatagram(data, address, port);
    m_mrp->messageSent(data, address, port, msgHeader.messageCounter, protoHeader.exchangeId, true);
}

void Matter::sendEncrypted(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator, quint32 ackCounter)
{
    session->localMessageCounter++;

    MessageHeader msgHeader;
    msgHeader.flags = 0x00;
    msgHeader.securityFlags = 0x00;
    msgHeader.sessionId = session->peerSessionId;
    msgHeader.messageCounter = session->localMessageCounter;

    QByteArray header = MessageCodec::encodeHeader(msgHeader);

    // build protocol header + payload (this is what gets encrypted)
    ProtocolHeader protoHeader;
    protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Reliability);

    if (initiator)
        protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);

    if (ackCounter)
    {
        protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Acknowledgement);
        protoHeader.ackCounter = ackCounter;
        m_mrp->cancelPendingAck(ackCounter);
    }

    protoHeader.opcode = opcode;
    protoHeader.exchangeId = exchangeId;
    protoHeader.protocolId = protocolId;

    QByteArray plaintext = MessageCodec::encodeProtocolHeader(protoHeader);
    plaintext.append(payload);

    QByteArray nonce = SessionManager::buildNonce(msgHeader.securityFlags, msgHeader.messageCounter, session->active ? m_nodeId : 0);
    QByteArray encrypted = Crypto::aesCcmEncrypt(session->i2rKey, nonce, header, plaintext, SESSION_TAG_LENGTH);

    QByteArray data = header;
    data.append(encrypted);

    sendRawDatagram(data, session->peerAddress, session->peerPort);
    m_mrp->messageSent(data, session->peerAddress, session->peerPort, msgHeader.messageCounter, exchangeId, true, session->idleInterval);
}

void Matter::sendEncryptedBle(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator)
{
    session->localMessageCounter++;

    MessageHeader msgHeader;
    msgHeader.flags = 0x00;
    msgHeader.securityFlags = 0x00;
    msgHeader.sessionId = session->peerSessionId;
    msgHeader.messageCounter = session->localMessageCounter;

    QByteArray header = MessageCodec::encodeHeader(msgHeader);

    ProtocolHeader protoHeader;
    protoHeader.exchangeFlags = 0;

    if (initiator)
        protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);

    protoHeader.opcode = opcode;
    protoHeader.exchangeId = exchangeId;
    protoHeader.protocolId = protocolId;

    QByteArray plaintext = MessageCodec::encodeProtocolHeader(protoHeader);
    plaintext.append(payload);

    QByteArray nonce = SessionManager::buildNonce(msgHeader.securityFlags, msgHeader.messageCounter, 0);
    QByteArray encrypted = Crypto::aesCcmEncrypt(session->i2rKey, nonce, header, plaintext, SESSION_TAG_LENGTH);

    QByteArray data = header;
    data.append(encrypted);

    m_btp->sendMessage(data);
}

// --- Incoming message handling ---

void Matter::handleSecureChannel(const MessageHeader &msgHeader, const ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port)
{
    Q_UNUSED(address)
    Q_UNUSED(port)

    switch (static_cast <SecureChannelOpcode> (protoHeader.opcode))
    {
        case SecureChannelOpcode::PBKDFParamResponse:
        {
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().exchangeId == protoHeader.exchangeId)
                {
                    it.value().pase->setLastPeerMessageCounter(msgHeader.messageCounter);
                    it.value().pase->handlePBKDFParamResponse(payload);
                    break;
                }
            }

            break;
        }

        case SecureChannelOpcode::PASEPake2:
        {
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().exchangeId == protoHeader.exchangeId)
                {
                    it.value().pase->setLastPeerMessageCounter(msgHeader.messageCounter);
                    it.value().pase->handlePake2(payload);
                    break;
                }
            }

            break;
        }

        case SecureChannelOpcode::StatusReport:
        {
            // check if this is for a PASE session
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().exchangeId == protoHeader.exchangeId && it.value().state == CommissioningState::PASE)
                {
                    it.value().pase->handleStatusReport(payload);
                    return;
                }
            }

            // check if this is for a CASE session
            if (m_pendingCASEs.contains(protoHeader.exchangeId))
            {
                m_pendingCASEs.value(protoHeader.exchangeId).session->handleStatusReport(payload);
                return;
            }

            logDebug(m_debug) << "StatusReport from session" << msgHeader.sessionId;
            break;
        }

        case SecureChannelOpcode::CASESigma1:
            logDebug(m_debug) << "CASE Sigma1 from" << msgHeader.sourceNodeId;
            break;

        case SecureChannelOpcode::CASESigma2:
        {
            if (m_pendingCASEs.contains(protoHeader.exchangeId))
            {
                CASESession *session = m_pendingCASEs.value(protoHeader.exchangeId).session;
                session->setLastPeerMessageCounter(msgHeader.messageCounter);
                session->handleSigma2(payload);
            }
            else
            {
                logDebug(m_debug) << "Sigma2 from unknown exchange" << protoHeader.exchangeId << ", ignoring";
            }

            break;
        }

        case SecureChannelOpcode::CASESigma2Resume:
        {
            if (m_pendingCASEs.contains(protoHeader.exchangeId))
            {
                CASESession *session = m_pendingCASEs.value(protoHeader.exchangeId).session;
                session->setLastPeerMessageCounter(msgHeader.messageCounter);
                session->handleSigma2Resume(payload);
            }
            else
            {
                logDebug(m_debug) << "Sigma2_Resume from unknown exchange" << protoHeader.exchangeId << ", ignoring";
            }

            break;
        }

        case SecureChannelOpcode::MRPStandaloneAck:
            break;

        default:
            logWarning << "Unknown secure channel opcode:" << QString::number(protoHeader.opcode, 16);
            break;
    }
}

void Matter::handleInteractionModel(const MessageHeader &msgHeader, const ProtocolHeader &protoHeader, const QByteArray &payload, const QHostAddress &address, quint16 port)
{
    Q_UNUSED(address)
    Q_UNUSED(port)

    switch (static_cast <InteractionModelOpcode> (protoHeader.opcode))
    {
        case InteractionModelOpcode::ReportData:
        {
            QList <AttributeReport> reports = InteractionModel::decodeReportData(payload);
            QList <AttributePath> pendingSubPaths;
            QList <EventPath> pendingSubEvents;
            SessionInfo *pendingSubSession = nullptr;
            DeviceObject *pendingSubDevice = nullptr;

            // check for subscriptionId and suppressResponse in ReportData
            bool hasSubscriptionId = false;
            bool suppressResponse = false;

            {
                MatterTLV::Decoder rdDecoder(payload);
                MatterTLV::Element rdRoot = rdDecoder.decode();

                for (const MatterTLV::Element &el : rdRoot.children)
                {
                    if (el.tag == 0)
                    {
                        hasSubscriptionId = true;
                        logDebug(m_debug) << "ReportData subscriptionId:" << el.value.toUInt();
                    }

                    if (el.tag == 3)
                    {
                        suppressResponse = el.value.toBool();
                        logDebug(m_debug) << "ReportData suppressResponse:" << suppressResponse;
                    }
                }
            }

            for (const AttributeReport &report : reports)
            {
                if (report.hasError)
                {
                    logWarning << "Attribute error, cluster:" << QString::number(report.path.clusterId, 16) << "attr:" << QString::number(report.path.attributeId, 16) << "status:" << report.status;
                    continue;
                }

                logDebug(m_debug) << "Attribute, ep:" << report.path.endpointId << "cluster:" << QString::number(report.path.clusterId, 16) << "attr:" << QString::number(report.path.attributeId, 16) << "value:" << report.value;

                // update device state from subscription reports
                {
                    SessionInfo *attrSession = m_sessions->findByLocalId(msgHeader.sessionId);

                    if (attrSession)
                    {
                        for (int i = 0; i < m_devices->count(); i++)
                        {
                            DeviceObject *dev = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

                            if (dev->nodeId() == attrSession->peerNodeId)
                            {
                                if (report.path.clusterId == Clusters::OnOff::Id && report.path.attributeId == Clusters::OnOff::Attributes::OnOff)
                                    dev->updateEndpoint(report.path.endpointId, "status", report.value.toBool() ? "on" : "off");
                                else if (report.path.clusterId == Clusters::LevelControl::Id && report.path.attributeId == Clusters::LevelControl::Attributes::CurrentLevel)
                                    dev->updateEndpoint(report.path.endpointId, "level", qMin(report.value.toUInt() * 0xFF / 0xFE, 0xFFu));
                                else if (report.path.clusterId == Clusters::ColorControl::Id && (report.path.attributeId == Clusters::ColorControl::Attributes::CurrentHue || report.path.attributeId == Clusters::ColorControl::Attributes::CurrentSaturation))
                                {
                                    Endpoint ep = dev->endpoints().value(report.path.endpointId);

                                    if (!ep.isNull())
                                    {
                                        if (report.path.attributeId == Clusters::ColorControl::Attributes::CurrentHue)
                                            ep->status().insert("colorH", report.value.toUInt());
                                        else
                                            ep->status().insert("colorS", report.value.toUInt());

                                        if (ep->status().contains("colorH") && ep->status().contains("colorS"))
                                        {
                                            Color color = Color::fromHS(ep->status().value("colorH").toDouble() / 0xFE, ep->status().value("colorS").toDouble() / 0xFE);
                                            dev->updateEndpoint(report.path.endpointId, "color", QVariant(QList <QVariant> {static_cast <int> (color.r() * 0xFF), static_cast <int> (color.g() * 0xFF), static_cast <int> (color.b() * 0xFF)}));
                                        }
                                    }
                                }
                                else if (report.path.clusterId == Clusters::ColorControl::Id && report.path.attributeId == Clusters::ColorControl::Attributes::ColorTemperatureMireds)
                                    dev->updateEndpoint(report.path.endpointId, "colorTemperature", report.value.toUInt());
                                else if (report.path.clusterId == Clusters::ColorControl::Id && report.path.attributeId == Clusters::ColorControl::Attributes::ColorMode)
                                    dev->updateEndpoint(report.path.endpointId, "colorMode", report.value.toUInt() != 2);
                                else if (report.path.clusterId == Clusters::PowerSource::Id && report.path.attributeId == Clusters::PowerSource::Attributes::BatPercentRemaining)
                                    dev->updateEndpoint(report.path.endpointId, "battery", report.value.toDouble() / 2.0);
                                else if (report.path.clusterId == Clusters::TemperatureMeasurement::Id && report.path.attributeId == Clusters::TemperatureMeasurement::Attributes::MeasuredValue)
                                    dev->updateEndpoint(report.path.endpointId, "temperature", report.value.toDouble() / 100.0);
                                else if (report.path.clusterId == Clusters::RelativeHumidityMeasurement::Id && report.path.attributeId == Clusters::RelativeHumidityMeasurement::Attributes::MeasuredValue)
                                    dev->updateEndpoint(report.path.endpointId, "humidity", report.value.toDouble() / 100.0);
                                else if (report.path.clusterId == Clusters::ElectricalPowerMeasurement::Id && report.path.attributeId == Clusters::ElectricalPowerMeasurement::Attributes::ActivePower)
                                    dev->updateEndpoint(report.path.endpointId, "power", report.value.toLongLong() / 1000.0);
                                else if (report.path.clusterId == Clusters::ElectricalEnergyMeasurement::Id && report.path.attributeId == Clusters::ElectricalEnergyMeasurement::Attributes::CumulativeEnergyImported)
                                {
                                    for (const MatterTLV::Element &child : report.rawValue.children)
                                    {
                                        if (child.tag == 0)
                                            dev->updateEndpoint(report.path.endpointId, "energy", child.value.toLongLong() / 1000.0);
                                    }
                                }

                                break;
                            }
                        }
                    }
                }

                // check if this is part of commissioning (BasicInformation read)
                for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
                {
                    PendingCommission &commission = it.value();

                    if (commission.state == CommissioningState::ReadBasicInfo && commission.device)
                    {
                        if (report.path.clusterId == Clusters::BasicInformation::Id)
                        {
                            switch (report.path.attributeId)
                            {
                                case Clusters::BasicInformation::Attributes::VendorName:
                                    commission.device->setManufacturerName(report.value.toString());
                                    break;

                                case Clusters::BasicInformation::Attributes::ProductName:
                                    commission.device->setModelName(report.value.toString());
                                    break;

                                case Clusters::BasicInformation::Attributes::VendorID:
                                    commission.device->setVendorId(report.value.toUInt());
                                    break;

                                case Clusters::BasicInformation::Attributes::ProductID:
                                    commission.device->setProductId(report.value.toUInt());
                                    break;
                            }
                        }
                    }

                    if (commission.state == CommissioningState::ReadNetworkType && report.path.clusterId == Clusters::NetworkCommissioning::Id && report.path.attributeId == Clusters::NetworkCommissioning::Attributes::FeatureMap)
                    {
                        commission.networkFeatureMap = report.value.toUInt();
                    }
                }
            }

            // process event reports — currently used for Switch cluster button actions (Matter §1.13)
            {
                SessionInfo *evSession = m_sessions->findByLocalId(msgHeader.sessionId);
                DeviceObject *evDevice = nullptr;

                if (evSession)
                {
                    for (int i = 0; i < m_devices->count(); i++)
                    {
                        DeviceObject *dev = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

                        if (dev->nodeId() == evSession->peerNodeId)
                        {
                            evDevice = dev;
                            break;
                        }
                    }
                }

                if (evDevice)
                {
                    QList <EventReport> events = InteractionModel::decodeEventReports(payload);

                    for (const EventReport &event : events)
                    {
                        logDebug(m_debug) << "Event, ep:" << event.path.endpointId << "cluster:" << QString::number(event.path.clusterId, 16) << "event:" << QString::number(event.path.eventId, 16) << "number:" << event.eventNumber;

                        // drop events arriving in the priming ReportData (peer dumps its event buffer there);
                        // we only care about events that occur after subscribe is established
                        if (!evDevice->subscriptionPrimed())
                            continue;

                        if (event.path.clusterId != Clusters::Switch::Id)
                            continue;

                        // map Switch events to action strings (zigbee-style: single_click/double_click/hold/release/latched).
                        // we use MultiPressComplete for click counts when available (it carries the final N), and fall
                        // back to ShortRelease as "single_click" for devices without the MSM feature.
                        QString action;

                        switch (event.path.eventId)
                        {
                            case Clusters::Switch::Events::SwitchLatched:
                                action = "latched";
                                break;

                            case Clusters::Switch::Events::InitialPress:
                            {
                                // only encoder endpoints subscribe to InitialPress (regular buttons don't need it);
                                // map it to "start" so consumers see rotation begin before MultiPressComplete fires
                                Endpoint endpoint = evDevice->endpoints().value(static_cast <quint8> (event.path.endpointId));
                                quint32 features = endpoint.isNull() ? 0 : reinterpret_cast <EndpointObject*> (endpoint.data())->meta().value("switchFeatures").toUInt();
                                quint8 cap = endpoint.isNull() ? 0 : static_cast <quint8> (reinterpret_cast <EndpointObject*> (endpoint.data())->meta().value("switchMultiPressMax").toUInt());

                                if ((features & Clusters::Switch::Features::MSM) && !(features & Clusters::Switch::Features::MSL) && cap > 5)
                                    action = "start";

                                break;
                            }

                            case Clusters::Switch::Events::ShortRelease:
                            {
                                // for devices supporting MSM (multi-press), peer will follow up with MultiPressComplete
                                // carrying the press count — emitting singleClick here causes a duplicate before the
                                // doubleClick arrives. only fall back to ShortRelease for devices without MSM.
                                Endpoint endpoint = evDevice->endpoints().value(static_cast <quint8> (event.path.endpointId));
                                quint32 features = endpoint.isNull() ? 0 : reinterpret_cast <EndpointObject*> (endpoint.data())->meta().value("switchFeatures").toUInt();

                                if (!(features & Clusters::Switch::Features::MSM))
                                    action = "singleClick";

                                break;
                            }

                            case Clusters::Switch::Events::LongPress:
                                action = "hold";
                                break;

                            case Clusters::Switch::Events::LongRelease:
                                action = "release";
                                break;

                            case Clusters::Switch::Events::MultiPressComplete:
                            {
                                // MultiPressComplete data (Matter §1.13.6.6): tag 0=PreviousPosition, tag 1=TotalNumberOfPressesCounted
                                quint8 count = 0;

                                for (const MatterTLV::Element &child : event.data.children)
                                {
                                    if (child.tag == 1)
                                        count = static_cast <quint8> (child.value.toUInt());
                                }

                                // encoder endpoints (high MultiPressMax + no MSL) report rotation detents in count;
                                // map MultiPressComplete to "stop" (paired with the earlier "start" from InitialPress)
                                // and surface the burst size as a separate numeric property so consumers see motion +
                                // amount, not a fake click count
                                Endpoint endpoint = evDevice->endpoints().value(static_cast <quint8> (event.path.endpointId));
                                quint32 features = endpoint.isNull() ? 0 : reinterpret_cast <EndpointObject*> (endpoint.data())->meta().value("switchFeatures").toUInt();
                                quint8 cap = endpoint.isNull() ? 0 : static_cast <quint8> (reinterpret_cast <EndpointObject*> (endpoint.data())->meta().value("switchMultiPressMax").toUInt());
                                bool encoder = (features & Clusters::Switch::Features::MSM) && !(features & Clusters::Switch::Features::MSL) && cap > 5;

                                if (encoder)
                                {
                                    action = "stop";
                                    // stash the burst size into endpoint status without emitting yet — the action
                                    // updateEndpoint below fires the single endpointUpdated that publishes both
                                    if (!endpoint.isNull() && count > 0)
                                        reinterpret_cast <EndpointObject*> (endpoint.data())->status().insert("count", count);
                                    break;
                                }

                                switch (count)
                                {
                                    case 1: action = "singleClick"; break;
                                    case 2: action = "doubleClick"; break;
                                    case 3: action = "tripleClick"; break;
                                    default:
                                        if (count > 0)
                                            action = "multipleClick";
                                        break;
                                }

                                break;
                            }
                        }

                        if (!action.isEmpty())
                        {
                            quint8 epId = static_cast <quint8> (event.path.endpointId);
                            evDevice->updateEndpoint(epId, "action", action);
                            // "action" is a transient event — clear it from endpoint status right after publish
                            // so subsequent unrelated updates don't carry the stale value, and HA picks up each
                            // press as a fresh transition. encoder "count" stays as a sticky last-burst value.
                            Endpoint endpoint = evDevice->endpoints().value(epId);
                            if (!endpoint.isNull())
                                reinterpret_cast <EndpointObject*> (endpoint.data())->status().remove("action");
                        }
                    }
                }
            }

            // process Descriptor cluster reports — build endpoints and exposes
            {
                SessionInfo *reportSession = m_sessions->findByLocalId(msgHeader.sessionId);
                DeviceObject *reportDevice = nullptr;

                if (reportSession)
                {
                    for (int i = 0; i < m_devices->count(); i++)
                    {
                        DeviceObject *dev = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

                        if (dev->nodeId() == reportSession->peerNodeId)
                        {
                            reportDevice = dev;
                            break;
                        }
                    }
                }

                if (reportDevice)
                {
                    Device reportDeviceHolder; // keep shared pointer alive

                    for (int di = 0; di < m_devices->count(); di++)
                    {
                        if (m_devices->at(di).data() == reportDevice)
                        {
                            reportDeviceHolder = m_devices->at(di);
                            break;
                        }
                    }

                    // step 1 response: PartsList — request ServerList for discovered endpoints
                    QList <quint8> discoveredEndpoints;

                    for (const AttributeReport &report : reports)
                    {
                        if (!report.hasError && report.path.clusterId == Clusters::Descriptor::Id && report.path.attributeId == Clusters::Descriptor::Attributes::PartsList && report.path.endpointId == 0)
                        {
                            // PartsList — complete array or individual list items
                            for (const MatterTLV::Element &child : report.rawValue.children)
                                discoveredEndpoints.append(static_cast <quint8> (child.value.toUInt()));

                            if (report.value.isValid() && report.value.canConvert <uint> ())
                                discoveredEndpoints.append(static_cast <quint8> (report.value.toUInt()));
                        }
                    }

                    if (!discoveredEndpoints.isEmpty() && reportDevice->endpoints().isEmpty())
                    {
                        logInfo << reportDevice << "found" << discoveredEndpoints.count() << "endpoints";

                        QList <quint8> queryEndpoints = QList <quint8> {0} + discoveredEndpoints; // include root in case PowerSource lives there
                        QList <AttributePath> serverPaths;

                        for (quint8 ep : queryEndpoints)
                            serverPaths.append(AttributePath(ep, Clusters::Descriptor::Id, Clusters::Descriptor::Attributes::ServerList));

                        QByteArray serverPayload = InteractionModel::encodeReadRequest(serverPaths);
                        sendEncrypted(reportSession, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), serverPayload, m_exchangeCounter++, true);
                    }

                    // discovery is split across two reads to keep the path count bounded for multi-endpoint peers
                    // (Aqara W100 hits PathsExhausted otherwise): step 2 collects ServerList per endpoint, step 3
                    // collects cluster-specific attrs (Switch features, Color caps) only on endpoints that need them.
                    // setupEndpoint runs ONCE per endpoint at the end — only after both stages have populated clusters
                    // and meta — so exposes and their option enums are built in a single pass and published once.
                    QMap <quint8, QList <quint32>> endpointClusters;
                    bool wroteFollowupMeta = false;

                    for (const AttributeReport &report : reports)
                    {
                        if (report.hasError)
                            continue;

                        if (report.path.clusterId == Clusters::Descriptor::Id && report.path.attributeId == Clusters::Descriptor::Attributes::ServerList)
                        {
                            // ServerList — complete array or individual list items
                            for (const MatterTLV::Element &child : report.rawValue.children)
                                endpointClusters[report.path.endpointId].append(child.value.toUInt());

                            if (report.value.isValid() && report.value.canConvert <uint> ())
                                endpointClusters[report.path.endpointId].append(report.value.toUInt());
                        }
                        else
                        {
                            // step 3 follow-up: write attribute value to endpoint meta. expose-building is deferred
                            // to the finalize block below so meta is fully populated when setupEndpoint runs.
                            QString metaKey;

                            switch (report.path.clusterId)
                            {
                                case Clusters::ColorControl::Id:
                                    switch (report.path.attributeId)
                                    {
                                        case Clusters::ColorControl::Attributes::ColorCapabilities:        metaKey = "colorCapabilities"; break;
                                        case Clusters::ColorControl::Attributes::ColorTempPhysicalMinMireds: metaKey = "colorTempMin"; break;
                                        case Clusters::ColorControl::Attributes::ColorTempPhysicalMaxMireds: metaKey = "colorTempMax"; break;
                                    }
                                    break;

                                case Clusters::Switch::Id:
                                    switch (report.path.attributeId)
                                    {
                                        case Clusters::Switch::Attributes::FeatureMap:    metaKey = "switchFeatures"; break;
                                        case Clusters::Switch::Attributes::MultiPressMax: metaKey = "switchMultiPressMax"; break;
                                    }
                                    break;
                            }

                            if (!metaKey.isEmpty() && reportDevice)
                            {
                                Endpoint endpoint = reportDevice->endpoints().value(static_cast <quint8> (report.path.endpointId));

                                if (!endpoint.isNull())
                                {
                                    reinterpret_cast <EndpointObject*> (endpoint.data())->meta().insert(metaKey, report.value.toUInt());
                                    wroteFollowupMeta = true;
                                }
                            }
                        }
                    }

                    bool finalizeDiscovery = false;

                    if (!endpointClusters.isEmpty() && reportDevice)
                    {
                        // step 2: register endpoints with their clusters (no exposes yet — meta from step 3 isn't in)
                        for (auto it = endpointClusters.begin(); it != endpointClusters.end(); it++)
                            m_devices->addEndpoint(reportDevice, it.key(), it.value());

                        // build follow-up paths only for endpoints that actually need cluster-specific attrs
                        QList <AttributePath> followupPaths;

                        for (auto it = endpointClusters.begin(); it != endpointClusters.end(); it++)
                        {
                            if (it.value().contains(Clusters::ColorControl::Id))
                            {
                                followupPaths.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorCapabilities));
                                followupPaths.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorTempPhysicalMinMireds));
                                followupPaths.append(AttributePath(it.key(), Clusters::ColorControl::Id, Clusters::ColorControl::Attributes::ColorTempPhysicalMaxMireds));
                            }

                            if (it.value().contains(Clusters::Switch::Id))
                            {
                                followupPaths.append(AttributePath(it.key(), Clusters::Switch::Id, Clusters::Switch::Attributes::FeatureMap));
                                followupPaths.append(AttributePath(it.key(), Clusters::Switch::Id, Clusters::Switch::Attributes::MultiPressMax));
                            }
                        }

                        if (!followupPaths.isEmpty() && reportSession)
                        {
                            QByteArray followupPayload = InteractionModel::encodeReadRequest(followupPaths);
                            sendEncrypted(reportSession, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), followupPayload, m_exchangeCounter++, true);
                        }
                        else
                        {
                            // no step 3 needed for this peer — finalize directly from step 2
                            finalizeDiscovery = true;
                        }
                    }

                    if (wroteFollowupMeta && reportDevice)
                        finalizeDiscovery = true;

                    if (finalizeDiscovery && reportDevice && reportSession)
                    {
                        // single-pass expose-build for every registered endpoint with full clusters + meta
                        for (auto ep = reportDevice->endpoints().begin(); ep != reportDevice->endpoints().end(); ep++)
                            m_devices->setupEndpoint(reportDevice, ep.key());

                        m_devices->updateMultiple(reportDevice);

                        // late session persistence: caseEstablished can't tell whether a freshly-commissioned device is
                        // battery-powered until PowerSource is detected here in discovery. now that the flag is set,
                        // capture the active CASE keys onto the device so serialize() can write them to disk.
                        if (reportDevice->batteryPowered() && !reportDevice->hasPersistedSession())
                        {
                            SessionInfo *active = m_sessions->findByPeerNodeId(reportDevice->nodeId());

                            if (active)
                            {
                                reportDevice->setSessionLocalId(active->localSessionId);
                                reportDevice->setSessionPeerId(active->peerSessionId);
                                reportDevice->setSessionI2RKey(active->i2rKey);
                                reportDevice->setSessionR2IKey(active->r2iKey);
                                reportDevice->setSessionAttestation(active->attestationChallenge);
                                reportDevice->setSessionLocalCounter(0);
                                reportDevice->setSessionIdleInterval(active->idleInterval);
                                reportDevice->setSessionActiveInterval(active->activeInterval);
                                reportDevice->setSessionActiveThreshold(active->activeThreshold);
                            }
                        }

                        m_devices->store(true);

                        pendingSubPaths = buildSubscribePaths(reportDevice);
                        pendingSubEvents = buildSubscribeEvents(reportDevice);
                        pendingSubSession = reportSession;
                        pendingSubDevice = reportDevice;
                    }
                }
            }

            // send StatusResponse (success) to acknowledge ReportData
            SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

            if (session && !suppressResponse && !m_bleCommissioning && (!reports.isEmpty() || hasSubscriptionId))
            {
                logDebug(m_debug) << "Sending StatusResponse(0) for ReportData, exchange:" << protoHeader.exchangeId << "ack:" << msgHeader.messageCounter;
                QByteArray statusPayload = InteractionModel::encodeStatusResponse(0);
                sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::StatusResponse), static_cast <quint16> (ProtocolId::InteractionModel), statusPayload, protoHeader.exchangeId, !protoHeader.isInitiator(), msgHeader.messageCounter);
            }

            // send SubscribeRequest after StatusResponse has been sent
            if ((!pendingSubPaths.isEmpty() || !pendingSubEvents.isEmpty()) && pendingSubSession && pendingSubDevice)
            {
                logInfo << pendingSubDevice << "subscribing to" << pendingSubPaths.count() << "attributes," << pendingSubEvents.count() << "events";
                pendingSubDevice->setSubscriptionPrimed(false);
                QByteArray subPayload = InteractionModel::encodeSubscribeRequest(pendingSubPaths, pendingSubEvents, 0, 60);
                sendEncrypted(pendingSubSession, static_cast <quint8> (InteractionModelOpcode::SubscribeRequest), static_cast <quint16> (ProtocolId::InteractionModel), subPayload, m_exchangeCounter++, true);
                pendingSubDevice->deviceUpdated(pendingSubDevice);
            }

            // continue commissioning if applicable
            for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
            {
                if (it.value().state == CommissioningState::ReadBasicInfo)
                {
                    it.value().state = CommissioningState::RequestPAI;
                    continueCommissioning(it.value());
                    break;
                }

                if (it.value().state == CommissioningState::ReadNetworkType)
                {
                    quint32 features = it.value().networkFeatureMap;
                    bool hasWiFi   = features & 0x01;
                    bool hasThread = features & 0x02;
                    bool hasEth    = features & 0x04;

                    logInfo << "Device NetworkCommissioning features:" << QString("WiFi=%1 Thread=%2 Ethernet=%3").arg(hasWiFi).arg(hasThread).arg(hasEth);

                    if (hasThread && !m_threadDataset.isEmpty())
                    {
                        logInfo << "Sending Thread Operational Dataset over BLE...";
                        it.value().useThread = true;
                        it.value().state = CommissioningState::AddThreadNetwork;
                    }
                    else if (hasWiFi && !m_wifiSSID.isEmpty())
                    {
                        logInfo << "Sending WiFi credentials over BLE...";
                        it.value().useThread = false;
                        it.value().state = CommissioningState::AddWiFiNetwork;
                    }
                    else
                    {
                        logWarning << "No matching credentials for device features (WiFi=" << hasWiFi << "Thread=" << hasThread << "Ethernet=" << hasEth << "), commissioning will fail";
                        break;
                    }

                    continueCommissioning(it.value());
                    break;
                }
            }

            break;
        }

        case InteractionModelOpcode::StatusResponse:
        {
            quint8 status = InteractionModel::decodeStatusResponse(payload);
            logDebug(m_debug) << "StatusResponse:" << status;

            // TimedRequest was ACKed with StatusResponse(0) — now send the actual command
            if (status == 0)
            {
                for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
                {
                    if (it.value().timedInvokePending)
                    {
                        it.value().lastPeerCounter = msgHeader.messageCounter;
                        continueCommissioning(it.value());
                        break;
                    }
                }

                // check pending shares
                SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

                if (session)
                {
                    auto shareIt = m_pendingShares.find(session->peerNodeId);

                    if (shareIt != m_pendingShares.end() && shareIt->timedInvokePending)
                    {
                        shareIt->lastPeerCounter = msgHeader.messageCounter;
                        shareIt->timedInvokePending = false;

                        // send OpenCommissioningWindow
                        QByteArray verifier = m_shareVerifiers.take(session->peerNodeId);
                        QByteArray salt = m_shareSalts.take(session->peerNodeId);
                        quint32 iterations = m_shareIterations.take(session->peerNodeId);

                        MatterTLV::Encoder fields;
                        fields.openStructure();
                        fields.encodeUnsignedInt(0, shareIt->timeout);       // CommissioningTimeout
                        fields.encodeByteString(1, verifier);                // PAKEPasscodeVerifier
                        fields.encodeUnsignedInt(2, shareIt->discriminator); // Discriminator
                        fields.encodeUnsignedInt(3, iterations);             // Iterations
                        fields.encodeByteString(4, salt);                    // Salt
                        fields.closeContainer();

                        QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::AdministratorCommissioning::Id, Clusters::AdministratorCommissioning::Commands::OpenCommissioningWindow), fields, true);
                        sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, shareIt->exchangeId, true, shareIt->lastPeerCounter);

                        logInfo << shareIt->device << "sent OpenCommissioningWindow";
                    }
                }
            }

            break;
        }

        case InteractionModelOpcode::SubscribeResponse:
        {
            MatterTLV::Decoder decoder(payload);
            MatterTLV::Element root = decoder.decode();
            quint32 subscriptionId = 0;
            quint16 maxInterval = 0;

            for (const MatterTLV::Element &el : root.children)
            {
                if (el.tag == 0) subscriptionId = el.value.toUInt();
                if (el.tag == 2) maxInterval = el.value.toUInt();
            }

            logInfo << "Subscription established, id:" << subscriptionId << "maxInterval:" << maxInterval;

            SessionInfo *subSession = m_sessions->findByLocalId(msgHeader.sessionId);
            if (subSession)
            {
                Device device = m_devices->byNodeId(subSession->peerNodeId);
                if (!device.isNull())
                {
                    DeviceObject *obj = reinterpret_cast <DeviceObject*> (device.data());
                    obj->setSubMaxInterval(maxInterval);
                    // priming Reports (which carry the buffered event history) arrive before SubscribeResponse —
                    // anything from now on is real-time, safe to process events normally
                    obj->setSubscriptionPrimed(true);
                }
            }
            break;
        }

        case InteractionModelOpcode::InvokeResponse:
        {
            QList <CommandResponse> responses = InteractionModel::decodeInvokeResponse(payload);

            logDebug(m_debug) << "InvokeResponse received, entries:" << responses.count() << "payload size:" << payload.size();

            for (const CommandResponse &response : responses)
            {
                logDebug(m_debug) << "InvokeResponse, cluster:" << QString::number(response.path.clusterId, 16) << "cmd:" << QString::number(response.path.commandId, 16) << "status:" << response.status;

                // check commissioning responses
                for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
                {
                    PendingCommission &commission = it.value();

                    if ((commission.state == CommissioningState::AddWiFiNetwork || commission.state == CommissioningState::AddThreadNetwork) && response.path.clusterId == Clusters::NetworkCommissioning::Id && response.path.commandId == Clusters::NetworkCommissioning::Commands::NetworkConfigResponse)
                    {
                        logInfo << "Network credentials added, connecting...";
                        commission.state = CommissioningState::ConnectNetwork;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::ConnectNetwork && response.path.clusterId == Clusters::NetworkCommissioning::Id && response.path.commandId == Clusters::NetworkCommissioning::Commands::ConnectNetworkResponse)
                    {
                        quint8 networkingStatus = 0xFF;

                        for (const MatterTLV::Element &field : response.data.children)
                        {
                            if (field.tag == 0) networkingStatus = field.value.toUInt();
                        }

                        if (networkingStatus != 0)
                        {
                            logWarning << "ConnectNetwork failed, status:" << networkingStatus;
                            break;
                        }

                        logInfo << commission.device << (commission.useThread ? "joined Thread mesh, starting CASE..." : "connected to WiFi, starting CASE...");
                        m_bleCommissioning = false;
                        m_ble->disconnectDevice();
                        m_caseNeedsCommissioningComplete = true;

                        commission.device->setThread(commission.useThread);
                        commission.device->setNetworkPort(5540);
                        m_pendingCommissionDevice = commission.device;

                        // clean up PASE session
                        m_sessions->removeSession(commission.localSessionId);
                        m_pendingCommissions.remove(it.key());

                        if (commission.pase)
                            commission.pase->deleteLater();

                        // search for device on WiFi via mDNS (_matter._tcp or _matterc._udp)
                        m_searching = true;
                        m_searchTimer->start(60000);
                        m_mdns->browse();
                        break;
                    }

                    if (commission.state == CommissioningState::ArmFailSafe && response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::ArmFailSafeResponse)
                    {
                        logDebug(m_debug) << "ArmFailSafe response, setting regulatory config...";
                        commission.state = CommissioningState::SetRegulatoryConfig;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::SetRegulatoryConfig && response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::SetRegulatoryConfigResponse)
                    {
                        logDebug(m_debug) << "SetRegulatoryConfig response, reading basic info...";
                        commission.state = CommissioningState::ReadBasicInfo;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::RequestPAI && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::CertificateChainResponse)
                    {
                        logDebug(m_debug) << "PAI certificate received, requesting DAC...";
                        commission.state = CommissioningState::RequestDAC;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::RequestDAC && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::CertificateChainResponse)
                    {
                        logDebug(m_debug) << "DAC certificate received, requesting attestation...";
                        commission.state = CommissioningState::RequestAttestation;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::RequestAttestation && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::AttestationResponse)
                    {
                        logDebug(m_debug) << "Attestation received, sending CSR request...";
                        commission.state = CommissioningState::CSRRequest;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::CSRRequest && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::CSRResponse)
                    {
                        logDebug(m_debug) << "CSRResponse received";

                        for (const MatterTLV::Element &field : response.data.children)
                        {
                            if (field.tag == 0 && field.type == MatterTLV::Type::ByteString)
                            {
                                MatterTLV::Decoder nocsrDecoder(field.value.toByteArray());
                                MatterTLV::Element nocsrRoot = nocsrDecoder.decode();

                                for (const MatterTLV::Element &el : nocsrRoot.children)
                                {
                                    if (el.tag == 1 && el.type == MatterTLV::Type::ByteString)
                                        commission.devicePublicKey = Crypto::parseCSRPublicKey(el.value.toByteArray());
                                }
                            }
                        }

                        if (commission.devicePublicKey.isEmpty())
                        {
                            logWarning << "Failed to parse device public key from CSR";
                            break;
                        }

                        logDebug(m_debug) << "Device public key extracted," << commission.devicePublicKey.length() << "bytes";

                        commission.rcacTLV = generateFabricCert(m_fabricId, 0, m_fabricPublicKey, true);
                        commission.nocTLV = generateFabricCert(m_fabricId, commission.device->nodeId(), commission.devicePublicKey, false);

                        logDebug(m_debug) << "Generated RCAC" << commission.rcacTLV.length() << "bytes, NOC" << commission.nocTLV.length() << "bytes";
        logDebug(m_debug) << "NOC hex:" << commission.nocTLV.toHex();
        logDebug(m_debug) << "RCAC hex:" << commission.rcacTLV.toHex();

                        commission.state = CommissioningState::AddTrustedRootCert;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::AddTrustedRootCert && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::AddTrustedRootCertificate)
                    {
                        if (response.status != 0)
                        {
                            logWarning << "AddTrustedRootCertificate failed, status:" << response.status;
                            break;
                        }

                        logDebug(m_debug) << "AddTrustedRootCertificate accepted, sending AddNOC...";
                        commission.state = CommissioningState::AddNOC;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::AddNOC && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::NOCResponse)
                    {
                        quint8 nocStatus = 0xFF;

                        for (const MatterTLV::Element &field : response.data.children)
                        {
                            if (field.tag == 0) nocStatus = field.value.toUInt();
                            if (field.tag == 1) commission.device->setFabricIndex(field.value.toUInt());
                        }

                        if (nocStatus != 0)
                        {
                            logWarning << "AddNOC failed, status:" << nocStatus;
                            break;
                        }

                        logInfo << "AddNOC success";

                        if (m_bleCommissioning)
                        {
                            // BLE path: ask the device which network type it supports, then push matching credentials
                            emit deviceEvent(commission.device, Event::networkSetup);
                            commission.state = CommissioningState::ReadNetworkType;
                            continueCommissioning(commission);
                        }
                        else
                        {
                            // UDP path: start CASE for CommissioningComplete
                            commission.device->setNetworkAddress(commission.address);
                            commission.device->setNetworkPort(commission.port);
                            commission.device->setThread(commission.address.protocol() == QAbstractSocket::IPv6Protocol);
                            m_caseNeedsCommissioningComplete = true;

                            QTimer::singleShot(5000, this, [this, commission]() mutable { connectDevice(commission.device); });

                            m_sessions->removeSession(commission.localSessionId);
                            m_pendingCommissions.remove(commission.localSessionId);

                            if (commission.pase)
                                commission.pase->deleteLater();
                        }

                        break;
                    }

                    if (commission.state == CommissioningState::CommissioningComplete && response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::CommissioningCompleteResponse)
                    {
                        logInfo << "Commissioning complete!";
                        commission.state = CommissioningState::Done;
                        continueCommissioning(commission);
                        break;
                    }
                }
            }

            // handle RemoveFabric response (NOCResponse cmd 0x08)
            if (m_pendingRemoveDevice)
            {
                for (const CommandResponse &response : responses)
                {
                    if (response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::NOCResponse)
                    {
                        quint8 status = 0xFF;

                        for (const MatterTLV::Element &field : response.data.children)
                        {
                            if (field.tag == 0) status = field.value.toUInt();
                        }

                        int index = -1;
                        m_devices->byName(m_pendingRemoveDevice->name(), &index);

                        emit deviceEvent(m_pendingRemoveDevice, Event::removed, {{"success", status == 0}});

                        // tear down any in-flight CASE for this device — its raw DeviceObject* would dangle once
                        // the QSharedPointer in m_devices drops to zero on removeAt, and caseFailed/Established
                        // would crash dereferencing it
                        for (auto it = m_pendingCASEs.begin(); it != m_pendingCASEs.end(); )
                        {
                            if (it.value().device == m_pendingRemoveDevice)
                            {
                                it.value().session->deleteLater();
                                it = m_pendingCASEs.erase(it);
                            }
                            else
                                it++;
                        }

                        // also drop any encrypted session (session manager keys by localSessionId/peerNodeId, not pointer)
                        SessionInfo *deadSession = m_sessions->findByPeerNodeId(m_pendingRemoveDevice->nodeId());

                        if (deadSession)
                            m_sessions->removeSession(deadSession->localSessionId);

                        if (index >= 0)
                        {
                            m_devices->removeAt(index);
                            m_devices->store(true);
                        }

                        m_pendingRemoveDevice = nullptr;
                    }
                }
            }

            // handle OpenCommissioningWindow response (device sharing)
            {
                SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

                if (session)
                {
                    auto shareIt = m_pendingShares.find(session->peerNodeId);

                    if (shareIt != m_pendingShares.end())
                    {
                        for (const CommandResponse &response : responses)
                        {
                            if (response.path.clusterId == Clusters::AdministratorCommissioning::Id)
                            {
                                if (response.status == 0)
                                {
                                    QString manualCode = generateManualCode(shareIt->passcode, shareIt->discriminator);
                                    QString qrCode = generateQRCode(shareIt->passcode, shareIt->discriminator);
                                    logInfo << shareIt->device << "sharing window opened, manual code:" << manualCode;
                                    emit deviceShared(shareIt->device, manualCode, qrCode, shareIt->timeout);
                                }
                                else
                                    logWarning << shareIt->device << "OpenCommissioningWindow failed, status:" << response.status;

                                m_pendingShares.erase(shareIt);
                                break;
                            }
                        }
                    }
                }
            }

            // handle CommissioningComplete response on CASE session (after AddNOC → CASE)
            if (m_pendingCommissionDevice)
            {
                for (const CommandResponse &response : responses)
                {
                    if (response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::CommissioningCompleteResponse)
                    {
                        logInfo << m_pendingCommissionDevice << "commissioned successfully";
                        m_devices->append(Device(m_pendingCommissionDevice));
                        connectDeviceSignals(m_pendingCommissionDevice);
                        emit deviceEvent(m_pendingCommissionDevice, Event::added);
                        discoverDevice(m_pendingCommissionDevice);
                        m_pendingCommissionDevice = nullptr;
                    }
                }
            }

            break;
        }

        default:
            logWarning << "Unknown IM opcode:" << QString::number(protoHeader.opcode, 16);
            break;
    }
}

// --- Commissioning flow ---

void Matter::startCommissioning(const MatterService &service)
{
    PASESession *pase = new PASESession(this);

    connect(pase, &PASESession::sendPBKDFParamRequest, this, &Matter::paseSendPBKDFParamRequest);
    connect(pase, &PASESession::sendPake1, this, &Matter::paseSendPake1);
    connect(pase, &PASESession::sendPake3, this, &Matter::paseSendPake3);
    connect(pase, &PASESession::established, this, &Matter::paseEstablished);
    connect(pase, &PASESession::failed, this, &Matter::paseFailed);

    quint16 sessionId = m_sessionCounter++;
    quint16 exchangeId = m_exchangeCounter++;

    PendingCommission commission;
    commission.pase = pase;
    commission.address = service.address;
    commission.port = service.port;
    commission.exchangeId = exchangeId;
    commission.localSessionId = sessionId;
    commission.passcode = m_searchPasscode;
    commission.assignedNodeId = m_searchNodeId;
    commission.service = service;
    commission.state = CommissioningState::PASE;

    m_pendingCommissions.insert(sessionId, commission);

    logInfo << "Starting commissioning with" << service.address.toString() << ":" << service.port;
    emit deviceEvent(nullptr, Event::deviceConnecting, {{"nodeId", QString::number(m_searchNodeId, 16)}});
    pase->start(commission.passcode, sessionId);
}

void Matter::sendCommissioningMessage(SessionInfo *session, quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId)
{
    if (m_bleCommissioning)
        sendEncryptedBle(session, opcode, protocolId, payload, exchangeId, true);
    else
        sendEncrypted(session, opcode, protocolId, payload, exchangeId, true);
}

void Matter::continueCommissioning(PendingCommission &commission)
{
    SessionInfo *session = m_sessions->findByLocalId(commission.localSessionId);

    if (!session)
    {
        logWarning << "No session for commissioning";
        return;
    }

    switch (commission.state)
    {
        case CommissioningState::ReadNetworkType:
        {
            logInfo << "Reading NetworkCommissioning FeatureMap...";

            QList <AttributePath> paths = {AttributePath(0, Clusters::NetworkCommissioning::Id, Clusters::NetworkCommissioning::Attributes::FeatureMap)};
            QByteArray payload = InteractionModel::encodeReadRequest(paths);
            sendEncryptedBle(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::AddWiFiNetwork:
        {
            logInfo << "Sending AddOrUpdateWiFiNetwork...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, m_wifiSSID.toUtf8());
            fields.encodeByteString(1, m_wifiPassword.toUtf8());
            fields.encodeUnsignedInt(2, 1); // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::NetworkCommissioning::Id, Clusters::NetworkCommissioning::Commands::AddOrUpdateWiFiNetwork), fields);
            sendEncryptedBle(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::AddThreadNetwork:
        {
            logInfo << "Sending AddOrUpdateThreadNetwork...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, m_threadDataset);
            fields.encodeUnsignedInt(1, 1); // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::NetworkCommissioning::Id, Clusters::NetworkCommissioning::Commands::AddOrUpdateThreadNetwork), fields);
            sendEncryptedBle(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::ConnectNetwork:
        {
            logInfo << "Sending ConnectNetwork...";

            QByteArray networkId = commission.useThread ? m_threadExtPanId : m_wifiSSID.toUtf8();

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, networkId);
            fields.encodeUnsignedInt(1, 1); // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::NetworkCommissioning::Id, Clusters::NetworkCommissioning::Commands::ConnectNetwork), fields);
            sendEncryptedBle(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::ArmFailSafe:
        {
            logDebug(m_debug) << "Sending ArmFailSafe...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 900);  // expiryLengthSeconds
            fields.encodeUnsignedInt(1, 1);    // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::ArmFailSafe), fields);
            sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++);
            break;
        }

        case CommissioningState::SetRegulatoryConfig:
        {
            logDebug(m_debug) << "Sending SetRegulatoryConfig...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 0);                  // newRegulatoryConfig: Indoor (0)
            fields.encodeUTF8String(1, QString("XX"));       // countryCode
            fields.encodeUnsignedInt(2, 0);                  // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::SetRegulatoryConfig), fields);
            sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++);
            break;
        }

        case CommissioningState::ReadBasicInfo:
        {
            logDebug(m_debug) << "Reading BasicInformation cluster...";

            QList <AttributePath> paths;
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::VendorName));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::VendorID));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::ProductName));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::ProductID));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::SoftwareVersionString));

            QByteArray payload = InteractionModel::encodeReadRequest(paths);
            sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++);
            break;
        }

        case CommissioningState::RequestPAI:
        {
            logDebug(m_debug) << "Requesting PAI certificate...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 1);  // CertificateType = PAI
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CertificateChainRequest), fields);
            sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++);
            break;
        }

        case CommissioningState::RequestDAC:
        {
            logDebug(m_debug) << "Requesting DAC certificate...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 2);  // CertificateType = DAC
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CertificateChainRequest), fields);
            sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++);
            break;
        }

        case CommissioningState::RequestAttestation:
        {
            logDebug(m_debug) << "Requesting attestation...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, Crypto::randomBytes(32));  // AttestationNonce
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AttestationRequest), fields);
            sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++);
            break;
        }

        case CommissioningState::CSRRequest:
        {
            logDebug(m_debug) << "Sending CSRRequest...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, Crypto::randomBytes(32)); // CSRNonce
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CSRRequest), fields);
            sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++);
            break;
        }

        case CommissioningState::AddTrustedRootCert:
        {
            logDebug(m_debug) << "Sending AddTrustedRootCertificate...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, commission.rcacTLV);
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AddTrustedRootCertificate), fields);
            sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++);
            break;
        }

        case CommissioningState::AddNOC:
        {
            logDebug(m_debug) << "Sending AddNOC...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, commission.nocTLV);   // NOCValue
            // tag 1: ICACValue (skip, no intermediate CA)
            fields.encodeByteString(2, m_ipk);               // IPKValue (16 bytes)
            fields.encodeUnsignedInt(3, m_nodeId);            // CaseAdminSubject
            fields.encodeUnsignedInt(4, 0xFFF1);              // AdminVendorId (test)
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AddNOC), fields);
            sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++);
            break;
        }

        case CommissioningState::CommissioningComplete:
        {
            if (!commission.timedInvokePending)
            {
                logDebug(m_debug) << "Sending TimedRequest for CommissioningComplete...";
                commission.exchangeId = m_exchangeCounter++;
                QByteArray payload = InteractionModel::encodeTimedRequest(5000);
                sendCommissioningMessage(session, static_cast <quint8> (InteractionModelOpcode::TimedRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, commission.exchangeId);
                commission.timedInvokePending = true;
                break;
            }

            commission.timedInvokePending = false;
            logDebug(m_debug) << "Sending CommissioningComplete...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::CommissioningComplete), fields, true);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, commission.exchangeId, true, commission.lastPeerCounter);
            break;
        }

        case CommissioningState::Done:
        {
            logInfo << commission.device << "commissioned successfully";
            logDebug(m_debug) << "CommissioningComplete success, starting CASE...";
            session->peerNodeId = commission.device->nodeId();
            session->active = false;
            m_devices->append(Device(commission.device));
            connectDeviceSignals(commission.device);
            emit deviceEvent(commission.device, Event::added);

            connectDevice(commission.device);

            m_pendingCommissions.remove(commission.localSessionId);

            if (commission.pase)
                commission.pase->deleteLater();

            break;
        }

        default:
            break;
    }
}

// --- Certificate generation ---

QByteArray Matter::generateFabricCert(quint64 fabricId, quint64 nodeId, const QByteArray &subjectPubKey, bool isRCAC)
{
    QByteArray derCert = Crypto::generateX509Cert(m_rootCAId, fabricId, nodeId, subjectPubKey, m_fabricKey, m_fabricPublicKey, isRCAC);

    if (derCert.isEmpty())
    {
        logWarning << "Failed to generate X.509 certificate";
        return QByteArray();
    }

    QByteArray tlvCert = Crypto::x509DerToMatterTLV(derCert);
    logDebug(m_debug) << "Generated" << (isRCAC ? "RCAC" : "NOC") << derCert.length() << "DER bytes," << tlvCert.length() << "TLV bytes";

    if (!isRCAC)
        logDebug(m_debug) << "NOC DER hex:" << derCert.toHex();
    return tlvCert;
}

// --- Standalone ACK ---

void Matter::sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port, bool initiator)
{
    SessionInfo *session = m_sessions->findByLocalId(sessionId);

    if (session && session->active)
    {
        session->localMessageCounter++;

        MessageHeader msgHeader;
        msgHeader.flags = 0x00;
        msgHeader.securityFlags = 0x00;
        msgHeader.sessionId = session->peerSessionId;
        msgHeader.messageCounter = session->localMessageCounter;

        QByteArray header = MessageCodec::encodeHeader(msgHeader);

        ProtocolHeader protoHeader;
        protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Acknowledgement);

        if (initiator)
            protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);
        protoHeader.opcode = static_cast <quint8> (SecureChannelOpcode::MRPStandaloneAck);
        protoHeader.exchangeId = exchangeId;
        protoHeader.protocolId = static_cast <quint16> (ProtocolId::SecureChannel);
        protoHeader.ackCounter = ackCounter;

        QByteArray plaintext = MessageCodec::encodeProtocolHeader(protoHeader);
        QByteArray nonce = SessionManager::buildNonce(msgHeader.securityFlags, msgHeader.messageCounter, session->active ? m_nodeId : 0);
        QByteArray encrypted = Crypto::aesCcmEncrypt(session->i2rKey, nonce, header, plaintext, SESSION_TAG_LENGTH);

        QByteArray data = header;
        data.append(encrypted);
        sendRawDatagram(data, session->peerAddress, session->peerPort);
    }
    else
    {
        MessageHeader msgHeader;
        msgHeader.flags = 0x00;
        msgHeader.securityFlags = 0x00;
        msgHeader.sessionId = sessionId;
        msgHeader.messageCounter = ++m_messageCounter;

        ProtocolHeader protoHeader;
        protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Acknowledgement);

        if (initiator)
            protoHeader.exchangeFlags |= static_cast <quint8> (ExchangeFlag::Initiator);

        protoHeader.opcode = static_cast <quint8> (SecureChannelOpcode::MRPStandaloneAck);
        protoHeader.exchangeId = exchangeId;
        protoHeader.protocolId = static_cast <quint16> (ProtocolId::SecureChannel);
        protoHeader.ackCounter = ackCounter;

        QByteArray data = MessageCodec::encodeMessage(msgHeader, protoHeader, QByteArray());
        sendRawDatagram(data, address, port);
    }
}

// --- UDP read ---

void Matter::readyRead(void)
{
    while (m_udp->hasPendingDatagrams())
    {
        QByteArray datagram;
        QHostAddress sender;
        quint16 senderPort;

        datagram.resize(m_udp->pendingDatagramSize());
        m_udp->readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);

        // normalize IPv4-mapped IPv6 to plain IPv4
        bool ok;
        quint32 ipv4 = sender.toIPv4Address(&ok);

        if (ok)
            sender = QHostAddress(ipv4);

        MessageHeader msgHeader;
        ProtocolHeader protoHeader;
        quint32 headerOffset, payloadOffset;

        if (!MessageCodec::decodeHeader(datagram, msgHeader, headerOffset))
        {
            logDebug(m_debug) << "Invalid message header from" << sender.toString() << "size:" << datagram.size() << "hex:" << datagram.left(16).toHex();
            continue;
        }

        if (m_mrp->isDuplicate(sender, msgHeader.messageCounter))
            continue;

        QByteArray payload;

        if (msgHeader.sessionId != 0)
        {
            // encrypted session
            SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

            if (!session)
                continue;

            QByteArray header = datagram.left(headerOffset);
            QByteArray ciphertext = datagram.mid(headerOffset);

            payload = m_sessions->decrypt(session, msgHeader.securityFlags, msgHeader.messageCounter, session->peerNodeId, header, ciphertext);

            if (payload.isEmpty())
            {
                logDebug(m_debug) << "Decryption failed for session" << msgHeader.sessionId << "counter:" << msgHeader.messageCounter << "from" << sender.toString() << "size:" << ciphertext.size();
                continue;
            }

            logDebug(m_debug) << "Decrypted message from session" << msgHeader.sessionId << "counter:" << msgHeader.messageCounter << "size:" << payload.size();

            // device sent something — refresh lastSeen and bring online if not already (covers both Offline → Online and
            // Unknown → Online for sessions restored from disk that hadn't seen any traffic yet)
            Device backDevice = m_devices->byNodeId(session->peerNodeId);
            if (!backDevice.isNull())
            {
                DeviceObject *bd = reinterpret_cast <DeviceObject*> (backDevice.data());
                bd->updateLastSeen();
                if (bd->availability() != Availability::Online)
                {
                    bd->setAvailability(Availability::Online);
                    resetReconnectBackoff(bd);
                    emit updateAvailability(bd);
                }
            }
        }
        else
        {
            payload = datagram.mid(headerOffset);
        }

        if (!MessageCodec::decodeProtocolHeader(payload, 0, protoHeader, payloadOffset))
        {
            logDebug(m_debug) << "Invalid protocol header from" << sender.toString();
            continue;
        }

        m_mrp->messageReceived(msgHeader.messageCounter, protoHeader.exchangeId, protoHeader.hasAck(), protoHeader.ackCounter, sender, senderPort, msgHeader.sessionId, protoHeader.needsAck(), protoHeader.isInitiator());

        QByteArray messagePayload = payload.mid(payloadOffset);

        switch (static_cast <ProtocolId> (protoHeader.protocolId))
        {
            case ProtocolId::SecureChannel:
                handleSecureChannel(msgHeader, protoHeader, messagePayload, sender, senderPort);
                break;

            case ProtocolId::InteractionModel:
                handleInteractionModel(msgHeader, protoHeader, messagePayload, sender, senderPort);
                break;

            default:
                logWarning << "Unknown protocol:" << QString::number(protoHeader.protocolId, 16);
                break;
        }
    }
}

// --- Timer callbacks ---

void Matter::searchTimeout(void)
{
    m_searching = false;
    m_ble->stopScan();
    m_mdns->stop();
    logWarning << "Device search timeout, device not found";
    emit deviceEvent(nullptr, Event::deviceNotFound, {{"nodeId", QString::number(m_searchNodeId, 16)}});
}

// --- BLE signal handlers ---

void Matter::bleDeviceFound(const BLEDevice &device)
{
    if (!m_searching)
        return;

    bool match = m_searchShortDiscriminator ? (device.discriminator >> 8) == m_searchDiscriminator : device.discriminator == m_searchDiscriminator;

    if (!match)
        return;

    logInfo << "BLE device matched, connecting:" << device.address;
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
    logInfo << "BLE data received:" << data.size() << "bytes:" << data.toHex();
    m_btp->handleData(data);
}

void Matter::btpHandshakeComplete(void)
{
    logInfo << "BTP handshake complete, starting PASE over BLE...";
    emit deviceEvent(nullptr, Event::deviceConnecting, {{"nodeId", QString::number(m_searchNodeId, 16)}});
    m_bleCommissioning = true;

    PASESession *pase = new PASESession(this);
    quint16 localSessionId = m_sessionCounter++;

    connect(pase, &PASESession::sendPBKDFParamRequest, this, &Matter::paseSendPBKDFParamRequest);
    connect(pase, &PASESession::sendPake1, this, &Matter::paseSendPake1);
    connect(pase, &PASESession::sendPake3, this, &Matter::paseSendPake3);
    connect(pase, &PASESession::established, this, &Matter::paseEstablished);
    connect(pase, &PASESession::failed, this, &Matter::paseFailed);

    PendingCommission commission;
    commission.pase = pase;
    commission.localSessionId = localSessionId;
    commission.exchangeId = m_exchangeCounter++;
    commission.passcode = m_searchPasscode;
    commission.assignedNodeId = m_searchNodeId;
    commission.state = CommissioningState::PASE;

    m_pendingCommissions.insert(localSessionId, commission);
    pase->start(m_searchPasscode, localSessionId);
}

void Matter::btpMessageReceived(const QByteArray &message)
{
    if (!m_bleCommissioning)
        return;

    MatterProtocol::MessageHeader msgHeader;
    MatterProtocol::ProtocolHeader protoHeader;
    quint32 headerOffset, payloadOffset;

    if (!MatterProtocol::MessageCodec::decodeHeader(message, msgHeader, headerOffset))
    {
        logWarning << "BLE: failed to decode message header";
        return;
    }

    QByteArray payload = message.mid(headerOffset);

    if (!MatterProtocol::MessageCodec::decodeProtocolHeader(payload, 0, protoHeader, payloadOffset))
    {
        logWarning << "BLE: failed to decode protocol header";
        return;
    }

    // encrypted BLE message — decrypt first
    if (msgHeader.sessionId != 0)
    {
        SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

        if (!session)
            return;

        QByteArray header = message.left(headerOffset);
        QByteArray ciphertext = message.mid(headerOffset);
        QByteArray decrypted = m_sessions->decrypt(session, msgHeader.securityFlags, msgHeader.messageCounter, session->peerNodeId, header, ciphertext);

        if (decrypted.isEmpty())
        {
            logWarning << "BLE: decryption failed";
            return;
        }

        if (!MatterProtocol::MessageCodec::decodeProtocolHeader(decrypted, 0, protoHeader, payloadOffset))
            return;

        payload = decrypted.mid(payloadOffset);
    }
    else
    {
        payload = payload.mid(payloadOffset);
    }

    logInfo << "BLE message: protocol:" << QString::number(protoHeader.protocolId, 16) << "opcode:" << QString::number(protoHeader.opcode, 16) << "exchange:" << protoHeader.exchangeId << "payload:" << payload.size() << "bytes";

    if (protoHeader.protocolId == static_cast <quint16> (MatterProtocol::ProtocolId::SecureChannel))
        handleSecureChannel(msgHeader, protoHeader, payload, QHostAddress(), 0);
    else if (protoHeader.protocolId == static_cast <quint16> (MatterProtocol::ProtocolId::InteractionModel))
        handleInteractionModel(msgHeader, protoHeader, payload, QHostAddress(), 0);
}

void Matter::btpWriteData(const QByteArray &data)
{
    m_ble->write(data);
}

void Matter::resetReconnectBackoff(DeviceObject *device)
{
    if (!device)
        return;

    device->setNextReconnectAt(0);
}

void Matter::scheduleReconnect(void)
{
    if (!m_devices)
        return;

    qint64 now = QDateTime::currentMSecsSinceEpoch();
    qint64 nearest = -1;

    for (int i = 0; i < m_devices->count(); i++)
    {
        DeviceObject *device = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

        if (device->availability() == Availability::Online || device->networkAddress().isNull())
            continue;

        // already have a session (e.g. restored from disk) — no CASE needed, MRP will signal if it's actually dead
        if (m_sessions->findByPeerNodeId(device->nodeId()))
            continue;

        // skip devices with an in-flight CASE — they'll come back via caseEstablished/Failed
        bool inProgress = false;

        for (auto it = m_pendingCASEs.begin(); it != m_pendingCASEs.end(); it++)
        {
            if (it.value().device == device)
            {
                inProgress = true;
                break;
            }
        }

        if (inProgress)
            continue;

        qint64 ts = device->nextReconnectAt();

        if (ts == 0)
            ts = now;

        if (nearest == -1 || ts < nearest)
            nearest = ts;
    }

    if (nearest == -1)
    {
        logDebug(m_debug) << "scheduleReconnect: no eligible offline devices";
        return;
    }

    qint64 delay = qMax <qint64> (0, nearest - now);
    logDebug(m_debug) << "scheduleReconnect: timer set for" << delay << "ms";
    m_reconnectTimer->start(static_cast <int> (delay));
}

void Matter::reconnectTimeout(void)
{
    if (!m_devices)
        return;

    qint64 now = QDateTime::currentMSecsSinceEpoch();
    bool hasOffline = false;
    logDebug(m_debug) << "reconnectTimeout fired";

    for (int i = 0; i < m_devices->count(); i++)
    {
        DeviceObject *device = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

        if (device->availability() == Availability::Online || device->networkAddress().isNull())
            continue;

        // already have a session (just restored from disk and waiting for first ack) — don't trigger CASE; we'll only
        // know it's dead once an MRP retransmit fails, and that path explicitly schedules a reconnect
        if (m_sessions->findByPeerNodeId(device->nodeId()))
            continue;

        // skip devices that already have a CASE handshake in flight — caseEstablished/caseFailed will trigger the next attempt
        bool inProgress = false;

        for (auto it = m_pendingCASEs.begin(); it != m_pendingCASEs.end(); it++)
        {
            if (it.value().device == device)
            {
                inProgress = true;
                break;
            }
        }

        if (inProgress)
            continue;

        hasOffline = true;

        if (device->nextReconnectAt() <= now)
            connectDevice(device);
    }

    if (hasOffline)
        scheduleReconnect();
}

void Matter::pingTimeout(void)
{
    if (!m_devices)
        return;

    qint64 now = QDateTime::currentSecsSinceEpoch();

    for (int i = 0; i < m_devices->count(); i++)
    {
        DeviceObject *device = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

        if (device->availability() != Availability::Online)
            continue;

        SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

        if (!session)
        {
            handleDeviceUnreachable(device);
            continue;
        }

        // mirror current counter to device so the next store() persists a fresh value;
        // on restart we restore counter+10000 margin to stay strictly monotonic across restarts
        device->setSessionLocalCounter(session->localMessageCounter);

        if (!device->lastSeen())
            continue;

        // battery-powered devices: trust subscription as keepalive, don't ping (saves battery),
        // but mark offline if no reports within maxInterval+30s window
        if (device->batteryPowered())
        {
            quint16 maxInt = device->subMaxInterval();

            if (maxInt && now - device->lastSeen() > maxInt + 30)
            {
                logWarning << device << "no subscription reports for" << maxInt << "+30s, marking offline";
                device->setAvailability(Availability::Offline);
                emit updateAvailability(device);
            }
            continue;
        }

        // mains-powered: legacy 60s read-as-ping refreshes lastSeen and detects dead sessions
        if (now - device->lastSeen() > 60)
        {
            QList <AttributePath> paths = {AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::DataModelRevision)};
            QByteArray payload = InteractionModel::encodeReadRequest(paths);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
        }
    }
}

void Matter::mrpRetransmit(const QByteArray &data, const QHostAddress &address, quint16 port)
{
    sendRawDatagram(data, address, port);
}

void Matter::handleDeviceUnreachable(DeviceObject *device)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (session)
        m_sessions->removeSession(session->localSessionId);

    if (device->availability() == Availability::Online)
    {
        logWarning << device << "is unreachable, marking offline";
        device->setAvailability(Availability::Offline);
        emit updateAvailability(device);
    }

    // first failure since last success — nextReconnectAt is 0, go straight to CASE (covers restored-session-dead
    // case, where we'd otherwise wait 10-15s for nothing). Anything else means we already had a retry scheduled
    // or in flight; keep the 10-15s spacing so we don't spam a stuck/asleep peer
    qint64 now = QDateTime::currentMSecsSinceEpoch();

    if (device->nextReconnectAt() == 0)
        device->setNextReconnectAt(now);
    else if (device->nextReconnectAt() < now)
        device->setNextReconnectAt(now + 10000 + QRandomGenerator::global()->bounded(5000));

    scheduleReconnect();
}

void Matter::mrpRetransmitFailed(quint32 messageCounter, quint16 exchangeId, const QHostAddress &address, quint16 port)
{
    logWarning << "Message delivery failed, counter:" << messageCounter << "exchange:" << exchangeId;

    // check if this is a pending CASE handshake failure — match by exchangeId so the right CASESession gets the failure
    if (m_pendingCASEs.contains(exchangeId))
    {
        PendingCASE pending = m_pendingCASEs.take(exchangeId);
        DeviceObject *failedDevice = pending.device;
        pending.session->deleteLater();

        qint64 jitterMs = QRandomGenerator::global()->bounded(5000);
        failedDevice->setNextReconnectAt(QDateTime::currentMSecsSinceEpoch() + 10000 + jitterMs);
        logDebug(m_debug) << failedDevice << "MRP retransmit failed during CASE, retry in 10-15s";
        scheduleReconnect();
        return;
    }

    SessionInfo *session = m_sessions->findByPeerAddress(address, port);

    if (!session || !m_devices)
        return;

    quint64 nodeId = session->peerNodeId;

    for (int i = 0; i < m_devices->count(); i++)
    {
        DeviceObject *device = reinterpret_cast <DeviceObject*> (m_devices->at(i).data());

        if (device->nodeId() == nodeId)
        {
            handleDeviceUnreachable(device);
            break;
        }
    }
}

void Matter::mrpSendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port, bool initiator)
{
    sendStandaloneAck(ackCounter, exchangeId, sessionId, address, port, initiator);
}

void Matter::mdnsServiceFound(const MatterService &service)
{
    if (!m_searching)
        return;

    // operational service — device found after BLE commissioning + WiFi connect
    if (service.operational)
    {
        if (!m_caseNeedsCommissioningComplete || !m_pendingCommissionDevice)
            return;

        // instance name format: <compressed-fabric-id>-<node-id>._matter._tcp.local
        // verify node ID matches the device we just commissioned
        QString instanceName = service.instanceName.split('.').first();
        int dash = instanceName.indexOf('-');

        if (dash > 0)
        {
            bool ok;
            quint64 nodeId = instanceName.mid(dash + 1).toULongLong(&ok, 16);

            if (!ok || nodeId != m_pendingCommissionDevice->nodeId())
                return;
        }

        logInfo << "Operational device found:" << service.instanceName << "at" << service.address.toString() << ":" << service.port;

        m_searching = false;
        m_searchTimer->stop();
        m_mdns->stop();
        m_ble->stopScan();

        m_pendingCommissionDevice->setNetworkAddress(service.address);
        m_pendingCommissionDevice->setNetworkPort(service.port);
        connectDevice(m_pendingCommissionDevice);
        return;
    }

    // after BLE commissioning, only accept operational services
    if (m_caseNeedsCommissioningComplete)
        return;

    // commissionable service — match discriminator
    if (m_searchShortDiscriminator)
    {
        if ((service.discriminator >> 8) != m_searchDiscriminator)
            return;
    }
    else
    {
        if (service.discriminator != m_searchDiscriminator)
            return;
    }

    // check if already commissioning this device
    for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
    {
        if (it.value().address == service.address && it.value().port == service.port)
            return;
    }

    logInfo << "Commissionable device found:" << service.deviceName << "discriminator:" << service.discriminator << "at" << service.address.toString() << ":" << service.port;
    emit deviceEvent(nullptr, Event::deviceFound, {{"nodeId", QString::number(m_searchNodeId, 16)}});

    m_searching = false;
    m_searchTimer->stop();
    m_mdns->stop();
    m_ble->stopScan();

    // check if we already have a PASE session from BLE provisioning
    for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
    {
        if (it.value().state == CommissioningState::ArmFailSafe)
        {
            logInfo << "Continuing commissioning over UDP at" << service.address.toString() << ":" << service.port;

            SessionInfo *session = m_sessions->findByLocalId(it.key());

            if (session)
            {
                session->peerAddress = service.address;
                session->peerPort = service.port;
            }

            it.value().address = service.address;
            it.value().port = service.port;
            it.value().device->setNetworkAddress(service.address);
            it.value().device->setNetworkPort(service.port);
            it.value().service = service;

            continueCommissioning(it.value());
            return;
        }
    }

    startCommissioning(service);
}

// --- PASE signal handlers ---

void Matter::sendBleMessage(quint8 opcode, quint16 protocolId, const QByteArray &payload, quint16 exchangeId, bool initiator)
{
    MatterProtocol::MessageHeader msgHeader;
    msgHeader.flags = 0x04; // source node ID present (required for BLE)
    msgHeader.securityFlags = 0x00;
    msgHeader.sessionId = 0;
    msgHeader.messageCounter = ++m_messageCounter;
    msgHeader.sourceNodeId = m_nodeId;

    MatterProtocol::ProtocolHeader protoHeader;
    protoHeader.exchangeFlags = 0;

    if (initiator)
        protoHeader.exchangeFlags |= static_cast <quint8> (MatterProtocol::ExchangeFlag::Initiator);

    // no MRP ACK/Reliability flags over BLE — BTP handles reliability

    protoHeader.opcode = opcode;
    protoHeader.exchangeId = exchangeId;
    protoHeader.protocolId = protocolId;

    QByteArray message = MatterProtocol::MessageCodec::encodeMessage(msgHeader, protoHeader, payload);
    m_btp->sendMessage(message);
}

void Matter::paseSendPBKDFParamRequest(const QByteArray &payload, quint16 localSessionId)
{
    if (!m_pendingCommissions.contains(localSessionId))
        return;

    const PendingCommission &commission = m_pendingCommissions.value(localSessionId);

    if (m_bleCommissioning)
        sendBleMessage(static_cast <quint8> (SecureChannelOpcode::PBKDFParamRequest), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, true);
    else
        sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::PBKDFParamRequest), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, commission.address, commission.port, true);
}

void Matter::paseSendPake1(const QByteArray &payload)
{
    PASESession *pase = qobject_cast <PASESession*> (sender());

    if (!pase)
        return;

    quint16 sessionId = pase->localSessionId();

    if (!m_pendingCommissions.contains(sessionId))
        return;

    const PendingCommission &commission = m_pendingCommissions.value(sessionId);

    if (m_bleCommissioning)
        sendBleMessage(static_cast <quint8> (SecureChannelOpcode::PASEPake1), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, true);
    else
        sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::PASEPake1), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, commission.address, commission.port, true, pase->lastPeerMessageCounter());
}

void Matter::paseSendPake3(const QByteArray &payload)
{
    PASESession *pase = qobject_cast <PASESession*> (sender());

    if (!pase)
        return;

    quint16 sessionId = pase->localSessionId();

    if (!m_pendingCommissions.contains(sessionId))
        return;

    const PendingCommission &commission = m_pendingCommissions.value(sessionId);

    if (m_bleCommissioning)
        sendBleMessage(static_cast <quint8> (SecureChannelOpcode::PASEPake3), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, true);
    else
        sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::PASEPake3), static_cast <quint16> (ProtocolId::SecureChannel), payload, commission.exchangeId, commission.address, commission.port, true, pase->lastPeerMessageCounter());
}

void Matter::paseEstablished(quint16 localSessionId, quint16 peerSessionId)
{
    if (!m_pendingCommissions.contains(localSessionId))
        return;

    PendingCommission &commission = m_pendingCommissions[localSessionId];

    // register encrypted session
    SessionInfo session;
    session.localSessionId = localSessionId;
    session.peerSessionId = peerSessionId;
    session.i2rKey = commission.pase->encryptKey();
    session.r2iKey = commission.pase->decryptKey();
    session.attestationChallenge = commission.pase->attestationChallenge();
    session.peerAddress = commission.address;
    session.peerPort = commission.port;
    session.peerNodeId = 0; // unknown until commissioning
    session.localMessageCounter = 0;
    session.active = false; // not yet operational

    m_sessions->addSession(session);

    // create device object
    quint64 nodeId = commission.assignedNodeId;
    commission.device = new DeviceObject(nodeId, QString("matter_%1").arg(nodeId, 0, 16));
    commission.device->setVendorId(commission.service.vendorId);
    commission.device->setProductId(commission.service.productId);
    commission.device->setNetworkAddress(commission.address);
    commission.device->setNetworkPort(commission.port);

    // both BLE and UDP: start with ArmFailSafe
    commission.state = CommissioningState::ArmFailSafe;
    continueCommissioning(commission);
}

void Matter::paseFailed(const QString &reason)
{
    PASESession *pase = qobject_cast <PASESession*> (sender());

    if (!pase)
        return;

    quint16 sessionId = pase->localSessionId();
    quint64 nodeId = m_pendingCommissions.value(sessionId).assignedNodeId;

    logWarning << "PASE failed:" << reason;
    emit deviceEvent(nullptr, Event::connectFailed, {{"nodeId", QString::number(nodeId, 16)}});

    if (m_bleCommissioning)
    {
        m_bleCommissioning = false;
        m_ble->disconnectDevice();
    }

    m_pendingCommissions.remove(sessionId);
    pase->deleteLater();
}

// --- CASE signal handlers ---

Matter::PendingCASE *Matter::findPendingCASE(CASESession *session)
{
    if (!session)
        return nullptr;

    for (auto it = m_pendingCASEs.begin(); it != m_pendingCASEs.end(); it++)
    {
        if (it.value().session == session)
            return &it.value();
    }

    return nullptr;
}

void Matter::caseSendSigma1(const QByteArray &payload, quint16 localSessionId)
{
    Q_UNUSED(localSessionId)

    CASESession *session = qobject_cast <CASESession*> (sender());
    PendingCASE *pending = findPendingCASE(session);

    if (!pending)
        return;

    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::CASESigma1), static_cast <quint16> (ProtocolId::SecureChannel), payload, pending->exchangeId, pending->address, pending->port, true);
}

void Matter::caseSendSigma3(const QByteArray &payload)
{
    CASESession *session = qobject_cast <CASESession*> (sender());
    PendingCASE *pending = findPendingCASE(session);

    if (!pending)
        return;

    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::CASESigma3), static_cast <quint16> (ProtocolId::SecureChannel), payload, pending->exchangeId, pending->address, pending->port, true, session->lastPeerMessageCounter());
}

void Matter::caseEstablished(quint16 localSessionId, quint16 peerSessionId)
{
    CASESession *caseSes = qobject_cast <CASESession*> (sender());
    PendingCASE *pending = findPendingCASE(caseSes);

    if (!pending)
        return;

    DeviceObject *device = pending->device;
    bool needsCC = pending->needsCommissioningComplete;
    quint16 exchangeId = pending->exchangeId;

    // CASE resumption: ack Sigma2_Resume with SecureChannel StatusReport(success), per CHIP HandleSigma2Resume.
    // Without this the responder never finalizes the resumed session and our first encrypted message goes unanswered.
    if (caseSes->resumed())
    {
        QByteArray status(8, 0);
        sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::StatusReport), static_cast <quint16> (ProtocolId::SecureChannel), status, exchangeId, pending->address, pending->port, true, caseSes->lastPeerMessageCounter());
    }

    // register encrypted session
    SessionInfo session;
    session.localSessionId = localSessionId;
    session.peerSessionId = peerSessionId;
    session.i2rKey = caseSes->encryptKey();
    session.r2iKey = caseSes->decryptKey();
    session.attestationChallenge = caseSes->attestationChallenge();
    session.peerNodeId = device->nodeId();
    session.localMessageCounter = 0;
    session.active = true;

    session.peerAddress = device->networkAddress();
    session.peerPort = device->networkPort();
    device->updateLastSeen();

    session.idleInterval = caseSes->idleInterval();
    session.activeInterval = caseSes->activeInterval();
    session.activeThreshold = caseSes->activeThreshold();

    // remove old (dead) session
    SessionInfo *existing = m_sessions->findByPeerNodeId(device->nodeId());

    if (existing)
        m_sessions->removeSession(existing->localSessionId);

    m_sessions->addSession(session);

    logInfo << device << "CASE session established";

    // discover device endpoints (skip during initial commissioning — discover after CommissioningComplete)
    if (device->endpoints().isEmpty() && !needsCC)
        discoverDevice(device);

    // send CommissioningComplete on CASE session only during initial commissioning
    SessionInfo *caseSession = m_sessions->findByLocalId(localSessionId);

    if (caseSession && needsCC)
    {
        m_pendingCommissionDevice = device;
        logDebug(m_debug) << "Sending CommissioningComplete on CASE session...";

        MatterTLV::Encoder fields;
        fields.openStructure();
        fields.closeContainer();

        QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::CommissioningComplete), fields);
        sendEncrypted(caseSession, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
    }

    // persist new resumption data so the next CASE can skip the full Sigma1/2/3 handshake (Matter §4.13.3)
    QByteArray newResumptionID = caseSes->newResumptionID();

    if (!newResumptionID.isEmpty())
    {
        device->setResumptionID(newResumptionID);
        device->setResumptionSharedSecret(caseSes->sharedSecret());
        logInfo << device << (caseSes->resumed() ? "session resumed" : "full handshake") << ", saving new resumptionID:" << newResumptionID.toHex();
    }

    // persist the secure session for battery-powered devices so a service restart can decrypt with the
    // existing keys instead of forcing a fresh CASE handshake (which wakes the radio and burns ~tens of
    // seconds on slow MRP intervals). mains devices skip persistence — CASE-with-resumption is already
    // sub-second so storing keys to disk has no upside. the battery flag may still be false here on the
    // very first caseEstablished after commissioning (PowerSource detection happens later in discovery);
    // discovery's finalize step late-populates session fields once the flag flips to true.
    if (device->batteryPowered())
    {
        device->setSessionLocalId(localSessionId);
        device->setSessionPeerId(peerSessionId);
        device->setSessionI2RKey(caseSes->encryptKey());
        device->setSessionR2IKey(caseSes->decryptKey());
        device->setSessionAttestation(caseSes->attestationChallenge());
        device->setSessionLocalCounter(0);
        device->setSessionIdleInterval(caseSes->idleInterval());
        device->setSessionActiveInterval(caseSes->activeInterval());
        device->setSessionActiveThreshold(caseSes->activeThreshold());
    }

    m_devices->store(true);

    device->setAvailability(Availability::Online);
    resetReconnectBackoff(device);
    emit updateAvailability(device);

    // subscribe to attributes for known devices (cold start or CASE reconnect)
    if (!device->endpoints().isEmpty())
        subscribeDevice(device, m_sessions->findByLocalId(localSessionId));

    caseSes->deleteLater();
    m_pendingCASEs.remove(exchangeId);
}

void Matter::caseFailed(const QString &reason)
{
    logWarning << "CASE failed:" << reason;

    CASESession *caseSes = qobject_cast <CASESession*> (sender());
    DeviceObject *failedDevice = nullptr;
    quint16 exchangeId = 0;

    if (caseSes)
    {
        PendingCASE *pending = findPendingCASE(caseSes);

        if (pending)
        {
            failedDevice = pending->device;
            exchangeId = pending->exchangeId;
        }
    }

    if (caseSes)
        caseSes->deleteLater();

    if (exchangeId)
        m_pendingCASEs.remove(exchangeId);

    // only Sigma2_Resume MIC failure proves our resumption secret is no longer valid; everything else (Busy, timeout,
    // MRP failure) is transient — peer is still cleaning up the previous session, dropping resumption just forces a
    // slower full handshake on the next attempt without making the current one succeed
    if (failedDevice && !failedDevice->resumptionID().isEmpty() && reason.startsWith("Sigma2_Resume MIC"))
    {
        logInfo << failedDevice << "clearing resumption data after MIC verification failure - next attempt will be full handshake";
        failedDevice->setResumptionID(QByteArray());
        failedDevice->setResumptionSharedSecret(QByteArray());
        m_devices->store(true);
    }

    if (failedDevice)
    {
        // simple retry policy: 10-15s for every CASE failure regardless of cause — small, predictable, recovers from sleeps fast,
        // and at home scale (a handful of devices) the network cost of a stuck Sigma1 every ~12s is negligible
        qint64 jitterMs = QRandomGenerator::global()->bounded(5000);
        failedDevice->setNextReconnectAt(QDateTime::currentMSecsSinceEpoch() + 10000 + jitterMs);
        logDebug(m_debug) << failedDevice << "CASE retry in 10-15s";
        scheduleReconnect();
    }
}

// --- Setup code parsing ---

static const char base38Alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-.";

static QByteArray base38Decode(const QString &encoded)
{
    QByteArray result;
    int i = 0;

    while (i < encoded.length())
    {
        int charsInChunk = qMin(encoded.length() - i, 5);
        int bytesInChunk = charsInChunk == 5 ? 3 : (charsInChunk == 4 ? 2 : 1);

        quint32 value = 0;
        quint32 base = 1;

        for (int j = 0; j < charsInChunk; j++)
        {
            const char *p = strchr(base38Alphabet, encoded.at(i + j).toLatin1());

            if (!p)
                return QByteArray();

            value += static_cast <quint32> (p - base38Alphabet) * base;
            base *= 38;
        }

        for (int j = 0; j < bytesInChunk; j++)
        {
            result.append(static_cast <char> (value & 0xFF));
            value >>= 8;
        }

        i += charsInChunk;
    }

    return result;
}

bool Matter::parseQRCode(const QString &payload, quint32 &passcode, quint16 &discriminator)
{
    if (!payload.startsWith("MT:"))
        return false;

    QByteArray data = base38Decode(payload.mid(3));

    if (data.length() < 11)
        return false;

    // 88-bit payload, little-endian bitfield:
    // bits  0-2:  version (3)
    // bits  3-18: vendorId (16)
    // bits 19-34: productId (16)
    // bits 35-36: commissioningFlow (2)
    // bits 37-44: rendezvousFlags (8)
    // bits 45-56: discriminator (12)
    // bits 57-83: passcode (27)
    // bits 84-87: padding (4)

    quint64 low;
    memcpy(&low, data.constData(), 8);
    low = qFromLittleEndian(low);

    quint32 high = 0;
    memcpy(&high, data.constData() + 8, 3);
    high = qFromLittleEndian(high);

    discriminator = static_cast <quint16> ((low >> 45) & 0xFFF);
    passcode = static_cast <quint32> (((low >> 57) | (static_cast <quint64> (high) << 7)) & 0x7FFFFFF);

    if (passcode == 0 || passcode > 99999998)
        return false;

    return true;
}

static QString base38Encode(const QByteArray &data)
{
    QString result;
    int i = 0;

    while (i < data.length())
    {
        int bytesInChunk = qMin(data.length() - i, 3);
        int charsInChunk = bytesInChunk == 3 ? 5 : (bytesInChunk == 2 ? 4 : 2);

        quint32 value = 0;

        for (int j = bytesInChunk - 1; j >= 0; j--)
            value = (value << 8) | static_cast <quint8> (data.at(i + j));

        for (int j = 0; j < charsInChunk; j++)
        {
            result.append(QLatin1Char(base38Alphabet[value % 38]));
            value /= 38;
        }

        i += bytesInChunk;
    }

    return result;
}

// Verhoeff checksum tables
static const int verhoeffD[10][10] = {
    {0,1,2,3,4,5,6,7,8,9}, {1,2,3,4,0,6,7,8,9,5}, {2,3,4,0,1,7,8,9,5,6},
    {3,4,0,1,2,8,9,5,6,7}, {4,0,1,2,3,9,5,6,7,8}, {5,9,8,7,6,0,4,3,2,1},
    {6,5,9,8,7,1,0,4,3,2}, {7,6,5,9,8,2,1,0,4,3}, {8,7,6,5,9,3,2,1,0,4},
    {9,8,7,6,5,4,3,2,1,0}
};

static const int verhoeffInv[] = {0,4,3,2,1,5,6,7,8,9};

static const int verhoeffP[8][10] = {
    {0,1,2,3,4,5,6,7,8,9}, {1,5,7,6,2,8,3,0,9,4}, {5,8,0,3,7,9,6,1,4,2},
    {8,9,1,6,0,4,3,5,2,7}, {9,4,5,3,1,2,6,8,7,0}, {4,2,8,6,5,7,3,9,0,1},
    {2,7,9,3,8,0,6,4,1,5}, {7,0,4,6,9,1,3,2,5,8}
};

static int verhoeffChecksum(const QString &digits)
{
    int c = 0;

    for (int i = digits.length() - 1; i >= 0; i--)
        c = verhoeffD[c][verhoeffP[(digits.length() - i) % 8][digits.at(i).digitValue()]];

    return verhoeffInv[c];
}

QString Matter::generateManualCode(quint32 passcode, quint16 discriminator)
{
    // short discriminator = top 4 bits of 12-bit discriminator
    quint8 shortDisc = (discriminator >> 8) & 0x0F;

    // chunk1 (1 digit): bit0 = vidPidPresent (0 for 11-digit), bits 1-2 = shortDisc MSBs
    quint32 chunk1 = (shortDisc >> 2) & 0x03;

    // chunk2 (5 digits): bits 14-15 = shortDisc LSBs, bits 0-13 = passcode low 14 bits
    quint32 chunk2 = ((shortDisc & 0x03) << 14) | (passcode & 0x3FFF);

    // chunk3 (4 digits): passcode bits 14-26
    quint32 chunk3 = (passcode >> 14) & 0x1FFF;

    QString digits = QString("%1%2%3").arg(chunk1, 1, 10, QLatin1Char('0')).arg(chunk2, 5, 10, QLatin1Char('0')).arg(chunk3, 4, 10, QLatin1Char('0'));
    digits.append(QString::number(verhoeffChecksum(digits)));
    return digits;
}

QString Matter::generateQRCode(quint32 passcode, quint16 discriminator)
{
    // 88-bit payload, little-endian bitfield
    quint64 low = 0;
    quint32 high = 0;

    // version = 0 (bits 0-2)
    // vendorId = 0 (bits 3-18)
    // productId = 0 (bits 19-34)
    // commissioningFlow = 2 (bits 35-36) — Enhanced Commissioning Method
    low |= (static_cast <quint64> (2) << 35);
    // rendezvousFlags = 4 (bits 37-44) — BLE
    low |= (static_cast <quint64> (4) << 37);
    // discriminator (bits 45-56)
    low |= (static_cast <quint64> (discriminator & 0xFFF) << 45);
    // passcode low 7 bits (bits 57-63)
    low |= (static_cast <quint64> (passcode & 0x7F) << 57);
    // passcode remaining 20 bits (bits 64-83 → high bits 0-19)
    high |= (passcode >> 7) & 0xFFFFF;

    QByteArray data(11, 0);
    quint64 lowLE = qToLittleEndian(low);
    memcpy(data.data(), &lowLE, 8);
    quint32 highLE = qToLittleEndian(high);
    memcpy(data.data() + 8, &highLE, 3);

    return "MT:" + base38Encode(data);
}

QByteArray Matter::extractThreadExtPanId(const QByteArray &dataset)
{
    // Thread MeshCoP TLV: <type:1><length:1, or 0xff + 2-byte length><value>; type 2 = ExtendedPanId
    int i = 0;

    while (i + 1 < dataset.size())
    {
        quint8 type = static_cast <quint8> (dataset[i++]);
        quint16 length = static_cast <quint8> (dataset[i++]);

        if (length == 0xFF)
        {
            if (i + 2 > dataset.size())
                return QByteArray();

            length = (static_cast <quint8> (dataset[i]) << 8) | static_cast <quint8> (dataset[i + 1]);
            i += 2;
        }

        if (i + length > dataset.size())
            return QByteArray();

        if (type == 2 && length == 8)
            return dataset.mid(i, 8);

        i += length;
    }

    return QByteArray();
}

void Matter::shareDevice(DeviceObject *device, quint16 timeout)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session || !session->active)
    {
        logWarning << device << "no active session to share";
        return;
    }

    if (m_pendingShares.contains(device->nodeId()))
    {
        logWarning << device << "already sharing";
        return;
    }

    // generate random passcode (1-99999998, excluding invalid values)
    quint32 passcode;

    do
    {
        QByteArray bytes = Crypto::randomBytes(4);
        memcpy(&passcode, bytes.constData(), 4);
        passcode = (passcode % 99999998) + 1;
    }
    while (passcode == 11111111 || passcode == 22222222 || passcode == 33333333 ||
           passcode == 44444444 || passcode == 55555555 || passcode == 66666666 ||
           passcode == 77777777 || passcode == 88888888 || passcode == 12345678 ||
           passcode == 87654321);

    // generate random 12-bit discriminator
    QByteArray discBytes = Crypto::randomBytes(2);
    quint16 discriminator = (static_cast <quint16> (static_cast <quint8> (discBytes[0])) | (static_cast <quint16> (static_cast <quint8> (discBytes[1])) << 8)) & 0xFFF;

    // compute PASE verifier: PBKDF2 → w0s || w1s → w0 || L (where L = w1 * G)
    quint32 iterations = 1000;
    QByteArray salt = Crypto::randomBytes(32);

    QByteArray passcodeBytes(4, 0);
    quint32 le = qToLittleEndian(passcode);
    memcpy(passcodeBytes.data(), &le, 4);

    QByteArray derived = Crypto::pbkdf2(passcodeBytes, salt, iterations, 80);
    BigNum w0s(derived.left(40));
    BigNum w1s(derived.mid(40, 40));
    BigNum order = BigNum::fromOrder();
    BigNum w0 = BigNum::mod(w0s, order);
    BigNum w1 = BigNum::mod(w1s, order);

    // w0 as 32-byte big-endian
    QByteArray w0Bytes(32, 0);
    BN_bn2bin(w0.bn(), reinterpret_cast <unsigned char*> (w0Bytes.data()) + (32 - BN_num_bytes(w0.bn())));

    // L = w1 * G (65-byte uncompressed point)
    ECPoint L = ECPoint::fromMultiply(ECPoint::generator(), w1.bn());
    QByteArray lBytes = L.toUncompressed();

    QByteArray verifier = w0Bytes + lBytes; // 97 bytes

    logInfo << device << "sharing, passcode:" << passcode << "discriminator:" << discriminator << "timeout:" << timeout;

    PendingShare share;
    share.device = device;
    share.passcode = passcode;
    share.discriminator = discriminator;
    share.timeout = timeout;
    share.timedInvokePending = false;
    share.exchangeId = m_exchangeCounter++;
    m_pendingShares.insert(device->nodeId(), share);

    // send TimedRequest first (required for OpenCommissioningWindow)
    QByteArray timedPayload = InteractionModel::encodeTimedRequest(5000);
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::TimedRequest), static_cast <quint16> (ProtocolId::InteractionModel), timedPayload, share.exchangeId, true);

    // store verifier/salt/iterations for sending after StatusResponse
    // reuse the struct — store in a QMap by nodeId, the invoke will be sent from handleInteractionModel
    share.timedInvokePending = true;
    m_pendingShares[device->nodeId()].timedInvokePending = true;

    // save verifier data as dynamic properties on the share (use a separate map)
    m_shareVerifiers.insert(device->nodeId(), verifier);
    m_shareSalts.insert(device->nodeId(), salt);
    m_shareIterations.insert(device->nodeId(), iterations);
}

bool Matter::parseManualCode(const QString &code, quint32 &passcode, quint16 &discriminator)
{
    QString clean;

    for (const QChar &ch : code)
    {
        if (ch.isDigit())
            clean.append(ch);
    }

    if (clean.length() != 11 && clean.length() != 21)
        return false;

    quint32 chunk1 = clean.mid(0, 1).toUInt();
    quint32 chunk2 = clean.mid(1, 5).toUInt();
    quint32 chunk3 = clean.mid(6, 4).toUInt();

    // short discriminator (4 bits): chunk1 bits[0:1] (MSBs) + chunk2 bits[14:15] (LSBs)
    discriminator = static_cast <quint16> (((chunk1 & 0x3) << 2) | ((chunk2 >> 14) & 0x3));

    // passcode (27 bits): chunk2 bits[0:13] (LSBs) + chunk3 bits[0:12] (MSBs)
    passcode = (chunk2 & 0x3FFF) | (chunk3 << 14);

    if (passcode == 0 || passcode > 99999998)
        return false;

    return true;
}

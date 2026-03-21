#include <QtEndian>
#include <QDateTime>
#include <cstring>
#include "matter.h"
#include "logger.h"
#include "tlv.h"
#include "clusters.h"

using namespace MatterProtocol;

Matter::Matter(QObject *parent) : QObject(parent), m_udp(new QUdpSocket(this)), m_mrp(new MRP(this)), m_mdns(new MDNS(this)), m_sessions(new SessionManager(this)), m_searchTimer(new QTimer(this)), m_port(5540), m_searching(false), m_searchShortDiscriminator(false), m_searchPasscode(0), m_searchDiscriminator(0), m_messageCounter(0), m_exchangeCounter(0), m_sessionCounter(1), m_fabricId(1), m_nodeId(1)
{
    connect(m_udp, &QUdpSocket::readyRead, this, &Matter::readyRead);
    connect(m_searchTimer, &QTimer::timeout, this, &Matter::searchTimeout);
    connect(m_mrp, &MRP::retransmit, this, &Matter::mrpRetransmit);
    connect(m_mrp, &MRP::retransmitFailed, this, &Matter::mrpRetransmitFailed);
    connect(m_mrp, &MRP::sendStandaloneAck, this, &Matter::mrpSendStandaloneAck);
    connect(m_mdns, &MDNS::serviceFound, this, &Matter::mdnsServiceFound);

    m_searchTimer->setSingleShot(true);

    // fabric credentials will be set by Controller after database init
    m_pendingCASE = nullptr;
    m_caseDevice = nullptr;
    m_caseExchangeId = 0;

    // start message counter from random value to avoid replay detection after restart
    QByteArray counterBytes = Crypto::randomBytes(4);
    memcpy(&m_messageCounter, counterBytes.constData(), 4);

    if (!m_udp->bind(QHostAddress::Any, m_port))
        logWarning << "Failed to bind UDP port" << m_port;
    else
        logInfo << "Matter controller listening on port" << m_port;
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
    if (m_pendingCASE)
    {
        logWarning << "CASE session already in progress";
        return;
    }

    SessionInfo *existing = m_sessions->findByPeerNodeId(device->nodeId());

    if (existing && existing->active)
    {
        logInfo << "Already have active session for" << device->name();
        return;
    }

    QHostAddress address = device->networkAddress();
    quint16 port = device->networkPort();

    if (address.isNull())
    {
        logWarning << "No address known for" << device->name();
        return;
    }

    CASESession *session = new CASESession(this);

    connect(session, &CASESession::sendSigma1, this, &Matter::caseSendSigma1);
    connect(session, &CASESession::sendSigma3, this, &Matter::caseSendSigma3);
    connect(session, &CASESession::established, this, &Matter::caseEstablished);
    connect(session, &CASESession::failed, this, &Matter::caseFailed);

    m_pendingCASE = session;
    m_caseDevice = device;
    m_caseExchangeId = m_exchangeCounter++;
    m_caseAddress = address;
    m_casePort = port;

    quint16 sessionId = m_sessionCounter++;

    logInfo << "Starting CASE with" << device->name() << "at" << address.toString() << ":" << port;

    session->start(sessionId, device->nodeId(),
                   m_fabricKey, m_fabricPublicKey,
                   m_operationalKey, m_operationalPubKey,
                   m_fabricId, m_nodeId, m_rootCAId,
                   m_ipk, m_controllerNOC, m_controllerRCAC);
}

void Matter::addDevice(quint32 passcode, quint16 discriminator, bool shortDiscriminator)
{
    m_searching = true;
    m_searchPasscode = passcode;
    m_searchDiscriminator = discriminator;
    m_searchShortDiscriminator = shortDiscriminator;

    m_searchTimer->start(60000);
    logInfo << "Searching for commissionable device, discriminator:" << discriminator << (shortDiscriminator ? "(short)" : "(full)");
    m_mdns->browse();
}

// --- Send command to a commissioned device ---

void Matter::sendCommand(DeviceObject *device, quint8 endpointId, const QString &name, const QVariant &value)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session)
    {
        logWarning << "No active session for device" << device->name();
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
        payload = InteractionModel::encodeMoveToLevelCommand(endpointId, static_cast <quint8> (value.toUInt()));
    else if (name == "colorTemperature")
        payload = InteractionModel::encodeMoveToColorTemperatureCommand(endpointId, static_cast <quint16> (value.toUInt()));
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

    logInfo << "Sending command" << name << "to" << device->name() << "endpoint" << endpointId;
    sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
}

void Matter::readAttributes(DeviceObject *device, const QList <AttributePath> &paths)
{
    SessionInfo *session = m_sessions->findByPeerNodeId(device->nodeId());

    if (!session)
    {
        logWarning << "No active session for device" << device->name();
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
    m_mrp->messageSent(data, session->peerAddress, session->peerPort, msgHeader.messageCounter, exchangeId, true);
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
            if (m_pendingCASE && protoHeader.exchangeId == m_caseExchangeId)
            {
                m_pendingCASE->handleStatusReport(payload);
                return;
            }

            logInfo << "StatusReport from session" << msgHeader.sessionId;
            break;
        }

        case SecureChannelOpcode::CASESigma1:
            logInfo << "CASE Sigma1 from" << msgHeader.sourceNodeId;
            break;

        case SecureChannelOpcode::CASESigma2:
        {
            if (m_pendingCASE)
            {
                m_pendingCASE->setLastPeerMessageCounter(msgHeader.messageCounter);
                m_pendingCASE->handleSigma2(payload);
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

            for (const AttributeReport &report : reports)
            {
                if (report.hasError)
                {
                    logWarning << "Attribute error, cluster:" << QString::number(report.path.clusterId, 16) << "attr:" << QString::number(report.path.attributeId, 16) << "status:" << report.status;
                    continue;
                }

                logInfo << "Attribute, ep:" << report.path.endpointId << "cluster:" << QString::number(report.path.clusterId, 16) << "attr:" << QString::number(report.path.attributeId, 16) << "value:" << report.value;

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
                }
            }

            // send StatusResponse (success) to acknowledge ReportData
            SessionInfo *session = m_sessions->findByLocalId(msgHeader.sessionId);

            if (session)
            {
                QByteArray statusPayload = InteractionModel::encodeStatusResponse(0);
                sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::StatusResponse), static_cast <quint16> (ProtocolId::InteractionModel), statusPayload, protoHeader.exchangeId, false);
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
            }

            break;
        }

        case InteractionModelOpcode::StatusResponse:
        {
            quint8 status = InteractionModel::decodeStatusResponse(payload);
            logInfo << "StatusResponse:" << status;

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
            }

            break;
        }

        case InteractionModelOpcode::InvokeResponse:
        {
            QList <CommandResponse> responses = InteractionModel::decodeInvokeResponse(payload);

            logInfo << "InvokeResponse received, entries:" << responses.count() << "payload size:" << payload.size();

            for (const CommandResponse &response : responses)
            {
                logInfo << "InvokeResponse, cluster:" << QString::number(response.path.clusterId, 16) << "cmd:" << QString::number(response.path.commandId, 16) << "status:" << response.status;

                // check commissioning responses
                for (auto it = m_pendingCommissions.begin(); it != m_pendingCommissions.end(); it++)
                {
                    PendingCommission &commission = it.value();

                    if (commission.state == CommissioningState::ArmFailSafe && response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::ArmFailSafeResponse)
                    {
                        logInfo << "ArmFailSafe response, setting regulatory config...";
                        commission.state = CommissioningState::SetRegulatoryConfig;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::SetRegulatoryConfig && response.path.clusterId == Clusters::GeneralCommissioning::Id && response.path.commandId == Clusters::GeneralCommissioning::Commands::SetRegulatoryConfigResponse)
                    {
                        logInfo << "SetRegulatoryConfig response, reading basic info...";
                        commission.state = CommissioningState::ReadBasicInfo;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::RequestPAI && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::CertificateChainResponse)
                    {
                        logInfo << "PAI certificate received, requesting DAC...";
                        commission.state = CommissioningState::RequestDAC;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::RequestDAC && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::CertificateChainResponse)
                    {
                        logInfo << "DAC certificate received, requesting attestation...";
                        commission.state = CommissioningState::RequestAttestation;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::RequestAttestation && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::AttestationResponse)
                    {
                        logInfo << "Attestation received, sending CSR request...";
                        commission.state = CommissioningState::CSRRequest;
                        continueCommissioning(commission);
                        break;
                    }

                    if (commission.state == CommissioningState::CSRRequest && response.path.clusterId == Clusters::OperationalCredentials::Id && response.path.commandId == Clusters::OperationalCredentials::Commands::CSRResponse)
                    {
                        logInfo << "CSRResponse received";

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

                        logInfo << "Device public key extracted," << commission.devicePublicKey.length() << "bytes";

                        commission.rcacTLV = m_controllerRCAC; // use persisted RCAC for all devices
                        commission.nocTLV = generateFabricCert(m_fabricId, commission.device->nodeId(), commission.devicePublicKey, false);

                        logInfo << "Generated RCAC" << commission.rcacTLV.length() << "bytes, NOC" << commission.nocTLV.length() << "bytes";
        logInfo << "NOC hex:" << commission.nocTLV.toHex();
        logInfo << "RCAC hex:" << commission.rcacTLV.toHex();

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

                        logInfo << "AddTrustedRootCertificate accepted, sending AddNOC...";
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

                        logInfo << "AddNOC success, starting CASE for CommissioningComplete...";
                        commission.device->setNetworkAddress(commission.address);
                        commission.device->setNetworkPort(commission.port);
                        emit deviceCommissioned(commission.device);

                        connectDevice(commission.device);

                        // clean up PASE session
                        m_sessions->removeSession(commission.localSessionId);
                        m_pendingCommissions.remove(commission.localSessionId);

                        if (commission.pase)
                            commission.pase->deleteLater();

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

            break;
        }

        case InteractionModelOpcode::SubscribeResponse:
            logInfo << "SubscribeResponse received";
            break;

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
    commission.service = service;
    commission.state = CommissioningState::PASE;

    m_pendingCommissions.insert(sessionId, commission);

    logInfo << "Starting commissioning with" << service.address.toString() << ":" << service.port;
    pase->start(commission.passcode, sessionId);
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
        case CommissioningState::ArmFailSafe:
        {
            logInfo << "Sending ArmFailSafe...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 900);  // expiryLengthSeconds
            fields.encodeUnsignedInt(1, 1);    // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::ArmFailSafe), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::SetRegulatoryConfig:
        {
            logInfo << "Sending SetRegulatoryConfig...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 0);                  // newRegulatoryConfig: Indoor (0)
            fields.encodeUTF8String(1, QString("XX"));       // countryCode
            fields.encodeUnsignedInt(2, 0);                  // breadcrumb
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::SetRegulatoryConfig), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::ReadBasicInfo:
        {
            logInfo << "Reading BasicInformation cluster...";

            QList <AttributePath> paths;
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::VendorName));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::VendorID));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::ProductName));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::ProductID));
            paths.append(AttributePath(0, Clusters::BasicInformation::Id, Clusters::BasicInformation::Attributes::SoftwareVersionString));

            QByteArray payload = InteractionModel::encodeReadRequest(paths);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::ReadRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::RequestPAI:
        {
            logInfo << "Requesting PAI certificate...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 1);  // CertificateType = PAI
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CertificateChainRequest), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::RequestDAC:
        {
            logInfo << "Requesting DAC certificate...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeUnsignedInt(0, 2);  // CertificateType = DAC
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CertificateChainRequest), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::RequestAttestation:
        {
            logInfo << "Requesting attestation...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, Crypto::randomBytes(32));  // AttestationNonce
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AttestationRequest), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::CSRRequest:
        {
            logInfo << "Sending CSRRequest...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, Crypto::randomBytes(32)); // CSRNonce
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::CSRRequest), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::AddTrustedRootCert:
        {
            logInfo << "Sending AddTrustedRootCertificate...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, commission.rcacTLV);
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AddTrustedRootCertificate), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::AddNOC:
        {
            logInfo << "Sending AddNOC...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.encodeByteString(0, commission.nocTLV);   // NOCValue
            // tag 1: ICACValue (skip, no intermediate CA)
            fields.encodeByteString(2, m_ipk);               // IPKValue (16 bytes)
            fields.encodeUnsignedInt(3, m_nodeId);            // CaseAdminSubject
            fields.encodeUnsignedInt(4, 0xFFF1);              // AdminVendorId (test)
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::OperationalCredentials::Id, Clusters::OperationalCredentials::Commands::AddNOC), fields);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
            break;
        }

        case CommissioningState::CommissioningComplete:
        {
            if (!commission.timedInvokePending)
            {
                logInfo << "Sending TimedRequest for CommissioningComplete...";
                commission.exchangeId = m_exchangeCounter++;
                QByteArray payload = InteractionModel::encodeTimedRequest(5000);
                sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::TimedRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, commission.exchangeId, true);
                commission.timedInvokePending = true;
                break;
            }

            commission.timedInvokePending = false;
            logInfo << "Sending CommissioningComplete...";

            MatterTLV::Encoder fields;
            fields.openStructure();
            fields.closeContainer();

            QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::CommissioningComplete), fields, true);
            sendEncrypted(session, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, commission.exchangeId, true, commission.lastPeerCounter);
            break;
        }

        case CommissioningState::Done:
        {
            logInfo << "CommissioningComplete success, starting CASE...";
            session->peerNodeId = commission.device->nodeId();
            session->active = false;
            emit deviceCommissioned(commission.device);

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
    logInfo << "Generated" << (isRCAC ? "RCAC" : "NOC") << derCert.length() << "DER bytes," << tlvCert.length() << "TLV bytes";

    if (!isRCAC)
        logInfo << "NOC DER hex:" << derCert.toHex();
    return tlvCert;
}

// --- Standalone ACK ---

void Matter::sendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port)
{
    MessageHeader msgHeader;
    msgHeader.flags = 0x00;
    msgHeader.securityFlags = 0x00;
    msgHeader.sessionId = sessionId;
    msgHeader.messageCounter = ++m_messageCounter;

    ProtocolHeader protoHeader;
    protoHeader.exchangeFlags = static_cast <quint8> (ExchangeFlag::Acknowledgement);
    protoHeader.opcode = static_cast <quint8> (SecureChannelOpcode::MRPStandaloneAck);
    protoHeader.exchangeId = exchangeId;
    protoHeader.protocolId = static_cast <quint16> (ProtocolId::SecureChannel);
    protoHeader.ackCounter = ackCounter;

    QByteArray data = MessageCodec::encodeMessage(msgHeader, protoHeader, QByteArray());
    sendRawDatagram(data, address, port);
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
            logWarning << "Invalid message header from" << sender.toString() << "size:" << datagram.size() << "hex:" << datagram.left(16).toHex();
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
            {
                logWarning << "Unknown session" << msgHeader.sessionId << "from" << sender.toString();
                continue;
            }

            QByteArray header = datagram.left(headerOffset);
            QByteArray ciphertext = datagram.mid(headerOffset);

            payload = m_sessions->decrypt(session, msgHeader.securityFlags, msgHeader.messageCounter, session->peerNodeId, header, ciphertext);

            if (payload.isEmpty())
            {
                logWarning << "Decryption failed for session" << msgHeader.sessionId << "from" << sender.toString() << "size:" << ciphertext.size();
                continue;
            }

            logInfo << "Decrypted message from session" << msgHeader.sessionId << "counter:" << msgHeader.messageCounter << "size:" << payload.size();
        }
        else
        {
            payload = datagram.mid(headerOffset);
        }

        if (!MessageCodec::decodeProtocolHeader(payload, 0, protoHeader, payloadOffset))
        {
            logWarning << "Invalid protocol header from" << sender.toString();
            continue;
        }

        m_mrp->messageReceived(msgHeader.messageCounter, protoHeader.exchangeId, protoHeader.hasAck(), protoHeader.ackCounter, sender, senderPort, msgHeader.sessionId, protoHeader.needsAck());

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
    m_mdns->stop();
    logWarning << "Device search timeout, device not found";
}

void Matter::mrpRetransmit(const QByteArray &data, const QHostAddress &address, quint16 port)
{
    sendRawDatagram(data, address, port);
}

void Matter::mrpRetransmitFailed(quint32 messageCounter, quint16 exchangeId)
{
    logWarning << "Message delivery failed, counter:" << messageCounter << "exchange:" << exchangeId;
}

void Matter::mrpSendStandaloneAck(quint32 ackCounter, quint16 exchangeId, quint16 sessionId, const QHostAddress &address, quint16 port)
{
    sendStandaloneAck(ackCounter, exchangeId, sessionId, address, port);
}

void Matter::mdnsServiceFound(const MatterService &service)
{
    if (!m_searching)
        return;

    // match discriminator
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

    m_searching = false;
    m_searchTimer->stop();
    m_mdns->stop();

    startCommissioning(service);
}

// --- PASE signal handlers ---

void Matter::paseSendPBKDFParamRequest(const QByteArray &payload, quint16 localSessionId)
{
    if (!m_pendingCommissions.contains(localSessionId))
        return;

    const PendingCommission &commission = m_pendingCommissions.value(localSessionId);
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
    quint64 nodeId = m_nodeId + m_sessionCounter;
    commission.device = new DeviceObject(nodeId, commission.service.deviceName.isEmpty() ? QString("matter_%1").arg(commission.service.discriminator) : commission.service.deviceName);
    commission.device->setVendorId(commission.service.vendorId);
    commission.device->setProductId(commission.service.productId);
    commission.device->setNetworkAddress(commission.address);
    commission.device->setNetworkPort(commission.port);

    // start commissioning: ArmFailSafe → ReadBasicInfo → CommissioningComplete
    commission.state = CommissioningState::ArmFailSafe;
    continueCommissioning(commission);
}

void Matter::paseFailed(const QString &reason)
{
    PASESession *pase = qobject_cast <PASESession*> (sender());

    if (!pase)
        return;

    logWarning << "PASE failed:" << reason;

    quint16 sessionId = pase->localSessionId();
    m_pendingCommissions.remove(sessionId);
    pase->deleteLater();
}

// --- CASE signal handlers ---

void Matter::caseSendSigma1(const QByteArray &payload, quint16 localSessionId)
{
    Q_UNUSED(localSessionId)

    if (!m_pendingCASE)
        return;

    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::CASESigma1), static_cast <quint16> (ProtocolId::SecureChannel), payload, m_caseExchangeId, m_caseAddress, m_casePort, true);
}

void Matter::caseSendSigma3(const QByteArray &payload)
{
    if (!m_pendingCASE)
        return;

    sendUnencrypted(static_cast <quint8> (SecureChannelOpcode::CASESigma3), static_cast <quint16> (ProtocolId::SecureChannel), payload, m_caseExchangeId, m_caseAddress, m_casePort, true, m_pendingCASE->lastPeerMessageCounter());
}

void Matter::caseEstablished(quint16 localSessionId, quint16 peerSessionId)
{
    if (!m_pendingCASE || !m_caseDevice)
        return;

    // register encrypted session
    SessionInfo session;
    session.localSessionId = localSessionId;
    session.peerSessionId = peerSessionId;
    session.i2rKey = m_pendingCASE->encryptKey();
    session.r2iKey = m_pendingCASE->decryptKey();
    session.attestationChallenge = m_pendingCASE->attestationChallenge();
    session.peerNodeId = m_caseDevice->nodeId();
    session.localMessageCounter = 0;
    session.active = true;

    session.peerAddress = m_caseDevice->networkAddress();
    session.peerPort = m_caseDevice->networkPort();

    // remove old (dead) session
    SessionInfo *existing = m_sessions->findByPeerNodeId(m_caseDevice->nodeId());

    if (existing)
        m_sessions->removeSession(existing->localSessionId);

    m_sessions->addSession(session);

    logInfo << "CASE session established with" << m_caseDevice->name();

    // send CommissioningComplete on CASE session if device not yet fully commissioned
    SessionInfo *caseSession = m_sessions->findByLocalId(localSessionId);

    if (caseSession && m_caseDevice->availability() != Availability::Online)
    {
        logInfo << "Sending CommissioningComplete on CASE session...";

        MatterTLV::Encoder fields;
        fields.openStructure();
        fields.closeContainer();

        QByteArray payload = InteractionModel::encodeInvokeRequest(CommandPath(0, Clusters::GeneralCommissioning::Id, Clusters::GeneralCommissioning::Commands::CommissioningComplete), fields);
        sendEncrypted(caseSession, static_cast <quint8> (InteractionModelOpcode::InvokeRequest), static_cast <quint16> (ProtocolId::InteractionModel), payload, m_exchangeCounter++, true);
    }

    m_caseDevice->setAvailability(Availability::Online);

    m_pendingCASE->deleteLater();
    m_pendingCASE = nullptr;
    m_caseDevice = nullptr;
}

void Matter::caseFailed(const QString &reason)
{
    logWarning << "CASE failed:" << reason;

    if (m_pendingCASE)
    {
        m_pendingCASE->deleteLater();
        m_pendingCASE = nullptr;
    }

    m_caseDevice = nullptr;
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

bool Matter::parseManualCode(const QString &code, quint32 &passcode, quint16 &discriminator)
{
    if (code.length() != 11 && code.length() != 21)
        return false;

    for (int i = 0; i < code.length(); i++)
    {
        if (!code.at(i).isDigit())
            return false;
    }

    quint32 chunk1 = code.mid(0, 1).toUInt();
    quint32 chunk2 = code.mid(1, 5).toUInt();
    quint32 chunk3 = code.mid(6, 4).toUInt();

    // short discriminator (4 bits): chunk1 bits[0:1] (MSBs) + chunk2 bits[14:15] (LSBs)
    discriminator = static_cast <quint16> (((chunk1 & 0x3) << 2) | ((chunk2 >> 14) & 0x3));

    // passcode (27 bits): chunk2 bits[0:13] (LSBs) + chunk3 bits[0:12] (MSBs)
    passcode = (chunk2 & 0x3FFF) | (chunk3 << 14);

    if (passcode == 0 || passcode > 99999998)
        return false;

    return true;
}

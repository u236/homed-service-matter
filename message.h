// NOT REWIEWED

#ifndef MESSAGE_H
#define MESSAGE_H

#define MESSAGE_FLAG_SOURCE_NODE_ID     0x04
#define MESSAGE_FLAG_DESTINATION_MASK   0x03
#define MESSAGE_DESTINATION_NODE_ID     0x01
#define MESSAGE_DESTINATION_GROUP_ID    0x02

#include <QByteArray>

#pragma pack(push, 1)

struct messageHeaderStruct
{
    quint8  flags;
    quint16 sessionId;
    quint8  securityFlags;
    quint32 messageCounter;
};

struct protocolHeaderStruct
{
    quint8  exchangeFlags;
    quint8  opcode;
    quint16 exchangeId;
    quint16 protocolId;
};

struct statusReportStruct
{
    quint16 generalCode;
    quint32 protocolId;
    quint16 protocolCode;
};

#pragma pack(pop)

namespace MatterProtocol
{
    enum class SecurityFlag : quint8
    {
        Privacy          = 0x01,
        Control          = 0x02,
        Extensions       = 0x04
    };

    enum class ExchangeFlag : quint8
    {
        Initiator        = 0x01,
        Acknowledgement  = 0x02,
        Reliability      = 0x04,
        SecuredExtension = 0x08,
        Vendor           = 0x10
    };

    enum class ProtocolId : quint16
    {
        SecureChannel    = 0x0000,
        InteractionModel = 0x0001
    };

    enum class SecureChannelOpcode : quint8
    {
        MsgCounterSyncReq   = 0x00,
        MsgCounterSyncRsp   = 0x01,
        MRPStandaloneAck    = 0x10,
        PBKDFParamRequest   = 0x20,
        PBKDFParamResponse  = 0x21,
        PASEPake1           = 0x22,
        PASEPake2           = 0x23,
        PASEPake3           = 0x24,
        CASESigma1          = 0x30,
        CASESigma2          = 0x31,
        CASESigma3          = 0x32,
        CASESigma2Resume    = 0x33,
        StatusReport        = 0x40
    };

    enum class InteractionModelOpcode : quint8
    {
        StatusResponse      = 0x01,
        ReadRequest         = 0x02,
        SubscribeRequest    = 0x03,
        SubscribeResponse   = 0x04,
        ReportData          = 0x05,
        WriteRequest        = 0x06,
        WriteResponse       = 0x07,
        InvokeRequest       = 0x08,
        InvokeResponse      = 0x09,
        TimedRequest        = 0x0A
    };

    struct MessageHeader
    {
        quint8  flags;
        quint8  securityFlags;
        quint16 sessionId;
        quint32 messageCounter;
        quint64 sourceNodeId;
        quint64 destinationNodeId;
        quint16 destinationGroupId;

        MessageHeader(void) : flags(0), securityFlags(0), sessionId(0), messageCounter(0), sourceNodeId(0), destinationNodeId(0), destinationGroupId(0) {}
    };

    struct ProtocolHeader
    {
        quint8  exchangeFlags;
        quint8  opcode;
        quint16 exchangeId;
        quint16 protocolId;
        quint16 vendorId;
        quint32 ackCounter;

        ProtocolHeader(void) : exchangeFlags(0), opcode(0), exchangeId(0), protocolId(0), vendorId(0), ackCounter(0) {}
    };

    class MessageCodec
    {

    public:

        static bool decodeHeader(const QByteArray &data, MessageHeader &header, quint32 &offset);
        static bool decodeProtocolHeader(const QByteArray &data, ProtocolHeader &header, quint32 &offset);

        static QByteArray encodeHeader(const MessageHeader &header);
        static QByteArray encodeProtocolHeader(const ProtocolHeader &header);
        static QByteArray encodeMessage(const MessageHeader &messageHeader, const ProtocolHeader &protocolHeader, const QByteArray &payload);

    };
}

#endif

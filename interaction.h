#ifndef INTERACTION_H
#define INTERACTION_H

#include <QObject>
#include <QMap>
#include <QVariant>
#include "tlv.h"
#include "clusters.h"

/*
    Matter Interaction Model (spec section 8)

    TLV structure for IM messages:

    AttributePathIB:
        0 = enableTagCompression (bool)
        1 = nodeId (u64, optional)
        2 = endpointId (u16)
        3 = clusterId (u32)
        4 = attributeId (u32)
        5 = listIndex (u16, optional)

    CommandPathIB:
        0 = endpointId (u16)
        1 = clusterId (u32)
        2 = commandId (u32)

    ReadRequest:
        0 = attributeRequests (array of AttributePathIB)

    WriteRequest:
        0 = suppressResponse (bool)
        1 = timedRequest (bool)
        2 = writeRequests (array of AttributeDataIB)

    InvokeRequest:
        0 = suppressResponse (bool)
        1 = timedRequest (bool)
        2 = invokeRequests (array of CommandDataIB)

    ReportData:
        0 = subscriptionId (u32, optional)
        1 = attributeReports (array of AttributeReportIB)
*/

struct AttributePath
{
    quint16 endpointId;
    quint32 clusterId;
    quint32 attributeId;

    AttributePath(void) : endpointId(0), clusterId(0), attributeId(0) {}
    AttributePath(quint16 ep, quint32 cl, quint32 at) : endpointId(ep), clusterId(cl), attributeId(at) {}
};

struct CommandPath
{
    quint16 endpointId;
    quint32 clusterId;
    quint32 commandId;

    CommandPath(void) : endpointId(0), clusterId(0), commandId(0) {}
    CommandPath(quint16 ep, quint32 cl, quint32 cmd) : endpointId(ep), clusterId(cl), commandId(cmd) {}
};

struct AttributeReport
{
    AttributePath path;
    QVariant value;
    MatterTLV::Element rawValue;
    quint8 status;
    bool hasError;

    AttributeReport(void) : status(0), hasError(false) {}
};

struct CommandResponse
{
    CommandPath path;
    quint8 status;
    MatterTLV::Element data;

    CommandResponse(void) : status(0) {}
};

class InteractionModel
{

public:

    // --- Encoding ---

    static QByteArray encodeReadRequest(const QList <AttributePath> &paths);
    static QByteArray encodeWriteRequest(quint16 endpointId, quint32 clusterId, quint32 attributeId, const MatterTLV::Encoder &valueEncoder);
    static QByteArray encodeInvokeRequest(const CommandPath &path, const MatterTLV::Encoder &fieldsEncoder, bool timedRequest = false);
    static QByteArray encodeSubscribeRequest(const QList <AttributePath> &paths, quint16 minInterval, quint16 maxInterval);

    static QByteArray encodeTimedRequest(quint16 timeoutMs);
    static QByteArray encodeStatusResponse(quint8 status);

    // --- Decoding ---

    static QList <AttributeReport> decodeReportData(const QByteArray &payload);
    static QList <CommandResponse> decodeInvokeResponse(const QByteArray &payload);
    static quint8 decodeStatusResponse(const QByteArray &payload);

    // --- Helpers ---

    static QByteArray encodeOnOffCommand(quint16 endpointId, bool on);
    static QByteArray encodeToggleCommand(quint16 endpointId);
    static QByteArray encodeMoveToLevelCommand(quint16 endpointId, quint8 level, quint16 transitionTime = 0);
    static QByteArray encodeMoveToColorTemperatureCommand(quint16 endpointId, quint16 mireds, quint16 transitionTime = 0);
    static QByteArray encodeLockCommand(quint16 endpointId, bool lock);
    static QByteArray encodeCoverCommand(quint16 endpointId, quint8 command, quint16 position = 0);

private:

    static void encodeAttributePath(MatterTLV::Encoder &encoder, const AttributePath &path);
    static void encodeCommandPath(MatterTLV::Encoder &encoder, const CommandPath &path);

    static AttributePath decodeAttributePath(const MatterTLV::Element &element);
    static CommandPath decodeCommandPath(const MatterTLV::Element &element);

};

#endif

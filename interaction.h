// NOT REWIEWED

#ifndef INTERACTION_H
#define INTERACTION_H

#define INTERACTION_MODEL_REVISION      11
#define INTERACTION_MODEL_REVISION_TAG  0xFF

#include "tlv.h"

struct AttributePath
{
    quint16 endpointId;
    quint32 clusterId;
    quint32 attributeId;

    AttributePath(quint16 endpointId = 0, quint32 clusterId = 0, quint32 attributeId = 0) : endpointId(endpointId), clusterId(clusterId), attributeId(attributeId) {}
};

struct EventPath
{
    quint16 endpointId;
    quint32 clusterId;
    quint32 eventId;
    bool    urgent;

    EventPath(quint16 endpointId = 0, quint32 clusterId = 0, quint32 eventId = 0, bool urgent = false) : endpointId(endpointId), clusterId(clusterId), eventId(eventId), urgent(urgent) {}
};

struct CommandPath
{
    quint16 endpointId;
    quint32 clusterId;
    quint32 commandId;

    CommandPath(quint16 endpointId = 0, quint32 clusterId = 0, quint32 commandId = 0) : endpointId(endpointId), clusterId(clusterId), commandId(commandId) {}
};

struct AttributeReport
{
    AttributePath      path;
    QVariant           value;
    MatterTLV::Element data;
    quint8             status;
    bool               error;

    AttributeReport(void) : status(0), error(false) {}
};

struct EventReport
{
    EventPath          path;
    quint64            eventNumber;
    quint8             priority;
    MatterTLV::Element data;

    EventReport(void) : eventNumber(0), priority(0) {}
};

struct CommandResponse
{
    CommandPath        path;
    quint8             status;
    MatterTLV::Element data;

    CommandResponse(void) : status(0) {}
};

class InteractionModel
{

public:

    static QByteArray readRequest(const QList <AttributePath> &attributes);
    static QByteArray writeRequest(const AttributePath &path, MatterTLV::Encoder &value);
    static QByteArray invokeRequest(const CommandPath &path, MatterTLV::Encoder &fields, bool timed = false);
    static QByteArray subscribeRequest(const QList <AttributePath> &attributes, const QList <EventPath> &events, quint16 minInterval, quint16 maxInterval);
    static QByteArray timedRequest(quint16 timeout);
    static QByteArray statusResponse(quint8 status);

    static QList <AttributeReport> attributeReports(const QByteArray &payload);
    static QList <EventReport> eventReports(const QByteArray &payload);
    static QList <CommandResponse> commandResponses(const QByteArray &payload);
    static quint8 status(const QByteArray &payload);

private:

    static void encodeAttributePath(MatterTLV::Encoder &encoder, const AttributePath &path);
    static void encodeEventPath(MatterTLV::Encoder &encoder, const EventPath &path);
    static void encodeCommandPath(MatterTLV::Encoder &encoder, const CommandPath &path);
    static void encodeElement(MatterTLV::Encoder &encoder, int tag, const MatterTLV::Element &element);

    static AttributePath decodeAttributePath(const MatterTLV::Element &element);
    static EventPath decodeEventPath(const MatterTLV::Element &element);
    static CommandPath decodeCommandPath(const MatterTLV::Element &element);

    static quint8 decodeStatus(const MatterTLV::Element &element);

};

#endif

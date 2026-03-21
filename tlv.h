#ifndef TLV_H
#define TLV_H

#include <QByteArray>
#include <QList>
#include <QVariant>

namespace MatterTLV
{
    enum class Type : quint8
    {
        SignedInt        = 0x00,
        UnsignedInt      = 0x04,
        Boolean          = 0x08,
        Float            = 0x0A,
        Double           = 0x0B,
        UTF8String       = 0x0C,
        ByteString       = 0x10,
        Null             = 0x14,
        Structure        = 0x15,
        Array            = 0x16,
        List             = 0x17,
        EndOfContainer   = 0x18
    };

    enum class TagControl : quint8
    {
        Anonymous        = 0x00,
        ContextSpecific  = 0x20,
        CommonProfile2   = 0x40,
        CommonProfile4   = 0x60,
        Implicit2        = 0x80,
        Implicit4        = 0xA0,
        FullyQualified6  = 0xC0,
        FullyQualified8  = 0xE0
    };

    struct Element
    {
        Type type;
        quint8 tag;
        QVariant value;
        QList <Element> children;

        Element(void) : type(Type::Null), tag(0) {}
        Element(Type type, quint8 tag, const QVariant &value = QVariant()) : type(type), tag(tag), value(value) {}
    };

    class Encoder
    {

    public:

        Encoder(void) {}

        void encodeSignedInt(quint8 tag, qint64 value);
        void encodeUnsignedInt(quint8 tag, quint64 value);
        void encodeBool(quint8 tag, bool value);
        void encodeFloat(quint8 tag, float value);
        void encodeDouble(quint8 tag, double value);
        void encodeUTF8String(quint8 tag, const QString &value);
        void encodeByteString(quint8 tag, const QByteArray &value);
        void encodeNull(quint8 tag);

        void openStructure(quint8 tag = 0);
        void openArray(quint8 tag = 0);
        void openList(quint8 tag = 0);
        void closeContainer(void);

        inline QByteArray data(void) const { return m_data; }

    private:

        QByteArray m_data;

        void encodeControl(Type type, quint8 tag);
        void encodeLength(quint32 length);

    };

    class Decoder
    {

    public:

        Decoder(const QByteArray &data) : m_data(data), m_offset(0) {}

        Element decode(void);
        QList <Element> decodeAll(void);

    private:

        QByteArray m_data;
        quint32 m_offset;

        quint8 readByte(void);
        QByteArray readBytes(quint32 count);

        qint64 readSignedInt(quint8 size);
        quint64 readUnsignedInt(quint8 size);

    };
}

#endif

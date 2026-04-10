// NOT REWIEWED

#ifndef TLV_H
#define TLV_H

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

        void encodeSignedInt(int tag, qint64 value);
        void encodeUnsignedInt(int tag, quint64 value);
        void encodeBool(int tag, bool value);
        void encodeFloat(int tag, float value);
        void encodeDouble(int tag, double value);
        void encodeUTF8String(int tag, const QString &value);
        void encodeByteString(int tag, const QByteArray &value);
        void encodeNull(int tag);

        void openStructure(int tag = -1);
        void openArray(int tag = -1);
        void openList(int tag = -1);
        void closeContainer(void);

        void encodeRaw(const QByteArray &raw);

        inline QByteArray data(void) const { return m_data; }

    private:

        QByteArray m_data;

        void encodeControl(Type type, int tag);
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

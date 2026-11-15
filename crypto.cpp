// NOT REWIEWED

#include <openssl/x509v3.h>
#include <QtEndian>
#include <QRandomGenerator>
#include "crypto.h"
#include "tlv.h"

EC_GROUP *ECPoint::s_group = nullptr;

static EVP_PKEY *ecPrivateKey(const QByteArray &data)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *value = BN_bin2bn(reinterpret_cast <const unsigned char*> (data.constData()), data.length(), nullptr);
    EC_POINT *point = EC_POINT_new(EC_KEY_get0_group(key));
    EVP_PKEY *result = EVP_PKEY_new();

    EC_KEY_set_private_key(key, value);
    EC_POINT_mul(EC_KEY_get0_group(key), point, value, nullptr, nullptr, nullptr);
    EC_KEY_set_public_key(key, point);
    EVP_PKEY_assign_EC_KEY(result, key);

    EC_POINT_free(point);
    BN_free(value);

    return result;
}

static EVP_PKEY *ecPublicKey(const QByteArray &data)
{
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *point = EC_POINT_new(EC_KEY_get0_group(key));
    EVP_PKEY *result = EVP_PKEY_new();

    EC_POINT_oct2point(EC_KEY_get0_group(key), point, reinterpret_cast <const unsigned char*> (data.constData()), data.length(), nullptr);
    EC_KEY_set_public_key(key, point);
    EVP_PKEY_assign_EC_KEY(result, key);

    EC_POINT_free(point);

    return result;
}

static QByteArray pointData(const EC_GROUP *group, const EC_POINT *point)
{
    QByteArray data(static_cast <int> (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr)), 0);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, reinterpret_cast <unsigned char*> (data.data()), data.length(), nullptr);
    return data;
}

static QByteArray signatureData(const BIGNUM *r, const BIGNUM *s)
{
    QByteArray data(64, 0);
    BN_bn2bin(r, reinterpret_cast <unsigned char*> (data.data()) + 32 - BN_num_bytes(r));
    BN_bn2bin(s, reinterpret_cast <unsigned char*> (data.data()) + 64 - BN_num_bytes(s));
    return data;
}

static void addNameEntry(X509_NAME *name, const char *oid, quint64 value)
{
    ASN1_OBJECT *object = OBJ_txt2obj(oid, 1);
    QByteArray data = QString("%1").arg(value, 16, 16, QChar('0')).toUpper().toUtf8();

    X509_NAME_add_entry_by_OBJ(name, object, MBSTRING_UTF8, reinterpret_cast <const unsigned char*> (data.constData()), data.length(), -1, 0);
    ASN1_OBJECT_free(object);
}

static void addExtension(X509 *certificate, X509V3_CTX *context, int nid, const char *value)
{
    X509_EXTENSION *extension = X509V3_EXT_nconf_nid(nullptr, context, nid, const_cast <char*> (value));
    X509_add_ext(certificate, extension, -1);
    X509_EXTENSION_free(extension);
}

static void convertName(X509_NAME *name, MatterTLV::Encoder &encoder)
{
    QList <QString> list = {MATTER_OID_NODE_ID, MATTER_OID_RCAC_ID, MATTER_OID_FABRIC_ID};

    for (int i = 0; i < X509_NAME_entry_count(name); i++)
    {
        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, i);
        ASN1_STRING *value = X509_NAME_ENTRY_get_data(entry);
        char oid[128];
        quint64 id;
        quint8 tag;

        OBJ_obj2txt(oid, sizeof(oid), X509_NAME_ENTRY_get_object(entry), 1);

        switch (list.indexOf(oid))
        {
            case 0:  tag = MATTER_TAG_NODE_ID; break;
            case 1:  tag = MATTER_TAG_RCAC_ID; break;
            case 2:  tag = MATTER_TAG_FABRIC_ID; break;
            default: continue;
        }

        // ids must be encoded as 8-byte unsigned integers regardless of value
        id = qToLittleEndian(QString::fromUtf8(reinterpret_cast <const char*> (ASN1_STRING_get0_data(value)), ASN1_STRING_length(value)).toULongLong(nullptr, 16));
        encoder.encodeRaw(QByteArray(1, 0x27).append(static_cast <char> (tag)).append(reinterpret_cast <char*> (&id), sizeof(id)));
    }
}

QByteArray Crypto::pbkdf2(const QByteArray &password, const QByteArray &salt, quint32 iterations, quint32 length)
{
    QByteArray data(length, 0);
    PKCS5_PBKDF2_HMAC(password.constData(), password.length(), reinterpret_cast <const unsigned char*> (salt.constData()), salt.length(), iterations, EVP_sha256(), length, reinterpret_cast <unsigned char*> (data.data()));
    return data;
}

QByteArray Crypto::hkdf(const QByteArray &key, const QByteArray &salt, const QByteArray &info, quint32 length)
{
    QByteArray prk = hmac(salt.isEmpty() ? QByteArray(32, 0) : salt, key), block, data;
    quint8 counter = 1;

    // manual RFC 5869 implementation, OpenSSL EVP doesn't handle empty salt properly
    while (static_cast <quint32> (data.length()) < length)
    {
        block = hmac(prk, QByteArray(block).append(info).append(static_cast <char> (counter++)));
        data.append(block);
    }

    return data.left(length);
}

QByteArray Crypto::hmac(const QByteArray &key, const QByteArray &data)
{
    QByteArray result(32, 0);
    unsigned int length = result.length();

    HMAC(EVP_sha256(), key.constData(), key.length(), reinterpret_cast <const unsigned char*> (data.constData()), data.length(), reinterpret_cast <unsigned char*> (result.data()), &length);
    return result;
}

QByteArray Crypto::sha1(const QByteArray &data)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    QByteArray result(20, 0);
    unsigned int length = result.length();

    EVP_DigestInit_ex(context, EVP_sha1(), nullptr);
    EVP_DigestUpdate(context, data.constData(), data.length());
    EVP_DigestFinal_ex(context, reinterpret_cast <unsigned char*> (result.data()), &length);
    EVP_MD_CTX_free(context);

    return result;
}

QByteArray Crypto::sha256(const QByteArray &data)
{
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    QByteArray result(32, 0);
    unsigned int length = result.length();

    EVP_DigestInit_ex(context, EVP_sha256(), nullptr);
    EVP_DigestUpdate(context, data.constData(), data.length());
    EVP_DigestFinal_ex(context, reinterpret_cast <unsigned char*> (result.data()), &length);
    EVP_MD_CTX_free(context);

    return result;
}

QByteArray Crypto::encrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad, const QByteArray &data, quint8 tagLength)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    QByteArray result(data.length() + tagLength, 0);
    int length = 0;

    if (!context)
        return QByteArray();

    EVP_EncryptInit_ex(context, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_SET_IVLEN, nonce.length(), nullptr);
    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_SET_TAG, tagLength, nullptr);
    EVP_EncryptInit_ex(context, nullptr, nullptr, reinterpret_cast <const unsigned char*> (key.constData()), reinterpret_cast <const unsigned char*> (nonce.constData()));
    EVP_EncryptUpdate(context, nullptr, &length, nullptr, data.length());

    if (!aad.isEmpty())
        EVP_EncryptUpdate(context, nullptr, &length, reinterpret_cast <const unsigned char*> (aad.constData()), aad.length());

    EVP_EncryptUpdate(context, reinterpret_cast <unsigned char*> (result.data()), &length, reinterpret_cast <const unsigned char*> (data.constData()), data.length());
    EVP_EncryptFinal_ex(context, reinterpret_cast <unsigned char*> (result.data()) + length, &length);
    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_GET_TAG, tagLength, result.data() + data.length());
    EVP_CIPHER_CTX_free(context);

    return result;
}

QByteArray Crypto::decrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad, const QByteArray &data, quint8 tagLength)
{
    EVP_CIPHER_CTX *context;
    QByteArray result, tag;
    int length = data.length() - tagLength, size = 0, check;

    if (length < 0 || !(context = EVP_CIPHER_CTX_new()))
        return QByteArray();

    result = QByteArray(length, 0);
    tag = data.mid(length, tagLength);

    EVP_DecryptInit_ex(context, EVP_aes_128_ccm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_SET_IVLEN, nonce.length(), nullptr);
    EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_CCM_SET_TAG, tagLength, tag.data());
    EVP_DecryptInit_ex(context, nullptr, nullptr, reinterpret_cast <const unsigned char*> (key.constData()), reinterpret_cast <const unsigned char*> (nonce.constData()));
    EVP_DecryptUpdate(context, nullptr, &size, nullptr, length);

    if (!aad.isEmpty())
        EVP_DecryptUpdate(context, nullptr, &size, reinterpret_cast <const unsigned char*> (aad.constData()), aad.length());

    check = EVP_DecryptUpdate(context, reinterpret_cast <unsigned char*> (result.data()), &size, reinterpret_cast <const unsigned char*> (data.constData()), length);
    EVP_CIPHER_CTX_free(context);

    return check > 0 ? result : QByteArray();
}

QByteArray Crypto::sign(const QByteArray &privateKey, const QByteArray &data)
{
    EVP_PKEY *key = ecPrivateKey(privateKey);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    const unsigned char *pointer;
    ECDSA_SIG *signature;
    QByteArray der, result;
    size_t length = 0;

    EVP_DigestSignInit(context, nullptr, EVP_sha256(), nullptr, key);
    EVP_DigestSignUpdate(context, data.constData(), data.length());
    EVP_DigestSignFinal(context, nullptr, &length);

    der = QByteArray(static_cast <int> (length), 0);
    EVP_DigestSignFinal(context, reinterpret_cast <unsigned char*> (der.data()), &length);
    der.resize(static_cast <int> (length));
    EVP_MD_CTX_free(context);

    pointer = reinterpret_cast <const unsigned char*> (der.constData());
    signature = d2i_ECDSA_SIG(nullptr, &pointer, der.length());

    if (signature)
    {
        BIGNUM *order = BN_new(), *half = BN_new(), *value;
        const BIGNUM *r, *s;

        ECDSA_SIG_get0(signature, &r, &s);
        EC_GROUP_get_order(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key)), order, nullptr);
        BN_rshift1(half, order);

        value = BN_dup(s);

        // low-S normalization
        if (BN_cmp(s, half) > 0)
            BN_sub(value, order, s);

        result = signatureData(r, value);

        BN_free(value);
        BN_free(half);
        BN_free(order);
        ECDSA_SIG_free(signature);
    }

    EVP_PKEY_free(key);
    return result;
}

bool Crypto::verify(const QByteArray &publicKey, const QByteArray &data, const QByteArray &signature)
{
    EC_KEY *key;
    EC_POINT *point;
    ECDSA_SIG *value;
    QByteArray hash;
    int result;

    if (publicKey.length() != 65 || signature.length() != 64)
        return false;

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    point = EC_POINT_new(EC_KEY_get0_group(key));
    value = ECDSA_SIG_new();
    hash = sha256(data);

    EC_POINT_oct2point(EC_KEY_get0_group(key), point, reinterpret_cast <const unsigned char*> (publicKey.constData()), publicKey.length(), nullptr);
    EC_KEY_set_public_key(key, point);
    ECDSA_SIG_set0(value, BN_bin2bn(reinterpret_cast <const unsigned char*> (signature.constData()), 32, nullptr), BN_bin2bn(reinterpret_cast <const unsigned char*> (signature.constData()) + 32, 32, nullptr));

    result = ECDSA_do_verify(reinterpret_cast <const unsigned char*> (hash.constData()), hash.length(), value, key);

    ECDSA_SIG_free(value);
    EC_POINT_free(point);
    EC_KEY_free(key);

    return result == 1;
}

QByteArray Crypto::csrPublicKey(const QByteArray &csr)
{
    const unsigned char *pointer = reinterpret_cast <const unsigned char*> (csr.constData());
    X509_REQ *request = d2i_X509_REQ(nullptr, &pointer, csr.length());
    EVP_PKEY *key = request ? X509_REQ_get_pubkey(request) : nullptr;
    EC_KEY *ec = key ? EVP_PKEY_get1_EC_KEY(key) : nullptr;
    QByteArray result;

    if (ec)
    {
        result = pointData(EC_KEY_get0_group(ec), EC_KEY_get0_public_key(ec));
        EC_KEY_free(ec);
    }

    if (key)
        EVP_PKEY_free(key);

    if (request)
        X509_REQ_free(request);

    return result;
}

QByteArray Crypto::generateCertificate(quint64 rootCaId, quint64 fabricId, quint64 nodeId, const QByteArray &publicKey, const QByteArray &signerPrivateKey, const QByteArray &signerPublicKey, bool root)
{
    X509 *certificate = X509_new();
    QByteArray serial = randomData(8), hash = sha1(signerPublicKey), result;
    ASN1_OCTET_STRING *octet = ASN1_OCTET_STRING_new();
    AUTHORITY_KEYID *authority = AUTHORITY_KEYID_new();
    X509_EXTENSION *extension;
    X509V3_CTX context;
    BIGNUM *number;
    EVP_PKEY *key;
    unsigned char *der = nullptr;
    int length;

    serial[0] = serial.at(0) & 0x7F;
    number = BN_bin2bn(reinterpret_cast <const unsigned char*> (serial.constData()), serial.length(), nullptr);

    X509_set_version(certificate, 2);
    BN_to_ASN1_INTEGER(number, X509_get_serialNumber(certificate));
    BN_free(number);

    X509_gmtime_adj(X509_getm_notBefore(certificate), 0);
    X509_gmtime_adj(X509_getm_notAfter(certificate), CERTIFICATE_VALIDITY);

    addNameEntry(X509_get_issuer_name(certificate), MATTER_OID_RCAC_ID, rootCaId);

    if (root)
        addNameEntry(X509_get_subject_name(certificate), MATTER_OID_RCAC_ID, rootCaId);
    else
    {
        addNameEntry(X509_get_subject_name(certificate), MATTER_OID_NODE_ID, nodeId);
        addNameEntry(X509_get_subject_name(certificate), MATTER_OID_FABRIC_ID, fabricId);
    }

    key = ecPublicKey(publicKey);
    X509_set_pubkey(certificate, key);
    EVP_PKEY_free(key);

    X509V3_set_ctx(&context, certificate, certificate, nullptr, nullptr, 0);

    if (root)
    {
        addExtension(certificate, &context, NID_basic_constraints, "critical,CA:TRUE");
        addExtension(certificate, &context, NID_key_usage, "critical,keyCertSign,cRLSign");
    }
    else
    {
        ASN1_OCTET_STRING *constraints = ASN1_OCTET_STRING_new();
        unsigned char data[] = {0x30, 0x00};

        // CA = false must be encoded as empty sequence to match connectedhomeip TLV to X.509 converter
        ASN1_OCTET_STRING_set(constraints, data, sizeof(data));
        extension = X509_EXTENSION_create_by_NID(nullptr, NID_basic_constraints, 1, constraints);
        X509_add_ext(certificate, extension, -1);
        X509_EXTENSION_free(extension);
        ASN1_OCTET_STRING_free(constraints);

        addExtension(certificate, &context, NID_key_usage, "critical,digitalSignature");
        addExtension(certificate, &context, NID_ext_key_usage, "critical,serverAuth,clientAuth");
    }

    addExtension(certificate, &context, NID_subject_key_identifier, "hash");

    ASN1_OCTET_STRING_set(octet, reinterpret_cast <const unsigned char*> (hash.constData()), hash.length());
    authority->keyid = octet;
    extension = X509V3_EXT_i2d(NID_authority_key_identifier, 0, authority);
    X509_add_ext(certificate, extension, -1);
    X509_EXTENSION_free(extension);
    AUTHORITY_KEYID_free(authority);

    key = ecPrivateKey(signerPrivateKey);
    X509_sign(certificate, key, EVP_sha256());
    EVP_PKEY_free(key);

    length = i2d_X509(certificate, &der);
    result = QByteArray(reinterpret_cast <char*> (der), length);

    OPENSSL_free(der);
    X509_free(certificate);

    return result;
}

QByteArray Crypto::convertCertificate(const QByteArray &certificate)
{
    const unsigned char *pointer = reinterpret_cast <const unsigned char*> (certificate.constData());
    X509 *x509 = d2i_X509(nullptr, &pointer, certificate.length());
    const ASN1_BIT_STRING *string;
    const X509_ALGOR *algorithm;
    const EC_KEY *key;
    ECDSA_SIG *signature;
    BIGNUM *number;
    MatterTLV::Encoder encoder;
    QByteArray serial;
    struct tm notBefore, notAfter;
    int index;

    if (!x509)
        return QByteArray();

    number = ASN1_INTEGER_to_BN(X509_get0_serialNumber(x509), nullptr);
    serial = QByteArray(BN_num_bytes(number), 0);
    BN_bn2bin(number, reinterpret_cast <unsigned char*> (serial.data()));
    BN_free(number);

    ASN1_TIME_to_tm(X509_get0_notBefore(x509), &notBefore);
    ASN1_TIME_to_tm(X509_get0_notAfter(x509), &notAfter);

    key = EVP_PKEY_get0_EC_KEY(X509_get0_pubkey(x509));

    encoder.openStructure();
    encoder.encodeByteString(1, serial);
    encoder.encodeUnsignedInt(2, 1); // signature algorithm

    encoder.openList(3);
    convertName(X509_get_issuer_name(x509), encoder);
    encoder.closeContainer();

    encoder.encodeUnsignedInt(4, static_cast <quint32> (timegm(&notBefore) - TIME_OFFSET));
    encoder.encodeUnsignedInt(5, static_cast <quint32> (timegm(&notAfter) - TIME_OFFSET));

    encoder.openList(6);
    convertName(X509_get_subject_name(x509), encoder);
    encoder.closeContainer();

    encoder.encodeUnsignedInt(7, 1); // public key algorithm
    encoder.encodeUnsignedInt(8, 1); // elliptic curve
    encoder.encodeByteString(9, pointData(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key)));
    encoder.openList(10);

    if ((index = X509_get_ext_by_NID(x509, NID_basic_constraints, -1)) >= 0)
    {
        BASIC_CONSTRAINTS *constraints = reinterpret_cast <BASIC_CONSTRAINTS*> (X509V3_EXT_d2i(X509_get_ext(x509, index)));

        encoder.openStructure(1);
        encoder.encodeBool(1, constraints->ca != 0);
        encoder.closeContainer();

        BASIC_CONSTRAINTS_free(constraints);
    }

    if ((index = X509_get_ext_by_NID(x509, NID_key_usage, -1)) >= 0)
    {
        ASN1_BIT_STRING *usage = reinterpret_cast <ASN1_BIT_STRING*> (X509V3_EXT_d2i(X509_get_ext(x509, index)));
        quint16 value = 0;

        if (ASN1_BIT_STRING_get_bit(usage, 0))
            value |= 0x0001; // digital signature

        if (ASN1_BIT_STRING_get_bit(usage, 5))
            value |= 0x0020; // key certificate sign

        if (ASN1_BIT_STRING_get_bit(usage, 6))
            value |= 0x0040; // CRL sign

        // key usage must be encoded as 2-byte unsigned integer regardless of value
        value = qToLittleEndian(value);
        encoder.encodeRaw(QByteArray(1, 0x25).append(static_cast <char> (0x02)).append(reinterpret_cast <char*> (&value), sizeof(value)));

        ASN1_BIT_STRING_free(usage);
    }

    if ((index = X509_get_ext_by_NID(x509, NID_ext_key_usage, -1)) >= 0)
    {
        EXTENDED_KEY_USAGE *usage = reinterpret_cast <EXTENDED_KEY_USAGE*> (X509V3_EXT_d2i(X509_get_ext(x509, index)));

        encoder.openArray(3);

        for (int i = 0; i < sk_ASN1_OBJECT_num(usage); i++)
        {
            switch (OBJ_obj2nid(sk_ASN1_OBJECT_value(usage, i)))
            {
                case NID_server_auth: encoder.encodeUnsignedInt(-1, 1); break;
                case NID_client_auth: encoder.encodeUnsignedInt(-1, 2); break;
            }
        }

        encoder.closeContainer();
        EXTENDED_KEY_USAGE_free(usage);
    }

    if ((index = X509_get_ext_by_NID(x509, NID_subject_key_identifier, -1)) >= 0)
    {
        ASN1_OCTET_STRING *identifier = reinterpret_cast <ASN1_OCTET_STRING*> (X509V3_EXT_d2i(X509_get_ext(x509, index)));
        encoder.encodeByteString(4, QByteArray(reinterpret_cast <const char*> (ASN1_STRING_get0_data(identifier)), ASN1_STRING_length(identifier)));
        ASN1_OCTET_STRING_free(identifier);
    }

    if ((index = X509_get_ext_by_NID(x509, NID_authority_key_identifier, -1)) >= 0)
    {
        AUTHORITY_KEYID *identifier = reinterpret_cast <AUTHORITY_KEYID*> (X509V3_EXT_d2i(X509_get_ext(x509, index)));

        if (identifier->keyid)
            encoder.encodeByteString(5, QByteArray(reinterpret_cast <const char*> (ASN1_STRING_get0_data(identifier->keyid)), ASN1_STRING_length(identifier->keyid)));

        AUTHORITY_KEYID_free(identifier);
    }

    encoder.closeContainer();

    X509_get0_signature(&string, &algorithm, x509);
    pointer = ASN1_STRING_get0_data(string);
    signature = d2i_ECDSA_SIG(nullptr, &pointer, ASN1_STRING_length(string));

    if (signature)
    {
        const BIGNUM *r, *s;

        ECDSA_SIG_get0(signature, &r, &s);
        encoder.encodeByteString(11, signatureData(r, s));
        ECDSA_SIG_free(signature);
    }

    encoder.closeContainer();
    X509_free(x509);

    return encoder.data();
}

QByteArray Crypto::randomData(quint32 length)
{
    QByteArray data(length, 0);

    QRandomGenerator::system()->generate(reinterpret_cast <quint32*> (data.data()), reinterpret_cast <quint32*> (data.data() + (length & ~3u)));

    if (length & 3u)
    {
        quint32 value = QRandomGenerator::system()->generate();
        memcpy(data.data() + (length & ~3u), &value, length & 3u);
    }

    return data;
}

ECPoint::ECPoint(void) : m_point(EC_POINT_new(group())) {}

ECPoint::ECPoint(const ECPoint &other) : m_point(EC_POINT_dup(other.m_point, group())) {}

ECPoint::~ECPoint(void)
{
    if (!m_point)
        return;

    EC_POINT_free(m_point);
}

ECPoint &ECPoint::operator = (const ECPoint &other)
{
    if (this != &other)
        EC_POINT_copy(m_point, other.m_point);

    return *this;
}

bool ECPoint::fromData(const QByteArray &data)
{
    return EC_POINT_oct2point(group(), m_point, reinterpret_cast <const unsigned char*> (data.constData()), data.length(), nullptr) == 1;
}

QByteArray ECPoint::toData(void)
{
    return pointData(group(), m_point);
}

EC_GROUP *ECPoint::group(void)
{
    if (!s_group)
        s_group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    return s_group;
}

ECPoint ECPoint::generator(void)
{
    ECPoint result;
    EC_POINT_copy(result.m_point, EC_GROUP_get0_generator(group()));
    return result;
}

ECPoint ECPoint::multiply(const ECPoint &point, const BIGNUM *scalar)
{
    BN_CTX *context = BN_CTX_new();
    ECPoint result;

    EC_POINT_mul(group(), result.m_point, nullptr, point.m_point, scalar, context);
    BN_CTX_free(context);

    return result;
}

ECPoint ECPoint::add(const ECPoint &a, const ECPoint &b)
{
    BN_CTX *context = BN_CTX_new();
    ECPoint result;

    EC_POINT_add(group(), result.m_point, a.m_point, b.m_point, context);
    BN_CTX_free(context);

    return result;
}

ECPoint ECPoint::subtract(const ECPoint &a, const ECPoint &b)
{
    ECPoint point(b);
    EC_POINT_invert(group(), point.m_point, nullptr);
    return add(a, point);
}

BigNum::BigNum(void) : m_bn(BN_new()) {}

BigNum::BigNum(const QByteArray &data) : m_bn(BN_bin2bn(reinterpret_cast <const unsigned char*> (data.constData()), data.length(), nullptr)) {}

BigNum::BigNum(const BigNum &other) : m_bn(BN_dup(other.m_bn)) {}

BigNum::~BigNum(void)
{
    if (!m_bn)
        return;

    BN_free(m_bn);
}

BigNum &BigNum::operator = (const BigNum &other)
{
    if (this != &other)
        BN_copy(m_bn, other.m_bn);

    return *this;
}

QByteArray BigNum::toData(int length)
{
    QByteArray data;
    int size = BN_num_bytes(m_bn);

    if (!length)
        length = size;

    data = QByteArray(length, 0);
    BN_bn2bin(m_bn, reinterpret_cast <unsigned char*> (data.data()) + length - size);

    return data;
}

BigNum BigNum::mod(const BigNum &a, const BigNum &m)
{
    BN_CTX *context = BN_CTX_new();
    BigNum result;

    BN_mod(result.m_bn, a.m_bn, m.m_bn, context);
    BN_CTX_free(context);

    return result;
}

BigNum BigNum::order(void)
{
    BigNum result;
    EC_GROUP_get_order(ECPoint::group(), result.m_bn, nullptr);
    return result;
}

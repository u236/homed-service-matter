// NOT REWIEWED

#ifndef CRYPTO_H
#define CRYPTO_H

#define MATTER_OID_NODE_ID          "1.3.6.1.4.1.37244.1.1"
#define MATTER_OID_RCAC_ID          "1.3.6.1.4.1.37244.1.4"
#define MATTER_OID_FABRIC_ID        "1.3.6.1.4.1.37244.1.5"

#define MATTER_TAG_NODE_ID          0x11
#define MATTER_TAG_RCAC_ID          0x14
#define MATTER_TAG_FABRIC_ID        0x15

#define CERTIFICATE_VALIDITY        315360000
#define TIME_OFFSET                 946684800

#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <QByteArray>

namespace Crypto
{
    QByteArray pbkdf2(const QByteArray &password, const QByteArray &salt, quint32 iterations, quint32 length);
    QByteArray hkdf(const QByteArray &key, const QByteArray &salt, const QByteArray &info, quint32 length);
    QByteArray hmac(const QByteArray &key, const QByteArray &data);
    QByteArray sha1(const QByteArray &data);
    QByteArray sha256(const QByteArray &data);

    QByteArray encrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad, const QByteArray &data, quint8 tagLength = 16);
    QByteArray decrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad, const QByteArray &data, quint8 tagLength = 16);

    QByteArray sign(const QByteArray &privateKey, const QByteArray &data);
    bool verify(const QByteArray &publicKey, const QByteArray &data, const QByteArray &signature);

    QByteArray csrPublicKey(const QByteArray &csr);
    QByteArray generateCertificate(quint64 rootCaId, quint64 fabricId, quint64 nodeId, const QByteArray &publicKey, const QByteArray &signerPrivateKey, const QByteArray &signerPublicKey, bool root);
    QByteArray convertCertificate(const QByteArray &certificate);

    QByteArray randomData(quint32 length);
}

class ECPoint
{

public:

    ECPoint(void);
    ECPoint(const ECPoint &other);
    ~ECPoint(void);

    ECPoint &operator = (const ECPoint &other);

    inline EC_POINT *point(void) { return m_point; }

    bool fromData(const QByteArray &data);
    QByteArray toData(void);

    static EC_GROUP *group(void);
    static ECPoint generator(void);

    static ECPoint multiply(const ECPoint &point, const BIGNUM *scalar);
    static ECPoint add(const ECPoint &a, const ECPoint &b);
    static ECPoint subtract(const ECPoint &a, const ECPoint &b);

private:

    EC_POINT *m_point;
    static EC_GROUP *s_group;

};

class BigNum
{

public:

    BigNum(void);
    BigNum(const QByteArray &data);
    BigNum(const BigNum &other);
    ~BigNum(void);

    BigNum &operator = (const BigNum &other);

    inline BIGNUM *bn(void) { return m_bn; }
    QByteArray toData(int length = 0);

    static BigNum mod(const BigNum &a, const BigNum &m);
    static BigNum order(void);

private:

    BIGNUM *m_bn;

};

#endif

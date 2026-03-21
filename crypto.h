#ifndef CRYPTO_H
#define CRYPTO_H

#include <QByteArray>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

/*
    Crypto utilities for Matter protocol using OpenSSL:
    - PBKDF2-HMAC-SHA256: derive w0, w1 from passcode
    - HKDF-SHA256: key derivation for session keys
    - HMAC-SHA256: key confirmation in SPAKE2+
    - AES-128-CCM: message encryption/decryption
    - EC P-256: SPAKE2+ point operations
*/

namespace Crypto
{
    QByteArray pbkdf2(const QByteArray &password, const QByteArray &salt, quint32 iterations, quint32 keyLength);
    QByteArray hkdfSha256(const QByteArray &ikm, const QByteArray &salt, const QByteArray &info, quint32 length);
    QByteArray hmacSha256(const QByteArray &key, const QByteArray &data);
    QByteArray sha256(const QByteArray &data);

    QByteArray aesCcmEncrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad, const QByteArray &plaintext, quint8 tagLength = 16);
    QByteArray aesCcmDecrypt(const QByteArray &key, const QByteArray &nonce, const QByteArray &aad, const QByteArray &ciphertext, quint8 tagLength = 16);

    QByteArray sha1(const QByteArray &data);
    QByteArray ecdsaSign(const QByteArray &privateKey, const QByteArray &message);
    bool ecdsaVerify(const QByteArray &publicKey, const QByteArray &message, const QByteArray &signature);
    QByteArray parseCSRPublicKey(const QByteArray &derCSR);

    QByteArray generateX509Cert(quint64 rootCAId, quint64 fabricId, quint64 nodeId, const QByteArray &subjectPubKey, const QByteArray &signerPrivKey, const QByteArray &signerPubKey, bool isRCAC);
    QByteArray x509DerToMatterTLV(const QByteArray &derCert);

    QByteArray randomBytes(quint32 length);
}

/*
    EC P-256 point wrapper for SPAKE2+ operations.
    Matter uses NIST P-256 (secp256r1) curve.
*/

class ECPoint
{

public:

    ECPoint(void);
    ECPoint(const ECPoint &other);
    ~ECPoint(void);

    ECPoint &operator=(const ECPoint &other);

    bool isValid(void) const;
    bool setFromUncompressed(const QByteArray &data);
    QByteArray toUncompressed(void) const;

    static ECPoint generator(void);
    static ECPoint fromMultiply(const ECPoint &point, const BIGNUM *scalar);
    static ECPoint add(const ECPoint &a, const ECPoint &b);
    static ECPoint subtract(const ECPoint &a, const ECPoint &b);

    EC_POINT *point(void) const { return m_point; }

    static EC_GROUP *group(void);
    static void initGroup(void);

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

    BigNum &operator=(const BigNum &other);

    BIGNUM *bn(void) const { return m_bn; }
    QByteArray toByteArray(int length = 0) const;

    static BigNum mod(const BigNum &a, const BigNum &m);
    static BigNum fromOrder(void);

private:

    BIGNUM *m_bn;

};

#endif

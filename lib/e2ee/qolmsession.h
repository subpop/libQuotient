// SPDX-FileCopyrightText: 2021 Alexey Andreyev <aa13q@ya.ru>
//
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "e2ee/e2ee.h"
#include "e2ee/qolmmessage.h"
#include "e2ee/qolmaccount.h"

struct OlmSession;

namespace Quotient {

//! Either an outbound or inbound session for secure communication.
class QUOTIENT_API QOlmSession
{
public:
    ~QOlmSession();
    //! Creates an inbound session for sending/receiving messages from a received 'prekey' message.
    static QOlmExpected<QOlmSessionPtr> createInboundSession(
        QOlmAccount* account, const QOlmMessage& preKeyMessage);

    static QOlmExpected<QOlmSessionPtr> createInboundSessionFrom(
        QOlmAccount* account, const QString& theirIdentityKey,
        const QOlmMessage& preKeyMessage);

    static QOlmExpected<QOlmSessionPtr> createOutboundSession(
        QOlmAccount* account, const QByteArray& theirIdentityKey,
        const QByteArray& theirOneTimeKey);

    //! Serialises an `QOlmSession` to encrypted Base64.
    QByteArray pickle(const PicklingMode &mode) const;

    //! Deserialises from encrypted Base64 previously made with pickle()
    static QOlmExpected<QOlmSessionPtr> unpickle(QByteArray&& pickled,
                                                 const PicklingMode& mode);

    //! Encrypts a plaintext message using the session.
    QOlmMessage encrypt(const QByteArray& plaintext);

    //! Decrypts a message using this session. Decoding is lossy, meaning if
    //! the decrypted plaintext contains invalid UTF-8 symbols, they will
    //! be returned as `U+FFFD` (�).
    QOlmExpected<QByteArray> decrypt(const QOlmMessage &message) const;

    //! Get a base64-encoded identifier for this session.
    QByteArray sessionId() const;

    //! Checker for any received messages for this session.
    bool hasReceivedMessage() const;

    //! Checks if the 'prekey' message is for this in-bound session.
    bool matchesInboundSession(const QOlmMessage& preKeyMessage) const;

    //! Checks if the 'prekey' message is for this in-bound session.
    bool matchesInboundSessionFrom(
        const QString& theirIdentityKey, const QOlmMessage& preKeyMessage) const;

    friend bool operator<(const QOlmSession& lhs, const QOlmSession& rhs)
    {
        return lhs.sessionId() < rhs.sessionId();
    }

    friend bool operator<(const QOlmSessionPtr& lhs, const QOlmSessionPtr& rhs)
    {
        return *lhs < *rhs;
    }

    OlmErrorCode lastErrorCode() const;
    const char* lastError() const;

    OlmSession* raw() const { return m_session; }

    QOlmSession(OlmSession* session);
private:
    //! Helper function for creating new sessions and handling errors.
    static OlmSession* create();
    static QOlmExpected<QOlmSessionPtr> createInbound(
        QOlmAccount* account, const QOlmMessage& preKeyMessage,
        bool from = false, const QString& theirIdentityKey = "");
    OlmSession* m_session;
};
} //namespace Quotient

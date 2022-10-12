// SPDX-FileCopyrightText: Tobias Fella <fella@posteo.de>
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "mxcreply.h"

#include <QtCore/QBuffer>
#include "room.h"

#ifdef Quotient_E2EE_ENABLED
#include "events/filesourceinfo.h"
#endif

using namespace Quotient;

class MxcReply::Private
{
public:
    QNetworkReply* m_reply = nullptr;
    QIODevice* m_device = nullptr;
#ifdef Quotient_E2EE_ENABLED
    Omittable<EncryptedFileMetadata> m_encryptedFile = none;
#endif

    void prepareForReading(MxcReply* q, QIODevice* source)
    {
        m_device = source;
        q->setOpenMode(ReadOnly);
    }
};

MxcReply::MxcReply(DeferredFlag) : d(makeImpl<Private>()) {}

MxcReply::MxcReply(QNetworkReply* reply) : MxcReply(Deferred)
{
    setNetworkReply(reply);
}

MxcReply::MxcReply(QNetworkReply* reply, Room* room, const QString& eventId)
    : MxcReply(Deferred)
{
#ifdef Quotient_E2EE_ENABLED
    if (auto eventIt = room->findInTimeline(eventId);
        eventIt != room->historyEdge()) {
        if (auto event = eventIt->viewAs<RoomMessageEvent>()) {
            if (auto* efm = std::get_if<EncryptedFileMetadata>(
                    &event->content()->fileInfo()->source))
                d->m_encryptedFile = *efm;
        }
    }
#endif
    setNetworkReply(reply);
}

void MxcReply::setNetworkReply(QNetworkReply* newReply)
{
    d->m_reply = newReply;
    d->m_reply->setParent(this);
    // Prepare for reading upfront if Quotient is built without E2EE or if it's
    // built with E2EE but that specific payload has no associated encrypted
    // file metadata
#ifdef Quotient_E2EE_ENABLED
    if (!d->m_encryptedFile)
#endif
        d->prepareForReading(this, d->m_reply);

    connect(d->m_reply, &QNetworkReply::finished, this, [this] {
        setError(d->m_reply->error(), d->m_reply->errorString());
#ifdef Quotient_E2EE_ENABLED
        if (d->m_encryptedFile.has_value()) {
            auto buffer = new QBuffer(this);
            buffer->setData(
                decryptFile(d->m_reply->readAll(), *d->m_encryptedFile));
            buffer->open(ReadOnly);
            d->prepareForReading(this, buffer);
        }
#endif
        emit finished();
    });
}

MxcReply::MxcReply(FailedFlag)
    : d(ZeroImpl<Private>())
{
    static const auto BadRequestPhrase = tr("Bad Request");
    QMetaObject::invokeMethod(this, [this]() {
            setAttribute(QNetworkRequest::HttpStatusCodeAttribute, 400);
            setAttribute(QNetworkRequest::HttpReasonPhraseAttribute,
                         BadRequestPhrase);
            setError(QNetworkReply::ProtocolInvalidOperationError,
                     BadRequestPhrase);
            setFinished(true);
            emit errorOccurred(QNetworkReply::ProtocolInvalidOperationError);
            emit finished();
        }, Qt::QueuedConnection);
}

qint64 MxcReply::readData(char *data, qint64 maxSize)
{
    return d->m_device->read(data, maxSize);
}

void MxcReply::abort()
{
    if (d->m_reply)
        d->m_reply->abort();
}

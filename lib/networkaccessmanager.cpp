// SPDX-FileCopyrightText: 2018 Kitsune Ral <kitsune-ral@users.sf.net>
// SPDX-License-Identifier: LGPL-2.1-or-later

#include "networkaccessmanager.h"

#include "connection.h"
#include "room.h"
#include "accountregistry.h"
#include "mxcreply.h"
#include "csapi/content-repo.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QThread>
#include <QtCore/QSettings>
#include <QtNetwork/QNetworkReply>

using namespace Quotient;

class NetworkAccessManager::Private {
public:
    QNetworkReply* createImplRequest(Operation op,
                                     const QNetworkRequest& mxcRequest,
                                     const Connection* connection) const
    {
        const auto mxcUrl = mxcRequest.url();
        Q_ASSERT(mxcUrl.scheme() == "mxc" && !mxcUrl.isRelative());
        const auto httpUrl = GetContentJob::makeRequestUrl(
            connection->homeserver(), mxcUrl.authority(), mxcUrl.path().mid(1));
        QNetworkRequest httpRequest(mxcRequest);
        httpRequest.setUrl(httpUrl);
        return q->createRequest(op, httpRequest);
    }

    NetworkAccessManager* q;
    QList<QSslError> ignoredSslErrors{};
    static inline std::atomic_bool allowDirectMediaRequests = false;
};

NetworkAccessManager::NetworkAccessManager(QObject* parent)
    : QNetworkAccessManager(parent), d(makeImpl<Private>(this))
{}

QList<QSslError> NetworkAccessManager::ignoredSslErrors() const
{
    return d->ignoredSslErrors;
}

void NetworkAccessManager::ignoreSslErrors(bool ignore) const
{
    if (ignore) {
        connect(this, &QNetworkAccessManager::sslErrors, this,
                [](QNetworkReply* reply) { reply->ignoreSslErrors(); });
    } else {
        disconnect(this, &QNetworkAccessManager::sslErrors, this, nullptr);
    }
}

void NetworkAccessManager::allowDirectMediaRequests(bool allow)
{
    Private::allowDirectMediaRequests = allow;
}

bool NetworkAccessManager::directMediaRequestsAllowed()
{
    return Private::allowDirectMediaRequests;
}

void NetworkAccessManager::addIgnoredSslError(const QSslError& error)
{
    d->ignoredSslErrors << error;
}

void NetworkAccessManager::clearIgnoredSslErrors()
{
    d->ignoredSslErrors.clear();
}

NetworkAccessManager* NetworkAccessManager::instance()
{
    thread_local auto* nam = [] {
        auto* namInit = new NetworkAccessManager();
        connect(QThread::currentThread(), &QThread::finished, namInit,
                &QObject::deleteLater);
        return namInit;
    }();
    return nam;
}

QNetworkReply* NetworkAccessManager::createRequest(
    Operation op, const QNetworkRequest& request, QIODevice* outgoingData)
{
    const auto& mxcUrl = request.url();
    if (mxcUrl.scheme() == "mxc") {
        const QUrlQuery query(mxcUrl.query());
        const auto accountId = query.queryItemValue(QStringLiteral("user_id"));
        if (accountId.isEmpty()) {
            if (!directMediaRequestsAllowed()) {
                qCWarning(NETWORK) << "No connection specified";
                return new MxcReply();
            }
            // Best effort with an unauthenticated request directly to the media
            // homeserver (rather than via own homeserver)
            auto* mxcReply = new MxcReply(MxcReply::Deferred);
            auto* mediaServerConnection = new Connection(mxcReply);
            connect(mediaServerConnection, &Connection::homeserverChanged,
                    mxcReply,
                    [this, mxcReply, op, request, mediaServerConnection] {
                        mxcReply->setNetworkReply(d->createImplRequest(
                            op, request, mediaServerConnection));
                        mediaServerConnection->deleteLater();
                    });
            mediaServerConnection->resolveServer("@:" % request.url().host());
            return mxcReply;
        }
        const auto* const connection = Accounts.get(accountId);
        if (!connection) {
            qCWarning(NETWORK) << "Connection" << accountId << "not found";
            return new MxcReply();
        }
        if (const auto roomId =
                query.queryItemValue(QStringLiteral("room_id"));
            !roomId.isEmpty()) {
            if (auto room = connection->room(roomId))
                return new MxcReply(
                    d->createImplRequest(op, request, connection), room,
                    query.queryItemValue(QStringLiteral("event_id")));

            qCWarning(NETWORK) << "Room" << roomId << "not found";
            return new MxcReply();
        }
        return new MxcReply(
            d->createImplRequest(op, request, connection));
    }
    auto reply = QNetworkAccessManager::createRequest(op, request, outgoingData);
    reply->ignoreSslErrors(d->ignoredSslErrors);
    return reply;
}

QStringList NetworkAccessManager::supportedSchemesImplementation() const
{
    auto schemes = QNetworkAccessManager::supportedSchemesImplementation();
    schemes += QStringLiteral("mxc");
    return schemes;
}

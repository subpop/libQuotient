// SPDX-FileCopyrightText: 2018 Kitsune Ral <kitsune-ral@users.sf.net>
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "util.h"

#include <QtNetwork/QNetworkAccessManager>

namespace Quotient {

class QUOTIENT_API NetworkAccessManager : public QNetworkAccessManager {
    Q_OBJECT
public:
    explicit NetworkAccessManager(QObject* parent = nullptr);

    static void allowDirectMediaRequests(bool allow = true);
    static bool directMediaRequestsAllowed();

    QList<QSslError> ignoredSslErrors() const;
    void addIgnoredSslError(const QSslError& error);
    void clearIgnoredSslErrors();
    void ignoreSslErrors(bool ignore = true) const;

    /** Get a pointer to the singleton */
    static NetworkAccessManager* instance();

public Q_SLOTS:
    QStringList supportedSchemesImplementation() const;

private:
    QNetworkReply* createRequest(Operation op, const QNetworkRequest& request,
                                 QIODevice* outgoingData = Q_NULLPTR) override;

    class Private;
    ImplPtr<Private> d;
};
} // namespace Quotient

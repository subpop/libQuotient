// SPDX-FileCopyrightText: Tobias Fella <fella@posteo.de>
// SPDX-License-Identifier: LGPL-2.1-or-later

#pragma once

#include "util.h"

#include <QtNetwork/QNetworkReply>

namespace Quotient {
class Room;

class QUOTIENT_API MxcReply : public QNetworkReply
{
    Q_OBJECT
public:
    enum DeferredFlag { Deferred };
    enum FailedFlag { Failed };

    explicit MxcReply(DeferredFlag);
    explicit MxcReply(FailedFlag);
    explicit MxcReply(QNetworkReply *reply);
    MxcReply(QNetworkReply* reply, Room* room, const QString& eventId);

    void setNetworkReply(QNetworkReply* newReply);

public Q_SLOTS:
    void abort() override;

protected:
    qint64 readData(char *data, qint64 maxSize) override;

private:
    class Private;
    ImplPtr<Private> d;
};
} // namespace Quotient

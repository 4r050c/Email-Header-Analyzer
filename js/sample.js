/* A hand-crafted, fully fictional sample header set (no real accounts/IPs)
   used for the "Load Sample" button so the tool is demonstrable with zero
   setup. Exercises: a 4-hop relay chain with one flagged delay, SPF/DKIM/DMARC
   all passing with relaxed alignment, a DKIM-Signature, and an ESP signature. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});

  EHA.SAMPLE_HEADERS = `Delivered-To: jane.doe@example.com
Received: by 2002:a05:6402:1a8b:0:0:0:0 with SMTP id ba11csp7719274edb;
        Fri, 17 Jul 2026 08:18:45 -0700 (PDT)
X-Google-Smtp-Source: AGHT+IH3Kx9pQZbC7exampleBase64OpaqueTokenValueString==
X-Received: by 2002:a17:907:7d94:b0:a12:3456:789a with SMTP id abcd1234plf.55.2026.07.17.08.18.44;
        Fri, 17 Jul 2026 08:18:44 -0700 (PDT)
Return-Path: <bounce+7f3a9c@mailer.notify-example.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id o5-20020a170907abcdb.20.2026.07.17.08.18.44
        for <jane.doe@example.com>
        (Google Transport Security);
        Fri, 17 Jul 2026 08:18:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of bounce+7f3a9c@mailer.notify-example.com designates 192.0.2.44 as permitted sender) client-ip=192.0.2.44;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@notify-example.com header.s=selector1 header.b=abcXYZ12;
       spf=pass (google.com: domain of bounce+7f3a9c@mailer.notify-example.com designates 192.0.2.44 as permitted sender) smtp.mailfrom=bounce+7f3a9c@mailer.notify-example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=notify-example.com
Received: from relay07.notify-example.com (relay07.notify-example.com [192.0.2.44])
        by mail-sor-f41.google.com with SMTP id o5-2026071720example
        for <jane.doe@example.com>;
        Fri, 17 Jul 2026 08:18:42 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=notify-example.com;
        s=selector1; h=from:to:subject:date:message-id:mime-version:content-type;
        bh=ExampleBodyHashValue1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ=;
        b=ExampleSignatureBase64ValueThatWouldNormallyBeMuchLongerThanThisPlaceholder123456789==
Received: from app-worker-12.notify-example.com (app-worker-12.notify-example.com [10.0.4.12])
        by relay07.notify-example.com with ESMTP id w4-app12example
        for <jane.doe@example.com>;
        Fri, 17 Jul 2026 08:12:21 -0700 (PDT)
Message-ID: <20260717151221.abc123.worker12@notify-example.com>
Date: Fri, 17 Jul 2026 08:12:21 -0700
ARC-Seal: i=1; a=rsa-sha256; t=1752765521; cv=none; d=notify-example.com; s=arc-selector;
        b=ArcSealExampleSignatureValuePlaceholder1234567890abcdefghij==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=notify-example.com; s=arc-selector;
        h=from:to:subject:date:message-id; bh=ArcBodyHashExampleValue1234567890=;
        b=ArcMsgSigExampleValuePlaceholderabcdefghij1234567890==
ARC-Authentication-Results: i=1; mx.google.com;
        dkim=pass header.i=@notify-example.com header.s=selector1;
        spf=pass smtp.mailfrom=bounce+7f3a9c@mailer.notify-example.com;
        dmarc=pass header.from=notify-example.com
From: "Example Notifications" <notifications@notify-example.com>
Reply-To: support@notify-example.com
To: Jane Doe <jane.doe@example.com>
Subject: =?UTF-8?B?WW91ciB3ZWVrbHkgc3VtbWFyeSBpcyByZWFkeSDwn5OK?=
List-Id: Example Weekly Digest <weekly.notify-example.com>
List-Unsubscribe: <https://notify-example.com/unsub?u=7f3a9c>, <mailto:unsub@notify-example.com>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Precedence: bulk
X-Spam-Status: No, score=-2.1 required=5.0 tests=DKIM_SIGNED,SPF_PASS
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-Mailer: ExampleMailer 3.2

<html><body><p>Hi Jane, here is your weekly summary...</p></body></html>`;
})(window);

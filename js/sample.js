/* Sample headers for the "Load Sample" button. The message itself is
   fabricated (fictional people, fabricated IDs/signature values), but sender
   domains, mail-server hostnames, IPs, and the DKIM selector are REAL
   Google/Gmail infrastructure -- MxToolbox live lookups against a fictional
   domain fail (their API answers 401 for nonexistent domains), so a
   demonstrable sample must reference resolvable ones.
   Exercises: a 4-hop relay chain with one flagged delay, SPF/DKIM/DMARC all
   passing with alignment, an ARC instance, RFC 2047 subject decoding,
   Google-Groups-style list headers, and per-hop TLS classification. */
(function (global) {
  "use strict";
  const EHA = global.EHA || (global.EHA = {});

  EHA.SAMPLE_HEADERS = `Delivered-To: jane.doe.demo@gmail.com
Received: by 2002:a05:6402:1a8b:0:0:0:0 with SMTP id ba11csp7719274edb;
        Fri, 17 Jul 2026 08:18:45 -0700 (PDT)
X-Google-Smtp-Source: AGHT+IH3Kx9pQZbC7exampleBase64OpaqueTokenValueString==
X-Received: by 2002:a17:907:7d94:b0:a12:3456:789a with SMTP id abcd1234plf.55.2026.07.17.08.18.44;
        Fri, 17 Jul 2026 08:18:44 -0700 (PDT)
Return-Path: <eha.demo.sender@gmail.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id o5-20020a170907abcdb.20.2026.07.17.08.18.44
        for <jane.doe.demo@gmail.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 17 Jul 2026 08:18:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of eha.demo.sender@gmail.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=abcXYZ12;
       spf=pass (google.com: domain of eha.demo.sender@gmail.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=eha.demo.sender@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
ARC-Seal: i=1; a=rsa-sha256; t=1752765521; cv=none; d=google.com; s=arc-20240605;
        b=ArcSealExampleSignatureValuePlaceholder1234567890abcdefghij==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=from:to:subject:date:message-id; bh=ArcBodyHashExampleValue1234567890=;
        b=ArcMsgSigExampleValuePlaceholderabcdefghij1234567890==
ARC-Authentication-Results: i=1; mx.google.com;
        dkim=pass header.i=@gmail.com header.s=20230601;
        spf=pass smtp.mailfrom=eha.demo.sender@gmail.com;
        dmarc=pass header.from=gmail.com
Received: from mail-yw1-f74.google.com (mail-yw1-f74.google.com [209.85.128.74])
        by mail-sor-f41.google.com with ESMTPS id w4-relay-example
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128)
        for <jane.doe.demo@gmail.com>;
        Fri, 17 Jul 2026 08:18:42 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=gmail.com;
        s=20230601; h=from:to:subject:date:message-id:mime-version:content-type;
        bh=ExampleBodyHashValue1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ=;
        b=ExampleSignatureBase64ValueThatWouldNormallyBeMuchLongerThanThisPlaceholder123456789==
Received: from [10.12.4.8] (unknown [10.12.4.8])
        by mail-yw1-f74.google.com with ESMTP id submission-example
        for <jane.doe.demo@gmail.com>;
        Fri, 17 Jul 2026 08:12:21 -0700 (PDT)
Message-ID: <20260717151221.abc123.demo@mail.gmail.com>
Date: Fri, 17 Jul 2026 08:12:21 -0700
From: "EHA Demo Sender" <eha.demo.sender@gmail.com>
To: Jane Doe <jane.doe.demo@gmail.com>
Subject: =?UTF-8?B?WW91ciB3ZWVrbHkgc3VtbWFyeSBpcyByZWFkeSDwn5OK?=
List-Id: EHA Demo Group <eha-demo.googlegroups.com>
List-Unsubscribe: <https://groups.google.com/g/eha-demo/subscribe>, <mailto:googlegroups-manage+unsubscribe@googlegroups.com>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
Precedence: list
X-Spam-Status: No, score=-2.1 required=5.0 tests=DKIM_SIGNED,DKIM_VALID,SPF_PASS
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-Mailer: ExampleMailer 3.2

<html><body><p>Hi Jane, here is your weekly summary...</p></body></html>`;
})(window);

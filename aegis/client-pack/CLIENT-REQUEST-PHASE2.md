# Money and server protection, phase 2: what we need from you

**To:** <Client> technology lead / database administrator · **Cc:** <Client> legal / compliance
**From:** <Assessor> · **Engagement:** <ENG-ref>, under NDA <NDA-ref> and authorization letter <AUTH-ref>
**Follows:** our earlier request for the read-only database access

## What phase 2 adds

The database check shows whether your wallet's own records add up. Phase 2 checks three more things:

1. **M-Pesa check.** We compare what M-Pesa really received and paid out (your Safaricom statement) with what your
   system was told (the payment messages your server receives) and with what your wallets were credited. This catches
   fake "payment successful" messages, payments that were replayed or had their amount changed, deposits credited
   after the customer cancelled, and withdrawals that were paid out *and* refunded. A forged deposit can balance
   perfectly in your own books. Only this comparison shows it.
2. **Server health check.** We check how the server running the betting system is set up. For example: is the
   database reachable from outside, are passwords or backups sitting in a folder anyone can download, is the system
   still getting security updates, are there signs someone has left a back door.
3. **Change alarm.** We take a fingerprint of your settlement and payment code, server access settings, and the
   structure of your money tables. You get an alert if anything changes that your team has not approved.

**As before, we only read.** We never change, fix, restart or move anything. Every action is recorded in a
tamper-evident log that your legal team receives with the report.

## What we need from you

**For the M-Pesa check**
- **The M-Pesa statement:** export the organisation statement for your paybill/till from the M-Pesa portal as
  **CSV**, for the period we agree. For ongoing monitoring, a daily export saved to an agreed folder.
- **Payment message log:** the raw messages your server receives from Safaricom (Daraja callbacks for STK push,
  paybill confirmations and withdrawal results), **including the sender's IP address and the time received**. This
  can be a log folder or a database table. If you do not keep these today, we will show your developers the one-line
  change that starts recording them.
- Confirm which column in your wallet table holds the **M-Pesa receipt number** for deposits *and* withdrawals, and
  how a refunded withdrawal points back to the original one. We add both to the confirmation sheet you already signed.

**For the server health check and the change alarm** (choose one)
- **Option A, install (recommended for ongoing protection):** a small read-only program on the betting server. It
  needs Python 3.11 or newer and a dedicated system account. We give your administrator the exact install steps and
  the schedule entry (e.g. once an hour). For a complete check-up it needs to *read* system settings, which on Linux
  normally means running with read-only administrator rights.
- **Option B, one-off:** your administrator runs the check once while we watch, or gives us a copy of the server's
  configuration folders. No installation.

**Please also confirm in writing**
- The server names and folders in scope (for example the application folder, the web server and SSH settings).
- Who may **approve changes** after a deployment (name and role). Approvals are recorded as evidence.
- If you use **MySQL**: whether your DBA will schedule a nightly "structure only" export of the database (we supply
  the one-line command). MySQL only shows database triggers to accounts that could also create them, and we do not
  ask for that right. The nightly export lets the change alarm watch triggers without it.
- Where alerts should go (email or a Slack/Teams channel), and the 24-hour contact for critical findings.

## Your data

- The M-Pesa statement includes customer phone numbers. We use them only to match payments, keep the file on the
  agreed machine, and delete working copies at the end of the engagement as agreed in the NDA.
- The server check reads settings but **never records passwords or API keys**: the report shows only *which* file
  holds a secret and *which* setting names, never the values.
- At the end of the engagement your administrator removes the program and the account using the steps we provide.

## What you get

- A report covering every mismatch between M-Pesa, the payment messages and the wallets, with receipt numbers,
  transaction numbers and the amount at risk.
- A server health report in plain language, with the fix for each item.
- Optional: hourly monitoring of all of the above, with one alert channel. You hear about **new** problems only, and
  about any part of the check that stopped working.

# Money-integrity check: what we need from you

**To:** <Client> technology lead / database administrator · **Cc:** <Client> legal / compliance
**From:** <Assessor> · **Engagement:** <ENG-ref>, under NDA <NDA-ref> and authorization letter <AUTH-ref>

## What we will do

We will check that the money in your system adds up. Every winnings credit should match a bet that really won.
No bet should be paid twice. Every M-Pesa receipt should be credited once only. Every wallet balance should equal
its transactions. Later, the same check can run every hour and alert your team when something new goes wrong,
including when old wallet records are edited or deleted.

**We only read. We never change, fix or move anything.** Every action we take is recorded in a tamper-evident log
that your legal team receives with the report.

## What we need from you: pick one option

**Option A: read-only database login (recommended for ongoing monitoring)**

1. Tell us the database type (MySQL/MariaDB, PostgreSQL, SQL Server, Oracle) and the host we connect to.
2. **Week 1, mapping:** a temporary read-only login that can see the betting schema, so we can identify the bets,
   wallet transaction and wallet balance tables. You can remove it after step 3.
3. We send you a **one-page confirmation sheet** listing exactly which tables and columns we read, and what we
   understand each status code to mean (for example "BET_WIN = winnings"). Your technical owner corrects it and
   signs it.
4. **From then on:** we give you a short SQL script that creates a login able to read **only those confirmed
   columns**. It cannot see customer names, phone numbers or ID numbers, and it cannot change data. Your DBA reviews
   the script and runs it. The same script includes the lines that remove the login at the end of the engagement.

**Option B: data export (no access to your systems at all)**

Export the confirmed columns of the three tables to CSV files (we give you the exact commands) and hand them to us
securely. We run the same checks on the files. This suits a one-time audit. Ongoing monitoring needs Option A or a
regular export.

## What we need confirmed in writing

- The databases and hosts in scope, and the **start and end dates** of the authorization.
- The name of the person who authorizes the work, and the person who signs the mapping sheet.
- Where alerts should go (an email address or a Slack/Teams channel webhook), if you want ongoing monitoring.
- A contact we can call immediately if we find a critical problem, for example winnings being paid on lost bets.

## Your data

- **Data minimisation (Kenya Data Protection Act, 2019):** we read money columns and an internal customer key only.
  Personal details stay in tables and columns our login cannot read.
- **Evidence:** results are stored only on the agreed machine. Passwords are never written to disk or logs.
- **End of engagement:** you remove the login with the script we provide. We hand over the full audit log and
  report, then delete working copies as agreed in the NDA.

## What you get

- A report of every money problem found, with the bet and transaction numbers and the amount at risk, in plain
  language your finance and legal teams can act on.
- A tamper-evident record of exactly what we did and when.
- Optional: an hourly watchdog that alerts your team to new problems, edited records, or the check itself failing.

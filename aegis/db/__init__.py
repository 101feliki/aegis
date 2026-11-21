"""
AEGIS database layer - identify any database, read it safely, understand its layout.

    identify.py   - what kind of database is this? (URL, file, or live host:port)
    connect.py    - one read-only interface over every engine (refuses writes)
    schemamap.py  - which tables/columns hold bets, wallet transactions, balances
"""

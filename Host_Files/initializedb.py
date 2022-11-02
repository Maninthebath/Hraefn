#!/usr/bin/python3

import sqlite3

con = sqlite3.connect("bots.db")

cur = con.cursor()

cur.execute("CREATE TABLE bots(ip_address, os)")

result = cur.execute("SELECT name FROM sqlite_master")

print(result.fetchone())

cur.execute("CREATE TABLE bots(ip_address, os)")

con.commit()

con.close()

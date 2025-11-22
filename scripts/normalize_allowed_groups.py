#!/usr/bin/env python3
import sqlite3
import os

DB = os.path.join(os.path.dirname(__file__), '..', 'data', 'flowcase.db')
DB = os.path.abspath(DB)

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row
cur = con.cursor()

# Build mapping display_name -> id
cur.execute('SELECT id, display_name FROM "group"')
rows = cur.fetchall()
name_to_id = {r['display_name']: r['id'] for r in rows}

# Process droplets
cur.execute('SELECT id, allowed_groups FROM droplet')
droplets = cur.fetchall()
updated = 0
for d in droplets:
    ag = d['allowed_groups']
    if not ag:
        continue
    tokens = [t.strip() for t in ag.split(',') if t.strip()]
    new_tokens = []
    changed = False
    for t in tokens:
        if t in name_to_id:
            new_tokens.append(name_to_id[t])
            changed = True
        else:
            new_tokens.append(t)
    if changed:
        new_val = ','.join(new_tokens)
        cur.execute('UPDATE droplet SET allowed_groups = ? WHERE id = ?', (new_val, d['id']))
        updated += 1

con.commit()
con.close()
print(f"Normalized allowed_groups for {updated} droplets")

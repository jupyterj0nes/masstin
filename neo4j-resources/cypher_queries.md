# Neo4j and Cypher Resources

## Important: Data Transformations

When masstin loads data into Neo4j, certain character transformations are applied due to Cypher language restrictions:

- **Dots (`.`) are replaced with underscores (`_`)** — e.g., `10.10.1.50` becomes `10_10_1_50`
- **Hyphens (`-`) are replaced with underscores (`_`)** — e.g., `SRV-FILE01` becomes `SRV_FILE01`
- **Spaces are replaced with underscores (`_`)**
- **All text is converted to UPPERCASE**
- **The `@` symbol and everything after it is removed** from usernames

Keep this in mind when writing Cypher queries — use the transformed values (e.g., `WS_HR02` instead of `WS-HR02`, `10_10_1_80` instead of `10.10.1.80`).

## Setting Up Neo4j

1. Download and install Neo4j from the [Neo4j Download Page](https://neo4j.com/download/)
2. Create a new database with a username and password
3. Ensure the database is running — masstin communicates via Bolt, typically at `localhost:7687`
4. Access Neo4j Browser at `http://localhost:7474`

**Tip:** Disable the option to automatically expand nodes in Neo4j Browser settings to avoid overloading the visualization.

## Cypher Queries

### 1) View all lateral movement

The most basic query — shows the entire graph with all connections:

```cypher
MATCH (h1:host)-[r]->(h2:host)
RETURN h1, r, h2
```

### 2) Filter by time range

This is the most powerful feature of masstin's Neo4j integration. Since masstin groups connections by source, destination, user, and logon type — and stores the earliest timestamp — filtering by time range automatically removes all previously established connections, revealing only new lateral movement in that window.

This is critical during incident response: if you know the attacker gained access on March 12th, filtering from that date forward shows you only the connections that appeared during the attack, cutting through the noise of months of legitimate activity.

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE datetime(r.time) >= datetime("2026-03-12T00:00:00.000000000Z")
  AND datetime(r.time) <= datetime("2026-03-13T00:00:00.000000000Z")
RETURN h1, r, h2
ORDER BY datetime(r.time)
```

### 3) Filter by time range excluding machine accounts

Machine accounts (ending in `$`) and connections without a resolved user (`NO_USER`) generate significant noise. This query filters them out to focus on human-initiated lateral movement:

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE datetime(r.time) >= datetime("2026-03-12T00:00:00.000000000Z")
  AND datetime(r.time) <= datetime("2026-03-13T00:00:00.000000000Z")
  AND NOT r.target_user_name ENDS WITH '$'
  AND NOT r.target_user_name = 'NO_USER'
RETURN h1, r, h2
ORDER BY datetime(r.time)
```

### 4) RDP-only connections (logon type 10)

Isolate Remote Desktop connections, which are often the primary method of interactive lateral movement:

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE datetime(r.time) >= datetime("2026-03-12T00:00:00.000000000Z")
  AND datetime(r.time) <= datetime("2026-03-13T00:00:00.000000000Z")
  AND NOT r.target_user_name ENDS WITH '$'
  AND r.logon_type = '10'
RETURN h1, r, h2
ORDER BY datetime(r.time)
```

### 5) Network logons only (logon type 3 — SMB, PsExec, WMI)

Logon type 3 captures SMB share access, PsExec execution, WMI remote commands, and similar network-based lateral movement:

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE datetime(r.time) >= datetime("2026-03-12T00:00:00.000000000Z")
  AND datetime(r.time) <= datetime("2026-03-13T00:00:00.000000000Z")
  AND NOT r.target_user_name ENDS WITH '$'
  AND r.logon_type = '3'
RETURN h1, r, h2
ORDER BY datetime(r.time)
```

### 6) Service accounts by naming convention

If your organization uses a naming convention for service accounts (e.g., `SVC_`), you can isolate their activity to verify whether it's legitimate:

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE datetime(r.time) >= datetime("2026-03-10T00:00:00.000000000Z")
  AND datetime(r.time) <= datetime("2026-03-14T00:00:00.000000000Z")
  AND (
    r.target_user_name STARTS WITH 'SVC'
    OR r.subject_user_name STARTS WITH 'SVC'
  )
RETURN h1, r, h2
ORDER BY datetime(r.time)
```

### 7) Filter by specific users, hosts, and IPs

When you've identified suspicious accounts or machines, use this query to trace their complete activity. Remember to use the transformed values (underscores, uppercase):

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE datetime(r.time) >= datetime("2026-03-12T00:00:00.000000000Z")
  AND datetime(r.time) <= datetime("2026-03-13T00:00:00.000000000Z")
  AND NOT r.target_user_name ENDS WITH '$'
  AND NOT r.target_user_name = 'NO_USER'
  AND r.logon_type IN ['3', '10']
  AND (
    (h1.name = 'WS_HR02' OR h2.name = 'WS_HR02')
    OR r.target_user_name IN ['ADM_DOMAIN', 'M_LOPEZ']
    OR r.subject_user_name IN ['ADM_DOMAIN', 'M_LOPEZ']
    OR r.src_ip IN ['10_99_88_77', '10_10_1_80']
  )
RETURN h1, r, h2
ORDER BY datetime(r.time)
```

### 8) Find all machines a specific user touched

Trace the complete path of a single user through the network:

```cypher
MATCH (h1:host)-[r]->(h2:host)
WHERE r.target_user_name = 'ADM_DOMAIN'
RETURN h1, r, h2
ORDER BY datetime(r.time)
```

### 9) Find the most connected nodes (potential targets or pivots)

Identify which machines have the most incoming connections — these are either high-value targets or pivot points:

```cypher
MATCH (h1:host)-[r]->(h2:host)
RETURN h2.name AS target, COUNT(r) AS connections
ORDER BY connections DESC
LIMIT 10
```

### 10) Temporal path between two hosts

This is one of the most powerful queries for incident reconstruction. It finds all paths between two hosts where **each hop is chronologically later than the previous one** — giving you the actual attack chain as it happened in time:

```cypher
MATCH path = (start:host {name:'10_99_88_77'})-[*]->(end:host {name:'SRV_BACKUP'})
WHERE ALL(i IN range(0, size(relationships(path))-2)
  WHERE datetime(relationships(path)[i].time) < datetime(relationships(path)[i+1].time))
RETURN path
ORDER BY length(path)
LIMIT 5
```

Replace the start and end host names with your own. The result shows the attacker's progression through the network, validated temporally:

<div align="center">
  <img src="neo4j-resources/temporal_path.png" alt="Temporal path showing attack chain"/>
</div>

For more Cypher queries and detailed documentation, visit the [Neo4j and Cypher guide](https://weinvestigateanything.com/en/tools/neo4j-cypher-visualization/) at We Investigate Anything.

For more information on the Cypher language, refer to the [official Cypher documentation](https://neo4j.com/docs/cypher-manual/current/).

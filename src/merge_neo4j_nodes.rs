use neo4rs::*;
use futures::stream::*;
use rpassword;

/// Merge two `:host` nodes in a Neo4j graph: transfer every relationship
/// touching `old` to `new`, preserving properties and relationship type,
/// then delete the orphan `old` node.
///
/// Why a custom action and not a single Cypher statement: vanilla Cypher
/// forbids dynamic relationship types in `CREATE`, and APOC's
/// `apoc.refactor.mergeNodes` is not always available. masstin generates
/// one rel type per `target_user_name` so the rel type set is unbounded.
/// We solve it client-side: introspect the rel types touching `old`, then
/// emit one transfer query per type. Each query is plain Cypher.
pub async fn merge_neo4j_nodes(
    database: &String,
    user: &String,
    db: &str,
    old_name: &String,
    new_name: &String,
) {
    let start_clock = std::time::Instant::now();

    crate::banner::print_phase("1", "4", "Connecting to Neo4j...");
    crate::banner::print_phase_detail("Database:", database);
    crate::banner::print_phase_detail("Old node:", old_name);
    crate::banner::print_phase_detail("New node:", new_name);

    // as load-neo4j and graph-hunt-neo4j: $NEO4J_PASSWORD, else a prompt
    let pass = match std::env::var("NEO4J_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => rpassword::prompt_password("MASSTIN - Enter Neo4j database password: ").unwrap_or_default(),
    };
    let config = match ConfigBuilder::default().uri(crate::graph_hunt_common::bolt_uri(database)).user(user).password(&pass).db(db).build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("MASSTIN - Error: failed to build Neo4j config: {}", e);
            return;
        }
    };
    let graph = match Graph::connect(config).await {
        Ok(g) => g,
        Err(e) => {
            eprintln!("MASSTIN - Error: cannot connect to {}: {}", database, e);
            return;
        }
    };
    crate::banner::print_phase_result("Connected");

    // Both nodes must be there, and be two. Merging into a name that does
    // not exist used to "transfer N edges" (the count of the old node's)
    // while moving none.
    if let Err(e) = crate::merge_neo4j_nodes::both_nodes_exist(&graph, old_name, new_name).await {
        eprintln!("MASSTIN - Error: {} Nothing was changed.", e);
        crate::mark_failed();
        return;
    }
    // an edge between the two would become an edge of the new node to
    // itself, which no loader writes: those go first
    crate::merge_neo4j_nodes::drop_edges_between(&graph, old_name, new_name).await;

    // Phase 2: discover rel types touching the old node
    crate::banner::print_phase("2", "4", "Discovering relationship types...");
    let out_types = discover_types(&graph, old_name, true).await;
    let in_types = discover_types(&graph, old_name, false).await;
    crate::banner::print_phase_detail("Outgoing types:", &format!("{:?}", out_types));
    crate::banner::print_phase_detail("Incoming types:", &format!("{:?}", in_types));

    if out_types.is_empty() && in_types.is_empty() {
        // Either the node doesn't exist or has no edges. Try deleting anyway.
        crate::banner::print_phase_result("No edges found");
    }

    // Phase 3: transfer relationships
    let total_types = out_types.len() + in_types.len();
    crate::banner::print_phase("3", "4", &format!("Transferring {} relationship type(s)...", total_types));
    let mut transferred_out: usize = 0;
    let mut transferred_in: usize = 0;

    for t in &out_types {
        let n = transfer_outgoing(&graph, old_name, new_name, t).await;
        transferred_out += n;
        crate::banner::print_phase_detail(&format!("  out :{}", t), &format!("{} edges", n));
    }
    for t in &in_types {
        let n = transfer_incoming(&graph, old_name, new_name, t).await;
        transferred_in += n;
        crate::banner::print_phase_detail(&format!("  in  :{}", t), &format!("{} edges", n));
    }


    // what the old node knew goes to the new one: the addresses folded
    // into it, its own name, and the time spans its logs cover (the hunt
    // reads them from the node)
    crate::merge_neo4j_nodes::carry_node_properties(&graph, old_name, new_name).await;

    // Phase 4: delete the orphan old node
    crate::banner::print_phase("4", "4", "Deleting old node...");
    let q = query("MATCH (n:host {name:$name}) DELETE n").param("name", old_name.as_str());
    if let Err(e) = graph.run(q).await {
        eprintln!("[ERROR] Failed to delete old node: {:?}", e);
        crate::mark_failed();
    } else {
        crate::banner::print_phase_result("Old node deleted");
    }

    let elapsed = start_clock.elapsed().as_secs_f64();
    crate::banner::print_info("");
    crate::banner::print_info(&format!(
        "  Merge complete: transferred {} outgoing + {} incoming edges in {:.2}s",
        transferred_out, transferred_in, elapsed
    ));
}

/// Return the distinct relationship types incident on `old_name`.
/// `outgoing=true` returns outgoing types, otherwise incoming.
async fn discover_types(graph: &Graph, old_name: &String, outgoing: bool) -> Vec<String> {
    let cypher = if outgoing {
        "MATCH (:host {name:$name})-[r]->() RETURN DISTINCT type(r) AS t"
    } else {
        "MATCH ()-[r]->(:host {name:$name}) RETURN DISTINCT type(r) AS t"
    };
    let q = query(cypher).param("name", old_name.as_str());
    let mut out = Vec::new();
    match graph.execute(q).await {
        Ok(mut result) => {
            while let Ok(Some(row)) = result.next().await {
                if let Some(t) = row.get::<String>("t") {
                    out.push(t);
                }
            }
        }
        Err(e) => {
            eprintln!("[ERROR] discover_types failed: {:?}", e);
        }
    }
    out
}

/// Transfer every outgoing edge of type `rt` from `old` to `new`,
/// copying properties and deleting the original. Returns the number of
/// edges moved (best-effort, not always available from the driver).
async fn transfer_outgoing(graph: &Graph, old: &String, new: &String, rt: &str) -> usize {
    // Validate rel type — only allow [A-Za-z0-9_] to prevent injection
    // (the value comes from Neo4j's own `type(r)` so this should always pass,
    // but we double-check.)
    if !rt.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        eprintln!("[ERROR] Invalid relationship type: {:?}", rt);
        return 0;
    }
    // Count first so we can report it; could be merged into the transfer
    // but a separate count is cheap and clearer.
    let count_cypher = format!(
        "MATCH (:host {{name:$old}})-[r:{}]->() RETURN count(r) AS c", rt
    );
    let count = run_count(graph, &count_cypher, old).await;

    let cypher = format!(
        "MATCH (new:host {{name:$new}}) \
         WITH new \
         MATCH (old:host {{name:$old}})-[r:{}]->(target) \
         CREATE (new)-[nr:{}]->(target) \
         SET nr = properties(r) \
         DELETE r",
        rt, rt
    );
    let q = query(&cypher).param("old", old.as_str()).param("new", new.as_str());
    if let Err(e) = graph.run(q).await {
        eprintln!("[ERROR] transfer_outgoing :{} failed: {:?}", rt, e);
        return 0;
    }
    count
}

/// Same as `transfer_outgoing` but for incoming edges.
async fn transfer_incoming(graph: &Graph, old: &String, new: &String, rt: &str) -> usize {
    if !rt.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        eprintln!("[ERROR] Invalid relationship type: {:?}", rt);
        return 0;
    }
    let count_cypher = format!(
        "MATCH ()-[r:{}]->(:host {{name:$old}}) RETURN count(r) AS c", rt
    );
    let count = run_count(graph, &count_cypher, old).await;

    let cypher = format!(
        "MATCH (new:host {{name:$new}}) \
         WITH new \
         MATCH (source)-[r:{}]->(old:host {{name:$old}}) \
         CREATE (source)-[nr:{}]->(new) \
         SET nr = properties(r) \
         DELETE r",
        rt, rt
    );
    let q = query(&cypher).param("old", old.as_str()).param("new", new.as_str());
    if let Err(e) = graph.run(q).await {
        eprintln!("[ERROR] transfer_incoming :{} failed: {:?}", rt, e);
        return 0;
    }
    count
}

async fn run_count(graph: &Graph, cypher: &str, old: &String) -> usize {
    let q = query(cypher).param("old", old.as_str());
    match graph.execute(q).await {
        Ok(mut result) => {
            if let Ok(Some(row)) = result.next().await {
                if let Some(c) = row.get::<i64>("c") {
                    return c as usize;
                }
            }
            0
        }
        Err(_) => 0,
    }
}

/// Whether `old` and `new` are two `:host` nodes of the graph; the error
/// says which one is missing. Shared with the Memgraph action.
pub(crate) async fn both_nodes_exist(graph: &Graph, old: &str, new: &str) -> std::result::Result<(), String> {
    if old == new {
        return Err(format!("--old-node and --new-node are the same node ({}).", old));
    }
    for (flag, name) in [("--old-node", old), ("--new-node", new)] {
        let q = query("MATCH (n:host {name:$name}) RETURN count(n) AS c").param("name", name);
        let n = match graph.execute(q).await {
            Ok(mut r) => match r.next().await {
                Ok(Some(row)) => row.get::<i64>("c").unwrap_or(0),
                _ => 0,
            },
            Err(e) => return Err(format!("cannot look for the node {}: {:?}.", name, e)),
        };
        if n == 0 {
            return Err(format!("{} {}: there is no host node with that name in the graph (names are written as the graph has them: upper case, short name).", flag, name));
        }
    }
    Ok(())
}

/// Before the old node goes: its aliases and its own name are added to
/// the new node's `aliases`, its coverage spans to the new node's
/// (`cov_ok` / `cov_fail` are lists of [start, end, start, end...]; the
/// hunt reads them pair by pair, in any order).
pub(crate) async fn carry_node_properties(graph: &Graph, old: &str, new: &str) {
    let steps = [
        ("aliases", "MATCH (o:host {name:$old}), (n:host {name:$new}) SET n.aliases = coalesce(n.aliases, []) + coalesce(o.aliases, []) + [$old]"),
        ("cov_ok", "MATCH (o:host {name:$old}), (n:host {name:$new}) WHERE o.cov_ok IS NOT NULL SET n.cov_ok = coalesce(n.cov_ok, []) + o.cov_ok"),
        ("cov_fail", "MATCH (o:host {name:$old}), (n:host {name:$new}) WHERE o.cov_fail IS NOT NULL SET n.cov_fail = coalesce(n.cov_fail, []) + o.cov_fail"),
    ];
    for (what, cypher) in steps {
        if let Err(e) = graph.run(query(cypher).param("old", old).param("new", new)).await {
            eprintln!("[ERROR] carrying {} to the new node failed: {:?}", what, e);
            crate::mark_failed();
        }
    }
}

/// The edges between the two nodes, in either direction, deleted.
pub(crate) async fn drop_edges_between(graph: &Graph, old: &str, new: &str) {
    let q = query("MATCH (o:host {name:$old})-[r]-(n:host {name:$new}) DELETE r").param("old", old).param("new", new);
    if let Err(e) = graph.run(q).await {
        eprintln!("[ERROR] deleting the edges between the two nodes failed: {:?}", e);
        crate::mark_failed();
    }
}

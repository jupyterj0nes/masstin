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
    old_name: &String,
    new_name: &String,
) {
    let start_clock = std::time::Instant::now();

    crate::banner::print_phase("1", "4", "Connecting to Neo4j...");
    crate::banner::print_phase_detail("Database:", database);
    crate::banner::print_phase_detail("Old node:", old_name);
    crate::banner::print_phase_detail("New node:", new_name);

    let pass = rpassword::prompt_password("MASSTIN - Enter Neo4j database password: ").unwrap();
    let graph = Graph::new(database, user, &pass).await.unwrap();
    crate::banner::print_phase_result("Connected");

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

    // Phase 4: delete the orphan old node
    crate::banner::print_phase("4", "4", "Deleting old node...");
    let q = query("MATCH (n:host {name:$name}) DELETE n").param("name", old_name.as_str());
    if let Err(e) = graph.run(q).await {
        eprintln!("[ERROR] Failed to delete old node: {:?}", e);
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

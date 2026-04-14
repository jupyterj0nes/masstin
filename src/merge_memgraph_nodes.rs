use neo4rs::*;
use futures::stream::*;

/// Memgraph counterpart of `merge_neo4j_nodes`. Same logic, different
/// driver init (Memgraph uses ConfigBuilder + db("memgraph"), no password).
/// See `merge_neo4j_nodes.rs` for the rationale on why we introspect rel
/// types client-side instead of using a single Cypher statement.
pub async fn merge_memgraph_nodes(
    database: &String,
    user: &String,
    old_name: &String,
    new_name: &String,
) {
    let start_clock = std::time::Instant::now();

    crate::banner::print_phase("1", "4", "Connecting to Memgraph...");
    crate::banner::print_phase_detail("Database:", database);
    crate::banner::print_phase_detail("Old node:", old_name);
    crate::banner::print_phase_detail("New node:", new_name);

    let config = ConfigBuilder::default()
        .uri(database)
        .user(user)
        .password("")
        .db("memgraph")
        .build()
        .unwrap();
    let graph = Graph::connect(config).await.unwrap();
    crate::banner::print_phase_result("Connected");

    crate::banner::print_phase("2", "4", "Discovering relationship types...");
    let out_types = discover_types(&graph, old_name, true).await;
    let in_types = discover_types(&graph, old_name, false).await;
    crate::banner::print_phase_detail("Outgoing types:", &format!("{:?}", out_types));
    crate::banner::print_phase_detail("Incoming types:", &format!("{:?}", in_types));

    if out_types.is_empty() && in_types.is_empty() {
        crate::banner::print_phase_result("No edges found");
    }

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

async fn transfer_outgoing(graph: &Graph, old: &String, new: &String, rt: &str) -> usize {
    if !rt.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        eprintln!("[ERROR] Invalid relationship type: {:?}", rt);
        return 0;
    }
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

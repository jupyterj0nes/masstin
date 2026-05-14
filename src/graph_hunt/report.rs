// Findings aggregator + CSV emitter. Combines per-detector findings by
// (host, time_window), computes a composite score, and writes a ranked CSV.
// Snippet column carries the Cypher query that reproduces the subgraph in
// Memgraph Lab. Implementation completes in task #7.

use crate::graph_hunt::detectors::Finding;
use std::io::Write;

pub fn emit_csv(findings: &[Finding], output: Option<&str>) -> std::io::Result<()> {
    let header = "rank,score,detector,host,time_window,summary,cypher_snippet\n";

    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    let mut buf = String::new();
    buf.push_str(header);
    for (rank, f) in sorted.iter().enumerate() {
        buf.push_str(&format!(
            "{},{:.4},{},{},{},{},{}\n",
            rank + 1,
            f.score,
            f.detector,
            csv_escape(&f.host),
            csv_escape(&f.time_window),
            csv_escape(&f.summary),
            csv_escape(&f.cypher_snippet),
        ));
    }

    match output {
        Some(path) => {
            let mut file = std::fs::File::create(path)?;
            file.write_all(buf.as_bytes())?;
        }
        None => {
            print!("{}", buf);
        }
    }
    Ok(())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

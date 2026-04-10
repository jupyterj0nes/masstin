// -----------------------------------------------------------------------------
//  Scheduled Task XML parser
//  Reads task XML files from Windows\System32\Tasks, extracts Author field
//  to identify remotely scheduled tasks (Author = MACHINE\user).
//  Only produces events where Author contains '\' (remote origin).
// -----------------------------------------------------------------------------

use std::fs;
use std::path::Path;
use crate::parse::{LogData, is_debug_mode};

/// Parse all Scheduled Task XML files in the given directories.
/// Returns LogData events for tasks with a remote Author (MACHINE\user format).
pub fn parse_scheduled_tasks(dirs: &[String], computer_name: &str) -> Vec<LogData> {
    let mut results = Vec::new();

    for dir in dirs {
        let dir_path = Path::new(dir);
        if !dir_path.exists() {
            continue;
        }
        parse_tasks_recursive(dir_path, dir, computer_name, &mut results);
    }

    if !results.is_empty() {
        crate::banner::print_phase_result(&format!(
            "{} remotely scheduled task(s) detected", results.len()
        ));
    }

    results
}

fn parse_tasks_recursive(dir: &Path, base_dir: &str, computer_name: &str, results: &mut Vec<LogData>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            parse_tasks_recursive(&path, base_dir, computer_name, results);
        } else if path.is_file() {
            if let Some(log_data) = parse_single_task(&path, base_dir, computer_name) {
                results.push(log_data);
            }
        }
    }
}

fn parse_single_task(path: &Path, base_dir: &str, computer_name: &str) -> Option<LogData> {
    // Read file content — tasks are XML, sometimes UTF-16
    let raw = fs::read(path).ok()?;
    let content = decode_task_xml(&raw);

    // Extract Author from <RegistrationInfo><Author>
    let author = extract_xml_value(&content, "Author")?;

    // Only interested in remote tasks: Author must contain '\'
    if !author.contains('\\') {
        return None;
    }

    let parts: Vec<&str> = author.splitn(2, '\\').collect();
    let src_machine = parts[0];
    let src_user = parts[1];

    // Skip if source machine is the same as destination (local task with domain\user)
    let src_short = src_machine.split('.').next().unwrap_or(src_machine);
    let dst_short = computer_name.split('.').next().unwrap_or(computer_name);
    if src_short.eq_ignore_ascii_case(dst_short) {
        return None;
    }

    // Skip system accounts
    if src_user.eq_ignore_ascii_case("SYSTEM") || src_user.eq_ignore_ascii_case("LOCAL SERVICE") || src_user.eq_ignore_ascii_case("NETWORK SERVICE") {
        return None;
    }

    // Extract registration date
    let date = extract_xml_value(&content, "Date").unwrap_or_default();
    // Normalize: "2026-04-08T15:50:14" -> "2026-04-08T15:50:14Z" (add Z if missing timezone)
    let time_created = if !date.is_empty() && !date.ends_with('Z') && !date.contains('+') && !date.contains("-00") {
        format!("{}Z", date)
    } else if date.is_empty() {
        // No date in XML — skip, we can't place this in the timeline
        return None;
    } else {
        date
    };

    // Extract command
    let command = extract_xml_value(&content, "Command").unwrap_or_default();

    // Extract task name (URI or filename)
    let task_name = extract_xml_value(&content, "URI")
        .unwrap_or_else(|| path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string());

    // Extract UserId from Principals (the account that runs the task)
    let run_as = extract_xml_value(&content, "UserId").unwrap_or_default();

    let detail = if command.is_empty() {
        format!("Task: {}", task_name)
    } else {
        format!("Task: {} -> {}", task_name, command)
    };

    if is_debug_mode() {
        eprintln!("[DEBUG] Remote task found: {} -> {} (author: {}, cmd: {})",
            src_machine, computer_name, author, command);
    }

    Some(LogData {
        time_created,
        computer: computer_name.to_string(),
        event_type: "CONNECT".to_string(),
        event_id: "SCHTASK".to_string(),
        subject_user_name: String::new(),
        subject_domain_name: String::new(),
        target_user_name: src_user.to_string(),
        target_domain_name: src_machine.to_string(),
        logon_type: String::new(),
        workstation_name: src_machine.to_string(),
        ip_address: src_machine.to_string(),
        logon_id: String::new(),
        filename: format!("{}:tasks:{}",
            Path::new(base_dir).parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or(base_dir),
            task_name.trim_start_matches('\\')),
        detail,
    })
}

/// Decode task XML content, handling UTF-16 encoding.
fn decode_task_xml(raw: &[u8]) -> String {
    // Check for UTF-16 BOM (FF FE or FE FF)
    if raw.len() >= 2 {
        if raw[0] == 0xFF && raw[1] == 0xFE {
            // UTF-16 LE
            let u16_data: Vec<u16> = raw[2..].chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            return String::from_utf16_lossy(&u16_data);
        }
        if raw[0] == 0xFE && raw[1] == 0xFF {
            // UTF-16 BE
            let u16_data: Vec<u16> = raw[2..].chunks_exact(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect();
            return String::from_utf16_lossy(&u16_data);
        }
    }
    // Try UTF-8 / ASCII
    String::from_utf8_lossy(raw).to_string()
}

/// Simple XML value extractor — finds <TagName>value</TagName>.
/// Not a full XML parser, but sufficient for the flat structure of task XMLs.
fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let value = xml[start..end].trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

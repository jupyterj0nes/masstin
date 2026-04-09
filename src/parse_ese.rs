// =============================================================================
//   ESE (Extensible Storage Engine) database wrapper
//   Uses libesedb (FFI to Joachim Metz's C library) for reliable ESE parsing.
//   libesedb handles dirty databases natively as a forensic library.
// =============================================================================

use std::collections::HashMap;

/// Typed column value from an ESE database record.
#[derive(Debug, Clone)]
pub enum EseValue {
    Text(String),
    Null,
}

impl std::fmt::Display for EseValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EseValue::Text(s) => write!(f, "{}", s),
            EseValue::Null => write!(f, ""),
        }
    }
}

/// Convert Windows FILETIME (100ns intervals since 1601-01-01) to "YYYY-MM-DD HH:MM:SS"
pub fn filetime_to_string(ft: i64) -> String {
    if ft <= 0 {
        return String::new();
    }
    let secs_since_unix = (ft / 10_000_000) - 11_644_473_600i64;
    if secs_since_unix < 0 || secs_since_unix > 253402300800 {
        return String::new();
    }

    let days = (secs_since_unix / 86400) as i32;
    let time_of_day = (secs_since_unix % 86400) as u32;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, month, day, hours, minutes, seconds)
}

fn days_to_ymd(days_since_epoch: i32) -> (i32, u32, u32) {
    let z = days_since_epoch + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Convert binary IP address hex string ("0A 0A 0C C8") to readable format
pub fn ip_from_hex_string(hex_str: &str) -> String {
    let bytes: Vec<u8> = hex_str.split_whitespace()
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();

    if bytes.len() == 4 {
        format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
    } else if bytes.len() == 16 {
        if bytes[0..10] == [0; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
            format!("{}.{}.{}.{}", bytes[12], bytes[13], bytes[14], bytes[15])
        } else if bytes[0..15] == [0; 15] && bytes[15] == 1 {
            "::1".to_string()
        } else {
            let parts: Vec<String> = (0..8)
                .map(|i| format!("{:04x}", u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]])))
                .collect();
            parts.join(":")
        }
    } else {
        hex_str.to_string()
    }
}

// =============================================================================
//   ESE Database access via libesedb
// =============================================================================

/// Open an ESE database and read a table, returning rows as Vec<HashMap<String, EseValue>>.
pub fn read_ese_table(path: &str, table_name: &str) -> Result<Vec<HashMap<String, EseValue>>, String> {
    let db = libesedb::EseDb::open(path)
        .map_err(|e| format!("Cannot open ESE database {}: {}", path, e))?;

    let table = db.table_by_name(table_name)
        .map_err(|e| format!("Cannot open table '{}' in {}: {}", table_name, path, e))?;

    let num_cols = table.count_columns().map_err(|e| e.to_string())? as usize;
    let mut col_names = Vec::with_capacity(num_cols);
    for i in 0..num_cols {
        let col = table.column(i as i32).map_err(|e| e.to_string())?;
        col_names.push(col.name().map_err(|e| e.to_string())?);
    }

    let mut rows = Vec::new();
    let records = table.iter_records().map_err(|e| e.to_string())?;

    for rec_result in records {
        let rec = match rec_result {
            Ok(r) => r,
            Err(_) => continue,
        };

        let mut row = HashMap::new();
        let values = match rec.iter_values() {
            Ok(v) => v,
            Err(_) => continue,
        };

        for (i, val_result) in values.enumerate() {
            if i >= col_names.len() { break; }
            let col_name = &col_names[i];

            let ese_val = match val_result {
                Ok(val) => {
                    let s = val.to_string();
                    if s.is_empty() {
                        EseValue::Null
                    } else {
                        EseValue::Text(s)
                    }
                }
                Err(_) => EseValue::Null,
            };

            row.insert(col_name.clone(), ese_val);
        }

        rows.push(row);
    }

    Ok(rows)
}

/// List all table names in an ESE database.
pub fn list_ese_tables(path: &str) -> Result<Vec<String>, String> {
    let db = libesedb::EseDb::open(path)
        .map_err(|e| format!("Cannot open ESE database {}: {}", path, e))?;

    let count = db.count_tables().map_err(|e| e.to_string())?;
    let mut names = Vec::new();
    for i in 0..count {
        if let Ok(table) = db.table(i as i32) {
            if let Ok(name) = table.name() {
                names.push(name);
            }
        }
    }
    Ok(names)
}

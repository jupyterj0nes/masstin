use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use chrono::NaiveDateTime;

const MASSTIN_HEADER: &str = "time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,log_filename";

pub fn merge_files(files: &Vec<String>, output: Option<&String>) -> Result<(), Box<dyn Error>> {
    let mut merged_lines: Vec<(NaiveDateTime, String)> = Vec::new();
    let mut seen_lines: HashSet<String> = HashSet::new();
    
    // Step 1: Verify that all files have the correct header
    for file_path in files {
        let file = fs::File::open(file_path)?;
        let reader = BufReader::new(file);
        
        // Read the first line to verify the header
        let mut lines = reader.lines();
        if let Some(Ok(header)) = lines.next() {
            if header != MASSTIN_HEADER {
                return Err(Box::from(format!("File {} does not have the correct Masstin header", file_path)));
            }
        } else {
            return Err(Box::from(format!("Could not read header from file: {}", file_path)));
        }

        // Step 2: Read the content and store non-duplicate lines sorted by time_created
        for line in lines {
            if let Ok(content) = line {
                let fields: Vec<&str> = content.split(',').collect();
                
                // Ensure the line has the correct number of fields
                if fields.len() != 11 {
                    continue; // Skip malformed lines
                }

                // Parse the time_created (assumed to be in the first column) as NaiveDateTime in ISO 8601 format
                if let Ok(time_created) = NaiveDateTime::parse_from_str(fields[0], "%Y-%m-%dT%H:%M:%S%.fZ") {
                    // Only add unique lines
                    if seen_lines.insert(content.clone()) {
                        merged_lines.push((time_created, content));
                    }
                }
            }
        }
    }

    // Step 3: Sort the merged lines by the time_created field
    merged_lines.sort_by(|a, b| a.0.cmp(&b.0));

    // Step 4: Write the sorted and unique lines to the output
    let mut result = String::new();
    
    // Ensure we only add the header once
    result.push_str(MASSTIN_HEADER);
    result.push('\n');

    // Append the sorted lines
    for (_, line) in merged_lines {
        result.push_str(&line);
        result.push('\n');
    }

    // Write the combined content to the output file, or print it if no output was specified
    if let Some(output_file) = output {
        fs::write(output_file, result)?;
    } else {
        println!("{}", result);
    }

    Ok(())
}
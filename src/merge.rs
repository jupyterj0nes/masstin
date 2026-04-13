use std::collections::HashSet;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use chrono::NaiveDateTime;

const MASSTIN_HEADER: &str = "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename";
const MASSTIN_HEADER_OLD: &str = "time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,process,log_filename";

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
            if header != MASSTIN_HEADER && header != MASSTIN_HEADER_OLD {
                return Err(Box::from(format!("File {} does not have the correct Masstin header", file_path)));
            }
        } else {
            return Err(Box::from(format!("Could not read header from file: {}", file_path)));
        }

        // Step 2: Read the content and store non-duplicate lines sorted by time_created
        for line in lines {
            if let Ok(content) = line {
                let fields: Vec<&str> = content.split(',').collect();

                // Ensure the line has the correct number of fields (14 for new format, 12 for old)
                if fields.len() != 14 && fields.len() != 12 {
                    continue; // Skip malformed lines
                }

                // Parse the time_created (first column) — supports both "...Z" and "...+00:00" formats
                let time_created_result = NaiveDateTime::parse_from_str(fields[0], "%Y-%m-%dT%H:%M:%S%.fZ")
                    .or_else(|_| NaiveDateTime::parse_from_str(fields[0], "%Y-%m-%dT%H:%M:%S%.f+00:00"))
                    .or_else(|_| NaiveDateTime::parse_from_str(fields[0], "%Y-%m-%dT%H:%M:%S+00:00"));
                if let Ok(time_created) = time_created_result {
                    // Apply noise filter. For the 14-column format:
                    //   0=time 1=dst 2=event_type 3=event_id 4=logon_type
                    //   5=target_user 6=target_domain 7=src_computer 8=src_ip
                    //   9=subject_user 10=subject_domain 11=logon_id
                    //   12=detail 13=log_filename
                    // For the 12-column legacy format:
                    //   0=time 1=dst 2=event_id 3=subject_user 4=subject_domain
                    //   5=target_user 6=target_domain 7=logon_type
                    //   8=src_computer 9=src_ip 10=process 11=log_filename
                    let ld = if fields.len() == 14 {
                        crate::parse::LogData {
                            time_created: fields[0].to_string(),
                            computer: fields[1].to_string(),
                            event_type: fields[2].to_string(),
                            event_id: fields[3].to_string(),
                            logon_type: fields[4].to_string(),
                            target_user_name: fields[5].to_string(),
                            target_domain_name: fields[6].to_string(),
                            workstation_name: fields[7].to_string(),
                            ip_address: fields[8].to_string(),
                            subject_user_name: fields[9].to_string(),
                            subject_domain_name: fields[10].to_string(),
                            logon_id: fields[11].to_string(),
                            detail: fields[12].to_string(),
                            filename: fields[13].to_string(),
                        }
                    } else {
                        crate::parse::LogData {
                            time_created: fields[0].to_string(),
                            computer: fields[1].to_string(),
                            event_type: String::new(),
                            event_id: fields[2].to_string(),
                            subject_user_name: fields[3].to_string(),
                            subject_domain_name: fields[4].to_string(),
                            target_user_name: fields[5].to_string(),
                            target_domain_name: fields[6].to_string(),
                            logon_type: fields[7].to_string(),
                            workstation_name: fields[8].to_string(),
                            ip_address: fields[9].to_string(),
                            logon_id: String::new(),
                            detail: fields[10].to_string(),
                            filename: fields[11].to_string(),
                        }
                    };
                    if !crate::filter::should_keep_record(&ld) {
                        continue;
                    }
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
use neo4rs::*;
use futures::stream::*;
use rpassword::read_password;
use std::io::{self, prelude::*};
use indicatif::ProgressBar;
use std::collections::HashSet;
use std::collections::HashMap;

pub mod load {
    // Load module code
}

#[derive(Debug)]
struct GroupedData {
    earliest_date: String, // Assuming the date is in String format
    count: usize,
}

pub async fn load_neo(files: &Vec<String>, database: &String, user: &String) {
    let pass = rpassword::prompt_password("MASSTIN - Enter Neo4j database password: ").unwrap();
    let graph = Graph::new(database, user, &pass).await.unwrap();
    for file in files {
        let file_contents: String = std::fs::read_to_string(file).unwrap();
        let mut lines: Vec<&str> = file_contents.lines().collect();

        // Verify the file header
        if lines.is_empty() || lines[0] != "time_created,dst_computer,event_id,subject_user_name,subject_domain_name,target_user_name,target_domain_name,logon_type,src_computer,src_ip,log_filename" {
            println!("MASSTIN - File {} has not been generated by Masstin", file);
            continue;
        }

        let local_values: HashSet<&str> = 
                ["LOCAL", "127.0.0.1", "::1", "DEFAULT_VALUE", "\"\"", "-", ""," ",]
                .iter().cloned().collect();

        let processed_lines: Vec<String> = lines
        .into_iter()
        .skip(1)
        .map(|line| line.replace("\\", "").replace("[", "").replace("]", "").to_uppercase())
        .filter_map(|line| {
            let mut row: Vec<&str> = line.split(',').collect();
            row.pop();
    
            if row[1].contains('.') && row[1].chars().any(|c| c.is_ascii_alphabetic()) {
                row[1] = row[1].split('.').next().unwrap_or(row[1]);
                //println!("Converted!: {}", row[1])
            }
    
            if row[8].contains('.') && row[8].chars().any(|c| c.is_ascii_alphabetic()) {
                row[8] = row[8].split('.').next().unwrap_or(row[8]);
                //println!("Converted!: {}", row[8])
            }

            if row[9].contains('.') && row[9].chars().any(|c| c.is_ascii_alphabetic()) {
                row[9] = row[9].split('.').next().unwrap_or(row[9]);
                //println!("Converted!: {}", row[8])
            }

            if row[1].contains(':') {
                row[1] = row[1].split(':').next().unwrap_or(row[1]);
                //println!("Converted!: {}", row[1])
            }
    
            if row[8].contains(':') {
                row[8] = row[8].split(':').next().unwrap_or(row[1]);
                //println!("Converted!: {}", row[1])
            }

            if row[9].contains(':') {
                row[9] = row[9].split(':').next().unwrap_or(row[1]);
                //println!("Converted!: {}", row[1])
            }
    
            if local_values.contains(&row[8]) && local_values.contains(&row[9]) {
                //println!("Local filter! {} {}", row[8], row[9]);
                None
            } else if row[1] == row[8] {
                //println!("Local name filter 2! {} {}", row[1], row[8]);
                None
            } else if row[1] == row[9] {
                //println!("Local name filter 3! {} {}", row[1], row[9]);
                None
            } else {
                Some(row.join(","))
            }
        })
        .collect();

        let mut grouped_map: HashMap<(String, String, String, String, String, String, String, String), GroupedData> = HashMap::new();
        let mut counts: HashMap<(String, String), u32> = HashMap::new();

        for line in processed_lines {
            let parts: Vec<String> = line.split(',').map(|s| s.to_string()).collect();

            if !local_values.contains(parts[8].as_str()) && !local_values.contains(parts[9].as_str()) && parts[8] != parts[9] {
                // Change the keys from `&str` to `String`
                *counts.entry((parts[9].clone(), parts[8].clone())).or_insert(0) += 1;
            }
            // Assuming the columns dst_computer, src_computer, target_user_name are 3, 4, and 5 respectively
            // and the date column is 0
            let key = (parts[1].clone(), parts[3].clone(), parts[4].clone(), parts[5].clone(), parts[6].clone(), parts[7].clone(), parts[8].clone(), parts[9].clone());
            let date = parts[0].clone();

            let entry = grouped_map.entry(key).or_insert(GroupedData {
                earliest_date: date.clone(),
                count: 0,
            });

            if date < entry.earliest_date {
                entry.earliest_date = date;
            }
            entry.count += 1;
        }

        for (key, count) in &counts {
            println!("{:?} has {} occurrences", key, count);
        }

        // Convert the HashMap to a vector of strings
        let mut grouped_lines: Vec<String> = Vec::new();
        for ((dst_computer, subject_user_name, subject_domain_name, target_user_name, target_domain_name, logon_type, src_computer, src_ip), data) in grouped_map {
            grouped_lines.push(format!("{},{},{},{},{},{},{},{},{},{}", data.earliest_date, dst_computer, data.count, subject_user_name, subject_domain_name, target_user_name, target_domain_name, logon_type, src_computer, src_ip));
        }

        // Initialize the progress bar with the correct number of lines
        let pb = ProgressBar::new(grouped_lines.len() as u64);

        for line in grouped_lines {
            let mut row: Vec<&str> = line.split(',').collect();
            let relation_type = if row[5].trim().is_empty() || row[5] == "\"\"" { "NO_USER" } else { &row[5] };
            let mut hostname = row[8];
            if local_values.contains(row[8]) || counts.iter().any(|((ip, _), _)| ip == &row[9]) {
                // Filter the HashMap entries to find those matching the target_ip
                let filtered_counts: Vec<(&(String, String), &u32)> = counts.iter()
                .filter(|&((ip, _), _)| ip == row[9])
                .collect();
                
                // Find the entry with the highest count
                if let Some(((_, most_frequent_value), &count)) = filtered_counts.iter()
                    .max_by_key(|&(_, &count)| count) {
                    println!("MASSTIN: IP {} has been resolved to hostname: {} as it has been seen {} times.", row[9], most_frequent_value, count);
                    hostname = most_frequent_value;
                } else {
                    hostname = row[9];
                }
            }
            
            let formatted_query = format!(
                "MERGE (origin:host{{name:'{}'}})
                MERGE (destination:host{{name:'{}'}})
                MERGE (origin)-[r:{}{{time:datetime('{}'), logon_type:'{}', src_computer:'{}', src_ip:'{}', target_user_name:'{}', target_domain_name:'{}', subject_user_name:'{}', subject_domain_name:'{}', count:'{}'}}]->(destination)",
                hostname.replace(".", "_").replace("-", "_").replace(" ", "_").split("@").next().unwrap(),
                row[1].replace(".", "_").replace("-", "_").replace(" ", "_"),
                if relation_type.chars().next().unwrap_or(' ').is_digit(10) { format!("u{}", relation_type) } else { relation_type.to_string() }
                    .replace(".", "_").replace("-", "_").replace(" ", "_").split("@").next().unwrap(),
                row[0].replace(" utc", "").replace(" ", "T"),
                row[7].replace(".", "_").replace("-", "_").replace(" ", "_"),
                row[8].replace(".", "_").replace("-", "_").replace(" ", "_"),
                row[9].replace(".", "_").replace("-", "_").replace(" ", "_"),
                relation_type.replace(".", "_").replace("-", "_").replace(" ", "_").split("@").next().unwrap(),
                row[6].replace(".", "_").replace("-", "_").replace(" ", "_"),
                row[3].replace(".", "_").replace("-", "_").replace(" ", "_"),
                row[4].replace(".", "_").replace("-", "_").replace(" ", "_"),
                row[2].replace(".", "_").replace("-", "_").replace(" ", "_"),
            );
            
            // Execute the query and handle possible errors
            match graph.execute(query(&formatted_query)).await {
                Ok(mut result) => {
                    let row = result.next().await.unwrap();  // Process the result
                    // You can add more logic here if you need to process the result
                },
                Err(e) => {
                    // Print the error message and the query that failed
                    println!("Error running the Cypher query: {:?}", e);
                    println!("Query with error: {}", formatted_query);
                    continue;  // Continue with the next line
                }
            }

            // Increment the progress bar
            pb.inc(1);
        }

        // Finish the progress bar
        // pb.finish_with_message("MASSTIN - File {} has been loaded");
    }
}

use serde::Deserialize;
use regex::Regex;
use log::warn; // Added log import

#[derive(Deserialize, Debug, Clone)] // Added Clone for easier ownership handling if needed later
pub struct PatternItem {
    #[serde(alias = "pattern")]
    pub pattern_str: String,
    pub score: f32,
    #[serde(alias = "ban")]
    pub instant_block: i32,
}

#[derive(Deserialize, Debug, Clone)] // Added Clone
pub struct FilterGroup {
    #[serde(alias = "filter")]
    pub filter_str: String, 
    pub items: Vec<PatternItem>,
}

pub fn load_patterns_from_file(file_path: &str) -> Result<Vec<FilterGroup>, Box<dyn std::error::Error>> {
    let file_content = std::fs::read_to_string(file_path)?;
    let patterns: Vec<FilterGroup> = serde_json::from_str(&file_content)?;
    Ok(patterns)
}

// Match message function
pub fn match_message<'a>(
    message: &'a str, // The log message content
    pattern_groups: &'a [FilterGroup],
) -> Option<(String, f32, i32)> {
    for group in pattern_groups {
        for item in &group.items {
            // Strip "MESSAGE=" prefix from pattern_str if it exists
            let mut actual_pattern_str = item.pattern_str.as_str();
            if let Some(stripped) = actual_pattern_str.strip_prefix("MESSAGE=") {
                actual_pattern_str = stripped;
            }
            
            // Compile regex on-the-fly
            // We need to handle potential regex compilation errors.
            // For this function, if a regex fails to compile, we'll skip it.
            // In a real app, these would likely be pre-compiled and validated at load time.
            if let Ok(re) = Regex::new(actual_pattern_str) {
                if let Some(captures) = re.captures(message) {
                    // Try to get the first capture group for the IP address
                    if let Some(ip_match) = captures.get(1) {
                        let ip_address = ip_match.as_str().to_string();
                        return Some((ip_address, item.score, item.instant_block));
                    }
                }
            } else {
                warn!("Failed to compile regex: '{}'", actual_pattern_str);
            }
        }
    }
    None // No match found
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json; // For test_load_sshd_patterns_example

    #[test]
    fn test_load_sshd_patterns_example() {
        let json_data = r#"[
            {
                "filter": "_COMM=sshd",
                "items": [
                    {
                        "pattern": "MESSAGE=Failed password for invalid user .* from ([0-9a-z:.]+) port \\d+ ssh2",
                        "score": 2.5,
                        "ban": 0
                    }
                ]
            }
        ]"#;
        let parsed_groups: Result<Vec<FilterGroup>, _> = serde_json::from_str(json_data);
        assert!(parsed_groups.is_ok(), "Failed to parse pattern JSON: {:?}", parsed_groups.err());
        let groups = parsed_groups.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].filter_str, "_COMM=sshd");
        assert_eq!(groups[0].items.len(), 1);
        assert_eq!(groups[0].items[0].pattern_str, "MESSAGE=Failed password for invalid user .* from ([0-9a-z:.]+) port \\d+ ssh2");
        assert_eq!(groups[0].items[0].score, 2.5);
        assert_eq!(groups[0].items[0].instant_block, 0);
    }

    #[test]
    fn test_match_message_success() {
        let patterns = vec![FilterGroup {
            filter_str: "_COMM=sshd".to_string(),
            items: vec![PatternItem {
                pattern_str: "Failed .* from ([0-9.]+) port".to_string(), // No "MESSAGE=" prefix here for direct testing
                score: 0.5,
                instant_block: 0,
            }],
        }];
        let message = "Failed password for invalid user test from 1.2.3.4 port 12345";
        let result = match_message(message, &patterns);
        assert_eq!(result, Some(("1.2.3.4".to_string(), 0.5, 0)));
    }

    #[test]
    fn test_match_message_no_match() {
        let patterns = vec![FilterGroup {
            filter_str: "_COMM=sshd".to_string(),
            items: vec![PatternItem {
                pattern_str: "Failed .* from ([0-9.]+) port".to_string(),
                score: 0.5,
                instant_block: 0,
            }],
        }];
        let message = "System startup complete";
        let result = match_message(message, &patterns);
        assert_eq!(result, None);
    }

    #[test]
    fn test_match_message_prefix_stripping() {
        let patterns = vec![FilterGroup {
            filter_str: "_COMM=any".to_string(),
            items: vec![PatternItem {
                // This pattern includes "MESSAGE=" which match_message should strip
                pattern_str: "MESSAGE=User admin logged out from ([0-9.]+)".to_string(),
                score: 1.0,
                instant_block: 0,
            }],
        }];
        // The message itself does not contain "MESSAGE="
        let message = "User admin logged out from 1.1.1.1"; 
        let result = match_message(message, &patterns);
        assert_eq!(result, Some(("1.1.1.1".to_string(), 1.0, 0)));
    }

    #[test]
    fn test_match_message_no_capture_group() {
        let patterns = vec![FilterGroup {
            filter_str: "_COMM=any".to_string(),
            items: vec![PatternItem {
                pattern_str: "No capture group here".to_string(),
                score: 1.0,
                instant_block: 0,
            }],
        }];
        let message = "No capture group here";
        let result = match_message(message, &patterns);
        // Expect None because the regex matches, but there's no capture group(1) for the IP.
        assert_eq!(result, None);
    }

    #[test]
    fn test_match_message_bad_regex_pattern() {
        let patterns = vec![FilterGroup {
            filter_str: "_COMM=any".to_string(),
            items: vec![
                PatternItem { // Invalid regex
                    pattern_str: "MESSAGE=***InvalidRegex[".to_string(),
                    score: 1.0,
                    instant_block: 0,
                },
                PatternItem { // Valid regex, should still be processed
                    pattern_str: "MESSAGE=Valid pattern with IP ([0-9.]+)" .to_string(),
                    score: 2.0,
                    instant_block: 0,
                }
            ],
        }];
        // This message should match the second, valid pattern
        let message = "Valid pattern with IP 2.2.2.2"; 
        let result = match_message(message, &patterns);
        // match_message logs a warning for bad regex and continues.
        assert_eq!(result, Some(("2.2.2.2".to_string(), 2.0, 0)));
    }
}

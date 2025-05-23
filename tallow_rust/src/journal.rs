use systemd::journal::{Journal, JournalSeek, OpenOptions, JournalWaitResult};
// use std::time::Duration; // Not used directly in this file
// use std::ffi::OsStr; // Not used as entry.get() returns Option<&String> for v0.10.0

pub fn open_journal() -> Result<Journal, Box<dyn std::error::Error>> {
    let mut options = OpenOptions::default();
    options.system(true); // Open system journal
    let journal = options.open()?;
    Ok(journal)
}

pub fn add_filter(journal: &mut Journal, filter_key: &str, filter_value: &str) -> Result<(), Box<dyn std::error::Error>> {
    journal.match_add(filter_key, filter_value.as_bytes())?;
    Ok(())
}

pub fn seek_to_tail(journal: &mut Journal) -> Result<(), Box<dyn std::error::Error>> {
    journal.seek(JournalSeek::Tail)?;
    Ok(())
}

pub fn wait_for_message(journal: &mut Journal) -> Result<JournalWaitResult, Box<dyn std::error::Error>> {
    match journal.wait(None) { // Wait indefinitely
        Ok(result) => Ok(result),
        Err(e) => Err(Box::new(e)), 
    }
}

pub fn next_message(journal: &mut Journal) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if let Some(entry) = journal.next_entry()? {
        // For systemd v0.10.0, entry.get("MESSAGE") returns Option<&String>
        if let Some(message_string_ref) = entry.get("MESSAGE") {
            return Ok(Some(message_string_ref.clone())); // Clone the &String to String
        }
    }
    Ok(None)
}

//! Shared Vault name rule.
//!
//! The HTTP API and the CLI importer must accept exactly the same folder and
//! file names, so both call [`valid_name`]. Keep this the single source of the
//! rule: anything accepted here is accepted by the server, and anything
//! rejected here would be rejected by the server.

/// Message returned with `VAULT_NAME_INVALID`.
pub const NAME_INVALID_MESSAGE: &str =
  "Names must be 1–128 bytes and cannot contain path separators.";

/// Validate a Vault folder or file name.
///
/// Returns the trimmed name, or a human-readable reason when the name is
/// rejected. Callers map the reason to their own error type.
pub fn valid_name(name: &str) -> Result<String, &'static str> {
  let name = name.trim();
  if name.is_empty()
    || name.len() > 128
    || name.chars().any(|value| matches!(value, '/' | '\\' | '\0'))
    || name == "."
    || name == ".."
  {
    return Err(NAME_INVALID_MESSAGE);
  }
  Ok(name.to_string())
}

#[cfg(test)]
mod tests {
  use super::{NAME_INVALID_MESSAGE, valid_name};

  #[test]
  fn rejects_the_names_the_server_rejects() {
    for name in [
      "",
      "   ",
      ".",
      "..",
      "a/b",
      "a\\b",
      "nul\0name",
      &"n".repeat(129),
    ] {
      assert_eq!(
        valid_name(name),
        Err(NAME_INVALID_MESSAGE),
        "name {name:?} must be rejected"
      );
    }
  }

  #[test]
  fn accepts_trimmed_names_up_to_128_bytes() {
    assert_eq!(valid_name("  deploy.sh  ").unwrap(), "deploy.sh");
    assert!(valid_name(&"n".repeat(128)).is_ok());
    assert!(
      valid_name("...").is_ok(),
      "only exact dot segments are rejected"
    );
    assert!(valid_name("Imported vault").is_ok());
  }
}

use crate::constants::tokens::PROJECT_ID_PREFIX;

const TARGET_EXAMPLE: &str = "payment-service/local";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnvironmentTarget {
  project: String,
  environment: String,
}

impl EnvironmentTarget {
  pub fn into_parts(self) -> (String, String) {
    (self.project, self.environment)
  }
}

pub fn parse_init(value: &str) -> Result<EnvironmentTarget, String> {
  let target = parse(value)?;
  if target.project.starts_with(PROJECT_ID_PREFIX) {
    return Err("project IDs cannot be used with init because it creates a new project".into());
  }
  Ok(target)
}

pub fn parse_create(value: &str) -> Result<EnvironmentTarget, String> {
  parse(value)
}

pub fn parse_name(value: &str) -> Result<String, String> {
  let value = value.trim();
  let length = value.chars().count();
  if length == 0 || length > 128 || value.chars().any(char::is_control) {
    return Err(
      "environment names must contain 1 to 128 characters and no control characters".into(),
    );
  }
  Ok(value.into())
}

fn parse(value: &str) -> Result<EnvironmentTarget, String> {
  let Some((project, environment)) = value.split_once('/') else {
    return Err(format!(
      "environment target must use PROJECT/ENVIRONMENT, for example {TARGET_EXAMPLE}"
    ));
  };
  let project = project.trim();
  let environment = environment.trim();
  if project.is_empty()
    || environment.is_empty()
    || environment.chars().any(char::is_control)
    || environment.chars().count() > 128
  {
    return Err(format!(
      "environment target must use PROJECT/ENVIRONMENT with a name of 1 to 128 characters, for example {TARGET_EXAMPLE}"
    ));
  }
  Ok(EnvironmentTarget {
    project: project.into(),
    environment: environment.into(),
  })
}

#[cfg(test)]
mod tests {
  use super::{parse_create, parse_name};

  #[test]
  fn accepts_display_names_with_case_spaces_unicode_and_punctuation() {
    assert_eq!(
      parse_create("prj_01JTEST/Release Candidate 2 (EU)!")
        .unwrap()
        .into_parts(),
      ("prj_01JTEST".into(), "Release Candidate 2 (EU)!".into())
    );
    assert_eq!(parse_name(" Dev! ").unwrap(), "Dev!");
  }
}

//! Backend routes shared by the HTTP server, OpenAPI, and the CLI.

macro_rules! api_path {
  ($path:literal) => {
    concat!("/api/v1", $path)
  };
}

pub const PREFIX: &str = "/api/";

fn render(
  template: &str,
  parameters: &[(&str, &str)],
) -> String {
  parameters
    .iter()
    .fold(template.to_owned(), |path, (name, value)| {
      path.replace(&format!("{{{name}}}"), value)
    })
}

fn with_query(
  path: &str,
  name: &str,
  value: &str,
) -> String {
  let value: String = url::form_urlencoded::byte_serialize(value.as_bytes()).collect();
  format!("{path}?{name}={value}")
}

pub mod docs {
  pub const UI: &str = "/api/docs";
  pub const OPENAPI: &str = api_path!("/openapi.json");
}

pub mod health {
  pub const ROOT: &str = api_path!("/health");
}

pub mod bootstrap {
  pub const STATUS: &str = api_path!("/bootstrap/status");
  pub const ADMIN: &str = api_path!("/bootstrap/admin");
  pub const RESTORE: &str = api_path!("/bootstrap/restore");
}

pub mod auth {
  pub const LOGIN: &str = api_path!("/auth/login");
  pub const LOGOUT: &str = api_path!("/auth/logout");
  pub const SESSION: &str = api_path!("/auth/session");
  pub const REAUTHENTICATE: &str = api_path!("/auth/reauthenticate");
  pub const CHANGE_PASSWORD: &str = api_path!("/auth/change-password");
}

pub mod projects {
  pub const COLLECTION: &str = api_path!("/projects");
  pub const INIT: &str = api_path!("/projects/init");
  pub const ITEM: &str = api_path!("/projects/{project_ref}");
  pub const ENVIRONMENTS: &str = api_path!("/projects/{project_ref}/environments");

  pub fn item(project_ref: &str) -> String {
    super::render(ITEM, &[("project_ref", project_ref)])
  }

  pub fn environments(project_ref: &str) -> String {
    super::render(ENVIRONMENTS, &[("project_ref", project_ref)])
  }
}

pub mod environments {
  pub const COLLECTION: &str = api_path!("/environments");
  pub const RESOLVE: &str = api_path!("/environments/resolve");
  pub const ITEM: &str = api_path!("/environments/{environment_id}");

  pub fn list(project: Option<&str>) -> String {
    project.map_or_else(
      || COLLECTION.to_owned(),
      |project| super::with_query(COLLECTION, "project", project),
    )
  }

  pub fn resolve(reference: &str) -> String {
    super::with_query(RESOLVE, "reference", reference)
  }

  pub fn item(environment_id: &str) -> String {
    super::render(ITEM, &[("environment_id", environment_id)])
  }
}

pub mod secrets {
  pub const COLLECTION: &str = api_path!("/environments/{environment_id}/secrets");
  pub const IMPORT: &str = api_path!("/environments/{environment_id}/secrets/import");
  pub const LAYOUT: &str = api_path!("/environments/{environment_id}/secrets/layout");
  pub const EXPORT: &str = api_path!("/environments/{environment_id}/secrets/export");
  pub const RUNTIME: &str = api_path!("/environments/{environment_id}/secrets/runtime");
  pub const ITEM: &str = api_path!("/environments/{environment_id}/secrets/{key}");
  pub const REVEAL: &str = api_path!("/environments/{environment_id}/secrets/{key}/reveal");
  pub const VERSIONS: &str = api_path!("/environments/{environment_id}/secrets/{key}/versions");
  pub const VERSION: &str =
    api_path!("/environments/{environment_id}/secrets/{key}/versions/{version}");
  pub const ROLLBACK: &str = api_path!("/environments/{environment_id}/secrets/{key}/rollback");

  pub fn collection(environment_id: &str) -> String {
    super::render(COLLECTION, &[("environment_id", environment_id)])
  }

  pub fn import(environment_id: &str) -> String {
    super::render(IMPORT, &[("environment_id", environment_id)])
  }

  pub fn layout(environment_id: &str) -> String {
    super::render(LAYOUT, &[("environment_id", environment_id)])
  }

  pub fn export(environment_id: &str) -> String {
    super::render(EXPORT, &[("environment_id", environment_id)])
  }

  pub fn runtime(environment_id: &str) -> String {
    super::render(RUNTIME, &[("environment_id", environment_id)])
  }

  pub fn item(
    environment_id: &str,
    key: &str,
  ) -> String {
    super::render(ITEM, &[("environment_id", environment_id), ("key", key)])
  }

  pub fn reveal(
    environment_id: &str,
    key: &str,
  ) -> String {
    super::render(REVEAL, &[("environment_id", environment_id), ("key", key)])
  }

  pub fn versions(
    environment_id: &str,
    key: &str,
  ) -> String {
    super::render(
      VERSIONS,
      &[("environment_id", environment_id), ("key", key)],
    )
  }

  pub fn version(
    environment_id: &str,
    key: &str,
    version: i64,
  ) -> String {
    super::render(
      VERSION,
      &[
        ("environment_id", environment_id),
        ("key", key),
        ("version", &version.to_string()),
      ],
    )
  }

  pub fn rollback(
    environment_id: &str,
    key: &str,
  ) -> String {
    super::render(
      ROLLBACK,
      &[("environment_id", environment_id), ("key", key)],
    )
  }
}

pub mod tokens {
  pub const COLLECTION: &str = api_path!("/environments/{environment_id}/tokens");
  pub const REVOKE: &str = api_path!("/tokens/{token_id}/revoke");

  pub fn collection(environment_id: &str) -> String {
    super::render(COLLECTION, &[("environment_id", environment_id)])
  }

  pub fn revoke(token_id: &str) -> String {
    super::render(REVOKE, &[("token_id", token_id)])
  }
}

pub mod vault {
  pub const TREE: &str = api_path!("/projects/{project_ref}/files/tree");
  pub const FOLDERS: &str = api_path!("/projects/{project_ref}/files/folders");
  pub const FOLDER: &str = api_path!("/projects/{project_ref}/files/folders/{id}");
  pub const FOLDER_ENVIRONMENT: &str =
    api_path!("/projects/{project_ref}/files/folders/{id}/environment");
  pub const FILES: &str = api_path!("/projects/{project_ref}/files/folders/{id}/files");
  pub const FILE: &str = api_path!("/projects/{project_ref}/files/{id}");
  pub const FILE_MOVE: &str = api_path!("/projects/{project_ref}/files/{id}/move");
  pub const FILE_NAME: &str = api_path!("/projects/{project_ref}/files/{id}/name");
  pub const FILE_ENVIRONMENT: &str = api_path!("/projects/{project_ref}/files/{id}/environment");
  pub const FILE_REVEAL: &str = api_path!("/projects/{project_ref}/files/{id}/reveal");
  pub const FILE_VERSIONS: &str = api_path!("/projects/{project_ref}/files/{id}/versions");
  pub const FILE_VERSION: &str = api_path!("/projects/{project_ref}/files/{id}/versions/{version}");
  pub const FILE_ROLLBACK: &str =
    api_path!("/projects/{project_ref}/files/{id}/versions/{version}/rollback");
  pub const IMPORT: &str = api_path!("/projects/{project_ref}/files/import");

  pub fn tree(project_ref: &str) -> String {
    super::render(TREE, &[("project_ref", project_ref)])
  }

  pub fn folders(project_ref: &str) -> String {
    super::render(FOLDERS, &[("project_ref", project_ref)])
  }

  pub fn folder_files(
    project_ref: &str,
    id: &str,
  ) -> String {
    super::render(FILES, &[("project_ref", project_ref), ("id", id)])
  }

  pub fn folder(
    project_ref: &str,
    id: &str,
  ) -> String {
    super::render(FOLDER, &[("project_ref", project_ref), ("id", id)])
  }

  pub fn folder_environment(
    project_ref: &str,
    id: &str,
  ) -> String {
    super::render(
      FOLDER_ENVIRONMENT,
      &[("project_ref", project_ref), ("id", id)],
    )
  }

  pub fn file(
    project_ref: &str,
    id: &str,
  ) -> String {
    super::render(FILE, &[("project_ref", project_ref), ("id", id)])
  }

  pub fn file_move(
    project_ref: &str,
    id: &str,
  ) -> String {
    super::render(FILE_MOVE, &[("project_ref", project_ref), ("id", id)])
  }

  pub fn file_name(
    project_ref: &str,
    id: &str,
  ) -> String {
    super::render(FILE_NAME, &[("project_ref", project_ref), ("id", id)])
  }

  pub fn file_environment(
    project_ref: &str,
    id: &str,
  ) -> String {
    super::render(
      FILE_ENVIRONMENT,
      &[("project_ref", project_ref), ("id", id)],
    )
  }

  pub fn reveal_file(
    project_ref: &str,
    id: &str,
  ) -> String {
    super::render(FILE_REVEAL, &[("project_ref", project_ref), ("id", id)])
  }

  pub fn file_versions(
    project_ref: &str,
    id: &str,
  ) -> String {
    super::render(FILE_VERSIONS, &[("project_ref", project_ref), ("id", id)])
  }

  pub fn file_version(
    project_ref: &str,
    id: &str,
    version: i64,
  ) -> String {
    super::render(
      FILE_VERSION,
      &[
        ("project_ref", project_ref),
        ("id", id),
        ("version", &version.to_string()),
      ],
    )
  }

  pub fn rollback_file(
    project_ref: &str,
    id: &str,
    version: i64,
  ) -> String {
    super::render(
      FILE_ROLLBACK,
      &[
        ("project_ref", project_ref),
        ("id", id),
        ("version", &version.to_string()),
      ],
    )
  }

  pub fn import(project_ref: &str) -> String {
    super::render(IMPORT, &[("project_ref", project_ref)])
  }
}

pub mod audit {
  pub const COLLECTION: &str = api_path!("/audit-events");
}

pub mod instance {
  pub const ROOT: &str = api_path!("/instance");
  pub const PUBLIC_STATUS: &str = api_path!("/status");
  pub const FACTORY_RESET: &str = api_path!("/instance/factory-reset");
}

pub mod users {
  pub const COLLECTION: &str = api_path!("/users");
  pub const ITEM: &str = api_path!("/users/{id}");

  pub fn item(id: &str) -> String {
    super::render(ITEM, &[("id", id)])
  }
}

pub mod service_accounts {
  pub const COLLECTION: &str = api_path!("/service-accounts");
  pub const ITEM: &str = api_path!("/service-accounts/{id}");
  pub const TOKENS: &str = api_path!("/service-accounts/{id}/tokens");
  pub const REVOKE_TOKEN: &str = api_path!("/service-accounts/{id}/tokens/{token_id}/revoke");

  pub fn item(id: &str) -> String {
    super::render(ITEM, &[("id", id)])
  }

  pub fn tokens(id: &str) -> String {
    super::render(TOKENS, &[("id", id)])
  }

  pub fn revoke_token(
    id: &str,
    token_id: &str,
  ) -> String {
    super::render(REVOKE_TOKEN, &[("id", id), ("token_id", token_id)])
  }
}

pub mod backups {
  pub const COLLECTION: &str = api_path!("/backups");
  pub const MASTER_KEY: &str = api_path!("/backups/master-key");
  pub const UPLOAD: &str = api_path!("/backups/upload");
  pub const ITEM: &str = api_path!("/backups/{key}");
  pub const RESTORE: &str = api_path!("/backups/{key}/restore");

  pub fn item(key: &str) -> String {
    super::render(ITEM, &[("key", key)])
  }

  pub fn restore(key: &str) -> String {
    super::render(RESTORE, &[("key", key)])
  }
}

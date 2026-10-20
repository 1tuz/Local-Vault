use crate::state::AppState;
use axum::{
  Router,
  routing::{delete, get, post, put},
};

pub mod controller;
pub mod doc;
pub mod model;
mod repository;
pub mod service;

pub fn routes() -> Router<AppState> {
  Router::new()
    .route(crate::constants::api::vault::TREE, get(controller::tree))
    .route(
      crate::constants::api::vault::FOLDERS,
      get(controller::list_folders).post(controller::create_folder),
    )
    .route(
      crate::constants::api::vault::FOLDER,
      put(controller::move_folder).delete(controller::delete_folder),
    )
    .route(
      crate::constants::api::vault::FOLDER_ENVIRONMENT,
      put(controller::set_folder_environment),
    )
    .route(
      crate::constants::api::vault::FILES,
      get(controller::list_files).post(controller::create_file),
    )
    .route(
      crate::constants::api::vault::FILE,
      get(controller::file_metadata)
        .put(controller::update_file)
        .delete(controller::delete_file),
    )
    .route(
      crate::constants::api::vault::FILE_NAME,
      put(controller::rename_file),
    )
    .route(
      crate::constants::api::vault::FILE_MOVE,
      post(controller::move_file),
    )
    .route(
      crate::constants::api::vault::FILE_ENVIRONMENT,
      put(controller::set_file_environment),
    )
    .route(
      crate::constants::api::vault::FILE_VERSIONS,
      get(controller::file_versions),
    )
    .route(
      crate::constants::api::vault::FILE_VERSION,
      delete(controller::delete_file_version),
    )
    .route(
      crate::constants::api::vault::FILE_ROLLBACK,
      post(controller::rollback_file),
    )
    .route(
      crate::constants::api::vault::FILE_REVEAL,
      post(controller::reveal_file),
    )
}

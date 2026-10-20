import { apiRequest } from "./http.client";

export interface VaultFolder {
  id: string;
  projectId: string;
  parentId: string | null;
  environmentId: string | null;
  isRoot: boolean;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export type VaultFileKind =
  "secret" | "env" | "kubeconfig" | "sshPrivateKey" | "certificate" | "text";

export interface VaultFileMetadata {
  id: string;
  folderId: string;
  environmentId: string | null;
  name: string;
  kind: VaultFileKind;
  encoding: "utf-8" | "base64";
  version: number;
  createdAt: string;
  updatedAt: string;
}

export interface VaultFolderContents {
  folder: VaultFolder;
  files: VaultFileMetadata[];
}

export interface VaultFileVersion {
  version: number;
  encoding: "utf-8" | "base64";
  createdAt: string;
  updatedAt: string;
  archivedAt: string;
}

export interface RevealedVaultFile {
  id: string;
  name: string;
  kind: VaultFileKind;
  encoding: "utf-8" | "base64";
  content: string;
  version: number;
}

const base = (projectRef: string): string =>
  `/api/v1/projects/${encodeURIComponent(projectRef)}/files`;

export async function listVaultFolders(
  projectRef: string,
): Promise<VaultFolder[]> {
  const { data } = await apiRequest<VaultFolder[]>(
    `${base(projectRef)}/folders`,
  );
  return data;
}

export async function listVaultTree(
  projectRef: string,
): Promise<VaultFolderContents[]> {
  const { data } = await apiRequest<VaultFolderContents[]>(
    `${base(projectRef)}/tree`,
  );
  return data;
}

export async function createVaultFolder(
  projectRef: string,
  name: string,
  parentId: string | null,
  environmentId: string | null = null,
): Promise<VaultFolder> {
  const { data } = await apiRequest<VaultFolder>(
    `${base(projectRef)}/folders`,
    {
      method: "POST",
      body: { name, parentId, environmentId },
    },
  );
  return data;
}

export async function setVaultFolderEnvironment(
  projectRef: string,
  id: string,
  environmentId: string | null,
): Promise<VaultFolder> {
  const { data } = await apiRequest<VaultFolder>(
    `${base(projectRef)}/folders/${encodeURIComponent(id)}/environment`,
    { method: "PUT", body: { environmentId } },
  );
  return data;
}

export async function setVaultFileEnvironment(
  projectRef: string,
  id: string,
  environmentId: string | null,
): Promise<VaultFileMetadata> {
  const { data } = await apiRequest<VaultFileMetadata>(
    `${base(projectRef)}/${encodeURIComponent(id)}/environment`,
    { method: "PUT", body: { environmentId } },
  );
  return data;
}

export async function listVaultFiles(
  projectRef: string,
  folderId: string,
): Promise<VaultFileMetadata[]> {
  const { data } = await apiRequest<VaultFileMetadata[]>(
    `${base(projectRef)}/folders/${encodeURIComponent(folderId)}/files`,
  );
  return data;
}

export async function createVaultFile(
  projectRef: string,
  folderId: string,
  name: string,
  kind: VaultFileKind,
  content: string,
  environmentId: string | null = null,
): Promise<VaultFileMetadata> {
  const { data } = await apiRequest<VaultFileMetadata>(
    `${base(projectRef)}/folders/${encodeURIComponent(folderId)}/files`,
    { method: "POST", body: { name, kind, content, environmentId } },
  );
  return data;
}

export async function revealVaultFile(
  projectRef: string,
  id: string,
): Promise<RevealedVaultFile> {
  const { data } = await apiRequest<RevealedVaultFile>(
    `${base(projectRef)}/${encodeURIComponent(id)}/reveal`,
    { method: "POST" },
  );
  return data;
}

export async function updateVaultFile(
  projectRef: string,
  id: string,
  content: string,
): Promise<VaultFileMetadata> {
  const { data } = await apiRequest<VaultFileMetadata>(
    `${base(projectRef)}/${encodeURIComponent(id)}`,
    { method: "PUT", body: { content } },
  );
  return data;
}

export async function moveVaultFolder(
  projectRef: string,
  id: string,
  name: string,
  parentId: string | null,
): Promise<VaultFolder> {
  const { data } = await apiRequest<VaultFolder>(
    `${base(projectRef)}/folders/${encodeURIComponent(id)}`,
    { method: "PUT", body: { name, parentId } },
  );
  return data;
}

export async function moveVaultFile(
  projectRef: string,
  id: string,
  folderId: string,
): Promise<VaultFileMetadata> {
  const { data } = await apiRequest<VaultFileMetadata>(
    `${base(projectRef)}/${encodeURIComponent(id)}/move`,
    { method: "POST", body: { folderId } },
  );
  return data;
}

export async function renameVaultFile(
  projectRef: string,
  id: string,
  name: string,
): Promise<VaultFileMetadata> {
  const { data } = await apiRequest<VaultFileMetadata>(
    `${base(projectRef)}/${encodeURIComponent(id)}/name`,
    { method: "PUT", body: { name } },
  );
  return data;
}

export async function listVaultFileVersions(
  projectRef: string,
  id: string,
): Promise<VaultFileVersion[]> {
  const { data } = await apiRequest<VaultFileVersion[]>(
    `${base(projectRef)}/${encodeURIComponent(id)}/versions`,
  );
  return data;
}

export async function rollbackVaultFile(
  projectRef: string,
  id: string,
  version: number,
): Promise<VaultFileMetadata> {
  const { data } = await apiRequest<VaultFileMetadata>(
    `${base(projectRef)}/${encodeURIComponent(id)}/versions/${version}/rollback`,
    { method: "POST" },
  );
  return data;
}

export async function deleteVaultFileVersion(
  projectRef: string,
  id: string,
  version: number,
): Promise<void> {
  await apiRequest(
    `${base(projectRef)}/${encodeURIComponent(id)}/versions/${version}`,
    { method: "DELETE" },
  );
}

export async function deleteVaultFile(
  projectRef: string,
  id: string,
): Promise<void> {
  await apiRequest(`${base(projectRef)}/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export async function deleteVaultFolder(
  projectRef: string,
  id: string,
): Promise<void> {
  await apiRequest(`${base(projectRef)}/folders/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

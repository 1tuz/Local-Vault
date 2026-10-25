<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import {
  ArchiveIcon,
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CopyIcon,
  EyeIcon,
  EyeOffIcon,
  FolderIcon,
  KeyIcon,
  LayersIcon,
  MoreHorizontalIcon,
  PencilIcon,
  PlusIcon,
  TrashIcon,
} from "~/assets/icons";
import {
  DbAlert,
  DbButton,
  DbInput,
  DbModal,
  DbSelect,
  DbTextarea,
} from "~/components/ui";
import {
  listEnvironments,
  type Environment,
} from "~/services/environments.api";
import EnvironmentTagPicker from "./EnvironmentTagPicker.vue";
import {
  createVaultFile,
  createVaultFolder,
  deleteVaultFile,
  deleteVaultFileVersion,
  deleteVaultFolder,
  listVaultFileVersions,
  listVaultFiles,
  listVaultTree,
  moveVaultFile,
  moveVaultFolder,
  renameVaultFile,
  revealVaultFile,
  rollbackVaultFile,
  setVaultFileEnvironment,
  setVaultFolderEnvironment,
  updateVaultFile,
  type RevealedVaultFile,
  type VaultFileKind,
  type VaultFileMetadata,
  type VaultFileVersion,
  type VaultFolder,
} from "~/services/vault.api";

const props = defineProps<{
  projectRef: string;
  createRequest?: { kind: "folder" | "file"; nonce: number } | null;
}>();
const emit = defineEmits<{
  "create-request-consumed": [];
  "environment-created": [environment: Environment];
  "environment-create-request": [];
  "environment-rename-request": [environment: Environment];
  "environment-delete-request": [environment: Environment];
}>();
const folders = ref<VaultFolder[]>([]);
const files = ref<VaultFileMetadata[]>([]);
const treeFiles = ref<VaultFileMetadata[]>([]);
const environments = ref<Environment[]>([]);
const environmentFilterId = ref<string | null | "all">("all");
const currentFolderId = ref<string | null>(null);
const loading = ref(true);
const busy = ref(false);
const error = ref("");
const notice = ref("");
let syncTimer: number | undefined;
let syncing = false;
const createFolderOpen = ref(false);
const createFileOpen = ref(false);
const folderMenuId = ref<string | null>(null);
const fileMenuId = ref<string | null>(null);
const environmentMenuId = ref<string | null>(null);
const expandedFolderIds = ref<Set<string>>(new Set());
let initializedExpandedFolders = false;
const tagTarget = ref<{
  kind: "folder";
  id: string;
  name: string;
} | null>(null);
const tagValue = ref("");
const renameTarget = ref<VaultFolder | null>(null);
const movingFolder = ref<VaultFolder | null>(null);
const movingFile = ref<VaultFileMetadata | null>(null);
const moveDestinationId = ref("");
const draggingItem = ref<{ kind: "folder" | "file"; id: string } | null>(null);
const dropTargetId = ref<string | null>(null);
const pointerDrag = ref<{
  item: { kind: "folder" | "file"; id: string };
  pointerId: number;
  startX: number;
  startY: number;
  source: HTMLElement;
  active: boolean;
} | null>(null);
const suppressDragClick = ref(false);
const confirmation = ref<{
  title: string;
  message: string;
  actionLabel: string;
  resolve: (confirmed: boolean) => void;
} | null>(null);
const folderName = ref("");
const fileName = ref("");
const fileKind = ref<VaultFileKind>("secret");
const fileContent = ref("");
const fileEnvironment = ref("");
const fileFormError = ref("");
const folderEnvironment = ref("");
const activeFile = ref<VaultFileMetadata | null>(null);
const revealed = ref<RevealedVaultFile | null>(null);
const versions = ref<VaultFileVersion[]>([]);
const editingFileName = ref(false);
const fileNameDraft = ref("");
const detailEnvironmentTag = ref("");
let hideTimer: ReturnType<typeof setTimeout> | null = null;
let noticeTimer: ReturnType<typeof setTimeout> | null = null;

function showNotice(message: string): void {
  notice.value = message;
  if (noticeTimer) clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => {
    notice.value = "";
    noticeTimer = null;
  }, 2000);
}

function askToConfirm(
  title: string,
  message: string,
  actionLabel: string,
): Promise<boolean> {
  return new Promise((resolve) => {
    confirmation.value = { title, message, actionLabel, resolve };
  });
}

function closeConfirmation(confirmed: boolean): void {
  const resolve = confirmation.value?.resolve;
  confirmation.value = null;
  resolve?.(confirmed);
}

const folderItems = computed(() => {
  const root = folders.value.find(({ isRoot }) => isRoot);
  const children = (
    parentId: string | null,
    depth: number,
  ): Array<VaultFolder & { depth: number }> =>
    folders.value
      .filter((folder) => folder.parentId === parentId)
      .flatMap((folder) => [
        { ...folder, depth },
        ...children(folder.id, depth + 1),
      ]);
  return children(root?.id ?? null, 0).filter(({ isRoot }) => !isRoot);
});
const rootFolder = computed(
  () => folders.value.find(({ isRoot }) => isRoot) ?? null,
);
const activeFolder = computed(
  () =>
    folders.value.find(
      (folder) => folder.id === currentFolderId.value && !folder.isRoot,
    ) ?? null,
);
const folderDescendants = (id: string): Set<string> => {
  const descendants = new Set<string>();
  const visit = (parentId: string): void => {
    for (const folder of folders.value.filter(
      (item) => item.parentId === parentId,
    )) {
      descendants.add(folder.id);
      visit(folder.id);
    }
  };
  visit(id);
  return descendants;
};
function folderPathLabel(id: string): string {
  const path: string[] = [];
  let folder = folders.value.find((item) => item.id === id);
  while (folder) {
    if (!folder.isRoot) path.unshift(folder.name);
    const parentId = folder.parentId;
    folder = parentId
      ? folders.value.find((item) => item.id === parentId)
      : undefined;
  }
  return path.join(" / ") || "Project root";
}
const projectRootOption = computed(() =>
  rootFolder.value
    ? [{ label: "Project root", value: rootFolder.value.id }]
    : [],
);
const moveFolderOptions = computed(() => {
  const excluded = movingFolder.value
    ? new Set([
        movingFolder.value.id,
        ...folderDescendants(movingFolder.value.id),
      ])
    : new Set<string>();
  return [
    ...projectRootOption.value,
    ...folderItems.value
      .filter(({ id }) => !excluded.has(id))
      .map(({ id }) => ({ label: folderPathLabel(id), value: id })),
  ];
});
const moveFileOptions = computed(() => [
  ...projectRootOption.value.filter(
    ({ value }) => value !== movingFile.value?.folderId,
  ),
  ...folderItems.value
    .filter(({ id }) => id !== movingFile.value?.folderId)
    .map(({ id }) => ({ label: folderPathLabel(id), value: id })),
]);
const kindOptions: Array<{ value: VaultFileKind; label: string }> = [
  { value: "secret", label: "Secret" },
  { value: "env", label: "Environment file" },
  { value: "kubeconfig", label: "Kubernetes config" },
  { value: "sshPrivateKey", label: "SSH private key" },
  { value: "certificate", label: "Certificate" },
  { value: "text", label: "Text file" },
];

function openFileCreation(): void {
  fileFormError.value = "";
  fileEnvironment.value = "";
  createFileOpen.value = true;
}

function matchesEnvironmentFilter(id: string | null): boolean {
  return environmentFilterId.value === "all"
    ? true
    : environmentFilterId.value === null
      ? id === null
      : id === environmentFilterId.value;
}

type FileTreeRow =
  | { kind: "folder"; folder: VaultFolder; depth: number }
  | { kind: "file"; file: VaultFileMetadata; depth: number };

const visibleTreeRows = computed<FileTreeRow[]>(() => {
  const rootId = rootFolder.value?.id;
  if (!rootId) return [];

  const visibleFiles = treeFiles.value.filter((file) =>
    matchesEnvironmentFilter(effectiveFileEnvironmentId(file)),
  );
  const foldersWithVisibleFiles = new Set<string>();
  for (const file of visibleFiles) {
    let folder = folders.value.find(({ id }) => id === file.folderId);
    while (folder && !folder.isRoot) {
      foldersWithVisibleFiles.add(folder.id);
      folder = folder.parentId
        ? folders.value.find(({ id }) => id === folder!.parentId)
        : undefined;
    }
  }

  const walk = (parentId: string, depth: number): FileTreeRow[] => {
    const childFolders = folders.value.filter(
      (folder) =>
        folder.parentId === parentId &&
        (environmentFilterId.value === "all" ||
          matchesEnvironmentFilter(effectiveFolderEnvironmentId(folder.id)) ||
          foldersWithVisibleFiles.has(folder.id)),
    );
    const childFiles = visibleFiles.filter(
      (file) => file.folderId === parentId,
    );
    const entries: FileTreeRow[] = [
      ...childFolders.map((folder) => ({
        kind: "folder" as const,
        folder,
        depth,
      })),
      ...childFiles.map((file) => ({ kind: "file" as const, file, depth })),
    ];
    entries.sort((left, right) => {
      const leftName =
        left.kind === "folder" ? left.folder.name : left.file.name;
      const rightName =
        right.kind === "folder" ? right.folder.name : right.file.name;
      return leftName.localeCompare(rightName, undefined, {
        sensitivity: "base",
      });
    });
    return entries.flatMap((entry) =>
      entry.kind === "folder" && expandedFolderIds.value.has(entry.folder.id)
        ? [entry, ...walk(entry.folder.id, depth + 1)]
        : [entry],
    );
  };

  return walk(rootId, 0);
});

function toggleFolder(folder: VaultFolder): void {
  const next = new Set(expandedFolderIds.value);
  if (next.has(folder.id)) next.delete(folder.id);
  else next.add(folder.id);
  expandedFolderIds.value = next;
}

function environmentName(id: string | null): string {
  if (!id) return "Shared";
  return (
    environments.value.find((environment) => environment.id === id)?.name ??
    "Environment"
  );
}

function effectiveFolderEnvironmentId(folderId: string): string | null {
  let folder = folders.value.find(({ id }) => id === folderId);
  while (folder) {
    if (folder.environmentId) return folder.environmentId;
    folder = folder.parentId
      ? folders.value.find(({ id }) => id === folder!.parentId)
      : undefined;
  }
  return null;
}

function effectiveFileEnvironmentId(file: VaultFileMetadata): string | null {
  return file.environmentId ?? effectiveFolderEnvironmentId(file.folderId);
}

async function resolveEnvironmentId(label: string): Promise<string | null> {
  const name = label.trim();
  if (!name) return null;
  const existing = environments.value.find(
    (environment) =>
      environment.name.toLocaleLowerCase() === name.toLocaleLowerCase(),
  );
  if (existing) return existing.id;
  throw new Error(`Choose “Create ${name}” from the tag list first.`);
}

function onEnvironmentCreated(environment: Environment): void {
  if (!environments.value.some(({ id }) => id === environment.id)) {
    environments.value = [...environments.value, environment];
  }
  emit("environment-created", environment);
}

async function refreshTree(): Promise<void> {
  const [tree, listedEnvironments] = await Promise.all([
    listVaultTree(props.projectRef),
    listEnvironments(props.projectRef),
  ]);
  folders.value = tree.map(({ folder }) => folder);
  treeFiles.value = tree.flatMap(({ files: folderFiles }) => folderFiles);
  environments.value = listedEnvironments;
}

async function loadFolders(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    await refreshTree();
    if (!initializedExpandedFolders) {
      expandedFolderIds.value = new Set(
        folders.value.filter(({ isRoot }) => !isRoot).map(({ id }) => id),
      );
      initializedExpandedFolders = true;
    }
    if (
      currentFolderId.value &&
      !folders.value.some(({ id }) => id === currentFolderId.value)
    ) {
      currentFolderId.value = null;
    }
    if (currentFolderId.value === null)
      currentFolderId.value = rootFolder.value?.id ?? null;
    await loadFiles();
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not load project files.";
  } finally {
    loading.value = false;
  }
}

async function loadFiles(): Promise<void> {
  files.value = currentFolderId.value
    ? await listVaultFiles(props.projectRef, currentFolderId.value)
    : [];
}

async function syncExternalChanges(): Promise<void> {
  if (
    syncing ||
    loading.value ||
    busy.value ||
    document.visibilityState === "hidden"
  )
    return;
  syncing = true;
  try {
    await refreshTree();
    if (
      currentFolderId.value &&
      !folders.value.some(({ id }) => id === currentFolderId.value)
    ) {
      currentFolderId.value = rootFolder.value?.id ?? null;
    }
    await loadFiles();
  } catch {
    // Keep the current view during transient CLI/MCP or network activity.
  } finally {
    syncing = false;
  }
}

function onVisibilityChange(): void {
  if (document.visibilityState === "visible") void syncExternalChanges();
}

async function selectFolder(id: string | null): Promise<void> {
  currentFolderId.value = id ?? rootFolder.value?.id ?? null;
  activeFile.value = null;
  revealed.value = null;
  error.value = "";
  try {
    await loadFiles();
  } catch (cause) {
    error.value =
      cause instanceof Error
        ? cause.message
        : "Could not load folder contents.";
  }
}

async function submitFolder(): Promise<void> {
  if (!folderName.value.trim()) return;
  busy.value = true;
  error.value = "";
  try {
    if (!rootFolder.value) await refreshTree();
    const environmentId = await resolveEnvironmentId(folderEnvironment.value);
    const folder = await createVaultFolder(
      props.projectRef,
      folderName.value,
      currentFolderId.value ?? rootFolder.value?.id ?? null,
      environmentId,
    );
    folders.value = [...folders.value, folder];
    expandedFolderIds.value = new Set([
      ...expandedFolderIds.value,
      ...(folder.parentId ? [folder.parentId] : []),
      folder.id,
    ]);
    folderName.value = "";
    folderEnvironment.value = "";
    createFolderOpen.value = false;
    showNotice("Folder created.");
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not create the folder.";
  } finally {
    busy.value = false;
  }
}

function startFolderTag(folder: VaultFolder): void {
  folderMenuId.value = null;
  tagTarget.value = { kind: "folder", id: folder.id, name: folder.name };
  tagValue.value = "";
}

async function saveFolderTag(
  folder: VaultFolder,
  environmentId: string | null,
): Promise<void> {
  tagTarget.value = { kind: "folder", id: folder.id, name: folder.name };
  await saveTag(environmentId);
}

async function saveTag(environmentId: string | null): Promise<void> {
  const target = tagTarget.value;
  if (!target) return;
  busy.value = true;
  error.value = "";
  try {
    const updated = await setVaultFolderEnvironment(
      props.projectRef,
      target.id,
      environmentId,
    );
    folders.value = folders.value.map((folder) =>
      folder.id === updated.id ? updated : folder,
    );
    showNotice(
      environmentId
        ? "Folder environment updated."
        : "Folder now inherits its environment.",
    );
    tagTarget.value = null;
  } catch (cause) {
    error.value =
      cause instanceof Error
        ? cause.message
        : "Could not update the environment tag.";
  } finally {
    busy.value = false;
  }
}

async function submitTag(): Promise<void> {
  try {
    await saveTag(await resolveEnvironmentId(tagValue.value));
  } catch (cause) {
    if (
      cause instanceof Error &&
      cause.message !== "Environment tag creation was cancelled."
    ) {
      error.value = cause.message;
    }
  }
}

async function submitFile(): Promise<void> {
  if (!fileName.value.trim()) return;
  busy.value = true;
  fileFormError.value = "";
  try {
    if (!rootFolder.value) await refreshTree();
    const folderId = currentFolderId.value ?? rootFolder.value?.id;
    if (!folderId) throw new Error("Project root is not available yet.");
    const environmentId = await resolveEnvironmentId(fileEnvironment.value);
    const file = await createVaultFile(
      props.projectRef,
      folderId,
      fileName.value,
      fileKind.value,
      fileContent.value,
      environmentId,
    );
    files.value = [...files.value, file];
    treeFiles.value = [...treeFiles.value, file];
    fileName.value = "";
    fileContent.value = "";
    fileEnvironment.value = "";
    createFileOpen.value = false;
    showNotice("Encrypted file created.");
  } catch (cause) {
    fileFormError.value =
      cause instanceof Error ? cause.message : "Could not create the file.";
  } finally {
    busy.value = false;
  }
}

async function revealFile(file: VaultFileMetadata): Promise<void> {
  if (revealed.value?.id === file.id) {
    hideRevealed();
    return;
  }
  busy.value = true;
  error.value = "";
  try {
    revealed.value = await revealVaultFile(props.projectRef, file.id);
    activeFile.value = file;
    detailEnvironmentTag.value = file.environmentId
      ? environmentName(file.environmentId)
      : "";
    versions.value = await listVaultFileVersions(props.projectRef, file.id);
    resetHideTimer();
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not reveal the file.";
  } finally {
    busy.value = false;
  }
}

async function openFileDetails(file: VaultFileMetadata): Promise<void> {
  hideRevealed();
  activeFile.value = file;
  detailEnvironmentTag.value = file.environmentId
    ? environmentName(file.environmentId)
    : "";
  error.value = "";
  busy.value = true;
  try {
    versions.value = await listVaultFileVersions(props.projectRef, file.id);
  } catch (cause) {
    error.value =
      cause instanceof Error
        ? cause.message
        : "Could not load version history.";
  } finally {
    busy.value = false;
  }
}

async function saveDetailEnvironment(): Promise<void> {
  if (!activeFile.value) return;
  busy.value = true;
  error.value = "";
  try {
    const environmentId = await resolveEnvironmentId(
      detailEnvironmentTag.value,
    );
    const updated = await setVaultFileEnvironment(
      props.projectRef,
      activeFile.value.id,
      environmentId,
    );
    treeFiles.value = treeFiles.value.map((file) =>
      file.id === updated.id ? updated : file,
    );
    files.value = files.value.map((file) =>
      file.id === updated.id ? updated : file,
    );
    activeFile.value = updated;
    detailEnvironmentTag.value = updated.environmentId
      ? environmentName(updated.environmentId)
      : "";
    showNotice("Environment tag updated.");
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not update the tag.";
  } finally {
    busy.value = false;
  }
}

async function copyContent(): Promise<void> {
  if (!revealed.value) return;
  error.value = "";
  try {
    await navigator.clipboard.writeText(revealed.value.content);
    showNotice("Copied to clipboard.");
  } catch {
    error.value = "Clipboard access was denied.";
  }
}

async function copyFile(file: VaultFileMetadata): Promise<void> {
  busy.value = true;
  error.value = "";
  try {
    let content = revealed.value?.id === file.id ? revealed.value.content : "";
    if (revealed.value?.id !== file.id) {
      const value = await revealVaultFile(props.projectRef, file.id);
      content = value.content;
    }
    await navigator.clipboard.writeText(content);
    showNotice("Copied to clipboard.");
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not copy the file.";
  } finally {
    busy.value = false;
  }
}

function hideRevealed(): void {
  revealed.value = null;
  activeFile.value = null;
  versions.value = [];
  editingFileName.value = false;
  detailEnvironmentTag.value = "";
  if (hideTimer) clearTimeout(hideTimer);
  hideTimer = null;
}

async function saveFileName(): Promise<void> {
  if (!activeFile.value || !fileNameDraft.value.trim()) return;
  busy.value = true;
  error.value = "";
  try {
    const updated = await renameVaultFile(
      props.projectRef,
      activeFile.value.id,
      fileNameDraft.value,
    );
    files.value = files.value.map((file) =>
      file.id === updated.id ? updated : file,
    );
    treeFiles.value = treeFiles.value.map((file) =>
      file.id === updated.id ? updated : file,
    );
    activeFile.value = updated;
    if (revealed.value?.id === updated.id) revealed.value.name = updated.name;
    editingFileName.value = false;
    showNotice("File renamed.");
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not rename file.";
  } finally {
    busy.value = false;
  }
}

function resetHideTimer(): void {
  if (hideTimer) clearTimeout(hideTimer);
  hideTimer = setTimeout(hideRevealed, 30_000);
}

async function saveFile(): Promise<void> {
  if (!revealed.value) return;
  busy.value = true;
  error.value = "";
  try {
    const updated = await updateVaultFile(
      props.projectRef,
      revealed.value.id,
      revealed.value.content,
    );
    files.value = files.value.map((file) =>
      file.id === updated.id ? updated : file,
    );
    treeFiles.value = treeFiles.value.map((file) =>
      file.id === updated.id ? updated : file,
    );
    activeFile.value = updated;
    revealed.value.version = updated.version;
    versions.value = await listVaultFileVersions(props.projectRef, updated.id);
    showNotice(`Saved as version ${updated.version}.`);
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not save the file.";
  } finally {
    busy.value = false;
  }
}

async function rollback(version: VaultFileVersion): Promise<void> {
  if (!activeFile.value) return;
  busy.value = true;
  error.value = "";
  try {
    const updated = await rollbackVaultFile(
      props.projectRef,
      activeFile.value.id,
      version.version,
    );
    files.value = files.value.map((file) =>
      file.id === updated.id ? updated : file,
    );
    treeFiles.value = treeFiles.value.map((file) =>
      file.id === updated.id ? updated : file,
    );
    activeFile.value = updated;
    revealed.value = await revealVaultFile(props.projectRef, updated.id);
    versions.value = await listVaultFileVersions(props.projectRef, updated.id);
    resetHideTimer();
    showNotice(`Restored as version ${updated.version}.`);
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not restore the version.";
  } finally {
    busy.value = false;
  }
}

async function confirmRollback(
  file: VaultFileMetadata,
  version: VaultFileVersion,
): Promise<void> {
  if (
    !(await askToConfirm(
      "Restore previous version",
      `Restore version ${version.version} of ${file.name}? This creates a new version.`,
      "Restore version",
    ))
  )
    return;
  await rollback(version);
}

async function removeVersion(
  file: VaultFileMetadata,
  version: VaultFileVersion,
): Promise<void> {
  if (
    !(await askToConfirm(
      "Delete saved version",
      `Permanently delete version ${version.version} of ${file.name}?`,
      "Delete version",
    ))
  )
    return;
  busy.value = true;
  error.value = "";
  try {
    await deleteVaultFileVersion(props.projectRef, file.id, version.version);
    versions.value = await listVaultFileVersions(props.projectRef, file.id);
    showNotice(`Version ${version.version} deleted.`);
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not delete the version.";
  } finally {
    busy.value = false;
  }
}

async function removeFile(file: VaultFileMetadata): Promise<void> {
  if (
    !(await askToConfirm(
      "Delete file",
      `Delete “${file.name}” and its version history?`,
      "Delete file",
    ))
  )
    return;
  busy.value = true;
  error.value = "";
  try {
    await deleteVaultFile(props.projectRef, file.id);
    files.value = files.value.filter(({ id }) => id !== file.id);
    treeFiles.value = treeFiles.value.filter(({ id }) => id !== file.id);
    if (activeFile.value?.id === file.id) {
      activeFile.value = null;
      revealed.value = null;
      versions.value = [];
    }
    showNotice("File deleted.");
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not delete the file.";
  } finally {
    busy.value = false;
  }
}

async function removeFolder(folder: VaultFolder): Promise<void> {
  if (
    !(await askToConfirm(
      "Delete empty folder",
      `Delete empty folder “${folder.name}”?`,
      "Delete folder",
    ))
  )
    return;
  busy.value = true;
  error.value = "";
  try {
    await deleteVaultFolder(props.projectRef, folder.id);
    folders.value = folders.value.filter(({ id }) => id !== folder.id);
    if (currentFolderId.value === folder.id) await selectFolder(null);
    showNotice("Folder deleted.");
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not delete the folder.";
  } finally {
    busy.value = false;
  }
}

function startRename(folder: VaultFolder): void {
  folderMenuId.value = null;
  folderName.value = folder.name;
  renameTarget.value = folder;
}

async function submitRename(): Promise<void> {
  const target = renameTarget.value;
  if (!target || !folderName.value.trim()) return;
  busy.value = true;
  error.value = "";
  try {
    const updated = await moveVaultFolder(
      props.projectRef,
      target.id,
      folderName.value,
      target.parentId,
    );
    folders.value = folders.value.map((folder) =>
      folder.id === updated.id ? updated : folder,
    );
    renameTarget.value = null;
    folderName.value = "";
    showNotice("Folder renamed.");
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not rename the folder.";
  } finally {
    busy.value = false;
  }
}

function startMoveFolder(folder: VaultFolder): void {
  folderMenuId.value = null;
  movingFolder.value = folder;
  moveDestinationId.value = folder.parentId ?? "";
}

function startMoveFile(file: VaultFileMetadata): void {
  movingFile.value = file;
  moveDestinationId.value = "";
}

async function submitMove(): Promise<void> {
  busy.value = true;
  error.value = "";
  try {
    if (movingFolder.value) {
      const folder = movingFolder.value;
      const updated = await moveVaultFolder(
        props.projectRef,
        folder.id,
        folder.name,
        moveDestinationId.value || null,
      );
      folders.value = folders.value.map((item) =>
        item.id === updated.id ? updated : item,
      );
      movingFolder.value = null;
      showNotice("Folder moved.");
    } else if (movingFile.value && moveDestinationId.value) {
      const updated = await moveVaultFile(
        props.projectRef,
        movingFile.value.id,
        moveDestinationId.value,
      );
      files.value = files.value.filter(({ id }) => id !== movingFile.value?.id);
      treeFiles.value = treeFiles.value.map((file) =>
        file.id === updated.id ? updated : file,
      );
      movingFile.value = null;
      showNotice("File moved.");
    }
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not move the item.";
  } finally {
    busy.value = false;
  }
}

function closeMove(): void {
  movingFolder.value = null;
  movingFile.value = null;
  moveDestinationId.value = "";
}

function startPointerDrag(
  event: PointerEvent,
  item: { kind: "folder" | "file"; id: string },
): void {
  if (event.button !== 0) return;
  const source = event.currentTarget as HTMLElement;
  pointerDrag.value = {
    item,
    pointerId: event.pointerId,
    startX: event.clientX,
    startY: event.clientY,
    source,
    active: false,
  };
  source.setPointerCapture?.(event.pointerId);
}

function canDropOnFolder(
  item: { kind: "folder" | "file"; id: string } | null,
  destination: VaultFolder,
): boolean {
  if (!item) return false;
  if (item.kind === "file") {
    const source = treeFiles.value.find(({ id }) => id === item.id);
    return Boolean(source && source.folderId !== destination.id);
  }
  return (
    item.id !== destination.id &&
    !folderDescendants(item.id).has(destination.id) &&
    folders.value.some(
      ({ id, parentId }) => id === item.id && parentId !== destination.id,
    )
  );
}

function dropTargetAt(x: number, y: number): string | null {
  const target = document.elementFromPoint(x, y);
  const folder = target?.closest<HTMLElement>("[data-drop-folder-id]");
  if (folder) return `folder:${folder.dataset.dropFolderId}`;
  if (target?.closest("[data-drop-root]")) return "root";
  return null;
}

function canDropOnRoot(item: { kind: "folder" | "file"; id: string }): boolean {
  const rootId = rootFolder.value?.id;
  const sourceFolder =
    item?.kind === "folder"
      ? folders.value.find(({ id }) => id === item.id)
      : undefined;
  const sourceFile =
    item?.kind === "file"
      ? treeFiles.value.find(({ id }) => id === item.id)
      : undefined;
  return Boolean(
    rootId &&
    ((sourceFolder && sourceFolder.parentId !== rootId) ||
      (sourceFile && sourceFile.folderId !== rootId)),
  );
}

function updatePointerDrag(event: PointerEvent): void {
  const drag = pointerDrag.value;
  if (!drag || drag.pointerId !== event.pointerId) return;
  const distance = Math.hypot(
    event.clientX - drag.startX,
    event.clientY - drag.startY,
  );
  if (!drag.active && distance < 6) return;
  if (!drag.active) {
    drag.active = true;
    draggingItem.value = drag.item;
  }
  event.preventDefault();
  const target = dropTargetAt(event.clientX, event.clientY);
  if (target === "root") {
    dropTargetId.value = canDropOnRoot(drag.item) ? target : null;
    return;
  }
  const folderId = target?.startsWith("folder:") ? target.slice(7) : "";
  const folder = folders.value.find(({ id }) => id === folderId);
  dropTargetId.value =
    folder && canDropOnFolder(drag.item, folder) ? target : null;
}

async function moveItemToFolder(
  item: { kind: "folder" | "file"; id: string },
  destinationId: string,
): Promise<void> {
  const destination = folders.value.find(({ id }) => id === destinationId);
  if (!destination) return;
  if (!canDropOnFolder(item, destination)) return;
  try {
    if (item.kind === "folder") {
      const source = folders.value.find(({ id }) => id === item.id);
      if (!source) return;
      await moveVaultFolder(
        props.projectRef,
        source.id,
        source.name,
        destination.id,
      );
      await refreshTree();
      await loadFiles();
      showNotice("Folder moved.");
    } else {
      const source = treeFiles.value.find(({ id }) => id === item.id);
      if (!source) return;
      await moveVaultFile(props.projectRef, source.id, destination.id);
      await refreshTree();
      await loadFiles();
      showNotice("File moved.");
    }
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not move the item.";
  }
}

async function moveItemToRoot(item: {
  kind: "folder" | "file";
  id: string;
}): Promise<void> {
  const rootId = rootFolder.value?.id;
  if (!rootId || !canDropOnRoot(item)) return;
  try {
    if (item.kind === "folder") {
      const source = folders.value.find(({ id }) => id === item.id);
      if (!source) return;
      await moveVaultFolder(props.projectRef, source.id, source.name, rootId);
      await refreshTree();
      await loadFiles();
      showNotice("Folder moved to project root.");
    } else {
      const source = treeFiles.value.find(({ id }) => id === item.id);
      if (!source) return;
      await moveVaultFile(props.projectRef, source.id, rootId);
      await refreshTree();
      await loadFiles();
      showNotice("File moved to project root.");
    }
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not move the item.";
  }
}

async function endPointerDrag(event: PointerEvent): Promise<void> {
  const drag = pointerDrag.value;
  if (!drag || drag.pointerId !== event.pointerId) return;
  const distance = Math.hypot(
    event.clientX - drag.startX,
    event.clientY - drag.startY,
  );
  const active = drag.active || distance >= 6;
  if (active && !drag.active) drag.active = true;
  const target = active ? dropTargetAt(event.clientX, event.clientY) : null;
  const item = drag.item;
  pointerDrag.value = null;
  draggingItem.value = null;
  dropTargetId.value = null;
  if (!active) return;
  suppressDragClick.value = true;
  setTimeout(() => (suppressDragClick.value = false), 0);
  if (target === "root") await moveItemToRoot(item);
  else if (target?.startsWith("folder:"))
    await moveItemToFolder(item, target.slice(7));
}

function cancelPointerDrag(event: PointerEvent): void {
  if (pointerDrag.value?.pointerId !== event.pointerId) return;
  pointerDrag.value = null;
  draggingItem.value = null;
  dropTargetId.value = null;
}

watch(
  () => props.projectRef,
  () => {
    currentFolderId.value = null;
    expandedFolderIds.value = new Set();
    initializedExpandedFolders = false;
    hideRevealed();
    void loadFolders();
  },
  { immediate: true },
);
watch(
  () => props.createRequest?.nonce,
  (nonce) => {
    if (!nonce || !props.createRequest) return;
    if (props.createRequest.kind === "folder") createFolderOpen.value = true;
    else openFileCreation();
    emit("create-request-consumed");
  },
  { immediate: true },
);
onMounted(() => {
  syncTimer = window.setInterval(() => void syncExternalChanges(), 5_000);
  window.addEventListener("focus", onVisibilityChange);
  document.addEventListener("visibilitychange", onVisibilityChange);
});
onBeforeUnmount(() => {
  if (syncTimer !== undefined) window.clearInterval(syncTimer);
  window.removeEventListener("focus", onVisibilityChange);
  document.removeEventListener("visibilitychange", onVisibilityChange);
  hideRevealed();
  if (noticeTimer) clearTimeout(noticeTimer);
  closeConfirmation(false);
});
</script>

<template>
  <div class="flex min-h-0 flex-col">
    <header
      class="flex flex-wrap items-center justify-end gap-2 border-b border-line-soft px-7 py-3">
      <DbButton size="sm" @click="createFolderOpen = true"
        ><FolderIcon class="h-4 w-4" /> New folder</DbButton
      >
      <DbButton
        size="sm"
        variant="primary"
        aria-label="Create file"
        @click="openFileCreation"
        ><PlusIcon class="h-4 w-4" /> New file</DbButton
      >
    </header>

    <div
      class="flex flex-wrap items-center gap-1.5 border-b border-line-soft px-7 py-2.5"
      aria-label="Filter project tree by environment tag">
      <span
        class="mr-2 text-[10px] font-semibold uppercase tracking-wider text-ink-faint">
        Tags
      </span>
      <button
        type="button"
        class="rounded-full border px-2.5 py-1 font-mono text-[11px] transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
        :class="
          environmentFilterId === 'all'
            ? 'border-accent/40 bg-accent-soft text-ink-strong'
            : 'border-line-soft text-ink-muted hover:bg-raised'
        "
        @click="environmentFilterId = 'all'">
        All
      </button>
      <button
        type="button"
        class="rounded-full border px-2.5 py-1 font-mono text-[11px] transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
        :class="
          environmentFilterId === null
            ? 'border-accent/40 bg-accent-soft text-ink-strong'
            : 'border-line-soft text-ink-muted hover:bg-raised'
        "
        @click="environmentFilterId = null">
        Shared
      </button>
      <div
        v-for="environment in environments"
        :key="environment.id"
        class="relative flex items-center gap-0.5 rounded-full border transition-colors"
        :class="
          environmentFilterId === environment.id
            ? 'border-accent/40 bg-accent-soft text-ink-strong'
            : 'border-line-soft text-ink-muted hover:bg-raised'
        ">
        <button
          type="button"
          class="rounded-full py-1 pl-2.5 pr-1 font-mono text-[11px] focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
          @click="environmentFilterId = environment.id">
          {{ environment.name }}
        </button>
        <button
          type="button"
          class="flex h-6 w-6 items-center justify-center rounded-full hover:bg-raised focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
          :aria-label="`Actions for tag ${environment.name}`"
          :aria-expanded="environmentMenuId === environment.id"
          @click="
            environmentMenuId =
              environmentMenuId === environment.id ? null : environment.id
          ">
          <MoreHorizontalIcon class="h-3.5 w-3.5" />
        </button>
        <div
          v-if="environmentMenuId === environment.id"
          class="absolute left-0 top-8 z-30 flex min-w-36 flex-col rounded-control border border-line-soft bg-panel p-1 text-ink-strong shadow-xl">
          <button
            class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-raised"
            @click="
              environmentMenuId = null;
              emit('environment-rename-request', environment);
            ">
            <PencilIcon class="h-3.5 w-3.5" />Rename tag
          </button>
          <button
            class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs text-crit hover:bg-raised"
            @click="
              environmentMenuId = null;
              emit('environment-delete-request', environment);
            ">
            <TrashIcon class="h-3.5 w-3.5" />Delete tag
          </button>
        </div>
      </div>
      <DbButton
        size="sm"
        variant="ghost"
        class="ml-1"
        aria-label="Create environment tag"
        @click="emit('environment-create-request')">
        <PlusIcon class="h-3.5 w-3.5" />Tag
      </DbButton>
    </div>

    <section class="min-w-0 px-7 py-5">
      <div
        data-testid="project-root-drop-target"
        data-drop-root
        class="mb-3 flex items-center justify-between gap-3 rounded px-1 py-1 transition-colors"
        :class="
          dropTargetId === 'root'
            ? 'bg-accent/10 ring-1 ring-inset ring-accent/50'
            : ''
        ">
        <div class="flex min-w-0 items-center gap-2 text-sm text-ink-muted">
          <FolderIcon class="h-4 w-4 shrink-0" />
          <span class="font-medium text-ink-strong">Project root</span>
        </div>
        <span class="text-xs text-ink-faint"
          >{{
            visibleTreeRows.filter((row) => row.kind === "file").length
          }}
          items</span
        >
      </div>

      <DbAlert v-if="error" tone="error" class="mb-3">{{ error }}</DbAlert>
      <div
        v-if="loading"
        class="rounded-panel border border-line-soft bg-panel p-8 text-sm text-ink-muted">
        Loading project tree…
      </div>
      <div
        v-else-if="visibleTreeRows.length === 0"
        class="rounded-panel border border-line-soft bg-panel px-6 py-14 text-center">
        <h2 class="font-semibold text-ink-strong">This project is empty</h2>
        <p class="mt-1 text-sm text-ink-muted">
          Create a folder or an encrypted secret or file to get started.
        </p>
        <div class="mt-4 flex justify-center gap-2">
          <DbButton
            size="sm"
            @click="
              ((currentFolderId = rootFolder?.id ?? null),
              (createFolderOpen = true))
            ">
            <FolderIcon class="h-4 w-4" />New folder
          </DbButton>
          <DbButton size="sm" variant="primary" @click="openFileCreation">
            <PlusIcon class="h-4 w-4" />New file
          </DbButton>
        </div>
      </div>
      <div v-else data-testid="project-file-tree" class="overflow-visible">
        <div
          data-testid="project-file-tree-header"
          class="flex items-center px-3 py-2 text-[10px] font-semibold uppercase tracking-wide text-ink-faint sm:px-4">
          <span class="min-w-0 flex-1">Name</span>
          <span class="mr-2 hidden w-28 text-right sm:block">Tag</span>
          <span class="mr-2 w-12 text-right">Version</span>
          <span class="w-28 text-right">Actions</span>
        </div>
        <div>
          <div
            v-for="row in visibleTreeRows"
            :key="
              row.kind === 'folder'
                ? `folder:${row.folder.id}`
                : `file:${row.file.id}`
            "
            class="group relative flex min-h-11 items-center gap-1 px-2 py-1.5 sm:px-3"
            :class="[
              draggingItem?.id ===
              (row.kind === 'folder' ? row.folder.id : row.file.id)
                ? 'opacity-50'
                : '',
              row.kind === 'folder' &&
              dropTargetId === `folder:${row.folder.id}`
                ? 'rounded bg-accent/10 ring-1 ring-inset ring-accent/50'
                : '',
            ]"
            :style="{ paddingLeft: `${12 + row.depth * 20}px` }"
            :data-drop-folder-id="
              row.kind === 'folder' ? row.folder.id : undefined
            ">
            <template v-if="row.kind === 'folder'">
              <button
                type="button"
                class="flex h-7 w-7 shrink-0 items-center justify-center rounded text-ink-faint hover:bg-raised hover:text-ink-strong focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
                :aria-label="`${expandedFolderIds.has(row.folder.id) ? 'Collapse' : 'Expand'} ${row.folder.name}`"
                :aria-expanded="expandedFolderIds.has(row.folder.id)"
                @click="toggleFolder(row.folder)">
                <ChevronDownIcon
                  v-if="expandedFolderIds.has(row.folder.id)"
                  class="h-3.5 w-3.5" />
                <ChevronRightIcon v-else class="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                title="Drag to move this folder"
                class="flex min-w-0 flex-1 cursor-grab select-none touch-none items-center gap-2 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent active:cursor-grabbing"
                :aria-pressed="currentFolderId === row.folder.id"
                @click="!suppressDragClick && void selectFolder(row.folder.id)"
                @pointerdown="
                  startPointerDrag($event, {
                    kind: 'folder',
                    id: row.folder.id,
                  })
                "
                @pointermove="updatePointerDrag"
                @pointerup="void endPointerDrag($event)"
                @pointercancel="cancelPointerDrag">
                <FolderIcon class="h-4 w-4 shrink-0 text-ink-muted" />
                <span class="truncate text-sm text-ink-strong">{{
                  row.folder.name
                }}</span>
                <span
                  v-if="effectiveFolderEnvironmentId(row.folder.id)"
                  class="hidden shrink-0 rounded bg-raised px-1.5 py-0.5 text-[10px] text-ink-muted sm:inline-flex">
                  {{
                    environmentName(effectiveFolderEnvironmentId(row.folder.id))
                  }}
                </span>
              </button>
              <span
                class="mr-2 hidden w-28 truncate text-right text-[10px] text-ink-faint sm:block">
                {{
                  row.folder.environmentId
                    ? environmentName(row.folder.environmentId)
                    : "Inherited"
                }}
              </span>
              <span class="mr-2 w-12 text-right text-xs text-ink-faint">—</span>
              <div class="relative flex w-28 justify-end">
                <button
                  type="button"
                  class="flex h-8 w-8 items-center justify-center rounded text-ink-muted hover:bg-raised hover:text-ink-strong focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
                  :aria-label="`Folder actions ${row.folder.name}`"
                  :aria-expanded="folderMenuId === row.folder.id"
                  @click="
                    folderMenuId =
                      folderMenuId === row.folder.id ? null : row.folder.id
                  ">
                  <MoreHorizontalIcon class="h-4 w-4" />
                </button>
                <div
                  v-if="folderMenuId === row.folder.id"
                  class="absolute right-0 top-9 z-30 flex min-w-40 flex-col rounded-control border border-line-soft bg-panel p-1 shadow-xl">
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-raised"
                    @click="
                      folderMenuId = null;
                      currentFolderId = row.folder.id;
                      createFolderOpen = true;
                    ">
                    <FolderIcon class="h-3.5 w-3.5" />New folder
                  </button>
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-raised"
                    @click="
                      folderMenuId = null;
                      currentFolderId = row.folder.id;
                      openFileCreation();
                    ">
                    <PlusIcon class="h-3.5 w-3.5" />New file
                  </button>
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-raised"
                    @click="startFolderTag(row.folder)">
                    <LayersIcon class="h-3.5 w-3.5" />Change tag…
                  </button>
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-raised"
                    @click="
                      folderMenuId = null;
                      void saveFolderTag(row.folder, null);
                    ">
                    <LayersIcon class="h-3.5 w-3.5" />Inherit tag
                  </button>
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-raised"
                    :aria-label="`Rename folder ${row.folder.name}`"
                    @click="startRename(row.folder)">
                    <PencilIcon class="h-3.5 w-3.5" />Rename
                  </button>
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-raised"
                    :aria-label="`Move folder ${row.folder.name}`"
                    @click="startMoveFolder(row.folder)">
                    <FolderIcon class="h-3.5 w-3.5" />Move to…
                  </button>
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs text-crit hover:bg-raised"
                    :aria-label="`Delete empty folder ${row.folder.name}`"
                    @click="
                      folderMenuId = null;
                      removeFolder(row.folder);
                    ">
                    <TrashIcon class="h-3.5 w-3.5" />Delete
                  </button>
                </div>
              </div>
            </template>
            <template v-else>
              <span class="w-7 shrink-0" aria-hidden="true"></span>
              <button
                type="button"
                title="Drag to move this file"
                class="flex min-w-0 flex-1 cursor-grab select-none touch-none items-center gap-2 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent active:cursor-grabbing"
                :aria-label="`${row.file.name}, ${kindOptions.find((kind) => kind.value === row.file.kind)?.label ?? row.file.kind}, version ${row.file.version}`"
                @click="!suppressDragClick && void openFileDetails(row.file)"
                @pointerdown="
                  startPointerDrag($event, { kind: 'file', id: row.file.id })
                "
                @pointermove="updatePointerDrag"
                @pointerup="void endPointerDrag($event)"
                @pointercancel="cancelPointerDrag">
                <KeyIcon class="h-4 w-4 shrink-0 text-accent-strong" />
                <span class="truncate text-sm font-medium text-ink-strong">{{
                  row.file.name
                }}</span>
                <span
                  class="shrink-0 rounded bg-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
                  {{
                    kindOptions.find((kind) => kind.value === row.file.kind)
                      ?.label ?? row.file.kind
                  }}
                </span>
              </button>
              <span
                class="mr-2 hidden w-28 truncate text-right text-[10px] text-ink-muted sm:block">
                {{ environmentName(effectiveFileEnvironmentId(row.file)) }}
              </span>
              <span
                class="mr-2 w-12 text-right font-mono text-xs text-ink-muted"
                >v{{ row.file.version }}</span
              >
              <div class="relative flex w-28 justify-end gap-0.5">
                <button
                  type="button"
                  class="flex h-8 w-8 items-center justify-center rounded text-ink-muted hover:bg-raised hover:text-ink-strong focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
                  :disabled="busy"
                  :aria-label="`${revealed?.id === row.file.id ? 'Hide' : 'Reveal'} ${row.file.name}`"
                  :title="`${revealed?.id === row.file.id ? 'Hide' : 'Reveal'} ${row.file.name}`"
                  @click="void revealFile(row.file)">
                  <EyeIcon
                    v-if="revealed?.id === row.file.id"
                    class="h-3.5 w-3.5" />
                  <EyeOffIcon v-else class="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  class="flex h-8 w-8 items-center justify-center rounded text-ink-muted hover:bg-raised hover:text-ink-strong focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
                  :disabled="busy"
                  :aria-label="`Copy ${row.file.name}`"
                  :title="`Copy ${row.file.name}`"
                  @click="void copyFile(row.file)">
                  <CopyIcon class="h-3.5 w-3.5" />
                </button>
                <button
                  type="button"
                  class="flex h-8 w-8 items-center justify-center rounded text-ink-muted hover:bg-raised hover:text-ink-strong focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
                  :aria-label="`Actions for ${row.file.name}`"
                  :aria-expanded="fileMenuId === row.file.id"
                  @click="
                    fileMenuId = fileMenuId === row.file.id ? null : row.file.id
                  ">
                  <MoreHorizontalIcon class="h-4 w-4" />
                </button>
                <div
                  v-if="fileMenuId === row.file.id"
                  class="absolute right-0 top-9 z-30 flex min-w-40 flex-col rounded-control border border-line-soft bg-panel p-1 shadow-xl">
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-raised"
                    @click="
                      fileMenuId = null;
                      void openFileDetails(row.file);
                    ">
                    <ArchiveIcon class="h-3.5 w-3.5" />Versions &amp; details
                  </button>
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs hover:bg-raised"
                    :aria-label="`Move ${row.file.name}`"
                    @click="
                      fileMenuId = null;
                      startMoveFile(row.file);
                    ">
                    <FolderIcon class="h-3.5 w-3.5" />Move to…
                  </button>
                  <button
                    class="flex min-h-9 items-center gap-2 rounded px-2 text-left text-xs text-crit hover:bg-raised"
                    @click="
                      fileMenuId = null;
                      void removeFile(row.file);
                    ">
                    <TrashIcon class="h-3.5 w-3.5" />Delete
                  </button>
                </div>
              </div>
            </template>
          </div>
        </div>
      </div>
    </section>
  </div>

  <Teleport to="body">
    <Transition name="project-toast">
      <div
        v-if="notice"
        data-testid="project-action-toast"
        role="status"
        aria-live="polite"
        class="pointer-events-none fixed inset-0 z-[100] flex items-center justify-center p-6">
        <div
          class="flex max-w-[min(28rem,calc(100vw-3rem))] items-center gap-2.5 rounded-xl border border-line-soft bg-panel/95 px-4 py-3 text-sm font-medium text-ink-strong shadow-2xl backdrop-blur-xl">
          <span
            class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-accent-soft text-accent-strong">
            <CheckIcon class="h-3.5 w-3.5" />
          </span>
          {{ notice }}
        </div>
      </div>
    </Transition>
  </Teleport>

  <DbModal
    :open="activeFile !== null"
    :title="
      editingFileName ? 'Rename file' : (activeFile?.name ?? 'File details')
    "
    size="lg"
    @close="hideRevealed">
    <div v-if="activeFile" class="flex flex-col gap-5">
      <div class="flex flex-wrap items-center gap-2 text-xs text-ink-muted">
        <span class="rounded bg-raised px-2 py-1 font-mono">{{
          kindOptions.find((kind) => kind.value === activeFile?.kind)?.label ??
          activeFile.kind
        }}</span>
        <span class="rounded bg-raised px-2 py-1 font-mono"
          >v{{ activeFile.version }}</span
        >
        <span class="rounded bg-raised px-2 py-1">{{
          environmentName(effectiveFileEnvironmentId(activeFile))
        }}</span>
        <DbButton
          size="sm"
          variant="ghost"
          @click="
            editingFileName = !editingFileName;
            fileNameDraft = activeFile!.name;
          ">
          <PencilIcon class="h-3.5 w-3.5" />Rename
        </DbButton>
      </div>

      <form
        v-if="editingFileName"
        class="flex flex-wrap items-end gap-2"
        @submit.prevent="saveFileName">
        <DbInput
          v-model="fileNameDraft"
          label="File name"
          required
          autofocus
          class="min-w-64 flex-1" />
        <DbButton variant="primary" type="submit" :loading="busy"
          >Save name</DbButton
        >
      </form>

      <template v-if="revealed?.id === activeFile.id">
        <DbTextarea
          v-model="revealed.content"
          :label="`Latest content${revealed.encoding === 'base64' ? ' · base64' : ''} · v${revealed.version}`"
          :rows="8" />
        <div class="flex flex-wrap gap-2">
          <DbButton
            size="sm"
            variant="primary"
            :loading="busy"
            @click="saveFile"
            >Save new version</DbButton
          >
          <DbButton size="sm" @click="copyContent"
            ><CopyIcon class="h-3.5 w-3.5" />Copy</DbButton
          >
          <DbButton size="sm" @click="hideRevealed"
            ><EyeOffIcon class="h-3.5 w-3.5" />Hide</DbButton
          >
        </div>
      </template>
      <div
        v-else
        class="flex flex-wrap items-center justify-between gap-3 rounded-control bg-raised p-3">
        <p class="text-sm text-ink-muted">
          The value is encrypted until you reveal it.
        </p>
        <DbButton
          size="sm"
          variant="primary"
          :loading="busy"
          @click="revealFile(activeFile!)">
          <EyeIcon class="h-3.5 w-3.5" />Reveal latest version
        </DbButton>
      </div>

      <section class="flex flex-col gap-2 border-t border-line-soft pt-4">
        <label class="text-xs font-semibold text-ink-muted">
          Environment tag
          <span class="mt-1 block font-normal text-ink-faint">
            {{
              activeFile.environmentId
                ? "Set an explicit project tag."
                : `Currently ${environmentName(effectiveFileEnvironmentId(activeFile))}; an empty value inherits from its folder.`
            }}
          </span>
        </label>
        <div class="flex flex-wrap items-center gap-2">
          <EnvironmentTagPicker
            v-model="detailEnvironmentTag"
            :project-ref="projectRef"
            :environments="environments"
            class="min-w-56 flex-1"
            @environment-created="onEnvironmentCreated" />
          <DbButton size="sm" :loading="busy" @click="saveDetailEnvironment"
            >Apply tag</DbButton
          >
        </div>
      </section>

      <section class="border-t border-line-soft pt-4">
        <h3
          class="mb-3 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-ink-faint">
          <ArchiveIcon class="h-3.5 w-3.5" />Version history
        </h3>
        <div v-if="versions.length" class="flex flex-col gap-2">
          <div
            v-for="version in versions"
            :key="version.version"
            class="flex flex-wrap items-center gap-2 rounded bg-raised px-3 py-2 text-xs">
            <span class="font-mono text-ink-strong"
              >v{{ version.version }}</span
            >
            <span class="text-ink-faint">{{
              new Date(version.archivedAt).toLocaleString()
            }}</span>
            <DbButton size="sm" @click="confirmRollback(activeFile!, version)"
              >Restore</DbButton
            >
            <DbButton
              size="sm"
              variant="ghost"
              :aria-label="`Delete version ${version.version} of ${activeFile.name}`"
              @click="removeVersion(activeFile!, version)">
              <TrashIcon class="h-3.5 w-3.5" />
            </DbButton>
          </div>
        </div>
        <p v-else class="text-xs text-ink-muted">
          No earlier versions yet. Saving an edit creates the first one.
        </p>
      </section>

      <DbAlert v-if="error" tone="error">{{ error }}</DbAlert>
    </div>
    <template #footer>
      <DbButton variant="ghost" @click="hideRevealed">Close</DbButton>
    </template>
  </DbModal>

  <DbModal
    :open="createFolderOpen"
    title="Create folder"
    @close="createFolderOpen = false">
    <form class="flex flex-col gap-4" @submit.prevent="submitFolder">
      <p class="text-sm text-ink-muted">
        Create inside {{ activeFolder?.name ?? "the project root" }}.
      </p>
      <DbInput
        v-model="folderName"
        label="Folder name"
        placeholder="Production"
        required
        autofocus />
      <label class="flex flex-col gap-1.5 text-xs font-semibold text-ink-muted">
        Environment tag
        <span class="font-normal text-ink-faint"
          >Optional · blank inherits the parent tag, or stays Shared at the
          root.</span
        >
        <EnvironmentTagPicker
          v-model="folderEnvironment"
          :project-ref="projectRef"
          :environments="environments"
          @environment-created="onEnvironmentCreated" />
      </label>
      <div class="flex justify-end gap-2">
        <DbButton @click="createFolderOpen = false">Cancel</DbButton
        ><DbButton variant="primary" type="submit" :loading="busy"
          >Create folder</DbButton
        >
      </div>
    </form>
  </DbModal>

  <DbModal
    :open="renameTarget !== null"
    title="Rename folder"
    @close="renameTarget = null">
    <form class="flex flex-col gap-4" @submit.prevent="submitRename">
      <DbInput v-model="folderName" label="Folder name" required autofocus />
      <div class="flex justify-end gap-2">
        <DbButton @click="renameTarget = null">Cancel</DbButton>
        <DbButton variant="primary" type="submit" :loading="busy"
          >Save name</DbButton
        >
      </div>
    </form>
  </DbModal>

  <DbModal
    :open="movingFolder !== null || movingFile !== null"
    :title="
      movingFolder
        ? `Move folder ${movingFolder.name}`
        : `Move file ${movingFile?.name ?? ''}`
    "
    @close="closeMove">
    <form class="flex flex-col gap-4" @submit.prevent="submitMove">
      <DbSelect
        v-model="moveDestinationId"
        label="Destination folder"
        :options="movingFolder ? moveFolderOptions : moveFileOptions"
        :disabled="busy" />
      <p class="text-xs leading-relaxed text-ink-faint">
        You can also drag folders and files onto a folder in the tree.
      </p>
      <div class="flex justify-end gap-2">
        <DbButton @click="closeMove">Cancel</DbButton>
        <DbButton
          variant="primary"
          type="submit"
          :loading="busy"
          :disabled="!moveDestinationId && !movingFolder"
          >Move</DbButton
        >
      </div>
    </form>
  </DbModal>

  <DbModal
    :open="createFileOpen"
    title="Create encrypted file"
    size="lg"
    @close="createFileOpen = false">
    <form class="flex flex-col gap-4" @submit.prevent="submitFile">
      <p class="text-sm text-ink-muted">
        Create inside
        <span class="font-medium text-ink-strong">{{
          currentFolderId ? folderPathLabel(currentFolderId) : "Project root"
        }}</span
        >.
      </p>
      <DbAlert v-if="fileFormError" tone="error">{{ fileFormError }}</DbAlert>
      <div class="grid gap-4 sm:grid-cols-2">
        <DbInput
          v-model="fileName"
          label="File name"
          placeholder="production.env"
          required
          autofocus /><label
          class="flex flex-col gap-1.5 text-xs font-semibold text-ink-muted"
          >Data type<select
            v-model="fileKind"
            class="h-10 rounded-control bg-raised px-3 text-sm text-ink-strong outline-none focus:ring-2 focus:ring-accent">
            <option
              v-for="kind in kindOptions"
              :key="kind.value"
              :value="kind.value">
              {{ kind.label }}
            </option>
          </select></label
        >
      </div>
      <DbTextarea
        v-model="fileContent"
        label="Content"
        :rows="12"
        placeholder="Paste the value or configuration…"
        required />
      <label class="flex flex-col gap-1.5 text-xs font-semibold text-ink-muted">
        Environment tag
        <span class="font-normal text-ink-faint">{{
          currentFolderId && effectiveFolderEnvironmentId(currentFolderId)
            ? `Optional · blank inherits ${environmentName(effectiveFolderEnvironmentId(currentFolderId))} from ${folderPathLabel(currentFolderId)}.`
            : "Optional · blank saves without a tag."
        }}</span>
        <EnvironmentTagPicker
          v-model="fileEnvironment"
          :project-ref="projectRef"
          :environments="environments"
          @environment-created="onEnvironmentCreated" />
      </label>
      <div class="flex justify-end gap-2">
        <DbButton @click="createFileOpen = false">Cancel</DbButton
        ><DbButton variant="primary" type="submit" :loading="busy"
          >Encrypt and save</DbButton
        >
      </div>
    </form>
  </DbModal>

  <DbModal
    :open="tagTarget !== null"
    :title="`Environment tag · ${tagTarget?.name ?? ''}`"
    @close="tagTarget = null">
    <form class="flex flex-col gap-4" @submit.prevent="submitTag">
      <label class="flex flex-col gap-1.5 text-xs font-semibold text-ink-muted">
        Environment
        <span class="font-normal text-ink-faint"
          >Choose an existing tag, create one from the list, or inherit from the
          parent.</span
        >
        <EnvironmentTagPicker
          v-model="tagValue"
          :project-ref="projectRef"
          :environments="environments"
          autofocus
          @environment-created="onEnvironmentCreated" />
      </label>
      <div class="flex flex-wrap justify-between gap-2">
        <DbButton :disabled="busy" @click="void saveTag(null)"
          >Inherit from parent</DbButton
        >
        <div class="flex gap-2">
          <DbButton @click="tagTarget = null">Cancel</DbButton>
          <DbButton variant="primary" type="submit" :loading="busy"
            >Save tag</DbButton
          >
        </div>
      </div>
    </form>
  </DbModal>

  <DbModal
    :open="confirmation !== null"
    :title="confirmation?.title ?? 'Confirm action'"
    @close="closeConfirmation(false)">
    <p class="text-sm leading-relaxed text-ink-muted">
      {{ confirmation?.message }}
    </p>
    <template #footer>
      <DbButton @click="closeConfirmation(false)">Cancel</DbButton>
      <DbButton variant="danger" @click="closeConfirmation(true)">{{
        confirmation?.actionLabel
      }}</DbButton>
    </template>
  </DbModal>
</template>

<style scoped>
.project-toast-enter-active,
.project-toast-leave-active {
  transition:
    opacity 180ms ease,
    transform 180ms cubic-bezier(0.2, 0.8, 0.2, 1);
}

.project-toast-enter-from,
.project-toast-leave-to {
  opacity: 0;
  transform: scale(0.96);
}

@media (prefers-reduced-motion: reduce) {
  .project-toast-enter-active,
  .project-toast-leave-active {
    transition: none;
  }
}
</style>

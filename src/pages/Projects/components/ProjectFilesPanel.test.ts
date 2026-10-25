import { createApp, h, nextTick } from "vue";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { api } = vi.hoisted(() => ({
  api: {
    createVaultFile: vi.fn(),
    createVaultFolder: vi.fn(),
    deleteVaultFile: vi.fn(),
    deleteVaultFileVersion: vi.fn(),
    listVaultFolders: vi.fn(),
    listVaultFiles: vi.fn(),
    listVaultFileVersions: vi.fn(),
    listVaultTree: vi.fn(),
    deleteVaultFolder: vi.fn(),
    moveVaultFolder: vi.fn(),
    moveVaultFile: vi.fn(),
    revealVaultFile: vi.fn(),
    rollbackVaultFile: vi.fn(),
    updateVaultFile: vi.fn(),
  },
}));

vi.mock("~/services/vault.api", () => api);
vi.mock("~/services/environments.api", () => ({
  createEnvironment: vi.fn(),
  listEnvironments: vi.fn(async () => []),
}));

import ProjectFilesPanel from "./ProjectFilesPanel.vue";

let app: ReturnType<typeof createApp> | null = null;

function pointerEvent(type: string, clientY: number, pointerId = 1): Event {
  const event = new Event(type, { bubbles: true, cancelable: true });
  Object.defineProperties(event, {
    button: { value: 0 },
    clientX: { value: 20 },
    clientY: { value: clientY },
    pointerId: { value: pointerId },
  });
  return event;
}

function mockDropTarget(target: Element): () => void {
  const previous = document.elementFromPoint;
  Object.defineProperty(document, "elementFromPoint", {
    configurable: true,
    value: () => target,
  });
  return () => {
    if (previous) {
      Object.defineProperty(document, "elementFromPoint", {
        configurable: true,
        value: previous,
      });
    } else {
      delete (document as Partial<Document>).elementFromPoint;
    }
  };
}

function dispatchPointerDrag(
  source: Element,
  target: Element,
  pointerId = 1,
): void {
  const restoreDropTarget = mockDropTarget(target);
  source.dispatchEvent(pointerEvent("pointerdown", 10, pointerId));
  source.dispatchEvent(pointerEvent("pointermove", 24, pointerId));
  source.dispatchEvent(pointerEvent("pointerup", 24, pointerId));
  restoreDropTarget();
}

afterEach(() => {
  app?.unmount();
  app = null;
  document.body.innerHTML = "";
});

describe("ProjectFilesPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.listVaultFolders.mockResolvedValue([
      {
        id: "folder-1",
        projectId: "project-1",
        parentId: null,
        name: "production",
        createdAt: "",
        updatedAt: "",
      },
    ]);
    api.listVaultFiles.mockResolvedValue([]);
    api.listVaultTree.mockImplementation(async (projectRef: string) => {
      const folders = await api.listVaultFolders(projectRef);
      const root = {
        id: "project-root",
        projectId: projectRef,
        parentId: null,
        isRoot: true,
        name: "Project root",
        createdAt: "",
        updatedAt: "",
      };
      return Promise.all([
        { folder: root, files: await api.listVaultFiles(projectRef, root.id) },
        ...folders.map(
          async (folder: { id: string; parentId?: string | null }) => ({
            folder: {
              ...folder,
              parentId: folder.parentId ?? root.id,
              isRoot: false,
            },
            files: await api.listVaultFiles(projectRef, folder.id),
          }),
        ),
      ]);
    });
    api.deleteVaultFolder.mockResolvedValue(undefined);
    api.moveVaultFolder.mockImplementation(
      async (_project, id, name, parentId) => ({
        id,
        projectId: "project-1",
        parentId,
        name,
        createdAt: "",
        updatedAt: "",
      }),
    );
    api.moveVaultFile.mockImplementation(async (_project, id, folderId) => ({
      id,
      folderId,
      name: "secret.txt",
      kind: "secret",
      environmentId: null,
      encoding: "utf-8",
      version: 1,
      createdAt: "",
      updatedAt: "",
    }));
  });

  it("offers rename and move actions for a folder", async () => {
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('[aria-label="Folder actions production"]'),
      ).not.toBeNull(),
    );

    host
      .querySelector<HTMLButtonElement>(
        '[aria-label="Folder actions production"]',
      )
      ?.click();
    await nextTick();
    expect(
      host.querySelector('[aria-label="Rename folder production"]'),
    ).not.toBeNull();
    expect(
      host.querySelector('[aria-label="Move folder production"]'),
    ).not.toBeNull();
  });

  it("renames a folder through its action menu", async () => {
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('[aria-label="Folder actions production"]'),
      ).not.toBeNull(),
    );
    host
      .querySelector<HTMLButtonElement>(
        '[aria-label="Folder actions production"]',
      )
      ?.click();
    await nextTick();
    host
      .querySelector<HTMLButtonElement>(
        '[aria-label="Rename folder production"]',
      )
      ?.click();
    await nextTick();
    const dialog = document.body.querySelector('[role="dialog"]');
    const input = dialog?.querySelector<HTMLInputElement>("input");
    if (!input) throw new Error("rename field was not rendered");
    input.value = "production-v2";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    Array.from(dialog?.querySelectorAll("button") ?? [])
      .find((button) => button.textContent?.trim() === "Save name")
      ?.click();

    await vi.waitFor(() =>
      expect(api.moveVaultFolder).toHaveBeenCalledWith(
        "project-1",
        "folder-1",
        "production-v2",
        "project-root",
      ),
    );
  });

  it("moves a file into another folder through the accessible move action", async () => {
    const file = {
      id: "file-1",
      folderId: "folder-1",
      name: "secret.txt",
      kind: "secret",
      encoding: "utf-8",
      version: 1,
      createdAt: "",
      updatedAt: "",
    };
    api.listVaultFolders.mockResolvedValue([
      {
        id: "folder-1",
        projectId: "project-1",
        parentId: null,
        name: "production",
        createdAt: "",
        updatedAt: "",
      },
      {
        id: "folder-2",
        projectId: "project-1",
        parentId: null,
        name: "staging",
        createdAt: "",
        updatedAt: "",
      },
    ]);
    api.listVaultFiles.mockImplementation(async (_project, folderId) =>
      folderId === "folder-1" ? [file] : [],
    );
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('[aria-label="Actions for secret.txt"]'),
      ).not.toBeNull(),
    );
    const actions = host.querySelector<HTMLButtonElement>(
      '[aria-label="Actions for secret.txt"]',
    );
    if (!actions) throw new Error("file actions button was not rendered");
    actions.click();
    await nextTick();
    const moveAction = host.querySelector<HTMLButtonElement>(
      '[aria-label="Move secret.txt"]',
    );
    if (!moveAction) throw new Error("move action was not rendered");
    moveAction.click();
    await vi.waitFor(() =>
      expect(document.body.textContent).toContain("Destination folder"),
    );
    const select = document.body.querySelector<HTMLSelectElement>("select");
    if (!select) throw new Error("move destination select was not rendered");
    select.value = "folder-2";
    select.dispatchEvent(new Event("change", { bubbles: true }));
    await nextTick();
    Array.from(document.body.querySelectorAll("button"))
      .find((button) => button.textContent?.trim() === "Move")
      ?.click();

    await vi.waitFor(() =>
      expect(api.moveVaultFile).toHaveBeenCalledWith(
        "project-1",
        "file-1",
        "folder-2",
      ),
    );
  });

  it("moves a file onto a folder in the tree by dragging it", async () => {
    const file = {
      id: "file-1",
      folderId: "folder-1",
      name: "secret.txt",
      kind: "secret",
      environmentId: null,
      encoding: "utf-8",
      version: 1,
      createdAt: "",
      updatedAt: "",
    };
    api.listVaultFolders.mockResolvedValue([
      {
        id: "folder-1",
        projectId: "project-1",
        parentId: null,
        name: "production",
        createdAt: "",
        updatedAt: "",
      },
      {
        id: "folder-2",
        projectId: "project-1",
        parentId: null,
        name: "staging",
        createdAt: "",
        updatedAt: "",
      },
    ]);
    api.listVaultFiles.mockImplementation(async (_project, folderId) =>
      folderId === "folder-1" ? [file] : [],
    );
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('[aria-label^="secret.txt, Secret"]'),
      ).not.toBeNull(),
    );

    const source = host.querySelector('[aria-label^="secret.txt, Secret"]');
    const destination = host.querySelector('[data-drop-folder-id="folder-2"]');
    if (!source || !destination)
      throw new Error("source file or destination folder was not rendered");
    dispatchPointerDrag(source, destination);

    await vi.waitFor(() =>
      expect(api.moveVaultFile).toHaveBeenCalledWith(
        "project-1",
        "file-1",
        "folder-2",
      ),
    );
  });

  it("moves a folder onto another folder by dragging it", async () => {
    api.listVaultFolders.mockResolvedValue([
      {
        id: "folder-1",
        projectId: "project-1",
        parentId: null,
        name: "production",
        createdAt: "",
        updatedAt: "",
      },
      {
        id: "folder-2",
        projectId: "project-1",
        parentId: null,
        name: "staging",
        createdAt: "",
        updatedAt: "",
      },
    ]);
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(host.querySelectorAll("[data-drop-folder-id]").length).toBe(2),
    );

    const source = host.querySelector(
      '[data-drop-folder-id="folder-1"] button[title="Drag to move this folder"]',
    );
    const destination = host.querySelector('[data-drop-folder-id="folder-2"]');
    if (!source || !destination)
      throw new Error("source or destination folder was not rendered");
    const restoreDropTarget = mockDropTarget(destination);
    source.dispatchEvent(pointerEvent("pointerdown", 10));
    source.dispatchEvent(pointerEvent("pointermove", 24));
    await nextTick();
    expect(destination.className).toContain("bg-accent/10");
    source.dispatchEvent(pointerEvent("pointerup", 24));
    restoreDropTarget();

    await vi.waitFor(() =>
      expect(api.moveVaultFolder).toHaveBeenCalledWith(
        "project-1",
        "folder-1",
        "production",
        "folder-2",
      ),
    );
  });

  it("shows a centered, transient success toast after a drag move", async () => {
    api.listVaultFolders.mockResolvedValue([
      {
        id: "folder-1",
        projectId: "project-1",
        parentId: null,
        name: "production",
        createdAt: "",
        updatedAt: "",
      },
      {
        id: "folder-2",
        projectId: "project-1",
        parentId: null,
        name: "staging",
        createdAt: "",
        updatedAt: "",
      },
    ]);
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(host.querySelectorAll("[data-drop-folder-id]").length).toBe(2),
    );

    const [sourceRow, destination] = Array.from(
      host.querySelectorAll<HTMLElement>("[data-drop-folder-id]"),
    );
    const source = sourceRow?.querySelector(
      'button[title="Drag to move this folder"]',
    );
    if (!source || !destination)
      throw new Error("source or destination folder was not rendered");
    const timeoutSpy = vi.spyOn(globalThis, "setTimeout");
    dispatchPointerDrag(source, destination);

    await vi.waitFor(() =>
      expect(
        document.body.querySelector('[role="status"]')?.textContent,
      ).toContain("Folder moved."),
    );
    const toast = document.body.querySelector<HTMLElement>(
      '[data-testid="project-action-toast"]',
    );
    expect(toast?.className).toMatch(/fixed|absolute/);
    expect(toast?.className).toMatch(/items-center|top-1\/2/);
    expect(timeoutSpy).toHaveBeenCalledWith(expect.any(Function), 2000);
    timeoutSpy.mockRestore();
  });

  it("moves files back to the project root by dropping on the root target", async () => {
    const file = {
      id: "file-1",
      folderId: "folder-1",
      name: "secret.txt",
      kind: "secret",
      environmentId: null,
      encoding: "utf-8",
      version: 1,
      createdAt: "",
      updatedAt: "",
    };
    api.listVaultFiles.mockImplementation(async (_project, folderId) =>
      folderId === "folder-1" ? [file] : [],
    );
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('[aria-label^="secret.txt, Secret"]'),
      ).not.toBeNull(),
    );

    const source = host.querySelector('[aria-label^="secret.txt, Secret"]');
    const root = host.querySelector('[data-testid="project-root-drop-target"]');
    if (!source || !root)
      throw new Error("source or project root not rendered");
    dispatchPointerDrag(source, root);

    await vi.waitFor(() =>
      expect(api.moveVaultFile).toHaveBeenCalledWith(
        "project-1",
        "file-1",
        "project-root",
      ),
    );
  });

  it("uses an in-app confirmation before deleting an empty folder", async () => {
    expect(window.confirm).toBeUndefined();
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('[aria-label="Folder actions production"]'),
      ).not.toBeNull(),
    );
    // Folder operations are grouped under the visible action menu.
    host
      .querySelector<HTMLButtonElement>(
        '[aria-label="Folder actions production"]',
      )
      ?.click();
    await nextTick();
    host
      .querySelector<HTMLButtonElement>(
        '[aria-label="Delete empty folder production"]',
      )
      ?.click();
    await nextTick();
    expect(
      document.body.querySelector('[role="dialog"]')?.textContent,
    ).toContain("Delete empty folder");
    expect(api.deleteVaultFolder).not.toHaveBeenCalled();

    Array.from(document.body.querySelectorAll("button"))
      .find((button) => button.textContent?.trim() === "Delete folder")
      ?.click();
    await vi.waitFor(() =>
      expect(api.deleteVaultFolder).toHaveBeenCalledWith(
        "project-1",
        "folder-1",
      ),
    );
    expect(
      host.querySelector('[aria-label="Delete empty folder production"]'),
    ).toBeNull();
  });

  it("creates a file from the project root without requiring a user folder", async () => {
    const root = {
      id: "project-root",
      projectId: "project-1",
      parentId: null,
      name: "Project root",
      createdAt: "",
      updatedAt: "",
    };
    api.listVaultFolders.mockResolvedValue([]);
    api.createVaultFolder.mockResolvedValue(root);
    api.createVaultFile.mockResolvedValue({
      id: "file-1",
      folderId: root.id,
      name: "notes.txt",
      kind: "text",
      encoding: "utf-8",
      version: 1,
      createdAt: "",
      updatedAt: "",
    });
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('button[aria-label="Create file"]'),
      ).not.toBeNull(),
    );

    host
      .querySelector<HTMLButtonElement>('button[aria-label="Create file"]')
      ?.click();
    await nextTick();
    const dialog = document.body.querySelector('[role="dialog"]');
    expect(dialog?.textContent).toContain("Create encrypted file");
    const nameInput = dialog?.querySelector<HTMLInputElement>("input");
    if (!nameInput) throw new Error("file name input was not rendered");
    nameInput.value = "notes.txt";
    nameInput.dispatchEvent(new Event("input", { bubbles: true }));
    const content = dialog?.querySelector<HTMLTextAreaElement>("textarea");
    if (!content) throw new Error("file content input was not rendered");
    content.value = "hello";
    content.dispatchEvent(new Event("input", { bubbles: true }));
    Array.from(dialog?.querySelectorAll("button") ?? [])
      .find((button) => button.textContent?.trim() === "Encrypt and save")
      ?.click();

    await vi.waitFor(() =>
      expect(api.createVaultFile).toHaveBeenCalledWith(
        "project-1",
        "project-root",
        "notes.txt",
        "secret",
        "hello",
        null,
      ),
    );
    expect(api.createVaultFolder).not.toHaveBeenCalled();
  });

  it("copies a file directly from its row in the current session", async () => {
    const file = {
      id: "file-1",
      folderId: "folder-1",
      name: "secret.txt",
      kind: "secret",
      encoding: "utf-8",
      version: 1,
      createdAt: "",
      updatedAt: "",
    };
    api.listVaultFiles.mockResolvedValue([file]);
    api.revealVaultFile.mockResolvedValue({
      ...file,
      content: "private value",
    });
    const writeText = vi.fn(async () => undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('button[aria-label="Copy secret.txt"]'),
      ).not.toBeNull(),
    );

    host
      .querySelector<HTMLButtonElement>('button[aria-label="Copy secret.txt"]')
      ?.click();
    await vi.waitFor(() =>
      expect(writeText).toHaveBeenCalledWith("private value"),
    );
    expect(api.revealVaultFile).toHaveBeenCalledWith("project-1", "file-1");
  });

  it("clears a failed copy error after a later copy succeeds", async () => {
    const file = {
      id: "file-1",
      folderId: "folder-1",
      name: "secret.txt",
      kind: "secret",
      encoding: "utf-8",
      version: 1,
      createdAt: "",
      updatedAt: "",
    };
    api.listVaultFiles.mockResolvedValue([file]);
    api.listVaultFileVersions.mockResolvedValue([]);
    api.revealVaultFile.mockResolvedValue({
      ...file,
      content: "private value",
    });
    const writeText = vi
      .fn<() => Promise<void>>()
      .mockRejectedValueOnce(new Error("denied"))
      .mockResolvedValueOnce(undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('button[aria-label="Reveal secret.txt"]'),
      ).not.toBeNull(),
    );

    host
      .querySelector<HTMLButtonElement>(
        'button[aria-label="Reveal secret.txt"]',
      )
      ?.click();
    await vi.waitFor(() =>
      expect(
        document.body.querySelector<HTMLTextAreaElement>(
          '[role="dialog"] textarea',
        )?.value,
      ).toBe("private value"),
    );

    const copyButton = Array.from(
      document.body.querySelectorAll<HTMLButtonElement>(
        '[role="dialog"] button',
      ),
    ).find((button) => button.textContent?.trim() === "Copy");
    if (!copyButton) throw new Error("detail copy button was not rendered");
    copyButton.click();
    await vi.waitFor(() =>
      expect(host.textContent).toContain("Clipboard access was denied."),
    );
    copyButton.click();
    await vi.waitFor(() =>
      expect(host.textContent).not.toContain("Clipboard access was denied."),
    );
    expect(writeText).toHaveBeenCalledTimes(2);
  });

  it("keeps the file tree visually seamless while retaining column labels", async () => {
    api.listVaultTree.mockResolvedValue([
      {
        folder: {
          id: "root",
          projectId: "project-1",
          parentId: null,
          isRoot: true,
          name: "Project root",
          createdAt: "",
          updatedAt: "",
        },
        files: [],
      },
      {
        folder: {
          id: "folder-1",
          projectId: "project-1",
          parentId: "root",
          isRoot: false,
          name: "production",
          createdAt: "",
          updatedAt: "",
        },
        files: [],
      },
    ]);
    const host = document.createElement("div");
    document.body.append(host);
    app = createApp({
      render: () => h(ProjectFilesPanel, { projectRef: "project-1" }),
    });
    app.mount(host);
    await vi.waitFor(() =>
      expect(
        host.querySelector('[data-testid="project-file-tree"]'),
      ).not.toBeNull(),
    );

    const tree = host.querySelector<HTMLElement>(
      '[data-testid="project-file-tree"]',
    );
    const header = host.querySelector<HTMLElement>(
      '[data-testid="project-file-tree-header"]',
    );
    expect(tree?.className).not.toMatch(/rounded-panel|border|bg-panel/);
    expect(header?.className).not.toMatch(/border|bg-raised/);
    expect(tree?.textContent).toContain("Name");
    expect(tree?.textContent).toContain("Tag");
    expect(tree?.textContent).toContain("Version");
    expect(tree?.textContent).toContain("Actions");
  });
});

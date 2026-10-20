<script setup lang="ts">
import { ref } from "vue";
import type { ProjectsController } from "~/pages/Projects/Projects.controller";
import NameDialog from "./NameDialog.vue";
import { DbConfirmDialog, DbSkeleton } from "~/components/ui";
import {
  BoxIcon,
  FolderIcon,
  MoreHorizontalIcon,
  PencilIcon,
  PlusIcon,
  TrashIcon,
} from "~/assets/icons";
import type { Project } from "~/services";

/**
 * ProjectRail — project navigation and project-level actions.
 *
 * Renders the project list and actions. Environment selection and management
 * live in the content header so they do not duplicate project navigation.
 */
const props = defineProps<{ controller: ProjectsController }>();

// Destructure so refs auto-unwrap in the template.
const { projects, projectsError } = props.controller;

type ProjectDialogState =
  { mode: "create" } | { mode: "rename"; project: Project } | null;
const projectDialog = ref<ProjectDialogState>(null);
const projectDelete = ref<Project | null>(null);
const projectMenuId = ref<string | null>(null);
const deleteLoading = ref(false);
const deleteError = ref<string | null>(null);

const isProjectActive = (project: Project): boolean =>
  props.controller.projectRef.value === project.name ||
  props.controller.projectRef.value === project.id;
async function confirmProjectDelete(): Promise<void> {
  if (!projectDelete.value) return;
  deleteLoading.value = true;
  deleteError.value = null;
  try {
    await props.controller.deleteProject(projectDelete.value.id);
    projectDelete.value = null;
  } catch {
    deleteError.value = "The project could not be deleted.";
  } finally {
    deleteLoading.value = false;
  }
}
</script>

<template>
  <aside
    class="sticky top-0 flex h-svh w-72 shrink-0 flex-col border-r border-line bg-panel/60">
    <header class="flex items-center justify-between px-4 py-3.5">
      <h2 class="font-mono text-xs uppercase tracking-wider text-ink-faint">
        projects
      </h2>
      <button
        type="button"
        class="cursor-pointer rounded-control bg-raised p-1 text-ink-muted transition-colors hover:bg-line hover:text-ink-strong"
        aria-label="New project"
        data-testid="new-project"
        @click="projectDialog = { mode: 'create' }">
        <PlusIcon class="h-4 w-4" />
      </button>
    </header>

    <div class="min-h-0 flex-1 overflow-y-auto px-2 pb-4">
      <!-- Skeleton loading projects -->
      <div
        v-if="!projects"
        class="flex flex-col gap-1 px-1 py-1"
        data-testid="projects-skeleton">
        <div
          v-for="i in 5"
          :key="i"
          class="flex items-center gap-2 rounded-control px-2 py-2">
          <DbSkeleton class="h-3.5 w-3.5 shrink-0 rounded" />
          <DbSkeleton class="h-3.5 w-32" />
        </div>
      </div>
      <p v-else-if="projectsError" class="px-2 py-4 text-xs text-crit">
        {{ projectsError }}
      </p>
      <ul v-else-if="projects.length > 0" class="flex flex-col gap-0.5">
        <li v-for="project in projects" :key="project.id">
          <!-- Project row -->
          <div
            class="group flex items-center gap-1 rounded-control px-2 py-1.5"
            :class="
              isProjectActive(project) ? 'bg-raised' : 'hover:bg-raised/60'
            ">
            <button
              type="button"
              class="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-left"
              @click="controller.selectProject(project.id)">
              <BoxIcon
                class="h-3.5 w-3.5 shrink-0"
                :class="
                  isProjectActive(project)
                    ? 'text-accent-strong'
                    : 'text-ink-faint'
                " />
              <span
                class="truncate font-mono text-xs"
                :class="
                  isProjectActive(project) ? 'text-ink-strong' : 'text-ink'
                ">
                {{ project.name }}
              </span>
            </button>
            <div class="relative flex shrink-0 items-center">
              <button
                type="button"
                class="cursor-pointer rounded p-1 text-ink-faint opacity-0 transition-opacity hover:bg-line hover:text-ink-strong focus:opacity-100 group-hover:opacity-100"
                :aria-label="`Actions for ${project.name}`"
                :aria-expanded="projectMenuId === project.id"
                @click="
                  projectMenuId =
                    projectMenuId === project.id ? null : project.id
                ">
                <MoreHorizontalIcon class="h-3.5 w-3.5" />
              </button>
              <div
                v-if="projectMenuId === project.id"
                class="absolute right-0 top-8 z-30 flex min-w-40 flex-col rounded-control border border-line-soft bg-panel p-1 shadow-xl">
                <button
                  class="flex min-h-8 items-center gap-2 rounded px-2 text-left text-xs text-ink-strong hover:bg-raised"
                  @click="
                    projectMenuId = null;
                    controller.requestFileCreation(project.id, 'folder');
                  ">
                  <FolderIcon class="h-3.5 w-3.5" />New folder
                </button>
                <button
                  class="flex min-h-8 items-center gap-2 rounded px-2 text-left text-xs text-ink-strong hover:bg-raised"
                  @click="
                    projectMenuId = null;
                    controller.requestFileCreation(project.id, 'file');
                  ">
                  <PlusIcon class="h-3.5 w-3.5" />New file
                </button>
                <button
                  class="flex min-h-8 items-center gap-2 rounded px-2 text-left text-xs text-ink-strong hover:bg-raised"
                  @click="
                    projectMenuId = null;
                    projectDialog = { mode: 'rename', project };
                  ">
                  <PencilIcon class="h-3.5 w-3.5" />Rename project
                </button>
                <button
                  class="flex min-h-8 items-center gap-2 rounded px-2 text-left text-xs text-crit hover:bg-raised"
                  @click="
                    projectMenuId = null;
                    projectDelete = project;
                  ">
                  <TrashIcon class="h-3.5 w-3.5" />Delete project
                </button>
              </div>
            </div>
          </div>
        </li>
      </ul>

      <p v-else class="px-2 py-4 text-xs leading-relaxed text-ink-muted">
        No projects yet. Create one with the + button above.
      </p>
    </div>

    <!-- Create / rename project -->
    <NameDialog
      :open="projectDialog !== null"
      :title="
        projectDialog?.mode === 'rename' ? 'Rename project' : 'New project'
      "
      label="Project name"
      :initial-name="
        projectDialog?.mode === 'rename' ? projectDialog.project.name : ''
      "
      :submit-label="projectDialog?.mode === 'rename' ? 'Rename' : 'Create'"
      hint="Any name up to 128 characters. Control characters are not allowed."
      :action="
        (name: string) =>
          projectDialog?.mode === 'rename'
            ? controller.renameProject(projectDialog.project.id, name)
            : controller.createProject(name)
      "
      @close="projectDialog = null" />

    <!-- Delete project -->
    <DbConfirmDialog
      :open="projectDelete !== null"
      title="Delete project"
      :description="`Deleting '${projectDelete?.name}' permanently removes the project and all data in its environment tags.`"
      :confirm-word="projectDelete?.name"
      confirm-label="Delete project"
      :loading="deleteLoading"
      :error="deleteError"
      @confirm="confirmProjectDelete"
      @close="projectDelete = null" />
  </aside>
</template>

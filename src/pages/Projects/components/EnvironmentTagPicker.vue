<script setup lang="ts">
import { computed, ref, useId, watch } from "vue";
import {
  createEnvironment,
  type Environment,
} from "~/services/environments.api";
import { LayersIcon } from "~/assets/icons";

const props = defineProps<{
  projectRef: string;
  environments: Environment[];
  modelValue: string;
  placeholder?: string;
  emptyLabel?: string;
  autofocus?: boolean;
}>();
const emit = defineEmits<{
  "update:modelValue": [value: string];
  "environment-created": [environment: Environment];
}>();

const open = ref(false);
const busy = ref(false);
const error = ref("");
const activeIndex = ref(0);
const listId = useId();
const query = computed(() => props.modelValue.trim());
const filtered = computed(() =>
  props.environments.filter((item) =>
    item.name.toLocaleLowerCase().includes(query.value.toLocaleLowerCase()),
  ),
);
const exactMatch = computed(() =>
  props.environments.some(
    (item) => item.name.toLocaleLowerCase() === query.value.toLocaleLowerCase(),
  ),
);
const canCreate = computed(() => query.value.length > 0 && !exactMatch.value);
const optionCount = computed(
  () => filtered.value.length + (canCreate.value ? 1 : 0) + 1,
);

watch(
  [query, () => props.environments],
  () => (activeIndex.value = query.value ? 1 : 0),
);

function choose(name: string): void {
  emit("update:modelValue", name);
  error.value = "";
  open.value = false;
}

async function createTag(): Promise<void> {
  if (!canCreate.value || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    const environment = await createEnvironment(props.projectRef, query.value);
    emit("environment-created", environment);
    choose(environment.name);
  } catch (cause) {
    error.value =
      cause instanceof Error ? cause.message : "Could not create tag.";
  } finally {
    busy.value = false;
  }
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === "ArrowDown") {
    event.preventDefault();
    open.value = true;
    activeIndex.value = (activeIndex.value + 1) % optionCount.value;
  } else if (event.key === "ArrowUp") {
    event.preventDefault();
    open.value = true;
    activeIndex.value =
      (activeIndex.value - 1 + optionCount.value) % optionCount.value;
  } else if (event.key === "Enter" && open.value) {
    event.preventDefault();
    if (activeIndex.value === 0) choose("");
    else if (canCreate.value && activeIndex.value === filtered.value.length + 1)
      void createTag();
    else {
      const item = filtered.value[activeIndex.value - 1];
      if (item) choose(item.name);
    }
  } else if (event.key === "Escape") {
    open.value = false;
  }
}

function closeAfterFocusOut(): void {
  window.setTimeout(() => (open.value = false), 100);
}
</script>

<template>
  <div class="relative">
    <div
      class="flex h-10 items-center gap-2 rounded-control bg-raised px-3 focus-within:ring-2 focus-within:ring-accent">
      <LayersIcon class="h-4 w-4 shrink-0 text-ink-faint" />
      <input
        :value="modelValue"
        role="combobox"
        aria-autocomplete="list"
        :aria-expanded="open"
        :aria-controls="listId"
        :placeholder="placeholder ?? 'No tag (inherit or Shared)'"
        :autofocus="autofocus"
        class="min-w-0 flex-1 bg-transparent text-sm text-ink-strong outline-none placeholder:text-ink-faint"
        @input="
          emit('update:modelValue', ($event.target as HTMLInputElement).value);
          open = true;
          error = '';
        "
        @focus="open = true"
        @focusout="closeAfterFocusOut"
        @keydown="onKeydown" />
    </div>
    <div
      v-if="open"
      :id="listId"
      role="listbox"
      class="absolute left-0 right-0 top-11 z-40 max-h-56 overflow-y-auto rounded-control border border-line-soft bg-panel p-1 shadow-xl">
      <button
        type="button"
        role="option"
        :aria-selected="!modelValue"
        class="flex min-h-9 w-full items-center rounded px-2.5 text-left text-sm text-ink-muted hover:bg-raised hover:text-ink-strong"
        @mousedown.prevent="choose('')">
        {{ emptyLabel ?? "No tag — inherit or Shared" }}
      </button>
      <button
        v-for="(environment, index) in filtered"
        :key="environment.id"
        type="button"
        role="option"
        :aria-selected="modelValue === environment.name"
        class="flex min-h-9 w-full items-center rounded px-2.5 text-left text-sm text-ink-strong hover:bg-raised"
        :class="activeIndex === index + 1 ? 'bg-raised' : ''"
        @mousedown.prevent="choose(environment.name)">
        {{ environment.name }}
      </button>
      <button
        v-if="canCreate"
        type="button"
        role="option"
        :aria-selected="activeIndex === filtered.length + 1"
        class="flex min-h-9 w-full items-center rounded px-2.5 text-left text-sm text-accent-strong hover:bg-raised disabled:opacity-50"
        :disabled="busy"
        @mousedown.prevent="void createTag()">
        Create “{{ query }}”
      </button>
    </div>
    <p v-if="error" class="mt-1 text-xs text-crit">{{ error }}</p>
  </div>
</template>

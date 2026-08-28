<template><n-tag :type="type" size="small" :bordered="false">{{ status }}</n-tag></template>

<script setup lang="ts">
import { computed } from 'vue'
import { NTag } from 'naive-ui'
import { statusTagType } from '../formatters'
const props = defineProps<{ status: string }>()
const type = computed(() => statusTagType(props.status))
</script>

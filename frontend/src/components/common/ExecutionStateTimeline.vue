<template>
  <n-timeline>
    <n-timeline-item
      v-for="item in items"
      :key="item.key"
      :type="item.type ?? 'default'"
      :title="item.title"
      :content="item.content"
      :time="item.time"
    />
  </n-timeline>
</template>

<script setup lang="ts">
import { NTimeline, NTimelineItem, type TimelineItemProps } from 'naive-ui'

interface ExecutionTimelineItem {
  key: string
  title: string
  content?: string
  time?: string
  type?: TimelineItemProps['type']
}

defineProps<{ items: ExecutionTimelineItem[] }>()
</script>

<script setup>
import { RouterView } from "vue-router";
import HeaderView from "./components/HeaderView.vue";
</script>
<template>
  <HeaderView />
  <RouterView v-slot="{ Component }">
    <keep-alive>
      <component :is="Component" />
    </keep-alive>
  </RouterView>
</template>
<style scoped></style>

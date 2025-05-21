<script setup>
import { RouterView } from "vue-router";
import HeaderView from "./components/HeaderView.vue";
</script>
<template>
  <HeaderView />
  <keep-alive>
    <RouterView />
  </keep-alive>
</template>
<style scoped></style>

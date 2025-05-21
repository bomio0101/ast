<script setup>
import { ref, onMounted, watch } from "vue";
import { useRoute } from "vue-router";

// 下面是处理监听路由变化
const route = useRoute();

const page = ref(0);

onMounted(() => {
  changeIndex(route.path);
});

watch(route, (to, _from) => {
  changeIndex(to.path);
});

const changeIndex = (path) => {
  switch (path) {
    case "/home":
      page.value = 1;
      break;
    case "/threat":
      page.value = 2;
      break;
    case "/about":
      page.value = 3;
      break;
    default:
      if (path.match("^/threat/.*")) page.value = 2;
      else page.value = 1;
      break;
  }
};
</script>

<template>
  <div class="header-container">
    <div class="logo" v-if="page !== 1">
      <!-- <img class="border-right" src="/bupt-logo.png" alt="" /> -->
      <img src="/logo.png" alt="" />
      <span>网盾</span>
    </div>
    <!-- <div class="logo" v-else>
      <img class="only" src="/bupt-logo.png" alt="" /> -->
    <!-- </div> -->

    <div class="nav">
      <router-link
        class="nav-item"
        :class="page === 1 ? 'active' : ''"
        to="/home"
        >首页</router-link
      >
      <router-link
        class="nav-item"
        :class="page === 2 ? 'active' : ''"
        to="/threat"
        >威胁告警</router-link
      >
      <router-link
        class="nav-item"
        :class="page === 3 ? 'active' : ''"
        to="/about"
        >关于我们</router-link
      >
    </div>
  </div>
</template>

<style scoped>
.header-container {
  display: flex;
  justify-content: left;
  align-items: center;
  height: 60px;
  padding: 0 20px;
  background-color: #f0f0f0;
  box-shadow: 0px 2px 10px rgba(0, 0, 0, 0.2);
}

.logo {
  display: flex;
  align-items: center;
  height: 60px;

  span {
    font-size: 28px;
    /* font-weight: bold; */
  }

  img {
    margin: 0 20px;
    height: 48px;

    &.only {
      margin-right: 180px;
    }

    &.border-right {
      padding-right: 36px;
      margin-right: 0;
      border-right: 2px solid #88888888;
    }
  }
}

.nav {
  margin-left: 60px;
  font-size: 18px;
  display: flex;
  height: 60px;

  .nav-item {
    height: 60px;
    line-height: 60px;
    text-decoration: none;
    color: #333;
    width: 100px;
    text-align: center;
    transition: color 0.25s, background-color 0.25s;

    &:hover {
      background-color: #cccccc;
    }

    &.active {
      background-color: #bbbbbb;
      border-bottom: 2px solid #e55847;
    }
  }
}
</style>

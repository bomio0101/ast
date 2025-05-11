<script setup>
import { ref } from "vue";

const features = ref([
  {
    title: "网络数据分析",
    description: "支持对PCAP文件进行深度分析，提取关键网络特征",
  },
  {
    title: "实时监控",
    description: "对网络流量进行实时监控和异常检测",
  },
  {
    title: "威胁告警",
    description: "基于机器学习的智能威胁识别系统",
  },
  {
    title: "数据可视化",
    description: "直观的数据展示和分析报告",
  },
]);

const team = ref([
  {
    name: "开发团队",
    role: "北京邮电大学",
    description: "致力于网络安全研究与开发",
  },
]);
</script>

<template>
  <div class="about-container">
    <el-card class="about-header">
      <template #header>
        <div class="card-header">
          <h1>关于网哨</h1>
        </div>
      </template>
      <p class="description">
        网哨是一个专业的网络流量分析工具，致力于为用户提供全面的网络安全解决方案。
        通过先进的数据分析技术，帮助用户识别和预防网络威胁。
      </p>
    </el-card>

    <el-card class="features-section">
      <template #header>
        <div class="card-header">
          <h2>主要功能</h2>
        </div>
      </template>
      <el-row :gutter="20">
        <el-col v-for="feature in features" :key="feature.title" :span="6">
          <el-card class="feature-card">
            <h3>{{ feature.title }}</h3>
            <p>{{ feature.description }}</p>
          </el-card>
        </el-col>
      </el-row>
    </el-card>

    <el-card class="team-section">
      <template #header>
        <div class="card-header">
          <h2>开发团队</h2>
        </div>
      </template>
      <el-row :gutter="20">
        <el-col v-for="member in team" :key="member.name" :span="8">
          <el-card class="member-card">
            <h3>{{ member.name }}</h3>
            <p class="role">{{ member.role }}</p>
            <p>{{ member.description }}</p>
          </el-card>
        </el-col>
      </el-row>
    </el-card>
  </div>
</template>

<style scoped>
.about-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
}

.about-header {
  margin-bottom: 30px;
}

.features-section,
.team-section {
  margin-bottom: 30px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.description {
  font-size: 16px;
  line-height: 1.6;
  color: #666;
}

.feature-card,
.member-card {
  height: 100%;
  text-align: center;
  transition: all 0.3s ease;
}

.feature-card:hover,
.member-card:hover {
  transform: translateY(-5px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

h1 {
  color: #409eff;
  margin: 0;
}

h2 {
  color: #409eff;
  margin: 0;
}

h3 {
  color: #303133;
  margin: 0 0 10px 0;
}

.role {
  color: #909399;
  font-size: 14px;
  margin: 5px 0;
}

.el-row {
  margin-bottom: 20px;
  &:last-child {
    margin-bottom: 0;
  }
}
</style>

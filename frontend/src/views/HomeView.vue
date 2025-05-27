<script setup>
import { ref, onMounted, onUnmounted } from "vue";
import {
  uploadFile,
  getResults,
  stopSniffing,
  startSniffing,
  getInterfaces,
  getSniffingStatus,
} from "../api";
import { ElMessage, ElMessageBox } from "element-plus";
import { UploadFilled } from "@element-plus/icons-vue";
import { useRouter } from "vue-router";
import axios from "axios";

const router = useRouter();
const results = ref([]);
const isSniffing = ref(false);
const interfaces = ref([]);
const selectedInterface = ref("");
const loading = ref(false);

const handleFileUpload = async (file) => {
  try {
    console.log("开始上传文件:", file);
    const response = await uploadFile(file);
    if (response.data.message === "success") {
      ElMessage.success("文件上传成功");
      await fetchResults();
      // 上传成功后跳转到威胁告警页面
      router.push("/threat");
    }
  } catch (error) {
    console.error("上传错误:", error);
    ElMessage.error(`上传失败: ${error.message}`);
  }
};

const fetchResults = async () => {
  try {
    const { data } = await getResults();
    results.value = data.result;
  } catch (error) {
    console.error("获取数据失败:", error);
    ElMessage.error(`获取数据失败: ${error.message}`);
  }
};

const handleSuccess = (response, file, fileList) => {
  console.log("上传成功:", response, file, fileList);
  ElMessage.success("文件上传成功");
  fetchResults();
  // 上传成功后跳转到威胁告警页面
  router.push("/threat");
};

const handleError = (error, file, fileList) => {
  console.error("上传失败:", error, file, fileList);
  ElMessage.error(`上传失败: ${error.message}`);
};

const handleBeforeUpload = (file) => {
  console.log("准备上传文件:", file);
  return true;
};

// 检查抓包状态
const checkSniffingStatus = async () => {
  // 如果用户没有主动开始抓包，直接返回
  if (!isSniffing.value) {
    return;
  }

  try {
    loading.value = true;
    const response = await getSniffingStatus();
    console.log("抓包状态响应:", response.data);

    if (response.data && response.data.status) {
      const newStatus = response.data.status === "running";
      console.log("更新抓包状态:", newStatus);
      isSniffing.value = newStatus;
    } else {
      console.log("未获取到有效的抓包状态，停止抓包");
      isSniffing.value = false;
    }
  } catch (error) {
    console.error("获取抓包状态失败:", error);
    isSniffing.value = false; // 发生错误时停止抓包
    if (error.response) {
      if (error.response.status === 403) {
        ElMessage.error("需要管理员权限才能获取抓包状态");
      } else {
        ElMessage.error(
          `服务器错误: ${error.response.data.error || "未知错误"}`
        );
      }
    } else {
      ElMessage.error("网络连接失败，请检查后端服务是否运行");
    }
  } finally {
    loading.value = false;
  }
};

// 获取可用网络接口
const fetchInterfaces = async () => {
  try {
    console.log("开始获取网络接口列表");
    const res = await getInterfaces();
    console.log("获取网络接口响应:", res);
    console.log("接口数据:", res.data);

    if (res.data.interfaces) {
      interfaces.value = res.data.interfaces;
      console.log("可用网络接口:", interfaces.value);

      if (interfaces.value.length > 0) {
        selectedInterface.value = interfaces.value[0];
        console.log("已选择默认接口:", selectedInterface.value);
      } else if (res.data.message) {
        console.log("接口列表为空，消息:", res.data.message);
        ElMessage.warning(res.data.message);
      }
    } else {
      console.log("响应中没有接口数据");
      ElMessage.warning("未获取到网络接口信息");
    }
  } catch (error) {
    console.error("获取网络接口失败:", error);
    if (error.response?.data?.requires_admin) {
      ElMessage.error({
        message: "请以管理员权限运行程序",
        duration: 5000,
        showClose: true,
      });
    } else {
      ElMessage.error("获取网络接口失败，请检查后端服务是否运行");
    }
  }
};

// 切换抓包状态
const toggleSniffing = async () => {
  try {
    console.log("开始切换抓包状态，当前状态:", isSniffing.value);

    if (isSniffing.value) {
      console.log("尝试停止抓包");
      const res = await stopSniffing();
      console.log("停止抓包响应:", res);

      if (res.data.success) {
        ElMessage.success("停止抓包成功");
        isSniffing.value = false;
      } else {
        ElMessage.error(res.data.message || "停止抓包失败");
      }
    } else {
      if (!selectedInterface.value) {
        ElMessage.warning("请先选择网络接口");
        return;
      }

      console.log("尝试开始抓包，选择的接口:", selectedInterface.value);
      const res = await startSniffing(selectedInterface.value);
      console.log("开始抓包响应:", res);

      if (res.data.success) {
        ElMessage.success("开始抓包成功");
        isSniffing.value = true;
      } else {
        ElMessage.error(res.data.message || "开始抓包失败");
      }
    }
  } catch (error) {
    console.error("切换抓包状态失败:", error);
    isSniffing.value = false; // 发生错误时确保状态为false
    if (error.response?.data?.requires_admin) {
      ElMessage.error({
        message: "请以管理员权限运行程序",
        duration: 5000,
        showClose: true,
      });
    } else {
      ElMessage.error("操作失败，请检查网络连接");
    }
  }
};

// 使用轮询而不是频繁请求
let statusCheckInterval;

onMounted(() => {
  fetchInterfaces();
  // 只在用户主动开始抓包后才启动状态检查
  statusCheckInterval = setInterval(checkSniffingStatus, 5000);
});

onUnmounted(() => {
  if (statusCheckInterval) {
    clearInterval(statusCheckInterval);
  }
});

const navigateToUpload = () => {
  router.push("/upload");
};

const navigateToThreat = () => {
  router.push("/threat");
};
</script>

<template>
  <div class="home-container">
    <div class="home">
      <div class="title">
        <h1>网盾</h1>
        <h2>基于 <span>3D-IDS</span> 的</h2>
        <h2>网络异常流量检测平台</h2>
      </div>
      <div class="logo">
        <img src="/logo.png" alt="logo" />
      </div>
    </div>
    <div class="upload-info">上传流量信息：</div>
    <el-upload
      class="upload"
      drag
      :action="'http://localhost:5000/upload'"
      :on-success="handleSuccess"
      :on-error="handleError"
      :before-upload="handleBeforeUpload"
      accept=".pcap,.pcapng"
    >
      <el-icon class="el-icon--upload"><upload-filled /></el-icon>
      <div class="el-upload__text">拖动文件到此处，或<em>点击上传</em></div>
      <template #tip>
        <div class="el-upload__tip">pcap files with a size less than 10MB</div>
      </template>
    </el-upload>

    <div class="control-section">
      <div class="sniffing-control">
        <el-select
          v-model="selectedInterface"
          placeholder="选择网络接口"
          :disabled="isSniffing"
          style="width: 200px; margin-right: 20px"
        >
          <el-option
            v-for="iface in interfaces"
            :key="iface"
            :label="iface"
            :value="iface"
          />
        </el-select>
        <el-button
          type="primary"
          :loading="isSniffing"
          @click="toggleSniffing"
          size="large"
        >
          {{ isSniffing ? "停止抓包" : "开始抓包" }}
        </el-button>
        <span class="status-text" :class="{ active: isSniffing }">
          {{ isSniffing ? "正在抓包..." : "未开始抓包" }}
        </span>
      </div>

      <!-- <div class="button-container">
        <el-button type="primary" @click="navigateToUpload" size="large">
          上传文件
        </el-button>
        <el-button type="success" @click="navigateToThreat" size="large">
          威胁告警
        </el-button>
      </div> -->
    </div>

    <el-table
      v-if="results.length"
      :data="results"
      style="width: 100%; margin-top: 20px"
    >
      <el-table-column prop="0" label="ID" width="180" />
      <el-table-column prop="1" label="数据" />
    </el-table>
  </div>
</template>

<style scoped>
.home-container {
  max-width: 800px;
  margin: 0 auto;
  padding-top: 20px;
  width: 80vw;
  min-height: calc(100vh - 50px);
}
.home {
  width: 100%;
  height: 400px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  .title {
    h1 {
      font-size: 5rem;
      position: relative;
      /* font-weight: bold; */
      &::after {
        content: "";
        position: absolute;
        bottom: 0.5rem;
        left: 0;
        width: 10rem;
        height: 20%;
        background-color: #e55847ee;
        z-index: -1;
      }
    }
    h2 {
      font-size: 2rem;
      span {
        font-weight: bold;
        color: #a83326ee;
      }
    }
  }
  .logo {
    margin-right: 50px;
    height: 350px;
    width: 350px;
    position: relative;
    img {
      height: 100%;
      width: 100%;
    }
  }
}
.upload-info {
  margin-bottom: 8px;
}

.control-section {
  margin-top: 20px;
  padding: 20px;
  background: #fff;
  border-radius: 8px;
  box-shadow: 0px 1px 3px rgba(0, 0, 0, 0.1);
}

.sniffing-control {
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 20px;
  padding-bottom: 20px;
  border-bottom: 1px solid #eee;
}

.status-text {
  color: #666;
  font-size: 16px;
}

.status-text.active {
  color: #67c23a;
  font-weight: bold;
}

.button-container {
  display: flex;
  gap: 20px;
  justify-content: center;
}
</style>

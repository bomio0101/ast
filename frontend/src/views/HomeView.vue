<script setup>
import { ref, onMounted } from "vue";
import { uploadFile, getResults } from "../api";
import { ElMessage } from "element-plus";
import { UploadFilled } from "@element-plus/icons-vue";

const results = ref([]);

const handleFileUpload = async (file) => {
  try {
    console.log("开始上传文件:", file);
    const response = await uploadFile(file);
    if (response.data.message === "success") {
      ElMessage.success("文件上传成功");
      await fetchResults();
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
};

const handleError = (error, file, fileList) => {
  console.error("上传失败:", error, file, fileList);
  ElMessage.error(`上传失败: ${error.message}`);
};

const handleBeforeUpload = (file) => {
  console.log("准备上传文件:", file);
  return true;
};

onMounted(() => {
  fetchResults();
});
</script>

<template>
  <div class="home-container">
    <div class="home">
      <div class="title">
        <h1>网哨</h1>
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
    height: 250px;
    width: 250px;
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
</style>

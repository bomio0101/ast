<script setup>
import { UploadFilled } from '@element-plus/icons-vue'
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
        <img src="/logo.png" alt="logo">
      </div>
    </div>
    <div class="upload-info">上传流量信息：</div>
    <el-upload class="upload" drag action="/upload" multiple>
      <el-icon class="el-icon--upload"><upload-filled /></el-icon>
      <div class="el-upload__text">
        拖动文件到此处，或<em>点击上传</em>
      </div>
      <template #tip>
        <div class="el-upload__tip">
          pcap files with a size less than 10MB
        </div>
      </template>
    </el-upload>
  </div>
</template>
<style>
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
      span{
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
.upload-info{
  margin-bottom: 8px;
}
</style>

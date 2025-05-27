import axios from "axios";

const baseURL = "http://localhost:5000";

// 创建axios实例
const api = axios.create({
  baseURL,
  timeout: 10000,
  headers: {
    "Content-Type": "application/json",
  },
});

// 请求拦截器
api.interceptors.request.use(
  (config) => {
    console.log("发送请求:", config);
    return config;
  },
  (error) => {
    console.error("请求错误:", error);
    return Promise.reject(error);
  }
);

// 响应拦截器
api.interceptors.response.use(
  (response) => {
    console.log("收到响应:", response);
    return response;
  },
  (error) => {
    console.error("响应错误:", error);
    if (error.response) {
      console.error("错误状态:", error.response.status);
      console.error("错误数据:", error.response.data);

      // 处理权限错误
      if (error.response.status === 403 && error.response.data.requires_admin) {
        error.message = "需要管理员权限才能执行此操作";
      }
    }
    return Promise.reject(error);
  }
);

// 上传文件
export const uploadFile = (file) => {
  const formData = new FormData();
  formData.append("file", file);
  return api.post("/upload", formData, {
    headers: {
      "Content-Type": "multipart/form-data",
    },
  });
};

// 获取结果
export const getResults = () => {
  return api.get("/results");
};

// 开始抓包
export const startSniffing = (interfaceName) => {
  return api.post("/start_sniffing", { interface: interfaceName });
};

// 停止抓包
export const stopSniffing = () => {
  return api.post("/stop_sniffing");
};

// 获取网络接口列表
export const getInterfaces = () => {
  return api.get("/interfaces");
};

// 获取抓包状态
export const getSniffingStatus = () => {
  return api.get("/sniffing_status");
};

export default api;

<template>
  <div v-if="dataLoaded">
    <div class="container">
      <el-breadcrumb :separator-icon="ArrowRight" class="breadcrumb">
        <el-breadcrumb-item :to="{ path: '/' }">首页</el-breadcrumb-item>
        <el-breadcrumb-item :to="{ path: '/threat' }"
          >威胁告警</el-breadcrumb-item
        >
      </el-breadcrumb>

      <div v-loading="loading" class="card">
        <div class="information">
          <span class="all"><span>共计</span> - {{ count.all }}条</span>
          <span class="critical"
            ><span>危急</span> - {{ count.critical }}条</span
          >
          <span class="high"><span>高危</span> - {{ count.highRisk }}条</span>
          <span class="medium"
            ><span>中危</span> - {{ count.mediumRisk }}条</span
          >
          <span class="low"><span>低危</span> - {{ count.lowRisk }}条</span>
        </div>
        <div class="overview">
          <div class="graph">
            <div class="graph-title">告警统计图</div>
            <div class="graph-chart" ref="chartDom_1"></div>
          </div>
          <div class="graph">
            <div class="graph-title">告警趋势图</div>
            <div class="graph-chart" ref="chartDom_2"></div>
          </div>
        </div>
        <div class="detail">
          <div class="detail-info">告警信息</div>
          <el-table
            ref="tableRef"
            row-key="date"
            :data="dataList"
            style="width: 100%"
          >
            <el-table-column
              prop="time"
              label="告警时间"
              sortable
              width="180"
              column-key="date"
            />
            <el-table-column prop="dst" label="受害者 IP" width="180" />
            <el-table-column prop="src" label="攻击者 IP" width="180" />
            <el-table-column prop="type" label="攻击类型" width="180" />

            <el-table-column
              prop="level"
              label="威胁级别"
              width="180"
              :filters="[
                { text: '危急', value: 'critical' },
                { text: '高危', value: 'high' },
                { text: '中危', value: 'medium' },
                { text: '低危', value: 'low' },
              ]"
              :filter-method="filterLevel"
              filter-placement="bottom-end"
            >
              <template #default="scope">
                <el-tag
                  :type="getLevelTag(scope.row.level)"
                  disable-transitions
                  >{{ getLevelName(scope.row.level) }}</el-tag
                >
              </template>
            </el-table-column>
          </el-table>
        </div>
      </div>
    </div>
  </div>
  <div v-else>Loading...</div>
</template>

<script setup>
import { ref, onMounted, onUnmounted, watch, nextTick } from "vue";
import { ArrowRight } from "@element-plus/icons-vue";
import axios from "axios";
import * as echarts from "echarts/core";
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
} from "echarts/components";
import { PieChart, LineChart } from "echarts/charts";
import { LabelLayout, UniversalTransition } from "echarts/features";
import { CanvasRenderer } from "echarts/renderers";
import { ElMessage } from "element-plus";

// 注册必需的组件
echarts.use([
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
  PieChart,
  LineChart,
  LabelLayout,
  UniversalTransition,
  CanvasRenderer,
]);

const dataList = ref([]);
const count = ref({
  all: 0,
  critical: 0,
  highRisk: 0,
  mediumRisk: 0,
  lowRisk: 0,
});
const chartDom_1 = ref();
const chartDom_2 = ref();
let myChart1, myChart2;

const loading = ref(true);
const dataLoaded = ref(false);

const fetchData = async () => {
  try {
    loading.value = true;
    const res = await axios.get("http://localhost:5000/results");
    if (res.status === 200) {
      console.log("获取到的原始数据:", res.data.result);
      dataList.value = res.data.result.map((item) => {
        try {
          const data =
            typeof item[1] === "string" ? JSON.parse(item[1]) : item[1];
          console.log("解析后的数据:", data);
          return {
            time: new Date().toLocaleString(),
            src: data.src_ip || data.src || "未知",
            dst: data.dst_ip || data.dst || "未知",
            type: getThreatType(data),
            level: getThreatLevel(data),
          };
        } catch (e) {
          console.error("数据解析错误:", e, item);
          return {
            time: new Date().toLocaleString(),
            src: "解析错误",
            dst: "解析错误",
            type: "未知攻击",
            level: "low",
          };
        }
      });
      console.log("处理后的数据列表:", dataList.value);
      initCount();
      dataLoaded.value = true;

      // 确保在 DOM 更新后初始化图表
      await nextTick();
      setTimeout(() => {
        initGraph_1();
        initGraph_2();
      }, 100);
    }
  } catch (error) {
    console.error("Error fetching results:", error);
    ElMessage.error("获取数据失败");
  } finally {
    loading.value = false;
  }
};

const getThreatType = (data) => {
  if (data.protocol === 6) {
    if (data.flags && data.flags.includes("S")) {
      return "TCP SYN 扫描";
    }
    return "TCP 异常连接";
  } else if (data.protocol === 17) {
    return "UDP 泛洪";
  } else if (data.protocol === 1) {
    return "ICMP 探测";
  }
  return "未知攻击";
};

const getThreatLevel = (data) => {
  if (data.protocol === 6 && data.flags && data.flags.includes("S")) {
    return "critical";
  } else if (data.protocol === 17) {
    return "high";
  } else if (data.protocol === 1) {
    return "medium";
  }
  return "low";
};

const initCount = () => {
  count.value = { all: 0, critical: 0, highRisk: 0, mediumRisk: 0, lowRisk: 0 };
  dataList.value.forEach((item) => {
    count.value.all++;
    switch (item.level) {
      case "critical":
        count.value.critical++;
        break;
      case "high":
        count.value.highRisk++;
        break;
      case "medium":
        count.value.mediumRisk++;
        break;
      case "low":
        count.value.lowRisk++;
        break;
    }
  });
};

const generatePieData = () => {
  const data = [];
  const type_list = [];
  dataList.value.forEach((item) => {
    const index = type_list.indexOf(item.type);
    if (index === -1) {
      type_list.push(item.type);
      data.push({ value: 1, name: item.type });
    } else {
      data[index].value++;
    }
  });
  return data;
};

const initGraph_1 = () => {
  if (!chartDom_1.value) return;
  myChart1 = echarts.init(chartDom_1.value);
  const option = {
    title: {
      text: "告警类型分布",
      left: "center",
    },
    tooltip: {
      trigger: "item",
      formatter: "{a} <br/>{b}: {c} ({d}%)",
    },
    legend: {
      orient: "vertical",
      left: "left",
      top: "middle",
    },
    series: [
      {
        name: "告警类型",
        type: "pie",
        radius: ["40%", "70%"],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 10,
          borderColor: "#fff",
          borderWidth: 2,
        },
        label: {
          show: true,
          formatter: "{b}: {c} ({d}%)",
        },
        emphasis: {
          label: {
            show: true,
            fontSize: "16",
            fontWeight: "bold",
          },
        },
        data: generatePieData(),
      },
    ],
  };
  myChart1.setOption(option);
};

const generateLineData = () => {
  const data = new Array(24).fill(0);
  dataList.value.forEach((item) => {
    try {
      const datetime = new Date(item.time);
      if (!isNaN(datetime.getTime())) {
        data[datetime.getHours()]++;
      } else {
        console.warn("Invalid date:", item.time);
      }
    } catch (e) {
      console.error("Error parsing date", item.time, e);
    }
  });
  return data;
};

const initGraph_2 = () => {
  if (!chartDom_2.value) return;
  myChart2 = echarts.init(chartDom_2.value);
  const hours = Array.from({ length: 24 }, (_, i) => `${i}:00`);
  const option = {
    title: {
      text: "告警趋势",
      left: "center",
    },
    tooltip: {
      trigger: "axis",
      axisPointer: {
        type: "shadow",
      },
    },
    grid: {
      left: "3%",
      right: "4%",
      bottom: "3%",
      containLabel: true,
    },
    xAxis: {
      type: "category",
      data: hours,
      axisLabel: {
        interval: 2,
      },
    },
    yAxis: {
      type: "value",
      name: "告警数量",
    },
    series: [
      {
        name: "告警数量",
        type: "line",
        smooth: true,
        data: generateLineData(),
        areaStyle: {
          opacity: 0.3,
        },
        lineStyle: {
          width: 3,
        },
        itemStyle: {
          borderWidth: 2,
        },
      },
    ],
  };
  myChart2.setOption(option);
};

const filterLevel = (value, row) => row.level === value;

const getLevelTag = (value) => {
  switch (value) {
    case "critical":
      return "danger";
    case "high":
      return "warning";
    case "medium":
      return "primary";
    case "low":
      return "info";
  }
};

const getLevelName = (value) => {
  switch (value) {
    case "critical":
      return "危急";
    case "high":
      return "高危";
    case "medium":
      return "中危";
    case "low":
      return "低危";
  }
};

watch(
  dataList,
  () => {
    if (dataLoaded.value) {
      nextTick(() => {
        initGraph_1();
        initGraph_2();
      });
    }
  },
  { deep: true }
);

onMounted(async () => {
  await fetchData();
});

onUnmounted(() => {
  if (myChart1) {
    myChart1.dispose();
  }
  if (myChart2) {
    myChart2.dispose();
  }
});
</script>

<style>
.container {
  max-width: 1000px;
  margin: 0 auto;
  width: 80vw;
  min-height: calc(100vh - 50px);
  position: relative;
  min-height: 400px;
}
.breadcrumb {
  padding: 16px;
  font-size: 16px;
}
.card {
  padding: 20px;
  background-color: #fff;
  border-radius: 8px;
  box-shadow: 0px 1px 3px rgba(0, 0, 0, 0.2);
  min-height: 300px;
}
.information {
  color: #666666;
  padding-bottom: 16px;
  border-bottom: 1px solid #888888;
  span ~ span {
    margin-left: 20px;
  }
  .all span {
    color: #000;
  }
  .critical span {
    color: red;
  }
  .high span {
    color: #e09406;
  }
  .medium span {
    color: #c1b50e;
  }
  .low span {
    color: #0e79c1;
  }
}
.overview {
  display: flex;
  padding-bottom: 16px;
  border-bottom: 1px solid #888888;
  .graph {
    margin-top: 20px;
    flex: 1;
    height: 400px;
    padding: 20px;
    box-sizing: border-box;
  }
  .graph ~ .graph {
    border-left: 1px solid #88888888;
    padding-left: 20px;
  }
  .graph-title {
    margin-bottom: 20px;
    margin-left: 10px;
    font-size: 16px;
    font-weight: bold;
  }
  .graph-chart {
    width: 100%;
    height: 350px;
    background: #fff;
  }
}
.detail {
  margin-top: 20px;
  .detail-info {
    margin-left: 10px;
    margin-bottom: 10px;
  }
}
</style>

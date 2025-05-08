<script setup>
import { ref, onMounted } from 'vue'

import { ArrowRight } from '@element-plus/icons-vue'

import axios from 'axios';

onMounted(() => {
  initCount()
  initGraph_1()
  initGraph_2()
})

const dataList = ref([])

// 从 /results 获取全部 datalist
const res = await axios.get('/results')
if (res.status === 200) {
  for (item in res.data.result) {
    dataList.value.push(JSON.parse(item))
  }
}

const count = ref({
  all: 0,
  critical: 0,
  highRisk: 0,
  mediumRisk: 0,
  lowRisk: 0,
})

const initCount = () => {
  for (let i = 0; i < dataList.value.length; i++) {
    count.value.all++
    switch (dataList.value[i].level) {
      case "critical":
        count.value.critical++
        break
      case "high":
        count.value.highRisk++
        break
      case "medium":
        count.value.mediumRisk++
        break
      case "low":
        count.value.lowRisk++
        break
    }
  }
}

// ----- 饼图+折线图 -----

import * as echarts from 'echarts/core';
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent
} from 'echarts/components';
import { PieChart } from 'echarts/charts';
import { LabelLayout } from 'echarts/features';
import { CanvasRenderer } from 'echarts/renderers';
import { LineChart } from 'echarts/charts';
import { UniversalTransition } from 'echarts/features';

echarts.use([
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  PieChart,
  CanvasRenderer,
  LabelLayout,
  LineChart,
  UniversalTransition,
  GridComponent
]);

const generatePieData = () => {
  var data = []
  var type_list = []
  for (let i = 0; i < dataList.value.length; i++) {
    if (type_list.indexOf(dataList.value[i].type) === -1) {
      type_list.push(dataList.value[i].type)
      data.push({ value: 1, name: dataList.value[i].type })
    }
    else {
      data[type_list.indexOf(dataList.value[i].type)].value++
    }
  }
  return data
}

const chartDom_1 = ref()
const initGraph_1 = () => {
  var myChart = echarts.init(chartDom_1.value);
  var option;

  option = {
    tooltip: {
      trigger: 'item'
    },
    legend: {
      top: 'top'
    },
    series: [
      {
        name: '告警类型',
        type: 'pie',
        radius: '50%',
        data: generatePieData(),
        emphasis: {
          itemStyle: {
            shadowBlur: 10,
            shadowOffsetX: 0,
            shadowColor: 'rgba(0, 0, 0, 0.5)'
          }
        }
      }
    ]
  };

  option && myChart.setOption(option);
}

const generateLineData = () => {
  var data = new Array(24).fill(0)
  for (let i = 0; i < dataList.value.length; i++) {
    var datetime = new Date(dataList.value[i].time)
    data[datetime.getHours()]++
  }
  return data
}

const chartDom_2 = ref()
const initGraph_2 = () => {
  var myChart = echarts.init(chartDom_2.value);
  var option;

  option = {

    tooltip: {
      trigger: 'axis'
    },
    xAxis: {
      type: 'category',
      data: ['0:00', '1:00', '2:00', '3:00', '4:00', '5:00', '6:00', '7:00', '8:00', '9:00', '10:00', '11:00', '12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00', '22:00', '23:00']
    },
    yAxis: {
      type: 'value'
    },
    series: [
      {
        data: generateLineData(),
        type: 'line',
        smooth: true
      }
    ]
  };

  option && myChart.setOption(option);
}

// ----- 表格部分 -----

const filterLevel = (value, row) => {
  return row.level === value
}

const getLevelTag = (value) => {
  switch (value) {
    case "critical":
      return "danger"
    case "high":
      return "warning"
    case "medium":
      return "primary"
    case "low":
      return "info"
  }
}
const getLevelName = (value) => {
  switch (value) {
    case "critical":
      return "危急"
    case "high":
      return "高危"
    case "medium":
      return "中危"
    case "low":
      return "低危"
  }
}
</script>
<template>
  <div class="container">
    <el-breadcrumb :separator-icon="ArrowRight" class="breadcrumb">
      <el-breadcrumb-item :to="{ path: '/' }">首页</el-breadcrumb-item>
      <el-breadcrumb-item :to="{ path: '/threat' }">威胁告警</el-breadcrumb-item>
    </el-breadcrumb>
    <div class="card">
      <div class="information">
        <span class="all"><span>共计</span> - {{ count.all }}条</span>
        <span class="critical"><span>危急</span> - {{ count.critical }}条</span>
        <span class="high"><span>高危</span> - {{ count.highRisk }}条</span>
        <span class="medium"><span>中危</span> - {{ count.mediumRisk }}条</span>
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
        <el-table ref="tableRef" row-key="date" :data="dataList" style="width: 100%">
          <el-table-column prop="time" label="告警时间" sortable width="180" column-key="date" />
          <el-table-column prop="dst" label="受害者 IP" width="180" />
          <el-table-column prop="src" label="攻击者 IP" width="180" />
          <el-table-column prop="type" label="攻击类型" width="180" />

          <el-table-column prop="level" label="威胁级别" width="180" :filters="[
            { text: '危急', value: 'critical' },
            { text: '高危', value: 'high' },
            { text: '中危', value: 'medium' },
            { text: '低危', value: 'low' }
          ]" :filter-method="filterLevel" filter-placement="bottom-end">
            <template #default="scope">
              <el-tag :type="getLevelTag(scope.row.level)"
                disable-transitions>{{ getLevelName(scope.row.level) }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </div>
  </div>
</template>
<style>
.container {
  max-width: 1000px;
  margin: 0 auto;
  width: 80vw;
  min-height: calc(100vh - 50px);
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
}
.information {
  color: #666666;
  padding-bottom: 16px;
  border-bottom: 1px solid #888888;
  span~span {
    margin-left: 20px;
  }
  .all span {
    color: #000;
  }
  .critical span {
    color: red;
  }
  .high span {
    color: #E09406;
  }
  .medium span {
    color: #C1B50E;
  }
  .low span {
    color: #0E79C1;
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
    /* width: 400px; */
    /* padding: 0 20px; */
  }
  .graph~.graph {
    border-left: 1px solid #88888888;
    padding-left: 20px;
  }
  .graph-title {
    margin-bottom: 1cap;
    margin-left: 10px;
  }
  .graph-chart {
    width: 100%;
    height: 100%;
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


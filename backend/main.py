from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
# 从 ids.py 导入业务逻辑函数，并使用别名
from ids import get_sniffing_status as actual_get_sniffing_status_logic
# 同样地，为其他业务逻辑函数也这样做，以确保清晰
from ids import start_sniffing as actual_start_sniffing_logic
from ids import stop_sniffing as actual_stop_sniffing_logic
from ids import get_available_interfaces # 如果这个名称没有冲突，可以不加别名
import os
import ctypes
import subprocess
import sys
import logging

# 配置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, 
     resources={r"/*": {
         "origins": ["http://localhost:5173"],
         "methods": ["GET", "POST", "OPTIONS", "PUT", "DELETE"],
         "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
         "expose_headers": ["Content-Type", "Authorization"],
         "supports_credentials": True,
         "max_age": 3600
     }},
     supports_credentials=True)

# 添加全局CORS头
# @app.after_request
# def after_request(response):
#     response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5173')
#     response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
#     response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
#     response.headers.add('Access-Control-Allow-Credentials', 'true')
#     return response

def is_admin():
    """检查程序是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_interface_permission(interface):
    """检查是否有权限访问指定的网络接口"""
    try:
        if sys.platform == 'win32':
            # Windows系统使用netsh命令检查接口状态
            result = subprocess.run(['netsh', 'interface', 'show', 'interface', interface], 
                                 capture_output=True, text=True)
            return result.returncode == 0
        else:
            # Linux/Unix系统使用ifconfig命令检查接口状态
            result = subprocess.run(['ifconfig', interface], capture_output=True, text=True)
            return result.returncode == 0
    except:
        return False

@app.before_request
def check_permission():
    """检查权限的中间件"""
    # 对于 OPTIONS 预检请求，直接允许通过，后续由 Flask-CORS 处理 CORS 头部
    if request.method == 'OPTIONS':
        return None # 或者根据需要返回一个带有CORS头部的空200响应，但通常Flask-CORS会处理

    # 不需要权限检查的路由
    public_routes = ['/upload', '/results', '/interfaces', '/sniffing_status']
    
    if request.path in public_routes:
        return None
            
    if request.path == '/start_sniffing':
        # 确保只在非 OPTIONS 请求（如 POST）时才尝试获取 JSON body
        if request.method == 'POST': # 或者其他您期望的方法
            if not request.is_json: # 检查 Content-Type 是否为 application/json
                return jsonify({"error": "Request must be JSON"}), 400 # 或者其他合适的错误处理
            
            data = request.get_json() # 安全地获取 JSON 数据
            if data is None:
                return jsonify({"error": "Invalid JSON data"}), 400

            interface = data.get('interface')
            if not interface: # 检查 interface 是否提供
                 return jsonify({"error": "Missing 'interface' parameter"}), 400

            if not check_interface_permission(interface):
                return jsonify({
                    'error': '没有权限访问指定的网络接口',
                    'requires_admin': True
                }), 403
    return None

def init_db():
    conn = sqlite3.connect('network_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets
                (id INTEGER PRIMARY KEY, data TEXT)''')
    conn.commit()
    conn.close()


@app.route('/interfaces', methods=['GET'])
def get_interfaces():
    try:
        logger.debug("收到获取网络接口请求")
        interfaces = get_available_interfaces()
        logger.debug(f"可用网络接口: {interfaces}")
        
        if not interfaces:
            logger.warning("未找到可用的网络接口")
            return jsonify({
                'interfaces': [],
                'message': '未找到可用的网络接口'
            }), 200
            
        logger.info(f"成功获取到 {len(interfaces)} 个网络接口")
        return jsonify({
            'interfaces': interfaces,
            'count': len(interfaces)
        }), 200
    except Exception as e:
        logger.error(f"获取网络接口时发生错误: {str(e)}", exc_info=True)
        return jsonify({
            'error': str(e),
            'interfaces': []
        }), 500


@app.route('/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part in the request'}), 400
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        if file:
            # 检查文件扩展名
            if not file.filename.endswith(('.pcap', '.pcapng')):
                return jsonify({'error': 'Invalid file format. Only .pcap and .pcapng files are allowed'}), 400
                
            # 检查文件大小（限制为10MB）
            file.seek(0, os.SEEK_END)
            size = file.tell()
            file.seek(0)
            if size > 10 * 1024 * 1024:  # 10MB
                return jsonify({'error': 'File too large. Maximum size is 10MB'}), 400
                
            analyze_pcap(file)
            return jsonify({'message': 'success'}), 200
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500


@app.route('/results', methods=['GET'])
def get_result():
    try:
        conn = sqlite3.connect('network_data.db')
        c = conn.cursor()
        c.execute('SELECT * FROM packets')
        result = c.fetchall()
        conn.close()
        return jsonify({'result': result}), 200
    except Exception as e:
        logger.error(f"获取结果时发生错误: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/start_sniffing', methods=['POST', 'OPTIONS'])
def start_sniffing_route(): # 建议重命名以区分业务逻辑函数
    # Flask-CORS 应该会自动处理 OPTIONS 请求并返回。
    # 此视图函数主要处理 POST 请求的逻辑。
    if request.method == 'OPTIONS':
        # 如果 Flask-CORS 由于某种原因没有提前响应 OPTIONS 请求，
        # 并且请求到达了这里，确保我们返回一个简单的成功响应。
        # Flask-CORS 之后应该会为这个响应添加正确的 CORS 头部。
        return '', 204  # 204 No Content 是 OPTIONS 响应的常见状态码

    # --- 以下是 POST 请求的处理逻辑 ---
    if request.method == 'POST':
        try:
            # 检查 Content-Type 是否为 application/json
            if not request.is_json:
                logger.warning("POST /start_sniffing: Request is not JSON")
                return jsonify({"error": "Request must be JSON"}), 400
            
            data = request.get_json() # 安全地获取 JSON 数据
            # 进一步检查 data 是否为 None (例如，空的 JSON body '{}' 也会通过 is_json 但 get_json() 可能返回字典)
            if data is None: # 或者 if not data: 来处理空字典的情况，取决于您的需求
                logger.warning("POST /start_sniffing: Invalid or empty JSON data")
                return jsonify({"error": "Invalid or empty JSON data"}), 400

            logger.debug(f"收到开始抓包请求 (POST): {data}")
            interface = data.get('interface') # 从解析后的 data 中获取 interface
            logger.debug(f"选择的网络接口: {interface}")

            if not interface:
                logger.warning("POST /start_sniffing: Missing 'interface' parameter")
                return jsonify({"error": "Missing 'interface' parameter"}), 400
            
            # 重要: 请确保调用的是实际执行抓包业务逻辑的函数。
            # 如果您的业务逻辑函数也叫 start_sniffing，它应该从其他地方导入，
            # 或者有不同的名称，以避免与此路由处理函数发生递归调用。
            # 假设您的业务逻辑函数在 ids.py 中，并且叫这个名字。
            # from ids import start_sniffing as actual_sniffing_logic 
            # success, message = actual_sniffing_logic(interface)
            # 为了演示，我们假设业务逻辑函数是 current_module.actual_start_sniffing_business_logic
            success, message = actual_start_sniffing_logic(interface) # 请替换为您的实际业务逻辑函数调用
            
            logger.debug(f"抓包结果: success={success}, message={message}")
            
            if success:
                return jsonify({
                    'success': True,
                    'message': message
                }), 200
            else:
                is_permission_error = 'permission' in str(message).lower() or '权限' in str(message)
                status_code = 403 if is_permission_error else 400 # 或者其他适当的错误码
                return jsonify({
                    'success': False,
                    'message': message,
                    'requires_admin': is_permission_error
                }), status_code
        except Exception as e:
            logger.error(f"开始抓包时发生严重错误 (POST): {str(e)}", exc_info=True) # exc_info=True 会记录堆栈跟踪
            return jsonify({
                'success': False,
                'message': f"开始抓包失败: 服务端发生内部错误" # 对客户端隐藏具体错误细节
            }), 500
            
    # 如果方法不是 OPTIONS 或 POST (理论上不应发生，因为 methods=['POST', 'OPTIONS'])
    return jsonify({"error": "Method Not Allowed"}), 405

# 您需要定义或导入 actual_start_sniffing_business_logic 函数
# 例如，在您的 ids.py 中可能有类似这样的函数：
# def start_sniffing(interface_name):
#     # ... 实际的抓包逻辑 ...
#     return True, "Sniffing started successfully on " + interface_name
# 您需要确保在上面的路由处理函数中正确调用它。


@app.route('/stop_sniffing', methods=['POST'])
def stop_sniffing():
    try:
        logger.debug("收到停止抓包请求")
        success, message = actual_stop_sniffing_logic()
        logger.debug(f"停止抓包结果: success={success}, message={message}")
        
        if success:
            return jsonify({
                'success': True,
                'message': message
            }), 200
        else:
            return jsonify({
                'success': False,
                'message': message
            }), 400
    except Exception as e:
        logger.error(f"停止抓包时发生错误: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"停止抓包失败: {str(e)}"
        }), 500


@app.route('/sniffing_status', methods=['GET'])
def get_sniffing_status():
    try:
        status = actual_get_sniffing_status_logic()
        return jsonify({
            'status': 'running' if status else 'stopped'
        }), 200
    except Exception as e:
        logger.error(f"获取抓包状态时发生错误: {str(e)}")
        return jsonify({
            'error': str(e)
        }), 500


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

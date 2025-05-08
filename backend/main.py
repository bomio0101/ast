from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
from ids import *

app = Flask(__name__)
CORS(app)  # 添加这一行

def init_db():
    conn = sqlite3.connect('network_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS packets
                (id INTEGER PRIMARY KEY, data TEXT)''')
    conn.commit()
    conn.close()


# @app.route('/')
# def home():
#     return jsonify({'message': 'API is running'}), 200


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        analyze_pcap(file)
        return jsonify({'message': 'success'}), 200


@app.route('/results', methods=['GET'])
def get_result():
    conn = sqlite3.connect('network_data.db')
    c = conn.cursor()
    c.execute(f'''SELECT * FROM packets''')
    result = c.fetchall()
    conn.close()
    return jsonify({'result': result}), 200


if __name__ == '__main__':
    init_db()
    app.run(debug=True)  # 修正缩进

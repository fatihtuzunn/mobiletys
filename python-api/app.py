# python-api/app.py

from flask import Flask, request, jsonify
from analyzer.analyze import analyze_file
import os
import pathlib
app = Flask(__name__)


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json(force=True, silent=True)
    if not data:
        print(data)
        return jsonify({"error": "JSON body eksik veya geçersiz."}), 400
    
    file_path = data.get("apk_path")
    print(f"APK path: {file_path}")

    if not file_path:
        return jsonify({"error": "apk_path alanı eksik."}), 400

    file_path = str(pathlib.Path(file_path))

    if not os.path.exists(file_path):
        return jsonify({"error": f"APK path geçersiz: {file_path}"}), 400

    try:
        result = analyze_file(file_path)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)

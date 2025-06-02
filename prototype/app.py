from flask import Flask, request, jsonify, send_from_directory, make_response
import os

app = Flask(__name__, static_folder='static')

@app.after_request
def add_header(response):
    # Disable caching for development
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/')
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico')

@app.route('/api/data', methods=['POST'])
def receive_data():
    data = request.get_json()
    location = data.get('location', {})
    print(f"Received location: {location}")
    return jsonify({
        'status': 'success',
        'message': 'Location received',
        'your_location': location
    })

if __name__ == '__main__':
    app.run(debug=True)

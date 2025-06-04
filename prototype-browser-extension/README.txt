# Geolocation System Setup

This system includes:
- A Firefox browser extension that collects geolocation (latitude/longitude)
  data
- A Python Flask server that converts the geolocation (latitude/longitude)
  data to geographic region data (city/state/country)

## 1. Firefox Browser Extension

### Files:
- manifest.json
- background.js
- popup.html
- popup.js

### Setup:
1. Open Firefox and go to: about:debugging#/runtime/this-firefox
2. Click *“Load Temporary Add-on”*
3. Select the manifest.json file from your extension folder
4. Click the extension icon and enter the domains you want to target (e.g.,
localhost)

## 2. Python Flask server

### Files:
- server.py

### Setup:
python server.py

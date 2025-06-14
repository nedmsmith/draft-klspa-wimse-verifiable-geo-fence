#!/usr/bin/env python3
# This script provides a comprehensive test of the tethered phone verification
# functionality in win-app.py by simulating native messaging requests

import subprocess
import json
import os
import sys
import time
import traceback
import struct
import base64

print("=== Tethered Phone Verification Test Suite ===")
print(f"Date/Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")

# Get the current directory of the script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(os.environ.get("LOCALAPPDATA", os.getcwd()), "test_verification.log")

def log_message(message):
    """Log a message to both console and log file"""
    print(message)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} - {message}\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

def check_environment():
    """Check that all required files and configurations exist"""
    log_message("Checking environment...")
    
    # Check for win-app.py existence
    win_app_py = os.path.join(SCRIPT_DIR, "win-app.py")
    if not os.path.exists(win_app_py):
        log_message(f"ERROR: win-app.py not found at {win_app_py}")
        return False
    log_message(f"win-app.py found at {win_app_py}")
    
    # Check for tethered_phone_info.json
    phone_info_path = os.path.join(SCRIPT_DIR, "tethered_phone_info.json")
    if not os.path.exists(phone_info_path):
        log_message(f"ERROR: tethered_phone_info.json not found at {phone_info_path}")
        return False
    
    try:
        with open(phone_info_path, "r") as f:
            phone_info = json.load(f)
        
        if "name" not in phone_info or "mac_address" not in phone_info:
            log_message("ERROR: tethered_phone_info.json is missing required fields (name or mac_address)")
            return False
            
        log_message(f"Phone info found: Name={phone_info['name']}, MAC={phone_info['mac_address']}")
    except Exception as e:
        log_message(f"ERROR: Failed to read tethered_phone_info.json: {e}")
        return False
    
    # Check Python installation
    python_path = sys.executable
    log_message(f"Using Python from: {python_path}")
    
    return True

def send_native_message(process, message):
    """Send a message formatted for native messaging to the process"""
    try:
        # Convert message to JSON and add the length prefix (4 bytes)
        message_json = json.dumps(message).encode('utf-8')
        message_length = len(message_json).to_bytes(4, byteorder='little')
        
        log_message(f"Sending message: {json.dumps(message, indent=2)}")
        log_message(f"Message length: {len(message_json)} bytes")
        
        # Send the message
        process.stdin.write(message_length)
        process.stdin.write(message_json)
        process.stdin.flush()
        log_message("Message sent successfully")
        return True
    except Exception as e:
        log_message(f"Error sending message: {e}")
        traceback.print_exc()
        return False

def read_native_response(process, timeout=10):
    """Read a response formatted for native messaging from the process with timeout"""
    log_message(f"Reading response (timeout: {timeout}s)...")
    
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            # Check if we can read anything
            if process.poll() is not None:
                log_message(f"Process exited with code {process.returncode}")
                return None
                
            # Read response length (4 bytes)
            response_length_bytes = process.stdout.read(4)
            if not response_length_bytes:
                time.sleep(0.1)
                continue
                
            if len(response_length_bytes) != 4:
                log_message(f"Error: Incomplete response length, got {len(response_length_bytes)} bytes")
                return None
            
            response_length = int.from_bytes(response_length_bytes, byteorder='little')
            log_message(f"Response length: {response_length} bytes")
            
            # Read response
            response_json = process.stdout.read(response_length)
            
            # Parse and return the response
            return json.loads(response_json)
        except Exception as e:
            log_message(f"Error reading response: {e}")
            traceback.print_exc()
            return None
    
    log_message(f"Timeout after {timeout} seconds waiting for response")
    return None

def test_phone_verification():
    """Test the tethered phone verification functionality"""
    log_message(f"Starting phone verification test...")
    
    # Create the test message
    test_message = {
        "command": "check_tethered_phone"
    }
    
    # Run the win-app.py script
    cmd = [
        sys.executable,
        os.path.join(SCRIPT_DIR, "win-app.py")
    ]
    
    log_message(f"Launching process: {' '.join(cmd)}")
    
    try:
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            bufsize=0
        )
    except Exception as e:
        log_message(f"Error launching process: {e}")
        traceback.print_exc()
        return False
        
    try:
        # Send the verification request
        if not send_native_message(process, test_message):
            return False
        
        # Read the response
        response = read_native_response(process, timeout=15)
        
        if response:
            log_message("\nResponse from win-app.py:")
            log_message(json.dumps(response, indent=2))
            
            if "verified" in response:
                if response["verified"]:
                    log_message("\nSUCCESS: Phone verification passed!")
                    if "phone_name" in response:
                        log_message(f"Phone name: {response['phone_name']}")
                    if "phone_mac" in response:
                        log_message(f"Phone MAC: {response['phone_mac']}")
                    return True
                else:
                    log_message("\nFAILURE: Phone verification failed.")
                    if "message" in response:
                        log_message(f"Reason: {response['message']}")
                    if "error" in response:
                        log_message(f"Error: {response['error']}")
                    return False
            else:
                log_message("\nERROR: Invalid response format, missing 'verified' field")
                return False
        else:
            log_message("No valid response received")
            return False
            
    except Exception as e:
        log_message(f"Unexpected error: {e}")
        traceback.print_exc()
        return False
    finally:
        # Get stderr for additional debugging information
        stderr_output = process.stderr.read()
        if stderr_output:
            log_message("\nStderr output:")
            log_message(stderr_output.decode('utf-8', errors='replace'))
        
        # Terminate the process
        try:
            process.terminate()
            log_message("Process terminated.")
        except Exception as e:
            log_message(f"Error terminating process: {e}")

def check_native_messaging_registry():
    """Check if the native messaging host is properly registered in the Windows registry"""
    log_message("Checking native messaging registry settings...")
    
    try:
        import winreg
        
        # Check Mozilla registry path
        registry_path = r"Software\Mozilla\NativeMessagingHosts\com.mycompany.geosign"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path) as key:
                value, _ = winreg.QueryValueEx(key, "")
                log_message(f"Mozilla registry value: {value}")
                
                # Check if the path exists
                if not os.path.exists(value):
                    log_message(f"ERROR: Manifest file at {value} does not exist")
                    return False
                    
                # Check if the path points to the expected file
                expected_path = os.path.join(SCRIPT_DIR, "com.mycompany.geosign.json")
                if value.lower() != expected_path.lower():
                    log_message(f"WARNING: Registry points to {value} but expected {expected_path}")
        except FileNotFoundError:
            log_message("ERROR: Mozilla registry key not found")
            return False
        except Exception as e:
            log_message(f"Error checking Mozilla registry key: {e}")
            return False
            
        return True
    except ImportError:
        log_message("winreg module not available - skipping registry check")
        return True
    except Exception as e:
        log_message(f"Error checking registry: {e}")
        return False

def main():
    """Main test function"""
    log_message("=== Starting Tethered Phone Verification Tests ===")
    
    # Check environment first
    if not check_environment():
        log_message("Environment check failed - aborting tests")
        return
    
    # Check registry
    check_native_messaging_registry()
    
    # Run the phone verification test
    log_message("\n=== Phone Verification Test ===")
    phone_result = test_phone_verification()
    
    if phone_result:
        log_message("\nAll tests passed! The native messaging connection and phone verification appear to be working correctly.")
    else:
        log_message("\nSome tests failed. Please review the log for details on what went wrong.")
    
    log_message("=== End of Tests ===")

if __name__ == "__main__":
    main()

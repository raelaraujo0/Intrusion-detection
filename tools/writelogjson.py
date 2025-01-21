import json
import os

def save_Json_Log(log_data, filename="scanlog.json"):
    json_dir = "../json"
    os.makedirs(json_dir, exist_ok=True)
    
    filepath = os.path.join(json_dir, filename)
    
    with open(filepath, "a") as json_file:
        json_file.write(json.dumps(log_data, indent=4))
        json_file.write(",\n")
import cv2
from ultralytics import YOLO
import requests
import json

def run_inventory_scan(image_path):
    # 1. Load your custom weights
    model = YOLO('ai_model/best.pt')

    # 2. Run Inference
    results = model.predict(source=image_path, conf=0.25)

    for result in results:
        detections = []
        for box in result.boxes:
            det = {
                "class": result.names[int(box.cls[0])],
                "confidence": round(float(box.conf[0]), 2),
                "bbox": [round(float(x), 1) for x in box.xyxy[0].tolist()]
            }
            detections.append(det)

        # 3. Create the Payload
        payload = {
            "total_items": len(detections),
            "items": detections
        }

        # 4. Push to the PHP Bridge (The Ingress)
        url = "http://localhost/smart_inventory/api/upload_scan.php"
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(url, data=json.dumps(payload), headers=headers)
            print(f"Server Response: {response.text}")
        except Exception as e:
            print(f"Connection Failed: {e}")

if __name__ == "__main__":
    # Test with your grocery image
    run_inventory_scan('ai_model\image.png')
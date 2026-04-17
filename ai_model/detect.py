import json
import cv2
from ultralytics import YOLO

def run_detection():
    # 1. Load the pre-trained YOLOv8 model
    # 'yolov8n.pt' is the lightweight version, perfect for real-time testing
    model = YOLO('yolov8n.pt') 

    # 2. Initialize the Camera (External Ingress)
    cap = cv2.VideoCapture(0)

    if not cap.isOpened():
        print("Error: Could not open camera.")
        return

    print("AI Ingress Active. Press 'q' to capture item and generate JSON...")

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        # Show the camera feed to the user
        cv2.imshow('AI Inventory Scanner', frame)

        # Wait for the user to press 'q' to "Scan" the item
        if cv2.waitKey(1) & 0xFF == ord('q'):
            # Perform inference on the captured frame
            results = model(frame)

            for result in results:
                # Check if any objects were detected
                if len(result.boxes) > 0:
                    # Get the top detected item's label
                    class_id = int(result.boxes.cls[0].item())
                    detected_name = result.names[class_id]
                    confidence = round(float(result.boxes.conf[0].item()), 2)

                    # 3. Create the 'Unique Specifications' Payload
                    # This matches the JSON structure required by your database layer
                    specs = {
                        "item_type": detected_name,
                        "confidence": confidence,
                        "scanner_id": "Station_01",
                        "status": "detected"
                    }

                    # 4. JSON Serialization (The Payload)
                    # This string is what Python will eventually send to PHP
                    json_payload = json.dumps(specs)
                    
                    print("\n--- AI PAYLOAD GENERATED ---")
                    print(json_payload)
                    print("----------------------------\n")
                else:
                    print("No object detected. Try again.")
            
            break

    # Cleanup
    cap.release()
    cv2.destroyAllWindows()

if __name__ == "__main__":
    run_detection()
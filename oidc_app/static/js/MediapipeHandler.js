// Import ESM directly from the CDN (avoids the "export" error in vision_bundle.js)
import { FaceDetector, FilesetResolver } from "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.0";

export class MediapipeHandler {
  constructor() {
    this.faceDetector = null;
  }

  async initialize() {
    if (this.faceDetector) return;
    const vision = await FilesetResolver.forVisionTasks(
      "https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.0/wasm"
    );
    this.faceDetector = await FaceDetector.createFromOptions(vision, {
      baseOptions: {
        modelAssetPath:
          "https://storage.googleapis.com/mediapipe-models/face_detector/blaze_face_short_range/float16/1/blaze_face_short_range.tflite",
        delegate: "GPU"
      },
      runningMode: "IMAGE",
      minDetectionConfidence: 0.5
    });
  }

  detect(imageCanvasOrImageData) {
    if (!this.faceDetector) throw new Error("FaceDetector no inicializado");
    return this.faceDetector.detect(imageCanvasOrImageData);
  }
}

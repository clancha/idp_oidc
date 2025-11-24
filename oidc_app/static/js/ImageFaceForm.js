import { cropTo160FromCanvas, dataUrlFromCanvas, canvasToBGR8Base64 } from "./FaceUtils.js";

export class ImageFaceForm {
  constructor(mediapipeHandler){
    this.mp = mediapipeHandler;

    // UI
    this.video       = document.getElementById("video");
    this.canvas      = document.getElementById("canvas");
    this.btnStart    = document.getElementById("btn-start");
    this.btnCapture  = document.getElementById("btn-capture");
    this.btnRetake   = document.getElementById("btn-retake");
    this.preview     = document.getElementById("preview");
    this.previewImg  = document.getElementById("preview-img");
    this.faceB64     = document.getElementById("face_b64");
    this.faceMime    = document.getElementById("face_mime");
    this.camError    = document.getElementById("cam-error");
    this.form        = document.getElementById("formulario");
    this.padRatio    = parseFloat(this.form?.dataset?.facePadding ?? "0");

    // Containers used to toggle the .captured state
    this.captureBox  = document.querySelector(".capture-box");
    this.videoBox    = document.getElementById("video-box");

    this.stream = null;
    this.captured = false;

    this.bind();
  }

  bind(){
    this.btnStart?.addEventListener("click", () => this.startCamera());
    this.btnCapture?.addEventListener("click", () => this.captureFromVideo());
    this.btnRetake?.addEventListener("click", () => this.retake());
    this.faceFile?.addEventListener("change", (ev) => this.processFile(ev));
  }

  showError(msg){
    if (!this.camError) return;
    this.camError.textContent = msg;
    this.camError.style.display = "block";
  }
  clearError(){
    if (!this.camError) return;
    this.camError.textContent = "";
    this.camError.style.display = "none";
  }

  async startCamera(){
    this.clearError();
    try{
      if (!this.mp.faceDetector) await this.mp.initialize();

      this.stream = await navigator.mediaDevices.getUserMedia({
        video:{ width:{ideal:1280}, height:{ideal:720}, aspectRatio:16/9 },
        audio:false
      });

      this.video.srcObject = this.stream;

      // Show video, hide preview
      this.video.style.display = "block";
      this.canvas.style.display = "none";
      if (this.preview) this.preview.style.display = "none";

      // Remove "captured" mode from the container
      this.captureBox?.classList.remove("captured");

      this.btnCapture && (this.btnCapture.disabled = false);
      this.btnRetake && (this.btnRetake.style.display = "none");
      this.captured = false;
    }catch(e){
      this.showError(`Could not access the camera: ${e.message}`);
    }
  }

  stopCamera(){
    if (this.stream){
      this.stream.getTracks().forEach(t => t.stop());
      this.stream = null;
    }
  }

  async captureFromVideo(){
    try{
      // Ensure the video already has dimensions
      if (!this.video.videoWidth || !this.video.videoHeight){
        await new Promise(res => { this.video.onloadedmetadata = () => res(); });
      }

      const w = this.video.videoWidth, h = this.video.videoHeight;
      this.canvas.width = w;
      this.canvas.height = h;
      this.canvas.getContext("2d").drawImage(this.video, 0, 0, w, h);

      // Detect face and fill preview + hidden inputs
      await this.detectCropAndSet(this.canvas);

      // Stop camera
      this.stopCamera();

      // Hide video/canvas and show preview
      this.video.style.display = "none";
      this.canvas.style.display = "none";
      if (this.preview) this.preview.style.display = "block";

      // Captured mode hides the black frame via CSS
      this.captureBox?.classList.add("captured");

      if (this.btnRetake) this.btnRetake.style.display = "inline-block";
      this.captured = true;
    }catch(e){
      this.showError(e.message || "Error al capturar.");
    }
  }

  async processFile(ev){
    const file = ev.target.files?.[0];
    if (!file) return;
    this.clearError();
    try{
      await this.processSelectedFileAndDetect(file);
      this.stopCamera();

      this.video.style.display = "none";
      this.canvas.style.display = "none";
      if (this.preview) this.preview.style.display = "block";

      // If a file is uploaded, we also want captured mode
      this.captureBox?.classList.add("captured");

      if (this.btnRetake) this.btnRetake.style.display = "inline-block";
      this.captured = true;
    }catch(e){
      this.showError(`Could not process the image: ${e.message}`);
    }
  }

  async prepareFaceIfNeeded(){
    // In case the form is submitted without calling captureFromVideo
    if (this.faceB64.value) return;

    // If the camera is active, capture from it
    if (this.stream){
      if (!this.video.videoWidth || !this.video.videoHeight){
        await new Promise(res => { this.video.onloadedmetadata = () => res(); });
      }
      const w = this.video.videoWidth, h = this.video.videoHeight;
      this.canvas.width = w; this.canvas.height = h;
      this.canvas.getContext("2d").drawImage(this.video, 0, 0, w, h);
      await this.detectCropAndSet(this.canvas);
      return;
    }

    // If there is an uploaded file (only if the input exists)
    const f = this.faceFile?.files?.[0];
    if (f){ await this.processSelectedFileAndDetect(f); return; }

    throw new Error("Missing face. Capture with camera.");
  }

  async processSelectedFileAndDetect(file){
    if (!this.mp.faceDetector) await this.mp.initialize();

    const dataUrl = await new Promise((res, rej) => {
      const r = new FileReader();
      r.onload = () => res(r.result);
      r.onerror = rej;
      r.readAsDataURL(file);
    });

    const im = await new Promise((res, rej) => {
      const img = new Image();
      img.onload = () => res(img);
      img.onerror = rej;
      img.src = dataUrl;
    });

    this.canvas.width  = im.naturalWidth || im.width;
    this.canvas.height = im.naturalHeight || im.height;
    this.canvas.getContext("2d").drawImage(im, 0, 0);

    await this.detectCropAndSet(this.canvas, file.type);
  }

  async detectCropAndSet(srcCanvas, mimeFallback = "image/jpeg"){
    const result = await this.mp.detect(srcCanvas);
    const dets = result?.detections || [];
  
    if (dets.length !== 1) {
      throw new Error(`Detected ${dets.length} faces. Exactly one is required.`);
    }

    const det = dets[0];
    const score = det?.categories?.[0]?.score ?? 0;
    if (score < 0.5) {
      throw new Error(`Insufficient confidence (${(score*100).toFixed(1)}%). Try again with better lighting/framing.`);
    }
  
    const mime = this.faceMime?.value || mimeFallback || "image/jpeg";
  
    /* 1) Show the full image from the camera in the same box as the video */
    const fullDataUrl = srcCanvas.toDataURL(mime, 0.92);
    this.previewImg.src = fullDataUrl;   // 👈 esto es lo que ves en pantalla
  
    /* 2) RECORTAR a 160x160 para enviar */
    const faceCanvas = cropTo160FromCanvas(srcCanvas, det.boundingBox, this.padRatio);
    const faceDataUrl = dataUrlFromCanvas(faceCanvas, mime, 0.92);
  
    // Store the cropped face in the hidden input sent with the form
    this.faceB64.value = faceDataUrl;
  
    // Raw BGR8 from the crop (same as before)
    const bgr8_b64 = canvasToBGR8Base64(faceCanvas);
    document.getElementById("face_raw_bgr8").value = bgr8_b64;
    document.getElementById("face_raw_meta").value = JSON.stringify({
      w: 160, h: 160, c: 3, order: "BGR", dtype: "uint8", endian: "le"
    });
  }



  retake(){
    // Clear captured data
    this.faceB64.value = "";
    if (this.preview) this.preview.style.display = "none";
    this.captureBox?.classList.remove("captured");
    this.captured = false;

    // Restart the camera
    this.startCamera();
  }
}

import { cropTo160FromCanvas, dataUrlFromCanvas, canvasToBGR8Base64 } from "./FaceUtils.js";

export class ImageFaceForm {
  constructor(mediapipeHandler){
    this.mp = mediapipeHandler;

    // UI
    this.video      = document.getElementById("video");
    this.canvas     = document.getElementById("canvas");
    this.btnStart   = document.getElementById("btn-start");
    this.btnCapture = document.getElementById("btn-capture");
    this.btnRetake  = document.getElementById("btn-retake");
    this.preview    = document.getElementById("preview");
    this.previewImg = document.getElementById("preview-img");
    this.faceB64    = document.getElementById("face_b64");
    this.faceMime   = document.getElementById("face_mime");
    this.faceFile   = document.getElementById("face_file");
    this.camError   = document.getElementById("cam-error");
    this.form       = document.getElementById("formulario");
    this.padRatio   = parseFloat(this.form?.dataset?.facePadding ?? "0"); // Padding form de image

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

  showError(msg){ this.camError.textContent = msg; this.camError.style.display = "block"; }
  clearError(){ this.camError.textContent = ""; this.camError.style.display = "none"; }

  async startCamera(){
    this.clearError();
    try{
      if (!this.mp.faceDetector) await this.mp.initialize();
      this.stream = await navigator.mediaDevices.getUserMedia({
        video:{ width:{ideal:1280}, height:{ideal:720}, aspectRatio:16/9 }, audio:false
      });
      this.video.srcObject = this.stream;
      this.video.style.display = "block";
      this.canvas.style.display = "none";
      this.preview.style.display= "none";
      this.btnCapture.disabled  = false;
      this.btnRetake.style.display = "none";
      this.captured = false;
    }catch(e){
      this.showError(`No se pudo acceder a la cámara: ${e.message}`);
    }
  }

  stopCamera(){
    if (this.stream){ this.stream.getTracks().forEach(t => t.stop()); this.stream = null; }
  }

  async captureFromVideo(){
    try{
      if (!this.video.videoWidth || !this.video.videoHeight){
        await new Promise(res => { this.video.onloadedmetadata = () => res(); });
      }
      const w = this.video.videoWidth, h = this.video.videoHeight;
      this.canvas.width = w; this.canvas.height = h;
      this.canvas.getContext("2d").drawImage(this.video, 0, 0, w, h);

      await this.detectCropAndSet(this.canvas);

      this.stopCamera();
      this.video.style.display = "none";
      this.canvas.style.display = "none";
      this.preview.style.display = "block";
      this.btnRetake.style.display = "inline-block";
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
      this.preview.style.display = "block";
      this.btnRetake.style.display = "inline-block";
      this.captured = true;
    }catch(e){
      this.showError(`No se pudo procesar la imagen: ${e.message}`);
    }
  }

  async prepareFaceIfNeeded(){
    if (this.faceB64.value) return;
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
    const f = this.faceFile?.files?.[0];
    if (f){ await this.processSelectedFileAndDetect(f); return; }
    throw new Error("Falta rostro. Captura con cámara o sube una imagen.");
  }

  async processSelectedFileAndDetect(file){
    if (!this.mp.faceDetector) await this.mp.initialize();

    const dataUrl = await new Promise((res, rej) => {
      const r = new FileReader(); r.onload = () => res(r.result); r.onerror = rej; r.readAsDataURL(file);
    });

    const im = await new Promise((res, rej) => {
      const img = new Image(); img.onload = () => res(img); img.onerror = rej; img.src = dataUrl;
    });

    this.canvas.width  = im.naturalWidth || im.width;
    this.canvas.height = im.naturalHeight || im.height;
    this.canvas.getContext("2d").drawImage(im, 0, 0);

    await this.detectCropAndSet(this.canvas, file.type);
  }

  async detectCropAndSet(srcCanvas, mimeFallback = "image/jpeg"){
    const result = await this.mp.detect(srcCanvas);
    const dets = result?.detections || [];

    if (dets.length !== 1) { throw new Error(`Se detectaron ${dets.length} rostros. Debe haber exactamente 1.`); }
    const det = dets[0];
    const score = det?.categories?.[0]?.score ?? 0;
    if (score < 0.5) { throw new Error(`Confianza insuficiente (${(score*100).toFixed(1)}%). Reintenta con mejor luz/encuadre.`); }

    const faceCanvas = cropTo160FromCanvas(srcCanvas, det.boundingBox, this.padRatio);

    const mime = this.faceMime.value || mimeFallback || "image/jpeg";
    const dataUrl = dataUrlFromCanvas(faceCanvas, mime, 0.92);
    this.faceB64.value = dataUrl;
    this.previewImg.src = dataUrl;
    
    const bgr8_b64 = canvasToBGR8Base64(faceCanvas);
    document.getElementById("face_raw_bgr8").value = bgr8_b64;
    document.getElementById("face_raw_meta").value = JSON.stringify({
      w: 160, h: 160, c: 3, order: "BGR", dtype: "uint8", endian: "le"
    });

    this.faceB64.value = dataUrl;
    this.previewImg.src = dataUrl;
  }

  retake(){
    this.faceB64.value = "";
    this.preview.style.display = "none";
    this.captured = false;
    this.startCamera();
  }
}

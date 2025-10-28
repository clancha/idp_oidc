export function toPixelBox(bbox, W, H) {
  let { originX, originY, width, height } = bbox;
  if (width <= 1 && height <= 1) {
    originX *= W; originY *= H; width *= W; height *= H;
  }
  const x = Math.max(0, Math.floor(originX));
  const y = Math.max(0, Math.floor(originY));
  const w = Math.max(1, Math.min(W - x, Math.floor(width)));
  const h = Math.max(1, Math.min(H - y, Math.floor(height)));
  return { x, y, w, h };
}

export function cropTo160FromCanvas(srcCanvas, bbox, paddingRatio = 0) {
  const W = srcCanvas.width, H = srcCanvas.height;
  const { x, y, w, h } = toPixelBox(bbox, W, H);

  const size = Math.max(w, h);
  const pad = Math.round(size * paddingRatio);
  const cx = x + Math.floor(w / 2);
  const cy = y + Math.floor(h / 2);

  let sx = Math.max(0, cx - Math.floor(size / 2) - pad);
  let sy = Math.max(0, cy - Math.floor(size / 2) - pad);
  let sw = Math.min(W - sx, size + 2 * pad);
  let sh = Math.min(H - sy, size + 2 * pad);

  const out = document.createElement("canvas");
  out.width = 160; out.height = 160;
  out.getContext("2d").drawImage(srcCanvas, sx, sy, sw, sh, 0, 0, 160, 160);
  return out;
}
// --- Para convertir ArrayBuffer -> base64 ---
export function arrayBufferToBase64(buf){
  let bin = "";
  const bytes = new Uint8Array(buf);
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

// --- Genera BGR8 base64 desde un canvas 160x160 ---
export function canvasToBGR8Base64(canvas){
  const ctx = canvas.getContext("2d");
  const { data } = ctx.getImageData(0, 0, 160, 160); // RGBA
  const out = new Uint8Array(160 * 160 * 3);         // BGR
  for (let i = 0, j = 0; i < data.length; i += 4) {
    out[j++] = (data[i + 2] / 127.5) -1; // B
    out[j++] = (data[i + 1] / 127.5) -1; // G
    out[j++] = (data[i + 0] / 127.5) -1; // R
  }
  return arrayBufferToBase64(out.buffer);
}

export function canvasToBGR8Bytes(canvas){
  const ctx = canvas.getContext("2d");
  const { data } = ctx.getImageData(0, 0, 160, 160); // RGBA
  const out = new Uint8Array(160*160*3);
  for (let i=0,j=0;i<data.length;i+=4){
    out[j++] = data[i+2]; // B
    out[j++] = data[i+1]; // G
    out[j++] = data[i+0]; // R
  }
  return out;
}


export function dataUrlFromCanvas(canvas, mime = "image/jpeg", quality = 0.92) {
  return canvas.toDataURL(mime, quality);
}

// /static/js/main.js
import { MediapipeHandler } from "./MediapipeHandler.js";
import { ImageFaceForm } from "./ImageFaceForm.js";
import { FormHandler } from "./FormHandler.js";

document.addEventListener("DOMContentLoaded", async () => {
  const mp = new MediapipeHandler();
  const imgForm = new ImageFaceForm(mp);

  new FormHandler(imgForm, {
    jwksUrl: "/.well-known/jwks.json", 
    formId: "formulario",
    errorId: "form-error"
  });
});

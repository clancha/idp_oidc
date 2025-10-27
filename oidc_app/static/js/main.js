// /static/js/main.js
import { MediapipeHandler } from "./MediapipeHandler.js";
import { ImageFaceForm } from "./ImageFaceForm.js";
import { FormHandler } from "./FormHandler.js";

document.addEventListener("DOMContentLoaded", async () => {
  const mp = new MediapipeHandler();
  const imgForm = new ImageFaceForm(mp);

  // Instancia el manejador del formulario (añade el listener de submit y cifra)
  new FormHandler(imgForm, {
    jwksUrl: "/.well-known/jwks.json", 
    formId: "formulario",
    errorId: "form-error"
  });
});

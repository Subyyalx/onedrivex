
document.addEventListener('DOMContentLoaded', function () {
  const uploadForm = document.getElementById('uploadFilesForm');
  const uploadProgress = document.getElementById('uploadProgress');

  if (uploadForm && uploadProgress) {
    uploadForm.addEventListener('submit', function (e) {
      e.preventDefault();

      const formData = new FormData(uploadForm);
      const xhr = new XMLHttpRequest();
      xhr.open('POST', uploadForm.action);

      xhr.upload.addEventListener('progress', function (e) {
        if (e.lengthComputable) {
          const percent = Math.round((e.loaded / e.total) * 100);
          uploadProgress.style.width = percent + '%';
          uploadProgress.textContent = percent + '%';
        }
      });

      xhr.onload = function () {
        if (xhr.status === 200 || xhr.status === 204) {
          uploadProgress.classList.add('bg-success');
          uploadProgress.textContent = 'Upload Complete!';
          setTimeout(() => window.location.reload(), 1000);
        } else {
          alert('Upload failed.');
        }
      };

      xhr.send(formData);
    });
  }
});


$(document).ready(function() {
  $('#createForm').validate({
    rules: {
      name: {
        required: true
      },
      return_url: {
        required: true,
        url: true
      }
    }
  });
});

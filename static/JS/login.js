// script.js
(function($) {
    'use strict';

    // Prevent form submission if validation fails
    window.addEventListener('load', function() {
        // Fetch form and apply custom Bootstrap validation
        const form = document.querySelector('.my-login-validation');
        
        form.addEventListener('submit', function(event) {
            if (form.checkValidity() === false) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    }, false);

    // Password toggle (show/hide)
    $(document).ready(function(){
        $("[data-eye]").each(function() {
            const input = $(this);
            const eye = $('<div class="input-group-append">'+
                            '<span class="input-group-text">'+
                                '<i class="fa fa-eye" style="cursor: pointer"></i>'+
                            '</span>'+
                        '</div>').insertAfter(input.parent());
            
            const eyeIcon = eye.find('i');
            
            eye.on('click', function() {
                if(input.attr('type') === 'password') {
                    input.attr('type', 'text');
                    eyeIcon.addClass('fa-eye-slash').removeClass('fa-eye');
                } else {
                    input.attr('type', 'password');
                    eyeIcon.addClass('fa-eye').removeClass('fa-eye-slash');
                }
            });
        });
    });

})(jQuery);
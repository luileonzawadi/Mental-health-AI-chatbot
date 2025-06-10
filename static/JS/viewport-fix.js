// Viewport height fix for mobile browsers
function setViewportHeight() {
  // First we get the viewport height and multiply it by 1% to get a value for a vh unit
  let vh = window.innerHeight * 0.01;
  // Then we set the value in the --vh custom property to the root of the document
  document.documentElement.style.setProperty('--vh', `${vh}px`);
}

// Set the height initially
setViewportHeight();

// Update the height whenever the window resizes or orientation changes
window.addEventListener('resize', setViewportHeight);
window.addEventListener('orientationchange', setViewportHeight);

// Fix for iOS Safari address bar appearing/disappearing
window.addEventListener('scroll', function() {
  // Slight delay to ensure the browser has finished any UI adjustments
  setTimeout(setViewportHeight, 100);
});

// Fix for input fields and virtual keyboard on mobile
document.addEventListener('DOMContentLoaded', function() {
  // Find all input fields
  const inputFields = document.querySelectorAll('input, textarea');
  
  // Add focus and blur event listeners
  inputFields.forEach(input => {
    input.addEventListener('focus', function() {
      // Small delay to let the keyboard appear
      setTimeout(function() {
        // Scroll the input into view
        input.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }, 300);
    });
    
    input.addEventListener('blur', function() {
      // Reset viewport when input loses focus
      setTimeout(setViewportHeight, 100);
    });
  });
});
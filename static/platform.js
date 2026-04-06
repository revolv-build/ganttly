// Platform enhancements: back to top
(function() {
  'use strict';

  // ── Back to Top ────────────────────────────────────────────────
  var btn = document.createElement('button');
  btn.className = 'back-to-top';
  btn.innerHTML = '&#9650;';
  btn.title = 'Back to top';
  btn.onclick = function() { window.scrollTo({top: 0, behavior: 'smooth'}); };
  document.body.appendChild(btn);

  window.addEventListener('scroll', function() {
    btn.classList.toggle('btt-show', window.scrollY > 400);
  });
})();

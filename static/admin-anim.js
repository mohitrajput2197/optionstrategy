// Anay Investments — Admin panel: count-up numbers + 3D tilt cards
document.addEventListener('DOMContentLoaded', function () {
  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // Animated count-up for stat card numbers
  document.querySelectorAll('[data-count]').forEach(function (el) {
    var target = parseInt(el.getAttribute('data-count'), 10) || 0;
    if (reduceMotion || target <= 0) {
      el.textContent = target.toLocaleString('en-IN');
      return;
    }
    var dur = 1000, start = null;
    function step(ts) {
      if (!start) start = ts;
      var p = Math.min((ts - start) / dur, 1);
      var eased = 1 - Math.pow(1 - p, 3);
      el.textContent = Math.round(target * eased).toLocaleString('en-IN');
      if (p < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  });

  // 3D tilt on stat cards (mouse only)
  if (reduceMotion) return;
  document.querySelectorAll('.ai-card').forEach(function (card) {
    // Entrance animation must release the transform so tilt can take over
    card.addEventListener('animationend', function () {
      card.style.animation = 'none';
      card.style.opacity = '1';
    });
    card.addEventListener('mousemove', function (e) {
      var r = card.getBoundingClientRect();
      var x = (e.clientX - r.left) / r.width - 0.5;
      var y = (e.clientY - r.top) / r.height - 0.5;
      card.style.transform =
        'perspective(750px) rotateY(' + (x * 11).toFixed(2) + 'deg)' +
        ' rotateX(' + (-y * 11).toFixed(2) + 'deg) translateY(-3px)';
    });
    card.addEventListener('mouseleave', function () {
      card.style.transform = '';
    });
  });
});

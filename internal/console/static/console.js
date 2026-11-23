// Copy buttons: <button class="copy" data-copy="text">. They're hidden
// without JavaScript (console.css), and found by delegation, so buttons
// htmx swaps in work too.
document.documentElement.classList.add("js");
document.addEventListener("click", function (e) {
  var b = e.target.closest("button.copy[data-copy]");
  if (!b || !navigator.clipboard) return;
  navigator.clipboard.writeText(b.dataset.copy).then(function () {
    var label = b.textContent;
    b.textContent = "Copied";
    setTimeout(function () { b.textContent = label; }, 1500);
  });
});

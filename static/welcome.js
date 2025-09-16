const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%^&*()";
const text1 = "Vulnerability Scanner";

function hackerTypeEffect(element, finalText, callback) {
  let iteration = 0;
  const interval = setInterval(() => {
    element.textContent = finalText
      .split("")
      .map((char, i) => {
        if (i < iteration) return finalText[i];
        return letters[Math.floor(Math.random() * letters.length)];
      })
      .join("");
    if (iteration >= finalText.length) {
      clearInterval(interval);
      if (callback) callback();
    }
    iteration += 1 / 2; // Speed
  }, 30);
}

function startAnimation() {
  const l1 = document.getElementById("line1");
  l1.textContent = "";
  hackerTypeEffect(l1, text1, () => {
    setTimeout(() => {
        window.location.href = "/scanner";
    }, 1000);
  });
}

window.onload = startAnimation;

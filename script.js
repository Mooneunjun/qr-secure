
  let scannedData = "";
  let lastDecrypted = "";
  let qrRecognized = false;

  function handleExpireUnitChange() {
    const unit = document.getElementById("expireUnit").value;
    document.getElementById("expireValue").disabled = (unit === 'none');
  }

  function getExpireInMs() {
    const unit = document.getElementById("expireUnit").value;
    const value = parseInt(document.getElementById("expireValue").value);
    if (unit === 'none' || !value || value <= 0) return null;
    if (unit === 'minute') return value * 60000;
    if (unit === 'hour') return value * 3600000;
    if (unit === 'day') return value * 86400000;
    return null;
  }

  function generateSecureQR() {
    const generateBtn = document.getElementById("generateBtn");
    const generateBtnText = document.getElementById("generateBtnText");
    const generateSpinner = document.getElementById("generateSpinner");

    // 로딩
    generateSpinner.style.display = "inline-block";
    generateBtn.disabled = true;
    generateBtnText.innerText = "🔄 생성 중...";

    setTimeout(() => {
      const text = document.getElementById("inputText").value.trim();
      const password = document.getElementById("inputPassword").value.trim();
      const author = document.getElementById("inputAuthor").value.trim();
      const expiresIn = getExpireInMs();

      if (!text) {
        alert("내용은 필수입니다.");
        generateSpinner.style.display = "none";
        generateBtn.disabled = false;
        generateBtnText.innerText = "✅ QR 생성";
        return;
      }

      // === 암호화 여부 결정 ===
      let dataObject = {
        encryption: false,
        text,
        author,
        createdAt: Date.now(),
        expiresIn
      };

      if (password) {
        dataObject.encryption = true;
        // 암호화 진행
        const salt = CryptoJS.lib.WordArray.random(128 / 8);
        const key = CryptoJS.PBKDF2(password, salt, {
          keySize: 256 / 32,
          iterations: 50000
        });
        const iv = CryptoJS.lib.WordArray.random(128 / 8);
        const encrypted = CryptoJS.AES.encrypt(JSON.stringify(dataObject), key, { iv });

        // 최종 result
        dataObject = {
          iv: iv.toString(CryptoJS.enc.Base64),
          salt: salt.toString(CryptoJS.enc.Base64),
          data: encrypted.toString(),
          encryption: true
        };
      }

      // QR 생성
      const qrContainer = document.getElementById("qrcode");
      qrContainer.innerHTML = "";

      const rawString = JSON.stringify(dataObject);
      const encoded = btoa(rawString);

      new QRCode(qrContainer, {
        text: encoded,
        width: 320,
        height: 320
      });

      // 로딩 해제
      generateSpinner.style.display = "none";
      generateBtn.disabled = false;
      generateBtnText.innerText = "✅ QR 생성";
    }, 300); // 0.3초 로딩 표시
  }

  function downloadQR() {
    const img = document.querySelector("#qrcode img");
    if (!img) {
      alert("QR 코드를 먼저 생성하세요.");
      return;
    }
    const link = document.createElement("a");
    link.href = img.src;
    link.download = "secure_qr.png";
    link.click();
  }

  function handleFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
      const img = document.getElementById("previewImage");
      img.src = e.target.result;
      img.style.display = "block";

      const canvas = document.getElementById("canvas");
      const ctx = canvas.getContext("2d");
      const image = new Image();
      image.onload = function() {
        canvas.width = image.width;
        canvas.height = image.height;
        ctx.drawImage(image, 0, 0);
        const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = jsQR(imageData.data, canvas.width, canvas.height);
        if (code) {
          scannedData = code.data;
          qrRecognized = true;
          showMessage("QR 인식 완료. 비밀번호가 있으면 입력 후 해석을 시도하세요.");
        } else {
          qrRecognized = false;
          showMessage("QR 인식 실패. 다른 파일을 시도해주세요.");
        }
      };
      image.src = e.target.result;
    };
    reader.readAsDataURL(file);
  }

  function tryDecrypt() {
    const decryptBtn = document.getElementById("decryptBtn");
    const decryptBtnText = document.getElementById("decryptBtnText");
    const decryptSpinner = document.getElementById("decryptSpinner");

    // 로딩 표시
    decryptSpinner.style.display = "inline-block";
    decryptBtn.disabled = true;
    decryptBtnText.innerText = "🔄 해석 중...";

    setTimeout(() => {
      if (!qrRecognized) {
        showMessage("QR 코드가 인식되지 않았습니다. 이미지를 업로드해주세요.");
        resetDecryptUI();
        return;
      }
      const password = document.getElementById("decryptPassword").value.trim();

      try {
        // base64 → json 파싱
        const parsed = JSON.parse(atob(scannedData));
        if (parsed.encryption) {
          // 암호화 QR
          if (!password) {
            showMessage("이 QR은 암호화되었습니다. 비밀번호를 입력하세요.");
            resetDecryptUI();
            return;
          }
          // 복호화
          const salt = CryptoJS.enc.Base64.parse(parsed.salt);
          const iv = CryptoJS.enc.Base64.parse(parsed.iv);
          const key = CryptoJS.PBKDF2(password, salt, {
            keySize: 256 / 32,
            iterations: 50000
          });
          const decrypted = CryptoJS.AES.decrypt(parsed.data, key, { iv });
          const resultText = decrypted.toString(CryptoJS.enc.Utf8);
          if (!resultText) throw new Error("복호화 실패");

          const realData = JSON.parse(resultText);
          // 만료여부
          if (realData.expiresIn && Date.now() > realData.createdAt + realData.expiresIn) {
            showMessage("⏰ QR 코드가 만료되었습니다.");
          } else {
            lastDecrypted = realData.text;
            showMessage("✅ 복호화 성공!");
            renderDecryptedOutput(realData.author, realData.text);
          }
        } else {
          // 평문
          if (parsed.expiresIn && Date.now() > parsed.createdAt + parsed.expiresIn) {
            showMessage("⏰ QR 코드가 만료되었습니다.");
          } else {
            lastDecrypted = parsed.text;
            showMessage("✅ 해석 성공(암호화 없음)!");
            renderDecryptedOutput(parsed.author, parsed.text);
          }
        }

      } catch (e) {
        console.error(e);
        showMessage("❌ 복호화 실패: 비밀번호가 틀렸거나 QR 내용이 잘못되었습니다.");
      }
      resetDecryptUI();
    }, 300);
  }

  function renderDecryptedOutput(author, text) {
    // 작성자 먼저, 내용은 아래. 작성자가 없으면 생략
    let html = `<div class="final-wrapper">`;
    if (author) {
      html += `<div class="final-author">작성자: ${author}</div>`;
    }
    html += `<div class="final-text">내용: ${text}</div>`;
    html += `</div>`;
    document.getElementById("finalOutput").innerHTML = html;
  }

  function resetDecryptUI() {
    const decryptBtn = document.getElementById("decryptBtn");
    const decryptBtnText = document.getElementById("decryptBtnText");
    const decryptSpinner = document.getElementById("decryptSpinner");

    decryptSpinner.style.display = "none";
    decryptBtn.disabled = false;
    decryptBtnText.innerText = "🔍 해석 시도";
  }

  function showMessage(msg) {
    const target = document.getElementById("decodeResult");
    target.innerHTML = "";
    let i = 0;
    const interval = setInterval(() => {
      target.innerHTML += msg[i];
      i++;
      if (i >= msg.length) clearInterval(interval);
    }, 20);
  }

  function copyDecryptedText() {
    if (!lastDecrypted) return;
    navigator.clipboard.writeText(lastDecrypted).then(() => {
      document.getElementById("copyMsg").textContent = "복호화된 텍스트가 복사되었습니다.";
      setTimeout(() => {
        document.getElementById("copyMsg").textContent = "";
      }, 2000);
    });
  }

// 전역 상태
let scannedData = "";
let lastDecrypted = "";
let qrRecognized = false;

// 만료 시간 단위 선택 처리
function handleExpireUnitChange() {
  const unit = document.getElementById("expireUnit").value;
  document.getElementById("expireValue").disabled = (unit === 'none');
}

// 만료 시간 (ms) 계산
function getExpireInMs() {
  const unit = document.getElementById("expireUnit").value;
  const value = parseInt(document.getElementById("expireValue").value);
  if (unit === 'none' || !value || value <= 0) return null;
  if (unit === 'minute') return value * 60000;
  if (unit === 'hour') return value * 3600000;
  if (unit === 'day') return value * 86400000;
  return null;
}

// 📌 QR 생성 (압축 + AES 암호화(옵션))
function generateSecureQR() {
  const generateBtn = document.getElementById("generateBtn");
  const generateBtnText = document.getElementById("generateBtnText");
  const generateSpinner = document.getElementById("generateSpinner");

  // 로딩 UI
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

    // 기본 payload (암호화 X)
    let dataObject = {
      encryption: false,
      text,
      author,
      createdAt: Date.now(),
      expiresIn
    };

    // 비밀번호가 있으면 AES 암호화
    if (password) {
      dataObject.encryption = true;
      const salt = CryptoJS.lib.WordArray.random(128 / 8);
      const key = CryptoJS.PBKDF2(password, salt, {
        keySize: 256 / 32,
        iterations: 50000
      });
      const iv = CryptoJS.lib.WordArray.random(128 / 8);
      const encrypted = CryptoJS.AES.encrypt(JSON.stringify(dataObject), key, { iv });

      dataObject = {
        iv: iv.toString(CryptoJS.enc.Base64),
        salt: salt.toString(CryptoJS.enc.Base64),
        data: encrypted.toString(),
        encryption: true
      };
    }

    // (1) JSON 직렬화
    const rawString = JSON.stringify(dataObject);
    // (2) LZ-String으로 압축
    const compressed = LZString.compressToBase64(rawString);

    // QR 생성
    const qrContainer = document.getElementById("qrcode");
    qrContainer.innerHTML = "";
    new QRCode(qrContainer, {
      text: compressed,
      width: 320,
      height: 320
    });

    // 로딩 해제
    generateSpinner.style.display = "none";
    generateBtn.disabled = false;
    generateBtnText.innerText = "✅ QR 생성";
  }, 300);
}

// QR 다운로드
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

// 파일 업로드 → QR 인식(jsQR)
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

// 📌 해석 시도 (압축 해제 + AES 복호화(옵션))
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
      // (1) LZ-String으로 압축 해제
      const decompressed = LZString.decompressFromBase64(scannedData);
      if (!decompressed) {
        showMessage("❌ 압축 해제 실패: QR 데이터가 손상되었습니다.");
        resetDecryptUI();
        return;
      }
      // (2) JSON 파싱
      const parsed = JSON.parse(decompressed);

      // (3) 암호화된 QR인지 여부
      if (parsed.encryption) {
        if (!password) {
          showMessage("이 QR은 암호화되었습니다. 비밀번호를 입력하세요.");
          resetDecryptUI();
          return;
        }
        // AES 복호화
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
        // 만료 체크
        if (realData.expiresIn && Date.now() > realData.createdAt + realData.expiresIn) {
          showMessage("⏰ QR 코드가 만료되었습니다.");
        } else {
          lastDecrypted = realData.text;
          showMessage("✅ 복호화 성공!");
          renderDecryptedOutput(realData.author, realData.text, realData.createdAt, realData.expiresIn);
        }
      } else {
        // 평문
        if (parsed.expiresIn && Date.now() > parsed.createdAt + parsed.expiresIn) {
          showMessage("⏰ QR 코드가 만료되었습니다.");
        } else {
          lastDecrypted = parsed.text;
          showMessage("✅ 해석 성공(암호화 없음)!");
          renderDecryptedOutput(parsed.author, parsed.text, parsed.createdAt, parsed.expiresIn);
        }
      }
    } catch (e) {
      console.error(e);
      showMessage("❌ 복호화 실패: QR 내용이 손상되었거나 비밀번호가 틀렸습니다.");
    }
    resetDecryptUI();
  }, 300);
}

function renderDecryptedOutput(author, text, createdAt, expiresIn) {
  const container = document.getElementById("finalOutput");

  const createdDate = new Date(createdAt).toLocaleString("ko-KR");
  let expireLine = "";
  if (expiresIn) {
    const expireDate = new Date(createdAt + expiresIn).toLocaleString("ko-KR");
    expireLine = `<div class="final-expire">만료 일시: ${expireDate}</div>`;
  }

  let html = `<div class="final-wrapper">`;
  html += `<div class="final-date">생성 일시: ${createdDate}</div>`;
  if (author) {
    html += `<div class="final-author">작성자: ${author}</div>`;
  }
  html += `<div class="final-text">내용: ${text}</div>`;
  html += expireLine;
  html += `</div>`;

  container.innerHTML = html;
}

// 복호화 UI 복원
function resetDecryptUI() {
  const decryptBtn = document.getElementById("decryptBtn");
  const decryptBtnText = document.getElementById("decryptBtnText");
  const decryptSpinner = document.getElementById("decryptSpinner");

  decryptSpinner.style.display = "none";
  decryptBtn.disabled = false;
  decryptBtnText.innerText = "🔍 해석 시도";
}

// 메시지 타자 효과
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

// 복호화된 텍스트 클립보드 복사
function copyDecryptedText() {
  if (!lastDecrypted) return;
  navigator.clipboard.writeText(lastDecrypted).then(() => {
    document.getElementById("copyMsg").textContent = "복호화된 텍스트가 복사되었습니다.";
    setTimeout(() => {
      document.getElementById("copyMsg").textContent = "";
    }, 2000);
  });
}

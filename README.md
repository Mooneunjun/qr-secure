# 🔐 Secure QR  - 보안 QR 코드 생성기

암호화된 QR 코드 생성 및 해석을 웹에서 손쉽게 할 수 있는 도구입니다.  
비밀번호 없이 평문 QR 생성도 가능하며, 선택적으로 고급 암호화 기능(AES + PBKDF2)을 적용할 수 있습니다.  

---

## ✅ 주요 기능

| 기능 | 설명 |
|------|------|
| ✅ QR 생성 (암호화 선택) | 내용 입력 후 QR 코드 생성 가능. 비밀번호가 입력되면 AES256 암호화 적용 |
| 🔓 복호화 | QR 이미지 업로드 후, 암호화 여부에 따라 자동 처리. 평문/암호화 QR 모두 지원 |
| ⏳ 만료 시간 설정 | QR 생성 시 유효기간을 설정 가능 (분, 시간, 일 단위 또는 없음) |
| 🧾 메타데이터 포함 | 작성자 및 생성 시간 포함 |
| 🎨 QR 프리뷰 & 다운로드 | QR 이미지를 실시간 미리보기 및 다운로드 가능 |
| 📋 복호화 결과 복사 | 해석된 텍스트를 클릭 한 번으로 클립보드에 복사 |
| 💬 UX 강화 | 로딩 애니메이션, 복호화 진행 중 메시지, 결과 시각화 등 UX 최적화 |

---

## 🔐 보안 설계

- **AES-256 CBC 모드**를 이용한 콘텐츠 암호화
- **PBKDF2 (SHA-256)** 키 스트레칭 적용 (Iterations: 50,000)
- **IV + Salt 동적 생성** 및 QR에 안전하게 포함
- 복호화 시 해당 키 기반으로 동적으로 해석
- **비밀번호 미입력 시 암호화 없이 QR 생성 가능 (일반 정보용)**

---

## 🖥 사용 방법

### 1. QR 생성

1. "내용 입력" 필드에 텍스트 입력
2. (선택) 작성자 / 만료시간 / 비밀번호 입력
3. `✅ QR 생성` 버튼 클릭 → QR 생성 완료
4. QR 이미지는 실시간 프리뷰 + 다운로드 가능

### 2. QR 해석

1. QR 이미지 업로드 (jpg/png 등 지원)
2. 비밀번호 입력 (암호화된 QR인 경우)
3. `🔍 해석 시도` 클릭 → 복호화 결과 출력
4. 복호화 성공 시, 작성자와 내용이 카드 형태로 정리되어 출력됨

---

## 🧠 기술 스택

- **HTML/CSS/Vanilla JS** 기반 SPA 구조
- [QRCode.js](https://github.com/davidshimjs/qrcodejs) (QR 생성)
- [jsQR](https://github.com/cozmo/jsQR) (QR 이미지 해석)
- [CryptoJS](https://github.com/brix/crypto-js) (AES/PBKDF2 암호화)

---

## 📦 개발/배포

### 로컬에서 테스트

```bash
git clone https://github.com/Mooneunjun/qr-secure.git
cd qr-secure
open index.html
```

### 바로 테스트 해보기 

```bash
https://mooneunjun.github.io/qr-secure/
```
// Vietnamese translations for OTP Revenge CTF Challenge

export const vi = {
  header: {
    title: "Báo Thù OTP",
    subtitle: "Thử Thách CTF Mật Mã",
    difficulty: "Độ khó"
  },
  
  hero: {
    title: "Báo Thù One-Time-Pad",
    description: "Thử thách mật mã học nâng cao khai thác lỗ hổng triển khai OTP. Hệ thống sử dụng key = SHA256(flag) để tạo keystream. Phân tích 1000 bản mã của cùng plaintext để khôi phục flag thông qua phân tích thống kê và tấn công known plaintext.",
    startButton: "Bắt Đầu Phân Tích",
    vulnerability: "Lỗ hổng tái sử dụng key trong OTP"
  },
  
  home: {
    challengeType: "Loại Thử Thách",
    challengeTypeValue: "Phân Tích Mật Mã",
    attackVector: "Vectơ Tấn Công",
    attackVectorValue: "Tái Sử Dụng Key",
    technique: "Kỹ Thuật",
    techniqueValue: "Thống Kê",
    status: "Trạng Thái",
    statusValue: "Đang Hoạt Động",
    footer: {
      title: "Nền Tảng Thử Thách CTF Mật Mã - Báo Thù One-Time-Pad",
      subtitle: "Công cụ giáo dục để học các kỹ thuật phân tích mật mã nâng cao",
      targetFlag: "Flag mục tiêu:"
    }
  },
  
  encryption: {
    title: "Mô Phỏng Mã Hóa OTP",
    plaintext: "Văn Bản Gốc",
    plaintextPlaceholder: "Nhập văn bản để mã hóa...",
    customKey: "Key Tùy Chỉnh (Tùy Chọn)",
    customKeyPlaceholder: "Để trống để tạo key ngẫu nhiên",
    encryptButton: "Mã Hóa với OTP",
    encrypting: "Đang Mã Hóa...",
    ciphertext: "Bản Mã (Hex)",
    key: "Key (Hex)",
    keyHash: "Hash SHA256 của Key",
    xorPreview: "Xem Trước Phép XOR",
    clickToEncrypt: "Nhấn 'Mã Hóa với OTP' để xem kết quả mã hóa và phép XOR",
    success: "Mã Hóa Thành Công",
    successDesc: "Văn bản đã được mã hóa bằng OTP.",
    failed: "Mã Hóa Thất Bại"
  },
  
  upload: {
    title: "Tải Lên Bản Mã",
    manualInput: "Nhập Thủ Công (Định Dạng Hex)",
    manualPlaceholder: "Nhập bản mã hex (ví dụ: 4a8b2e3f...)",
    whitespaceRemoved: "Khoảng trắng sẽ tự động bị xóa",
    addButton: "Thêm Bản Mã",
    or: "Hoặc",
    dragDrop: "Kéo thả file",
    clickBrowse: "hoặc nhấn để duyệt",
    selectedFiles: "File Đã Chọn",
    uploading: "Đang Tải Lên...",
    uploadButton: "Tải Lên {count} File",
    uploaded: "Bản Mã Đã Tải",
    clearAll: "Xóa Tất Cả",
    ciphertext: "Bản Mã",
    bytes: "bytes",
    hexChars: "ký tự hex",
    andMore: "...và {count} cái nữa",
    uploadComplete: "Tải Lên Hoàn Tất",
    uploadCompleteDesc: "Đã tải lên thành công {count} bản mã.",
    uploadFailed: "Tải Lên Thất Bại",
    cleared: "Đã Xóa Bản Mã",
    clearedDesc: "Tất cả bản mã đã được xóa."
  },
  
  statistical: {
    title: "Phân Tích Thống Kê",
    runButton: "Chạy Phân Tích",
    analyzing: "Đang Phân Tích...",
    totalCiphertexts: "Tổng Số Bản Mã",
    keyLength: "Độ Dài Key",
    entropyScore: "Điểm Entropy",
    avgByteValue: "Giá Trị Byte Trung Bình",
    bits: "bits",
    byteFreq: "Phân Bố Tần Suất Byte (32 vị trí đầu)",
    position: "Vị trí",
    noData: "Tải lên bản mã và chạy phân tích để xem dữ liệu thống kê",
    freqDesc: "Phân bố tần suất, tính toán entropy và nhận dạng mẫu sẽ xuất hiện ở đây",
    complete: "Phân Tích Hoàn Tất",
    completeDesc: "Phân tích thống kê đã được tạo thành công.",
    failed: "Phân Tích Thất Bại"
  },
  
  xor: {
    title: "Phân Tích Cặp XOR",
    index1: "Chỉ Số Bản Mã 1",
    index2: "Chỉ Số Bản Mã 2",
    analyzeButton: "Phân Tích Cặp XOR",
    analyzing: "Đang Phân Tích...",
    noResults: "Chưa có kết quả phân tích XOR",
    xorDesc: "XOR nhiều cặp bản mã để xác định mẫu trong keystream. Điều này tiết lộ mối tương quan có thể giúp khôi phục key mã hóa.",
    xorResult: "Kết Quả XOR (Hex Dump - 256 bytes đầu)",
    patterns: "mẫu",
    complete: "Phân Tích XOR Hoàn Tất",
    completeDesc: "Cặp bản mã đã được phân tích thành công.",
    failed: "Phân Tích Thất Bại",
    invalidInput: "Dữ Liệu Không Hợp Lệ",
    invalidInputDesc: "Vui lòng nhập chỉ số bản mã hợp lệ."
  },
  
  knownPlaintext: {
    title: "Tấn Công Known Plaintext",
    prefix: "Tiền Tố Plaintext Đã Biết",
    prefixPlaceholder: "ví dụ: VNFLAG{",
    prefixDesc: "Nhập phần đầu của plaintext đã biết để khôi phục keystream",
    executeButton: "Thực Thi Tấn Công Known Plaintext",
    running: "Đang Chạy Tấn Công...",
    complete: "Khôi Phục Keystream Hoàn Tất",
    recoveredKeystream: "Keystream Đã Khôi Phục (Hex)",
    confidenceLevel: "Mức Độ Tin Cậy",
    matched: "{count} bản mã khớp với keystream đồng thuận",
    recoveredPlaintext: "Xem Trước Plaintext Đã Khôi Phục",
    desc: "Tấn công này sử dụng tiền tố plaintext đã biết để XOR với bản mã, tiết lộ keystream được sử dụng để mã hóa.",
    attackComplete: "Tấn Công Hoàn Tất",
    attackCompleteDesc: "Keystream đã được khôi phục với {confidence} tin cậy.",
    attackFailed: "Tấn Công Thất Bại"
  },
  
  flag: {
    title: "Xác Minh Flag",
    submission: "Nộp Flag",
    placeholder: "VNFLAG{...}",
    desc: "Nhập flag đã khôi phục để xác minh",
    verifyButton: "Xác Minh Flag",
    verifying: "Đang Xác Minh...",
    valid: "Flag Hợp Lệ!",
    invalid: "Flag Không Hợp Lệ",
    providedHash: "SHA256 của Flag Đã Nhập",
    expectedHash: "Hash Mong Đợi",
    completed: "Hoàn Thành Thử Thách",
    format: "Định dạng flag là:",
    verificationDesc: "Xác minh sử dụng so sánh hash SHA256. Hệ thống kiểm tra rằng SHA256(flag) khớp với hash keystream mong đợi."
  },
  
  walkthrough: {
    title: "Hướng Dẫn Phân Tích Mật Mã",
    step: "Bước",
    difficulty: {
      beginner: "Người Mới",
      intermediate: "Trung Cấp",
      advanced: "Nâng Cao",
      master: "Chuyên Gia"
    },
    mathFoundation: "Nền Tảng Toán Học",
    codeExample: "Ví Dụ Code",
    steps: [
      {
        title: "Hiểu Lỗ Hổng OTP",
        difficulty: "beginner",
        content: "One-Time Pad (OTP) về mặt lý thuyết không thể phá được khi được triển khai đúng. Tuy nhiên, thử thách này khai thác một lỗ hổng nghiêm trọng: sử dụng hàm dẫn xuất key xác định thay vì key thực sự ngẫu nhiên."
      },
      {
        title: "Phân Tích Chuỗi XOR",
        difficulty: "intermediate",
        content: "Khi nhiều bản mã được mã hóa với cùng một key, việc XOR chúng với nhau sẽ tiết lộ các mẫu loại bỏ plaintext, chỉ để lại thông tin liên quan đến key."
      },
      {
        title: "Phân Tích Tần Suất Thống Kê",
        difficulty: "intermediate",
        content: "Bằng cách phân tích phân bố tần suất của các byte trên tất cả bản mã, chúng ta có thể xác định các mẫu và bất thường tiết lộ thông tin về keystream."
      },
      {
        title: "Tấn Công Known Plaintext",
        difficulty: "advanced",
        content: "Nếu chúng ta biết hoặc có thể đoán một phần plaintext (ví dụ: 'VNFLAG{'), chúng ta có thể XOR nó với bản mã để khôi phục các byte keystream tương ứng."
      },
      {
        title: "Khôi Phục Flag qua Ràng Buộc SHA256",
        difficulty: "master",
        content: "Sau khi khôi phục keystream, chúng ta biết nó bằng SHA256(flag). Chúng ta có thể thử tấn công từ điển hoặc khớp mẫu để tìm flag gốc tạo ra hash này."
      }
    ]
  },
  
  generator: {
    title: "Tạo Dữ Liệu Thử Thách",
    count: "Số Lượng Bản Mã",
    countDesc: "Tạo từ 1 đến 1000 bản mã được mã hóa với cùng key (tối đa 1000)",
    generateButton: "Tạo Bản Mã",
    generating: "Đang Tạo...",
    download: "Tải Xuống",
    info: "Thông Tin Thử Thách:",
    infoItems: [
      "Plaintext chứa flag: VNFLAG{...}",
      "Key được tạo từ: SHA256(flag)",
      "Tất cả bản mã dùng cùng key và plaintext",
      "Sử dụng phân tích thống kê để khôi phục flag"
    ],
    success: "Tạo Thành Công",
    successDesc: "Đã tạo {count} bản mã cho thử thách.",
    failed: "Tạo Thất Bại",
    invalidValue: "Giá Trị Không Hợp Lệ",
    invalidValueDesc: "Vui lòng nhập số từ 1 đến 1000"
  },
  
  common: {
    loading: "Đang tải...",
    error: "Lỗi",
    success: "Thành công",
    bytes: "bytes",
    count: "số lượng"
  }
};

// Technical terms that should remain in English
export const technicalTerms = {
  OTP: "OTP",
  SHA256: "SHA256",
  XOR: "XOR",
  hex: "hex",
  plaintext: "plaintext",
  ciphertext: "ciphertext",
  keystream: "keystream",
  entropy: "entropy"
};

export type Translation = typeof vi;
export default vi;

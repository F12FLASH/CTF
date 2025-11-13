import { createContext, useContext, useState, useEffect, ReactNode } from "react";

type Language = "en" | "vi";

interface LanguageContextType {
  language: Language;
  setLanguage: (lang: Language) => void;
  t: (key: string) => string;
}

const LanguageContext = createContext<LanguageContextType | undefined>(undefined);

const translations = {
  en: {
    challengeTitle: "MD5 is Alive",
    challengeSubtitle: "Exploit MD5 Length Extension Attack Vulnerability",
    category: "Crypto",
    difficulty: "Master Hacker",
    technology: "MD5 Cryptanalysis",
    startChallenge: "Start Challenge",
    oracleTitle: "MD5 Oracle Interface",
    oracleDescription: "The oracle computes MD5(flag + \"||\" + your_input) and returns the hash. Only the first 4 bytes are compared for validation.",
    yourInput: "Your Input",
    inputPlaceholder: "Enter your data here...",
    computeHash: "Compute Hash",
    hashResult: "Hash Result",
    first4Bytes: "First 4 Bytes (Validated)",
    remainingBytes: "Remaining Bytes",
    copyHash: "Copy Hash",
    challengeInfo: "Challenge Information",
    description: "Description",
    descriptionText: "\"MD5 is Alive\" is a challenge that exploits critical weaknesses in the MD5 hash function. The server provides an oracle that returns the MD5 hash of the concatenation of flag + \"||\" + user_input, but only compares the first 4 bytes for authentication checks.",
    technicalSpecs: "Technical Specifications",
    hashFunction: "Hash Function",
    format: "Format",
    formatValue: "md5(flag + \"||\" + user_input)",
    comparison: "Comparison",
    comparisonValue: "Only first 4 bytes checked",
    flagLength: "Flag Length",
    flagLengthValue: "64 bytes",
    oracleAccess: "Oracle Access",
    oracleAccessValue: "Can query any arbitrary string",
    attackVectors: "Attack Vectors",
    vector1Title: "Length Extension Attack",
    vector1Desc: "MD5 is vulnerable to length extension attacks, allowing you to extend a known hash without knowing the original content.",
    vector2Title: "4-Byte Collision",
    vector2Desc: "With only 4 bytes compared, birthday attack makes collision much easier to find.",
    vector3Title: "Known Structure",
    vector3Desc: "The format flag + \"||\" + input is known, which helps in crafting targeted attacks.",
    hintsTitle: "Hints & Resources",
    hint1Title: "Understanding MD5 Internals",
    hint1Content: "MD5 uses the Merkle-Damgård construction. This means you can extend a hash by adding data and calculating the new hash from the internal state. Study how MD5 processes blocks and maintains state.",
    hint2Title: "Finding 4-Byte Collisions",
    hint2Content: "With only 2^32 possible values for 4 bytes, a birthday attack requires approximately 2^16 (~65,000) attempts to find a collision. This is computationally feasible.",
    hint3Title: "Length Extension Tools",
    hint3Content: "Use tools like HashPump or implement your own length extension attack. You'll need to know the original message length and the hash value to extend it.",
    unlockHint: "Unlock Hint",
    hideHint: "Hide Hint",
    attackMethodology: "Attack Methodology",
    step1: "Query the Oracle",
    step1Desc: "Submit various inputs to understand hash patterns",
    step2: "Analyze Hash Structure",
    step2Desc: "Study the first 4 bytes and identify collision opportunities",
    step3: "Perform Length Extension",
    step3Desc: "Extend known hashes to craft new valid hashes",
    step4: "Extract the Flag",
    step4Desc: "Use cryptanalysis techniques to recover the flag",
    totalQueries: "Total Queries",
    submitFlag: "Submit Flag",
    flagPlaceholder: "VNFLAG{...}",
    footerNote: "Educational Disclaimer",
    footerText: "This challenge demonstrates why MD5 is no longer secure for cryptographic applications. Using only 4-byte comparison severely weakens security, and combined with length extension attacks, allows complete flag recovery. Always use modern hash functions like SHA-256 or SHA-3.",
    credits: "CTF Challenge Platform",
    tools: "Tools & Resources",
    toolHashPump: "HashPump - Length extension attack tool",
    toolHashcat: "Hashcat - Hash cracking",
    toolJohnTheRipper: "John the Ripper - Password cracking",
    computing: "Computing...",
    copied: "Copied to clipboard!",
    queryCount: "Queries",
    attemptCount: "Attempts",
    solved: "Solved!",
  },
  vi: {
    challengeTitle: "MD5 is Alive",
    challengeSubtitle: "Khai thác lỗ hổng Length Extension Attack trong MD5",
    category: "Mật mã",
    difficulty: "Master Hacker",
    technology: "Phân tích mật mã MD5",
    startChallenge: "Bắt đầu thử thách",
    oracleTitle: "Giao diện MD5 Oracle",
    oracleDescription: "Oracle tính toán MD5(flag + \"||\" + input_của_bạn) và trả về hash. Chỉ 4 byte đầu tiên được so sánh để xác thực.",
    yourInput: "Dữ liệu của bạn",
    inputPlaceholder: "Nhập dữ liệu vào đây...",
    computeHash: "Tính Hash",
    hashResult: "Kết quả Hash",
    first4Bytes: "4 Byte đầu (Được xác thực)",
    remainingBytes: "Các Byte còn lại",
    copyHash: "Sao chép Hash",
    challengeInfo: "Thông tin thử thách",
    description: "Mô tả",
    descriptionText: "\"MD5 is Alive\" là thử thách khai thác điểm yếu nghiêm trọng trong hàm băm MD5. Server cung cấp oracle trả về MD5 của chuỗi kết hợp flag + \"||\" + user_input, nhưng chỉ so sánh 4 byte đầu cho các kiểm tra xác thực.",
    technicalSpecs: "Thông số kỹ thuật",
    hashFunction: "Hàm băm",
    format: "Định dạng",
    formatValue: "md5(flag + \"||\" + user_input)",
    comparison: "So sánh",
    comparisonValue: "Chỉ kiểm tra 4 byte đầu",
    flagLength: "Độ dài flag",
    flagLengthValue: "64 byte",
    oracleAccess: "Truy cập Oracle",
    oracleAccessValue: "Có thể query bất kỳ chuỗi nào",
    attackVectors: "Phương thức tấn công",
    vector1Title: "Length Extension Attack",
    vector1Desc: "MD5 dễ bị tấn công length extension, cho phép mở rộng hash đã biết mà không cần biết nội dung gốc.",
    vector2Title: "4-Byte Collision",
    vector2Desc: "Với chỉ 4 byte được so sánh, birthday attack giúp tìm collision dễ dàng hơn nhiều.",
    vector3Title: "Cấu trúc đã biết",
    vector3Desc: "Định dạng flag + \"||\" + input đã biết, giúp tạo các cuộc tấn công có mục tiêu.",
    hintsTitle: "Gợi ý & Tài nguyên",
    hint1Title: "Hiểu cấu trúc bên trong MD5",
    hint1Content: "MD5 sử dụng Merkle-Damgård construction. Điều này có nghĩa bạn có thể mở rộng hash bằng cách thêm dữ liệu và tính hash mới từ internal state. Nghiên cứu cách MD5 xử lý blocks và duy trì state.",
    hint2Title: "Tìm 4-Byte Collisions",
    hint2Content: "Với chỉ 2^32 giá trị có thể cho 4 byte, birthday attack cần khoảng 2^16 (~65,000) lần thử để tìm collision. Điều này hoàn toàn khả thi.",
    hint3Title: "Công cụ Length Extension",
    hint3Content: "Sử dụng các công cụ như HashPump hoặc tự viết length extension attack. Bạn cần biết độ dài message gốc và giá trị hash để mở rộng nó.",
    unlockHint: "Mở khóa gợi ý",
    hideHint: "Ẩn gợi ý",
    attackMethodology: "Phương pháp tấn công",
    step1: "Truy vấn Oracle",
    step1Desc: "Gửi các input khác nhau để hiểu pattern của hash",
    step2: "Phân tích cấu trúc Hash",
    step2Desc: "Nghiên cứu 4 byte đầu và xác định cơ hội collision",
    step3: "Thực hiện Length Extension",
    step3Desc: "Mở rộng các hash đã biết để tạo hash hợp lệ mới",
    step4: "Trích xuất Flag",
    step4Desc: "Sử dụng kỹ thuật cryptanalysis để khôi phục flag",
    totalQueries: "Tổng số truy vấn",
    submitFlag: "Gửi Flag",
    flagPlaceholder: "VNFLAG{...}",
    footerNote: "Lưu ý giáo dục",
    footerText: "Thử thách này minh họa tại sao MD5 không còn an toàn cho các ứng dụng mật mã. So sánh chỉ 4 byte đầu làm yếu đáng kể tính bảo mật, kết hợp với length extension attack cho phép khôi phục toàn bộ flag. Luôn sử dụng các hash function hiện đại như SHA-256 hoặc SHA-3.",
    credits: "Nền tảng thử thách CTF",
    tools: "Công cụ & Tài nguyên",
    toolHashPump: "HashPump - Công cụ length extension attack",
    toolHashcat: "Hashcat - Bẻ khóa hash",
    toolJohnTheRipper: "John the Ripper - Bẻ khóa mật khẩu",
    computing: "Đang tính toán...",
    copied: "Đã sao chép!",
    queryCount: "Truy vấn",
    attemptCount: "Thử",
    solved: "Đã giải!",
  },
};

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [language, setLanguage] = useState<Language>(
    () => (localStorage.getItem("language") as Language) || "en"
  );

  const t = (key: string): string => {
    return translations[language][key as keyof typeof translations.en] || key;
  };

  useEffect(() => {
    localStorage.setItem("language", language);
    document.documentElement.lang = language;
  }, [language]);

  return (
    <LanguageContext.Provider value={{ language, setLanguage, t }}>
      {children}
    </LanguageContext.Provider>
  );
}

export const useLanguage = () => {
  const context = useContext(LanguageContext);
  if (!context) {
    throw new Error("useLanguage must be used within a LanguageProvider");
  }
  return context;
};

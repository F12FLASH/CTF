import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { BookOpen, Code2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";

const walkthroughSteps = [
  {
    id: "step-1",
    title: "Hiểu Lỗ Hổng OTP",
    difficulty: "Người Mới",
    content: `One-Time Pad (OTP) về mặt lý thuyết là không thể phá vỡ khi được triển khai đúng cách. Tuy nhiên, thử thách này khai thác một lỗ hổng nghiêm trọng: sử dụng hàm tạo khóa xác định thay vì khóa ngẫu nhiên thực sự.`,
    mathematical: `key = SHA256(flag)
ciphertext = plaintext ⊕ key`,
    code: `// Triển Khai Lỗ Hổng
const key = SHA256(flag);
const ciphertext = XOR(plaintext, key);`,
  },
  {
    id: "step-2",
    title: "Phân Tích Chuỗi XOR",
    difficulty: "Trung Cấp",
    content: `Khi nhiều bản mã được mã hóa với cùng một khóa, việc XOR chúng với nhau tiết lộ các mẫu làm triệt tiêu văn bản rõ, chỉ để lại thông tin liên quan đến khóa.`,
    mathematical: `C₁ ⊕ C₂ = (P ⊕ K) ⊕ (P ⊕ K) = 0
Với nhiễu: C₁ ⊕ C₂ ≈ biến đổi nhỏ`,
    code: `// XOR hai bản mã
function xorCiphertexts(ct1, ct2) {
  return ct1.map((byte, i) => byte ^ ct2[i]);
}`,
  },
  {
    id: "step-3",
    title: "Phân Tích Tần Suất Thống Kê",
    difficulty: "Trung Cấp",
    content: `Bằng cách phân tích phân bố tần suất byte trên tất cả các bản mã, chúng ta có thể xác định các mẫu và bất thường tiết lộ thông tin về keystream.`,
    mathematical: `entropy = -Σ(p(x) × log₂(p(x)))
trong đó p(x) là tần suất byte`,
    code: `// Tính tần suất byte
const freq = new Array(256).fill(0);
ciphertexts.forEach(ct => {
  ct.forEach(byte => freq[byte]++);
});`,
  },
  {
    id: "step-4",
    title: "Tấn Công Văn Bản Rõ Đã Biết",
    difficulty: "Nâng Cao",
    content: `Nếu chúng ta biết hoặc có thể đoán một phần của văn bản rõ (ví dụ: "VNFLAG{"), chúng ta có thể XOR nó với bản mã để khôi phục các byte keystream tương ứng.`,
    mathematical: `Đã biết: P[0..n]
Khôi phục Key: K[0..n] = C[0..n] ⊕ P[0..n]`,
    code: `// Khôi phục keystream từ văn bản rõ đã biết
function recoverKey(ciphertext, knownPlaintext) {
  return XOR(ciphertext, knownPlaintext);
}`,
  },
  {
    id: "step-5",
    title: "Khôi Phục Flag Qua Ràng Buộc SHA256",
    difficulty: "Chuyên Gia",
    content: `Khi chúng ta khôi phục được keystream, chúng ta biết nó bằng SHA256(flag). Chúng ta có thể thử tấn công từ điển hoặc khớp mẫu để tìm flag gốc tạo ra hash này.`,
    mathematical: `Cho: keystream = SHA256(flag)
Tìm: flag sao cho SHA256(flag) = keystream`,
    code: `// Xác minh ứng viên flag
function verifyFlag(candidate, keystream) {
  return SHA256(candidate) === keystream;
}`,
  },
];

export function EducationalWalkthrough() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BookOpen className="h-5 w-5 text-primary" />
          Hướng Dẫn Phân Tích Mật Mã
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Accordion type="multiple" className="space-y-4">
          {walkthroughSteps.map((step, index) => (
            <AccordionItem
              key={step.id}
              value={step.id}
              className="border rounded-md px-4 data-[state=open]:bg-card"
            >
              <AccordionTrigger className="hover:no-underline py-4">
                <div className="flex items-center gap-3 text-left">
                  <Badge variant="secondary" className="font-mono text-xs">
                    Bước {index + 1}
                  </Badge>
                  <span className="font-medium">{step.title}</span>
                  <Badge
                    variant="outline"
                    className="ml-auto mr-2 text-xs"
                  >
                    {step.difficulty}
                  </Badge>
                </div>
              </AccordionTrigger>
              <AccordionContent className="space-y-4 pb-4">
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {step.content}
                </p>

                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
                    <Code2 className="h-3 w-3" />
                    Nền Tảng Toán Học
                  </div>
                  <div className="p-4 bg-muted rounded-md font-mono text-xs whitespace-pre-wrap">
                    {step.mathematical}
                  </div>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
                    <Code2 className="h-3 w-3" />
                    Ví Dụ Code
                  </div>
                  <div className="p-4 bg-muted rounded-md font-mono text-xs overflow-x-auto">
                    <pre>{step.code}</pre>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </CardContent>
    </Card>
  );
}

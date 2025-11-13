import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Book, Target, Wrench, Star } from "lucide-react";
import { MathDisplay } from "./math-display";

export function ChallengeDescription() {
  return (
    <div className="space-y-8" data-testid="challenge-description">
      <Card className="border rounded-lg">
        <CardHeader className="p-6">
          <div className="flex items-start justify-between flex-wrap gap-4">
            <div>
              <CardTitle className="text-2xl mb-2">RSA in a Parallel Universe</CardTitle>
              <div className="flex items-center gap-2 flex-wrap">
                <Badge variant="destructive">Master</Badge>
                <Badge variant="outline">Cryptography</Badge>
                <Badge variant="outline">Gaussian Integers</Badge>
              </div>
            </div>
            <div className="text-right">
              <div className="text-sm text-muted-foreground">Difficulty</div>
              <div className="flex items-center gap-1">
                {[...Array(5)].map((_, i) => (
                  <Star key={i} className="w-5 h-5 fill-primary text-primary" />
                ))}
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-6 pt-0">
          <div className="prose prose-sm max-w-none dark:prose-invert">
            <p className="text-base leading-relaxed">
              <strong>"RSA in a Parallel Universe"</strong> là một biến thể cực kỳ phức tạp của RSA hoạt động trên vành số phức Gaussian (ℤ[i]). 
              Thay vì sử dụng số nguyên tố thông thường, hệ thống sử dụng các số phức Gaussian nguyên tố để tạo khóa.
            </p>
          </div>
        </CardContent>
      </Card>

      <Card className="border rounded-lg">
        <CardHeader className="p-6">
          <div className="flex items-center gap-3">
            <Target className="w-6 h-6 text-primary" />
            <CardTitle className="text-xl">Đặc điểm kỹ thuật</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-6 pt-0">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="p-4 border rounded-md bg-card/50">
              <div className="text-sm font-semibold text-muted-foreground mb-2">Vành tính toán</div>
              <MathDisplay math="\mathbb{Z}[i]" />
              <p className="text-xs text-muted-foreground mt-1">Gaussian Integers</p>
            </div>
            <div className="p-4 border rounded-md bg-card/50">
              <div className="text-sm font-semibold text-muted-foreground mb-2">Modulus</div>
              <MathDisplay math="n = p \times q" />
              <p className="text-xs text-muted-foreground mt-1">p, q là Gaussian primes</p>
            </div>
            <div className="p-4 border rounded-md bg-card/50">
              <div className="text-sm font-semibold text-muted-foreground mb-2">Encryption</div>
              <MathDisplay math="c = m^e \mod n" />
              <p className="text-xs text-muted-foreground mt-1">trong ℤ[i]</p>
            </div>
            <div className="p-4 border rounded-md bg-card/50">
              <div className="text-sm font-semibold text-muted-foreground mb-2">Decryption</div>
              <MathDisplay math="m = c^d \mod n" />
              <p className="text-xs text-muted-foreground mt-1">trong ℤ[i]</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card className="border rounded-lg">
        <CardHeader className="p-6">
          <div className="flex items-center gap-3">
            <Book className="w-6 h-6 text-primary" />
            <CardTitle className="text-xl">Lý thuyết toán học</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-6 pt-0">
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="gaussian-integers">
              <AccordionTrigger className="text-base font-semibold" data-testid="accordion-trigger-gaussian-integers">
                Gaussian Integers
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-4 pt-2">
                  <p className="text-sm leading-relaxed">
                    Gaussian integer có dạng <strong>a + bi</strong>, với a, b ∈ ℤ.
                  </p>
                  <MathDisplay math="N(a + bi) = a^2 + b^2" block />
                  <p className="text-sm text-muted-foreground">
                    Norm của một Gaussian integer là tổng bình phương của phần thực và phần ảo.
                  </p>
                </div>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="gaussian-primes">
              <AccordionTrigger className="text-base font-semibold" data-testid="accordion-trigger-gaussian-primes">
                Gaussian Primes
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-3 pt-2">
                  <p className="text-sm leading-relaxed">
                    Các số phức Gaussian nguyên tố bao gồm:
                  </p>
                  <ul className="list-disc list-inside space-y-2 text-sm text-muted-foreground">
                    <li>Số nguyên tố thông thường dạng 4k+3</li>
                    <li>Các số có norm là số nguyên tố dạng 4k+1</li>
                    <li>1 + i và các associate của nó</li>
                  </ul>
                </div>
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="key-generation">
              <AccordionTrigger className="text-base font-semibold" data-testid="accordion-trigger-key-generation">
                Key Generation
              </AccordionTrigger>
              <AccordionContent>
                <div className="space-y-3 pt-2">
                  <ol className="list-decimal list-inside space-y-2 text-sm">
                    <li>Chọn hai Gaussian primes p và q</li>
                    <li>Tính n = p × q</li>
                    <li>Tính φ(n) = N(p-1) × N(q-1)</li>
                    <li>Chọn e sao cho gcd(N(e), φ(n)) = 1</li>
                    <li>Tính d = e⁻¹ mod φ(n)</li>
                  </ol>
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>

      <Card className="border rounded-lg">
        <CardHeader className="p-6">
          <div className="flex items-center gap-3">
            <Wrench className="w-6 h-6 text-primary" />
            <CardTitle className="text-xl">Phương pháp giải quyết</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-6 pt-0">
          <div className="space-y-6">
            <div className="p-4 border-l-4 border-primary bg-primary/5 rounded">
              <h3 className="text-base font-semibold mb-2">Phương pháp 1: Phân tích modulus phức</h3>
              <p className="text-sm text-muted-foreground mb-3">
                Tìm p, q ∈ ℤ[i] sao cho p × q = n. Sử dụng factorization trên norm: N(n) = N(p) × N(q)
              </p>
              <div className="space-y-2 text-sm">
                <div className="flex items-start gap-2">
                  <span className="font-semibold min-w-[80px]">Bước 1:</span>
                  <span className="text-muted-foreground">Phân tích n thành Gaussian primes</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-semibold min-w-[80px]">Bước 2:</span>
                  <span className="text-muted-foreground">Tính φ(n) cho Gaussian integers</span>
                </div>
                <div className="flex items-start gap-2">
                  <span className="font-semibold min-w-[80px]">Bước 3:</span>
                  <span className="text-muted-foreground">Tính khóa bí mật d</span>
                </div>
              </div>
            </div>

            <div className="p-4 border-l-4 border-yellow-500 bg-yellow-500/5 rounded">
              <h3 className="text-base font-semibold mb-2">Phương pháp 2: Lattice Attack</h3>
              <p className="text-sm text-muted-foreground">
                Sử dụng LLL algorithm để biểu diễn bài toán dưới dạng lattice và tìm nghiệm ngắn.
              </p>
            </div>

            <div className="p-4 border-l-4 border-green-500 bg-green-500/5 rounded">
              <h3 className="text-base font-semibold mb-2">Phương pháp 3: Khai thác cấu trúc đặc biệt</h3>
              <p className="text-sm text-muted-foreground">
                Nếu p = a + bi, q = a - bi (complex conjugates), khi đó n = a² + b² (số nguyên thực) và bài toán quy về RSA thông thường.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

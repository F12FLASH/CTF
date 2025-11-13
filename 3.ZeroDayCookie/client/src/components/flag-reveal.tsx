import { Card, CardContent } from "@/components/ui/card";
import { Trophy, Sparkles } from "lucide-react";
import { useEffect, useState } from "react";

interface FlagRevealProps {
  flag: string;
}

export function FlagReveal({ flag }: FlagRevealProps) {
  const [revealed, setRevealed] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setRevealed(true), 300);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="mt-12 space-y-6">
      <div className="text-center space-y-4">
        <div className={`transition-all duration-500 ${revealed ? 'opacity-100 scale-100' : 'opacity-0 scale-95'}`}>
          <Trophy className="h-24 w-24 text-primary mx-auto animate-pulse" data-testid="icon-trophy" />
          <h2 className="text-4xl font-bold font-mono text-primary mt-6 uppercase tracking-wider">
            Đã Chiếm Flag!
          </h2>
          <p className="text-muted-foreground font-mono text-sm mt-2">
            Chúc mừng bạn đã khai thác thành công lỗ hổng nhầm lẫn thuật toán JWT
          </p>
        </div>
      </div>

      <Card className={`max-w-3xl mx-auto border-primary/50 bg-gradient-to-br from-primary/10 to-transparent backdrop-blur-sm transition-all duration-500 ${revealed ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`} data-testid="card-flag">
        <CardContent className="p-8">
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-sm font-mono text-muted-foreground">
              <Sparkles className="h-4 w-4 text-primary" />
              <span>FLAG CỦA BẠN</span>
            </div>
            <div className="bg-secondary/50 border-2 border-primary/30 rounded-md p-6">
              <code
                className="font-mono text-lg md:text-xl text-primary break-all"
                data-testid="text-flag"
              >
                {flag}
              </code>
            </div>
            <div className="pt-4 border-t border-border">
              <h3 className="font-mono text-sm font-medium text-foreground mb-3">
                Những Gì Bạn Đã Làm Được:
              </h3>
              <ul className="space-y-2 font-mono text-xs text-muted-foreground">
                <li className="flex items-start gap-2">
                  <span className="text-primary shrink-0">•</span>
                  <span>Xác định được lỗ hổng nhầm lẫn thuật toán JWT (HS256 vs RS256)</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary shrink-0">•</span>
                  <span>Hiểu cách hoạt động của RS256 (bất đối xứng) và HS256 (đối xứng)</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary shrink-0">•</span>
                  <span>Sử dụng khóa công khai RS256 làm secret HS256 để giả mạo token</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary shrink-0">•</span>
                  <span>Thay đổi role thành admin và nâng cấp quyền để vượt qua xác thực</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-primary shrink-0">•</span>
                  <span>Khai thác thành công lỗ hổng CVE-2016-5431 và chiếm được flag</span>
                </li>
              </ul>
            </div>
            <div className="pt-4 border-t border-border">
              <h3 className="font-mono text-sm font-medium text-foreground mb-3">
                Bài Học Bảo Mật:
              </h3>
              <p className="font-mono text-xs text-muted-foreground leading-relaxed">
                Lỗ hổng này xảy ra khi server không kiểm tra chặt chẽ thuật toán được chỉ định trong JWT header. 
                Trong thực tế, hãy luôn chỉ định rõ ràng thuật toán được phép và không bao giờ tin tưởng thuật toán 
                từ token do người dùng cung cấp. Sử dụng thư viện JWT cập nhật và tuân thủ các nguyên tắc bảo mật tốt nhất.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

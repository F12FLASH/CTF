import { Button } from "@/components/ui/button";
import { AlertCircle } from "lucide-react";

export function HeroSection() {
  const scrollToAnalysis = () => {
    document.getElementById("analysis-tools")?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <section className="h-64 border-b bg-gradient-to-b from-card to-background">
      <div className="container mx-auto h-full px-6 flex flex-col justify-center">
        <div className="max-w-3xl">
          <h1 className="font-display text-5xl font-bold mb-4">
            One-Time-Pad Revenge
          </h1>
          <p className="text-base text-muted-foreground mb-6 max-w-2xl">
            Một thử thách mật mã nâng cao khai thác lỗ hổng triển khai OTP. 
            Hệ thống sử dụng <span className="font-mono text-foreground">key = SHA256(flag)</span> để tạo luồng khóa. Phân tích 1000 bản mã của cùng một bản để khôi phục cờ thông qua phân tích thống kê và các cuộc tấn công bản rõ đã biết.
          </p>
          <div className="flex gap-4 items-center">
            <Button 
              size="lg"
              onClick={scrollToAnalysis}
              data-testid="button-start-analysis"
            >
              Start Analysis
            </Button>
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <AlertCircle className="h-4 w-4" />
              <span>Key reuse vulnerability in OTP context</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

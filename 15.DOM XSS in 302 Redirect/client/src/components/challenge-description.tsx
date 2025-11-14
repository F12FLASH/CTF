import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Shield, Target, AlertTriangle, CheckCircle2 } from "lucide-react";

export function ChallengeDescription() {
  const objectives = [
    "Hiểu cơ chế DOM-based XSS trong redirect",
    "Bypass Content Security Policy (CSP)",
    "Khai thác window.opener để đánh cắp cookie",
    "Capture admin cookie chứa flag"
  ];

  const techniques = [
    { name: "302 Redirect", desc: "Server trả về redirect đến URL do user kiểm soát" },
    { name: "DOM XSS", desc: "Lỗ hổng trong JavaScript xử lý redirect" },
    { name: "CSP Bypass", desc: "Sử dụng javascript: scheme và window.opener" },
    { name: "Cookie Theft", desc: "Đánh cắp cookie admin thông qua XSS" }
  ];

  return (
    <Card className="h-full" data-testid="card-challenge-description">
      <CardHeader className="space-y-1">
        <div className="flex items-center gap-2">
          <div className="flex items-center justify-center w-8 h-8 rounded-md bg-primary/10">
            <Shield className="w-4 h-4 text-primary" data-testid="icon-shield" />
          </div>
          <CardTitle className="text-xl" data-testid="title-challenge-description">Mô tả thử thách</CardTitle>
        </div>
        <CardDescription className="leading-relaxed" data-testid="text-challenge-summary">
          Ứng dụng web có lỗ hổng DOM-based XSS trong quá trình xử lý 302 redirect. 
          Mặc dù có CSP nghiêm ngặt, redirect mechanism tạo ra vector tấn công độc đáo.
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Target className="w-4 h-4 text-primary" />
            <h3 className="font-semibold text-sm" data-testid="heading-objectives">Mục tiêu</h3>
          </div>
          <ul className="space-y-2 ml-6">
            {objectives.map((objective, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground" data-testid={`objective-${i}`}>
                <CheckCircle2 className="w-4 h-4 mt-0.5 text-primary flex-shrink-0" />
                <span className="leading-relaxed">{objective}</span>
              </li>
            ))}
          </ul>
        </div>

        <Separator />

        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-primary" />
            <h3 className="font-semibold text-sm" data-testid="heading-techniques">Kỹ thuật khai thác</h3>
          </div>
          <ScrollArea className="h-[240px] pr-3">
            <div className="space-y-3">
              {techniques.map((tech, i) => (
                <div key={i} className="space-y-1.5" data-testid={`technique-${i}`}>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="text-xs font-mono" data-testid={`badge-technique-${i}`}>
                      {tech.name}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground leading-relaxed ml-1" data-testid={`text-technique-desc-${i}`}>
                    {tech.desc}
                  </p>
                </div>
              ))}
            </div>
          </ScrollArea>
        </div>

        <Separator />

        <div className="space-y-2">
          <h3 className="font-semibold text-sm" data-testid="heading-specs">Đặc điểm kỹ thuật</h3>
          <div className="grid gap-2">
            <div className="flex items-center justify-between gap-2 p-3 rounded-md bg-muted/50" data-testid="spec-redirect-type">
              <span className="text-xs text-muted-foreground">Redirect Type</span>
              <Badge variant="outline" className="font-mono text-xs">302 Found</Badge>
            </div>
            <div className="flex items-center justify-between gap-2 p-3 rounded-md bg-muted/50" data-testid="spec-protection">
              <span className="text-xs text-muted-foreground">Protection</span>
              <Badge variant="outline" className="font-mono text-xs">CSP Strict</Badge>
            </div>
            <div className="flex items-center justify-between gap-2 p-3 rounded-md bg-muted/50" data-testid="spec-vulnerability">
              <span className="text-xs text-muted-foreground">Vulnerability</span>
              <Badge variant="outline" className="font-mono text-xs">DOM XSS</Badge>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

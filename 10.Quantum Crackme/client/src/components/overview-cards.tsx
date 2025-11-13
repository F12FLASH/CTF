import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Info, Cpu, AlertTriangle } from "lucide-react";

export function OverviewCards() {
  return (
    <section id="challenge-overview" className="py-16 lg:py-24">
      <div className="max-w-7xl mx-auto px-6">
        <h2 className="text-3xl lg:text-4xl font-bold mb-12 font-display text-center">
          Tổng Quan <span className="text-primary">Thử Thách</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="hover-elevate border-primary/20" data-testid="card-basic-info">
            <CardHeader>
              <div className="flex items-center gap-2 mb-2">
                <Info className="w-5 h-5 text-primary" />
                <CardTitle className="text-xl font-display">Thông Tin Cơ Bản</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">Tên thử thách:</span>
                <span className="font-mono font-semibold" data-testid="text-challenge-name">Quantum Crackme</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">Thể loại:</span>
                <Badge variant="secondary" className="font-mono" data-testid="badge-category-type">Reverse Engineering</Badge>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">Độ khó:</span>
                <div className="flex gap-0.5">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <span key={star} className="text-primary text-sm">⭐</span>
                  ))}
                </div>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">Cấp độ:</span>
                <Badge className="font-mono bg-destructive/90 hover:bg-destructive" data-testid="badge-level">Master</Badge>
              </div>
            </CardContent>
          </Card>

          <Card className="hover-elevate border-primary/20" data-testid="card-technologies">
            <CardHeader>
              <div className="flex items-center gap-2 mb-2">
                <Cpu className="w-5 h-5 text-primary" />
                <CardTitle className="text-xl font-display">Công Nghệ</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {[
                "CPU-specific Execution",
                "QEMU Emulation",
                "Low-level Programming",
                "Binary Analysis",
                "Hardware Detection"
              ].map((tech, idx) => (
                <div key={idx} className="flex items-center gap-2">
                  <div className="w-1.5 h-1.5 rounded-full bg-primary" />
                  <span className="text-sm font-mono" data-testid={`tech-${idx}`}>{tech}</span>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card className="hover-elevate border-destructive/20" data-testid="card-difficulty">
            <CardHeader>
              <div className="flex items-center gap-2 mb-2">
                <AlertTriangle className="w-5 h-5 text-destructive" />
                <CardTitle className="text-xl font-display">Yêu Cầu</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <div>
                <div className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Kỹ Năng Bắt Buộc</div>
                <div className="space-y-1">
                  {[
                    "Kiến trúc x86",
                    "QEMU internals",
                    "Binary reversing",
                    "Low-level debugging"
                  ].map((skill, idx) => (
                    <div key={idx} className="text-sm font-mono flex items-center gap-2" data-testid={`skill-${idx}`}>
                      <span className="text-primary">›</span>
                      {skill}
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </section>
  );
}

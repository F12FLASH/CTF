import { Shield, Star, Target } from "lucide-react";
import { Badge } from "@/components/ui/badge";

export function ChallengeHero() {
  const difficultyStars = 4;
  
  return (
    <div className="relative min-h-[400px] bg-gradient-to-br from-mars-dark via-background to-mars-dark overflow-hidden border-b border-border">
      {/* Starfield background */}
      <div className="absolute inset-0 opacity-30">
        <div className="absolute w-1 h-1 bg-white rounded-full top-[10%] left-[15%] animate-pulse-glow" />
        <div className="absolute w-1 h-1 bg-white rounded-full top-[20%] left-[85%] animate-pulse-glow" style={{ animationDelay: '0.5s' }} />
        <div className="absolute w-1 h-1 bg-white rounded-full top-[60%] left-[25%] animate-pulse-glow" style={{ animationDelay: '1s' }} />
        <div className="absolute w-1 h-1 bg-white rounded-full top-[80%] left-[75%] animate-pulse-glow" style={{ animationDelay: '1.5s' }} />
        <div className="absolute w-0.5 h-0.5 bg-white rounded-full top-[40%] left-[50%] animate-pulse-glow" style={{ animationDelay: '0.3s' }} />
      </div>

      {/* Mars planet graphic */}
      <div className="absolute right-0 top-1/2 -translate-y-1/2 w-96 h-96 opacity-20 pointer-events-none">
        <div className="absolute inset-0 rounded-full bg-gradient-to-br from-mars-orange via-mars-red to-destructive shadow-glow-orange animate-pulse-glow" />
        <div className="absolute inset-4 rounded-full bg-gradient-to-tl from-mars-orange/50 to-transparent" />
      </div>

      {/* Content */}
      <div className="relative container mx-auto px-4 py-16 flex flex-col items-center text-center z-10">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-6 h-6 text-primary" data-testid="icon-shield" />
          <Badge variant="outline" className="border-primary text-primary font-mono" data-testid="badge-category">
            BẢO MẬT WEB
          </Badge>
        </div>

        <h1 className="text-5xl md:text-6xl font-bold mb-4 bg-gradient-to-r from-foreground via-primary to-foreground bg-clip-text text-transparent" data-testid="text-challenge-title">
          SSRF đến Sao Hỏa
        </h1>

        <p className="text-xl text-muted-foreground mb-6 max-w-2xl" data-testid="text-challenge-description">
          Vượt qua hệ thống lọc yêu cầu phía máy chủ để đến với hành tinh đỏ
        </p>

        <div className="flex flex-wrap items-center justify-center gap-4 mb-8">
          {/* Difficulty stars */}
          <div className="flex items-center gap-1">
            {Array.from({ length: 5 }).map((_, i) => (
              <Star
                key={i}
                className={`w-5 h-5 ${
                  i < difficultyStars
                    ? 'fill-primary text-primary'
                    : 'text-muted'
                }`}
              />
            ))}
            <span className="ml-2 text-sm text-muted-foreground font-mono">Cấp độ Chuyên gia</span>
          </div>

          <div className="w-px h-6 bg-border" />

          <div className="flex items-center gap-2">
            <Target className="w-4 h-4 text-primary" data-testid="icon-target" />
            <span className="text-sm text-muted-foreground font-mono" data-testid="text-points">500 Điểm</span>
          </div>
        </div>

        {/* Objective */}
        <div className="bg-card/50 backdrop-blur-sm border border-card-border rounded-md px-6 py-4 max-w-3xl">
          <div className="flex items-start gap-3">
            <div className="mt-0.5">
              <div className="w-2 h-2 bg-terminal-green rounded-full animate-pulse-glow" />
            </div>
            <div className="text-left">
              <p className="text-sm font-mono text-muted-foreground mb-1">MỤC TIÊU</p>
              <p className="text-foreground">
                Vượt qua hệ thống lọc tên miền để truy cập{" "}
                <code className="px-2 py-0.5 bg-muted rounded text-primary font-mono text-sm">
                  http://localhost:1337
                </code>{" "}
                và lấy được cờ (flag)
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

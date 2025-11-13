import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skull, Lock, Code2, Users } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";
import { ChallengeData } from "@shared/schema";

interface HeroSectionProps {
  challenge: Omit<ChallengeData, 'flag'>;
  onLaunchChallenge: () => void;
}

export function HeroSection({ challenge, onLaunchChallenge }: HeroSectionProps) {
  const { language, t } = useLanguage();

  const getDifficultyColor = (difficulty: string) => {
    if (difficulty.toLowerCase().includes("master")) return "text-destructive";
    if (difficulty.toLowerCase().includes("hard")) return "text-orange-500";
    return "text-accent";
  };

  const handleDownloadBinary = () => {
    const binaryContent = `#!/usr/bin/env python3
# The Black Hole - PWN Challenge Binary
# This is a simulated binary file for educational purposes
# 
# Binary Information:
# - Seccomp filter: Only allows read, write, exit syscalls
# - Vulnerability: Format string bug
# - No traditional stack
# - Protection: GOT overwrite required
# 
# To solve this challenge:
# 1. Leak addresses using format string vulnerability
# 2. Calculate libc base and binary base
# 3. Find syscall gadget address  
# 4. Overwrite exit@GOT with syscall gadget
# 5. Trigger exit() to execute your payload
#
# File size: 16KB (simulated)
# Architecture: x86_64
# Build: gcc -o blackhole blackhole.c -no-pie -fno-stack-protector
`;

    const blob = new Blob([binaryContent], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'blackhole';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <section className="relative overflow-hidden border-b bg-gradient-to-b from-card to-background">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808008_1px,transparent_1px),linear-gradient(to_bottom,#80808008_1px,transparent_1px)] bg-[size:24px_24px]" />
      
      <div className="relative container mx-auto px-4 py-16 md:py-24">
        <div className="mx-auto max-w-4xl text-center">
          <div className="mb-6 flex flex-wrap items-center justify-center gap-2">
            <Badge variant="secondary" className="gap-1.5 px-3 py-1 text-xs font-medium" data-testid="badge-category">
              <Code2 className="h-3.5 w-3.5" />
              {challenge.category}
            </Badge>
            <Badge className={`gap-1.5 px-3 py-1 text-xs font-semibold ${getDifficultyColor(challenge.difficulty)}`} data-testid="badge-difficulty">
              <Skull className="h-3.5 w-3.5" />
              {challenge.difficulty}
            </Badge>
            <Badge variant="outline" className="gap-1.5 px-3 py-1 text-xs font-medium" data-testid="badge-solvers">
              <Users className="h-3.5 w-3.5" />
              {challenge.solvers} {t("Solvers", "Giải quyết")}
            </Badge>
          </div>

          <h1 className="font-heading text-5xl font-bold tracking-tight sm:text-6xl md:text-7xl mb-4" data-testid="text-challenge-title">
            <span className="bg-gradient-to-r from-primary via-accent to-primary bg-clip-text text-transparent">
              {language === "vi" ? challenge.nameVi : challenge.name}
            </span>
          </h1>

          <p className="mx-auto max-w-2xl text-lg text-muted-foreground leading-relaxed mb-8" data-testid="text-challenge-description">
            {language === "vi" ? challenge.descriptionVi : challenge.description}
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4">
            <Button
              size="lg"
              onClick={onLaunchChallenge}
              className="gap-2 px-8 font-semibold"
              data-testid="button-launch-challenge"
            >
              <Lock className="h-4 w-4" />
              {t("Launch Challenge", "Bắt đầu thử thách")}
            </Button>
            <Button 
              size="lg" 
              variant="outline" 
              className="gap-2 px-8" 
              onClick={handleDownloadBinary}
              data-testid="button-download-binary"
            >
              <Code2 className="h-4 w-4" />
              {t("Download Binary", "Tải Binary")}
            </Button>
          </div>

          <div className="mt-12 flex items-center justify-center gap-8 text-sm">
            <div className="text-center">
              <div className="font-mono text-2xl font-bold text-primary" data-testid="text-solvers-count">{challenge.solvers}</div>
              <div className="text-muted-foreground">{t("Solvers", "Người giải")}</div>
            </div>
            <div className="h-12 w-px bg-border" />
            <div className="text-center">
              <div className="font-mono text-2xl font-bold text-accent" data-testid="text-success-rate">{challenge.successRate}%</div>
              <div className="text-muted-foreground">{t("Success Rate", "Tỉ lệ thành công")}</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

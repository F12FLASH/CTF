import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Bug, Lock, Server, Brain } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";
import { ChallengeData } from "@shared/schema";

interface TechnicalSpecsProps {
  challenge: Omit<ChallengeData, 'flag'>;
}

export function TechnicalSpecs({ challenge }: TechnicalSpecsProps) {
  const { t } = useLanguage();

  const specs = [
    {
      icon: Lock,
      title: t("Seccomp Rules", "Quy tắc Seccomp"),
      items: challenge.seccompRules,
      color: "text-primary",
    },
    {
      icon: Bug,
      title: t("Vulnerabilities", "Lỗ hổng"),
      items: challenge.vulnerabilities,
      color: "text-destructive",
    },
    {
      icon: Shield,
      title: t("Protections", "Bảo vệ"),
      items: challenge.protections,
      color: "text-accent",
    },
    {
      icon: Server,
      title: t("Environment", "Môi trường"),
      items: challenge.environment,
      color: "text-chart-3",
    },
    {
      icon: Brain,
      title: t("Required Skills", "Kỹ năng yêu cầu"),
      items: challenge.skills,
      color: "text-chart-4",
    },
  ];

  return (
    <section className="container mx-auto px-4 py-12">
      <div className="mb-8">
        <h2 className="font-heading text-3xl font-bold tracking-tight mb-2" data-testid="text-specs-title">
          {t("Technical Specifications", "Thông số kỹ thuật")}
        </h2>
        <p className="text-muted-foreground" data-testid="text-specs-description">
          {t("Detailed information about the challenge environment and requirements", "Thông tin chi tiết về môi trường thử thách và yêu cầu")}
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        {specs.map((spec, index) => {
          const Icon = spec.icon;
          return (
            <Card key={index} className="hover-elevate" data-testid={`card-spec-${index}`}>
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-2 text-base">
                  <Icon className={`h-5 w-5 ${spec.color}`} />
                  {spec.title}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {spec.items.map((item, idx) => (
                    <Badge key={idx} variant="secondary" className="font-mono text-xs">
                      {item}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </section>
  );
}

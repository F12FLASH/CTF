import { List, CheckCircle2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useLanguage } from "./language-context";

interface Step {
  numberKey: string;
  titleKey: string;
  descKey: string;
}

const steps: Step[] = [
  {
    numberKey: "1",
    titleKey: "step1",
    descKey: "step1Desc",
  },
  {
    numberKey: "2",
    titleKey: "step2",
    descKey: "step2Desc",
  },
  {
    numberKey: "3",
    titleKey: "step3",
    descKey: "step3Desc",
  },
  {
    numberKey: "4",
    titleKey: "step4",
    descKey: "step4Desc",
  },
];

export function AttackMethodology() {
  const { t } = useLanguage();

  return (
    <Card className="lg:sticky lg:top-24" data-testid="card-attack-methodology">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <List className="h-5 w-5 text-primary" />
          {t("attackMethodology")}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ol className="space-y-4">
          {steps.map((step) => (
            <li key={step.numberKey} className="flex gap-4" data-testid={`step-${step.numberKey}`}>
              <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-md bg-primary/10 font-heading font-bold text-primary">
                {step.numberKey}
              </div>
              <div className="flex-1 space-y-1 pt-0.5">
                <h4 className="font-medium leading-snug">{t(step.titleKey)}</h4>
                <p className="text-sm leading-snug text-muted-foreground">
                  {t(step.descKey)}
                </p>
              </div>
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}

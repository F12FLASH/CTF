import { FileText, Settings, Shield } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { useLanguage } from "./language-context";

export function ChallengeInfo() {
  const { t } = useLanguage();

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <FileText className="h-6 w-6 text-primary" />
        <h2 className="font-heading text-2xl font-semibold md:text-3xl">
          {t("challengeInfo")}
        </h2>
      </div>

      <Card data-testid="card-challenge-description">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            {t("description")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="leading-relaxed text-muted-foreground">
            {t("descriptionText")}
          </p>
        </CardContent>
      </Card>

      <Card data-testid="card-technical-specs">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Settings className="h-5 w-5" />
            {t("technicalSpecs")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="space-y-4">
            <div className="flex flex-col gap-1 sm:flex-row sm:gap-4">
              <dt className="min-w-32 font-medium">{t("hashFunction")}:</dt>
              <dd className="font-mono text-sm text-muted-foreground">MD5</dd>
            </div>
            <div className="flex flex-col gap-1 sm:flex-row sm:gap-4">
              <dt className="min-w-32 font-medium">{t("format")}:</dt>
              <dd className="font-mono text-sm text-muted-foreground">
                {t("formatValue")}
              </dd>
            </div>
            <div className="flex flex-col gap-1 sm:flex-row sm:gap-4">
              <dt className="min-w-32 font-medium">{t("comparison")}:</dt>
              <dd className="font-mono text-sm text-muted-foreground">
                {t("comparisonValue")}
              </dd>
            </div>
            <div className="flex flex-col gap-1 sm:flex-row sm:gap-4">
              <dt className="min-w-32 font-medium">{t("flagLength")}:</dt>
              <dd className="font-mono text-sm text-muted-foreground">
                {t("flagLengthValue")}
              </dd>
            </div>
            <div className="flex flex-col gap-1 sm:flex-row sm:gap-4">
              <dt className="min-w-32 font-medium">{t("oracleAccess")}:</dt>
              <dd className="font-mono text-sm text-muted-foreground">
                {t("oracleAccessValue")}
              </dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      <Card data-testid="card-attack-vectors">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            {t("attackVectors")}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="vector1" data-testid="accordion-vector-1">
              <AccordionTrigger className="font-medium">
                {t("vector1Title")}
              </AccordionTrigger>
              <AccordionContent className="text-muted-foreground">
                {t("vector1Desc")}
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vector2" data-testid="accordion-vector-2">
              <AccordionTrigger className="font-medium">
                {t("vector2Title")}
              </AccordionTrigger>
              <AccordionContent className="text-muted-foreground">
                {t("vector2Desc")}
              </AccordionContent>
            </AccordionItem>

            <AccordionItem value="vector3" data-testid="accordion-vector-3">
              <AccordionTrigger className="font-medium">
                {t("vector3Title")}
              </AccordionTrigger>
              <AccordionContent className="text-muted-foreground">
                {t("vector3Desc")}
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </CardContent>
      </Card>
    </div>
  );
}

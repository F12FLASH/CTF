import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Lightbulb } from "lucide-react";

interface HintsSectionProps {
  hints: string[];
}

export function HintsSection({ hints }: HintsSectionProps) {
  return (
    <Card className="border-chart-3/30 bg-card/50 backdrop-blur-sm" data-testid="card-hints">
      <CardHeader className="pb-4">
        <CardTitle className="text-lg font-mono flex items-center gap-2">
          <Lightbulb className="h-5 w-5 text-chart-3" />
          Gợi Ý Từng Bước
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Accordion type="single" collapsible className="space-y-2">
          {hints.map((hint, index) => (
            <AccordionItem
              key={index}
              value={`hint-${index}`}
              className="border border-border rounded-md px-4 bg-secondary/30"
              data-testid={`accordion-hint-${index}`}
            >
              <AccordionTrigger className="font-mono text-sm hover:no-underline py-3">
                <span className="text-chart-3">Gợi Ý #{index + 1}</span>
              </AccordionTrigger>
              <AccordionContent className="font-mono text-xs text-muted-foreground pt-2 pb-3 leading-relaxed">
                {hint}
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </CardContent>
    </Card>
  );
}

import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { useLanguage } from "@/components/app-sidebar";
import { BookOpen, Code2, Lightbulb, Wrench, Shield, Target } from "lucide-react";
import type { Instruction } from "@shared/schema";

const categoryIcons = {
  overview: BookOpen,
  theory: Lightbulb,
  technique: Code2,
  walkthrough: Target,
  resources: Wrench,
  security: Shield,
};

const categoryLabels = {
  overview: { en: "Overview", vi: "Tổng Quan" },
  theory: { en: "Theory", vi: "Lý Thuyết" },
  technique: { en: "Techniques", vi: "Kỹ Thuật" },
  walkthrough: { en: "Walkthrough", vi: "Hướng Dẫn" },
  resources: { en: "Resources", vi: "Tài Nguyên" },
  security: { en: "Security", vi: "Bảo Mật" },
};

export default function Instructions() {
  const { lang } = useLanguage();

  const { data: instructions = [], isLoading } = useQuery<Instruction[]>({
    queryKey: ["/api/instructions"],
  });

  const categories = ["overview", "theory", "technique", "walkthrough", "resources", "security"];
  
  const instructionsByCategory = categories.reduce((acc, category) => {
    acc[category] = instructions.filter(i => i.category === category);
    return acc;
  }, {} as Record<string, Instruction[]>);

  if (isLoading) {
    return (
      <div className="container mx-auto p-6 space-y-4">
        <Skeleton className="h-12 w-64" />
        <Skeleton className="h-[500px] w-full" />
      </div>
    );
  }

  return (
    <div className="flex flex-col flex-1 min-h-0 h-full">
      <div className="container mx-auto p-6 space-y-6 overflow-y-auto flex-1 min-h-0" data-testid="page-instructions">
      <div className="space-y-2">
        <div className="flex items-center gap-3">
          <BookOpen className="h-8 w-8 text-primary" />
          <div>
            <h1 className="text-3xl font-bold tracking-tight">
              {lang === "vi" ? "Hướng Dẫn Chi Tiết" : "Detailed Instructions"}
            </h1>
            <p className="text-muted-foreground">
              {lang === "vi" 
                ? "Học cách khai thác The Phoenix challenge từng bước một"
                : "Learn how to exploit The Phoenix challenge step by step"}
            </p>
          </div>
        </div>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="grid w-full grid-cols-6 gap-2">
          {categories.map((category) => {
            const Icon = categoryIcons[category as keyof typeof categoryIcons];
            const label = categoryLabels[category as keyof typeof categoryLabels];
            return (
              <TabsTrigger
                key={category}
                value={category}
                className="flex items-center gap-2"
                data-testid={`tab-${category}`}
              >
                <Icon className="h-4 w-4" />
                <span className="hidden sm:inline">{lang === "vi" ? label.vi : label.en}</span>
              </TabsTrigger>
            );
          })}
        </TabsList>

        {categories.map((category) => (
          <TabsContent key={category} value={category} className="space-y-3">
            <Accordion type="single" collapsible className="w-full space-y-2">
              {instructionsByCategory[category]?.map((instruction, index) => (
                <AccordionItem 
                  key={instruction.id} 
                  value={instruction.id}
                  className="border rounded-lg px-1 bg-card"
                >
                  <AccordionTrigger className="px-4" data-testid={`instruction-trigger-${index}`}>
                    <div className="flex items-center gap-3 text-left w-full">
                      <Badge variant="outline" className="min-w-6">
                        {instruction.orderIndex}
                      </Badge>
                      <span className="font-semibold">
                        {lang === "vi" && instruction.titleVi ? instruction.titleVi : instruction.title}
                      </span>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent className="px-4 pb-4">
                    <div className="space-y-3">
                      <p className="text-muted-foreground whitespace-pre-wrap text-sm">
                        {lang === "vi" && instruction.contentVi ? instruction.contentVi : instruction.content}
                      </p>
                      {instruction.codeExample && (
                        <div>
                          <div className="flex items-center gap-2 mb-2">
                            <Code2 className="h-4 w-4" />
                            <span className="text-sm font-semibold">
                              {lang === "vi" ? "Ví Dụ Code" : "Code Example"}
                            </span>
                          </div>
                          <div className="rounded-md bg-muted p-4 font-mono text-sm overflow-x-auto">
                            <pre className="text-foreground">{instruction.codeExample}</pre>
                          </div>
                        </div>
                      )}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>

            {(!instructionsByCategory[category] || instructionsByCategory[category].length === 0) && (
              <Card>
                <CardContent className="flex items-center justify-center py-12">
                  <p className="text-muted-foreground">
                    {lang === "vi" 
                      ? "Chưa có hướng dẫn cho phần này"
                      : "No instructions available for this section"}
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>
        ))}
      </Tabs>
      </div>
    </div>
  );
}

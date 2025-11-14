import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Lightbulb, Lock, Unlock } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import type { Hint } from "@shared/schema";

export function HintsPanel() {
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const { data: hints = [] } = useQuery<Hint[]>({
    queryKey: ["/api/hints"],
  });

  const revealHintMutation = useMutation({
    mutationFn: async (hintId: string) => {
      return await apiRequest("POST", `/api/hints/${hintId}/reveal`, {});
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/hints"] });
      toast({
        title: "Đã mở khóa gợi ý",
        description: "Gợi ý mới đã được mở khóa thành công.",
      });
    },
    onError: () => {
      toast({
        title: "Không thể mở khóa gợi ý",
        description: "Không thể mở khóa gợi ý này.",
        variant: "destructive",
      });
    },
  });

  const revealedCount = hints.filter((h) => h.revealed).length;

  return (
    <Card data-testid="card-hints">
      <CardHeader className="space-y-1">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="flex items-center justify-center w-8 h-8 rounded-md bg-primary/10">
              <Lightbulb className="w-4 h-4 text-primary" data-testid="icon-hints" />
            </div>
            <CardTitle className="text-lg" data-testid="title-hints">Gợi Ý Từng Bước</CardTitle>
          </div>
          <Badge variant="outline" className="font-mono text-xs" data-testid="badge-hints-progress">
            {revealedCount}/{hints.length}
          </Badge>
        </div>
        <CardDescription data-testid="text-hints-description">
          Mở khóa gợi ý để hướng dẫn hành trình khai thác của bạn
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-4">
        {hints.length === 0 ? (
          <div className="text-center py-8 text-sm text-muted-foreground">
            Không có gợi ý nào
          </div>
        ) : (
          <Accordion type="single" collapsible className="space-y-2">
            {hints.map((hint) => (
              <AccordionItem
                key={hint.id}
                value={hint.id}
                className="border rounded-md px-4 bg-card"
                data-testid={`hint-item-${hint.id}`}
              >
                <AccordionTrigger className="hover:no-underline py-3" data-testid={`accordion-trigger-${hint.id}`}>
                  <div className="flex items-center gap-3 w-full">
                    <div className={`flex items-center justify-center w-8 h-8 rounded-md ${
                      hint.revealed ? "bg-primary/10" : "bg-muted"
                    }`}>
                      {hint.revealed ? (
                        <Unlock className="w-4 h-4 text-primary" data-testid={`icon-unlocked-${hint.id}`} />
                      ) : (
                        <Lock className="w-4 h-4 text-muted-foreground" data-testid={`icon-locked-${hint.id}`} />
                      )}
                    </div>
                    <div className="flex-1 text-left">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-medium" data-testid={`text-hint-title-${hint.id}`}>{hint.title}</span>
                        <Badge variant="outline" className="text-xs" data-testid={`badge-hint-level-${hint.id}`}>
                          Cấp {hint.level}
                        </Badge>
                      </div>
                    </div>
                  </div>
                </AccordionTrigger>
                <AccordionContent className="pb-3 pt-2">
                  {hint.revealed ? (
                    <div className="p-3 rounded-md bg-muted/50 border">
                      <p className="text-sm text-foreground leading-relaxed" data-testid={`text-hint-content-${hint.id}`}>
                        {hint.content}
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      <p className="text-xs text-muted-foreground">
                        Gợi ý này đang bị khóa. Mở khóa để xem nội dung.
                      </p>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => revealHintMutation.mutate(hint.id)}
                        disabled={revealHintMutation.isPending}
                        data-testid={`button-reveal-hint-${hint.id}`}
                        className="gap-2"
                      >
                        <Unlock className="w-3.5 h-3.5" />
                        Mở Khóa Gợi Ý
                      </Button>
                    </div>
                  )}
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        )}

        <div className="p-3 rounded-md bg-muted/50 border">
          <p className="text-xs text-muted-foreground leading-relaxed">
            Gợi ý được sắp xếp theo độ khó. Bắt đầu từ Cấp 1 và tiến triển
            tuần tự để có trải nghiệm học tập tốt nhất.
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

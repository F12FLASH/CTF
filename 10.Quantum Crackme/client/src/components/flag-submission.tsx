import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Flag, Send, CheckCircle2, XCircle } from "lucide-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Submission } from "@shared/schema";

export function FlagSubmission() {
  const [flagInput, setFlagInput] = useState("");
  const { toast } = useToast();

  const submitMutation = useMutation({
    mutationFn: async (flag: string) => {
      const response = await apiRequest("POST", "/api/submissions", { attemptedFlag: flag });
      return await response.json() as { success: boolean; message: string };
    },
    onSuccess: (data: { success: boolean; message: string }) => {
      if (data.success) {
        toast({
          title: "✓ Flag Correct!",
          description: "Chúc mừng! Bạn đã giải quyết thành công thử thách này.",
          className: "border-primary bg-primary/10",
        });
        setFlagInput("");
      } else {
        toast({
          title: "✗ Flag Incorrect",
          description: "Flag không đúng. Hãy thử lại!",
          variant: "destructive",
        });
      }
      queryClient.invalidateQueries({ queryKey: ["/api/submissions"] });
      queryClient.invalidateQueries({ queryKey: ["/api/submissions/stats"] });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (flagInput.trim()) {
      submitMutation.mutate(flagInput.trim());
    }
  };

  const { data: stats } = useQuery<{ total: number; correct: number }>({
    queryKey: ["/api/submissions/stats"],
  });

  return (
    <section id="flag-submission" className="py-16 lg:py-24">
      <div className="max-w-4xl mx-auto px-6">
        <h2 className="text-3xl lg:text-4xl font-bold mb-12 font-display text-center">
          Nộp <span className="text-primary">Flag</span>
        </h2>

        <Card className="border-primary/30 shadow-xl shadow-primary/5" data-testid="card-flag-submission">
          <CardHeader className="bg-gradient-to-r from-primary/5 to-transparent border-b border-primary/20">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-primary/10">
                <Flag className="w-5 h-5 text-primary" />
              </div>
              <div>
                <CardTitle className="font-display text-2xl">Terminal Flag Submission</CardTitle>
                <p className="text-sm text-muted-foreground mt-1">
                  Nhập flag bạn tìm được từ binary
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-6 space-y-6">
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="bg-background border-2 border-primary/30 rounded-lg p-4 font-mono">
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-primary">flag@quantum:~$</span>
                  <Input
                    type="text"
                    placeholder="VNFLAG{...}"
                    value={flagInput}
                    onChange={(e) => setFlagInput(e.target.value)}
                    className="flex-1 border-0 bg-transparent focus-visible:ring-0 font-mono text-sm px-0"
                    data-testid="input-flag"
                  />
                </div>
              </div>

              <Button
                type="submit"
                className="w-full gap-2 uppercase tracking-wider font-mono"
                disabled={submitMutation.isPending || !flagInput.trim()}
                data-testid="button-submit-flag"
              >
                {submitMutation.isPending ? (
                  <>Submitting...</>
                ) : (
                  <>
                    <Send className="w-4 h-4" />
                    Execute Submit
                  </>
                )}
              </Button>
            </form>

            {stats && (
              <div className="grid grid-cols-2 gap-4 pt-4 border-t border-border">
                <div className="text-center" data-testid="stat-total-submissions">
                  <div className="text-3xl font-bold font-mono">{stats.total}</div>
                  <div className="text-xs text-muted-foreground uppercase tracking-wider">Total Attempts</div>
                </div>
                <div className="text-center" data-testid="stat-correct-submissions">
                  <div className="text-3xl font-bold font-mono text-primary">{stats.correct}</div>
                  <div className="text-xs text-muted-foreground uppercase tracking-wider">Successful</div>
                </div>
              </div>
            )}

            <div className="bg-muted/30 rounded-lg p-4 text-xs font-mono space-y-1">
              <div className="text-muted-foreground">// Flag format:</div>
              <div>VNFLAG{"{"}<span className="text-primary">YOUR_FLAG_HERE</span>{"}"}</div>
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

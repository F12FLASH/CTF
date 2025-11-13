import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Flag, Check, X, Loader2, Eye } from "lucide-react";
import { useLanguage } from "@/contexts/LanguageContext";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface SubmissionResponse {
  id: string;
  isCorrect: boolean;
  submittedAt: string;
  revealToken?: string;
  revealTokenExpiresAt?: string;
}

export function FlagSubmission() {
  const [flag, setFlag] = useState("");
  const [result, setResult] = useState<"correct" | "incorrect" | null>(null);
  const [revealedFlag, setRevealedFlag] = useState<string | null>(null);
  const [revealToken, setRevealToken] = useState<string | null>(null);
  const { t } = useLanguage();
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const submitFlagMutation = useMutation({
    mutationFn: async (submittedFlag: string) => {
      return await apiRequest<SubmissionResponse>("POST", "/api/submissions", {
        challengeId: "the-black-hole",
        flag: submittedFlag,
      });
    },
    onSuccess: (submission) => {
      setResult(submission.isCorrect ? "correct" : "incorrect");
      
      if (submission.isCorrect && submission.revealToken) {
        setRevealToken(submission.revealToken);
        toast({
          title: t("Congratulations!", "Chúc mừng!"),
          description: t("You've successfully solved The Black Hole! Click 'Reveal Flag' to see it.", "Bạn đã giải quyết thành công Lỗ Đen! Nhấp 'Hiện Flag' để xem."),
        });
      } else {
        toast({
          title: t("Incorrect Flag", "Flag không đúng"),
          description: t("Keep trying! Review the exploitation steps.", "Tiếp tục thử! Xem lại các bước khai thác."),
          variant: "destructive",
        });
      }
    },
    onError: () => {
      toast({
        title: t("Submission Error", "Lỗi gửi"),
        description: t("Failed to submit flag. Please try again.", "Không thể gửi flag. Vui lòng thử lại."),
        variant: "destructive",
      });
    },
  });

  const revealFlagMutation = useMutation({
    mutationFn: async (token: string) => {
      return await apiRequest<{ flag: string }>("POST", "/api/reveal-flag", { token });
    },
    onSuccess: (data) => {
      setRevealedFlag(data.flag);
      toast({
        title: t("Flag Revealed!", "Đã hiện Flag!"),
        description: t("Copy the flag below", "Sao chép flag bên dưới"),
      });
    },
    onError: () => {
      toast({
        title: t("Reveal Error", "Lỗi hiện flag"),
        description: t("Failed to reveal flag. Token may have expired.", "Không thể hiện flag. Token có thể đã hết hạn."),
        variant: "destructive",
      });
    },
  });

  const handleSubmit = () => {
    if (!flag.trim()) {
      toast({
        title: t("Empty Flag", "Flag trống"),
        description: t("Please enter a flag before submitting", "Vui lòng nhập flag trước khi gửi"),
        variant: "destructive",
      });
      return;
    }
    submitFlagMutation.mutate(flag);
  };

  return (
    <section className="container mx-auto px-4 py-12">
      <Card className={result === "correct" ? "border-primary" : result === "incorrect" ? "border-destructive" : ""}>
        <CardHeader>
          <CardTitle className="flex items-center gap-2" data-testid="text-flag-title">
            <Flag className="h-5 w-5 text-primary" />
            {t("Submit Flag", "Gửi Flag")}
          </CardTitle>
          <CardDescription data-testid="text-flag-description">
            {t("Enter the flag in the format: VNFLAG{...}", "Nhập flag theo định dạng: VNFLAG{...}")}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-2">
            <Input
              value={flag}
              onChange={(e) => setFlag(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
              placeholder="VNFLAG{...}"
              className="flex-1 font-mono"
              disabled={submitFlagMutation.isPending}
              data-testid="input-flag"
            />
            <Button
              onClick={handleSubmit}
              disabled={submitFlagMutation.isPending}
              className="gap-2 min-w-[120px]"
              data-testid="button-submit-flag"
            >
              {submitFlagMutation.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  {t("Checking...", "Đang kiểm tra...")}
                </>
              ) : (
                <>
                  <Flag className="h-4 w-4" />
                  {t("Submit", "Gửi")}
                </>
              )}
            </Button>
          </div>

          {result && (
            <div
              className={`flex items-center gap-2 rounded-md p-4 ${
                result === "correct" ? "bg-primary/10 text-primary" : "bg-destructive/10 text-destructive"
              }`}
              data-testid={`result-${result}`}
            >
              {result === "correct" ? (
                <>
                  <Check className="h-5 w-5" />
                  <span className="font-semibold">
                    {t("Correct! You've mastered The Black Hole!", "Đúng! Bạn đã làm chủ Lỗ Đen!")}
                  </span>
                </>
              ) : (
                <>
                  <X className="h-5 w-5" />
                  <span className="font-semibold">
                    {t("Incorrect flag. Try again!", "Flag không đúng. Thử lại!")}
                  </span>
                </>
              )}
            </div>
          )}

          {result === "correct" && revealToken && !revealedFlag && (
            <div className="flex gap-2">
              <Button
                onClick={() => revealFlagMutation.mutate(revealToken)}
                disabled={revealFlagMutation.isPending}
                className="gap-2"
                data-testid="button-reveal-flag"
              >
                {revealFlagMutation.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    {t("Revealing...", "Đang hiện...")}
                  </>
                ) : (
                  <>
                    <Eye className="h-4 w-4" />
                    {t("Reveal Flag", "Hiện Flag")}
                  </>
                )}
              </Button>
            </div>
          )}

          {revealedFlag && (
            <div className="rounded-md bg-primary/10 p-4 space-y-2">
              <div className="flex items-center gap-2 text-primary font-semibold">
                <Flag className="h-5 w-5" />
                <span>{t("Your Flag:", "Flag của bạn:")}</span>
              </div>
              <div 
                className="font-mono text-sm bg-background/50 p-3 rounded border border-primary/20 break-all select-all"
                data-testid="text-revealed-flag"
              >
                {revealedFlag}
              </div>
            </div>
          )}

          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Badge variant="outline" className="font-mono text-xs">
              {t("Hint", "Gợi ý")}
            </Badge>
            <span>
              {t("Use the exploitation guide and simulator to find the flag", "Sử dụng hướng dẫn khai thác và mô phỏng để tìm flag")}
            </span>
          </div>
        </CardContent>
      </Card>
    </section>
  );
}

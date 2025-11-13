import { useState } from "react";
import { Trophy, Send, Loader2, CheckCircle2, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card } from "@/components/ui/card";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import type { FlagSubmission, FlagSubmissionResponse } from "@shared/schema";
import { useToast } from "@/hooks/use-toast";

export function FlagSubmitCard() {
  const [flag, setFlag] = useState("");
  const [userAlias, setUserAlias] = useState("");
  const { toast } = useToast();

  const submitMutation = useMutation<FlagSubmissionResponse, Error, FlagSubmission>({
    mutationFn: async (data: FlagSubmission) => {
      const response = await apiRequest("POST", "/api/flag", data);
      return await response.json() as FlagSubmissionResponse;
    },
    onSuccess: (data) => {
      if (data.success) {
        toast({
          title: "🎉 Thành công!",
          description: data.message,
          variant: "default",
        });
        setFlag("");
        setUserAlias("");
      } else {
        toast({
          title: "❌ Không chính xác",
          description: data.message,
          variant: "destructive",
        });
      }
    },
    onError: () => {
      toast({
        title: "❌ Lỗi",
        description: "Không thể gửi flag. Vui lòng thử lại.",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (flag.trim()) {
      submitMutation.mutate({ 
        flag: flag.trim(),
        userAlias: userAlias.trim() || undefined,
      });
    }
  };

  return (
    <Card className="bg-card border-card-border shadow-glow-orange overflow-hidden">
      <div className="bg-gradient-to-r from-primary/20 to-primary/5 border-b border-border px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-full bg-primary/20 flex items-center justify-center">
            <Trophy className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h3 className="text-lg font-bold" data-testid="text-flag-submit-heading">Gửi Flag</h3>
            <p className="text-sm text-muted-foreground font-mono">Hoàn thành thử thách</p>
          </div>
        </div>
      </div>

      <div className="p-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="flag-input" className="text-sm font-mono text-muted-foreground">
              Flag <span className="text-destructive">*</span>
            </label>
            <Input
              id="flag-input"
              data-testid="input-flag"
              type="text"
              value={flag}
              onChange={(e) => setFlag(e.target.value)}
              placeholder="VNFLAG{...}"
              className="font-mono"
              disabled={submitMutation.isPending}
              required
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="alias-input" className="text-sm font-mono text-muted-foreground">
              Tên hiển thị (tùy chọn)
            </label>
            <Input
              id="alias-input"
              data-testid="input-alias"
              type="text"
              value={userAlias}
              onChange={(e) => setUserAlias(e.target.value)}
              placeholder="Hacker123"
              className="font-mono"
              disabled={submitMutation.isPending}
              maxLength={50}
            />
          </div>

          <Button
            data-testid="button-submit-flag"
            type="submit"
            disabled={submitMutation.isPending || !flag.trim()}
            className="w-full gap-2"
          >
            {submitMutation.isPending ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Đang gửi...
              </>
            ) : (
              <>
                <Send className="w-4 h-4" />
                Gửi Flag
              </>
            )}
          </Button>

          {submitMutation.data && (
            <div className={`mt-4 p-4 rounded-md border flex items-start gap-3 ${
              submitMutation.data.success 
                ? 'bg-terminal-green/10 border-terminal-green text-terminal-green' 
                : 'bg-terminal-red/10 border-terminal-red text-terminal-red'
            }`} data-testid="submission-result">
              {submitMutation.data.success ? (
                <CheckCircle2 className="w-5 h-5 shrink-0 mt-0.5" />
              ) : (
                <XCircle className="w-5 h-5 shrink-0 mt-0.5" />
              )}
              <div className="flex-1">
                <p className="font-mono text-sm font-semibold">
                  {submitMutation.data.message}
                </p>
                {submitMutation.data.points && (
                  <p className="font-mono text-xs mt-1 opacity-90">
                    Điểm: {submitMutation.data.points}
                  </p>
                )}
              </div>
            </div>
          )}
        </form>

        <div className="mt-6 pt-6 border-t border-border">
          <p className="text-xs text-muted-foreground font-mono">
            💡 Mẹo: Bạn cần bypass SSRF filter và truy cập http://localhost:1337/flag để lấy được flag
          </p>
        </div>
      </div>
    </Card>
  );
}

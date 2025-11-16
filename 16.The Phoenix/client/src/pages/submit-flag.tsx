import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { 
  Card, 
  CardContent, 
  CardDescription, 
  CardHeader, 
  CardTitle 
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { useLanguage } from "@/components/app-sidebar";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { 
  CheckCircle2, 
  XCircle, 
  Loader2, 
  Trophy, 
  Flag as FlagIcon, 
  Sparkles 
} from "lucide-react";
import type { Challenge } from "@shared/schema";

interface SubmitResult {
  correct: boolean;
  flag?: string;
  message?: string;
  messageVi?: string;
}

export default function SubmitFlag() {
  const { lang } = useLanguage();
  const { toast } = useToast();
  const [flagInput, setFlagInput] = useState("");
  const [submitResult, setSubmitResult] = useState<SubmitResult | null>(null);

  const { data: challenge, isLoading } = useQuery<Challenge>({
    queryKey: ["/api/challenge"],
  });

  const submitFlagMutation = useMutation<SubmitResult, Error, string>({
    mutationFn: async (flag: string) => {
      const response = await apiRequest("POST", "/api/flags/submit", { flag });
      return await response.json();
    },
    onSuccess: (data: SubmitResult) => {
      setSubmitResult(data);
      
      if (data.correct) {
        queryClient.invalidateQueries({ queryKey: ["/api/challenge"] });
        triggerConfetti();
        
        toast({
          title: lang === "vi" ? "Chúc Mừng! 🎉" : "Congratulations! 🎉",
          description: getLocalizedMessage(data),
        });
      } else {
        toast({
          title: lang === "vi" ? "Flag Không Đúng" : "Incorrect Flag",
          description: getLocalizedMessage(data),
          variant: "destructive",
        });
      }
    },
    onError: (error: Error) => {
      toast({
        title: lang === "vi" ? "Lỗi" : "Error",
        description: error.message || (
          lang === "vi" ? "Không thể submit flag" : "Failed to submit flag"
        ),
        variant: "destructive",
      });
    },
  });

  const triggerConfetti = () => {
    if (typeof window === 'undefined') return;

    const randomInRange = (min: number, max: number) => {
      return Math.random() * (max - min) + min;
    };
    
    const duration = 5000;
    const animationEnd = Date.now() + duration;
    const defaults = { 
      startVelocity: 30, 
      spread: 360, 
      ticks: 60, 
      zIndex: 0 
    };

    const interval = setInterval(() => {
      const timeLeft = animationEnd - Date.now();

      if (timeLeft <= 0) {
        return clearInterval(interval);
      }

      const particleCount = 50 * (timeLeft / duration);
      
      if ((window as any).confetti) {
        (window as any).confetti({ 
          ...defaults, 
          particleCount,
          origin: { x: randomInRange(0.1, 0.3), y: Math.random() - 0.2 }
        });
        (window as any).confetti({ 
          ...defaults, 
          particleCount,
          origin: { x: randomInRange(0.7, 0.9), y: Math.random() - 0.2 }
        });
      }
    }, 250);
  };

  const getLocalizedMessage = (data: SubmitResult): string => {
    return lang === "vi" ? data.messageVi || data.message || "" : data.message || "";
  };

  const getLocalizedChallengeName = (challenge: Challenge): string => {
    return lang === "vi" && challenge.nameVi ? challenge.nameVi : challenge.name;
  };

  const getLocalizedChallengeDescription = (challenge: Challenge): string => {
    return lang === "vi" && challenge.descriptionVi ? challenge.descriptionVi : challenge.description;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!flagInput.trim()) {
      toast({
        title: lang === "vi" ? "Lỗi" : "Error",
        description: lang === "vi" ? "Vui lòng nhập flag" : "Please enter a flag",
        variant: "destructive",
      });
      return;
    }
    
    submitFlagMutation.mutate(flagInput);
  };

  const renderDifficultyIndicator = (difficulty: number) => {
    return (
      <div className="flex gap-1 mt-1">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className={`h-2 w-8 rounded ${
              i < difficulty ? 'bg-primary' : 'bg-muted'
            }`}
          />
        ))}
      </div>
    );
  };

  const renderHints = (hints: Record<string, string>) => {
    if (!hints || Object.keys(hints).length === 0) return null;

    return (
      <div className="space-y-2">
        <h4 className="text-sm font-semibold flex items-center gap-2">
          <Sparkles className="h-4 w-4" />
          {lang === "vi" ? "Gợi Ý" : "Hints"}
        </h4>
        <ul className="text-sm text-muted-foreground space-y-1 ml-6">
          {Object.entries(hints).map(([key, hint]) => (
            <li key={key} className="list-disc">{String(hint)}</li>
          ))}
        </ul>
      </div>
    );
  };

  const renderChallengeCard = () => {
    if (!challenge) return null;

    return (
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <Trophy className="h-5 w-5" />
              {getLocalizedChallengeName(challenge)}
            </CardTitle>
            <Badge variant={challenge.isSolved ? "default" : "outline"}>
              {lang === "vi" 
                ? (challenge.isSolved ? "Đã Giải" : "Chưa Giải")
                : (challenge.isSolved ? "Solved" : "Unsolved")}
            </Badge>
          </div>
          <CardDescription>
            {getLocalizedChallengeDescription(challenge)}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">
                {lang === "vi" ? "Độ Khó:" : "Difficulty:"}
              </span>
              {renderDifficultyIndicator(challenge.difficulty)}
            </div>
            <div>
              <span className="text-muted-foreground">
                {lang === "vi" ? "Lần Thử:" : "Attempts:"}
              </span>
              <div className="font-semibold mt-1">{challenge.totalAttempts}</div>
            </div>
          </div>

          {challenge.hints && typeof challenge.hints === 'object' && challenge.hints !== null
            ? renderHints(challenge.hints as Record<string, string>)
            : null}
        </CardContent>
      </Card>
    );
  };

  const renderFlagInputForm = () => {
    if (challenge?.isSolved) return null;

    return (
      <Card>
        <CardHeader>
          <CardTitle>{lang === "vi" ? "Nhập Flag" : "Enter Flag"}</CardTitle>
          <CardDescription>
            {lang === "vi" 
              ? "Nhập flag bạn tìm được để hoàn thành thử thách"
              : "Enter the flag you discovered to complete the challenge"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="flag">{lang === "vi" ? "Flag" : "Flag"}</Label>
              <Input
                id="flag"
                data-testid="input-flag"
                placeholder="VNFLAG{...}"
                value={flagInput}
                onChange={(e) => setFlagInput(e.target.value)}
                className="font-mono"
              />
            </div>
            <Button 
              type="submit" 
              className="w-full"
              disabled={submitFlagMutation.isPending}
              data-testid="button-submit-flag"
            >
              {submitFlagMutation.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  {lang === "vi" ? "Đang Kiểm Tra..." : "Checking..."}
                </>
              ) : (
                <>
                  <FlagIcon className="mr-2 h-4 w-4" />
                  {lang === "vi" ? "Nộp Flag" : "Submit Flag"}
                </>
              )}
            </Button>
          </form>

          {submitResult && !submitResult.correct && (
            <div className="mt-4 p-4 rounded-md bg-destructive/10 border border-destructive/20 flex items-start gap-3">
              <XCircle className="h-5 w-5 text-destructive mt-0.5" />
              <div className="flex-1">
                <h4 className="font-semibold text-destructive">
                  {lang === "vi" ? "Flag Không Đúng" : "Incorrect Flag"}
                </h4>
                <p className="text-sm text-muted-foreground mt-1">
                  {getLocalizedMessage(submitResult)}
                </p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    );
  };

  const renderSuccessCard = () => {
    if (!challenge?.isSolved) return null;

    return (
      <Card className="border-primary/50 bg-primary/5">
        <CardContent className="pt-6">
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center">
              <CheckCircle2 className="h-6 w-6 text-primary" />
            </div>
            <div className="flex-1">
              <h3 className="font-semibold text-lg">
                {lang === "vi" ? "Thử Thách Đã Hoàn Thành!" : "Challenge Completed!"}
              </h3>
              <p className="text-sm text-muted-foreground">
                {lang === "vi" 
                  ? "Bạn đã giải thành công thử thách này!"
                  : "You have successfully solved this challenge!"}
              </p>
              {challenge.solvedAt && (
                <p className="text-xs text-muted-foreground mt-1">
                  {lang === "vi" ? "Giải lúc: " : "Solved at: "}
                  {new Date(challenge.solvedAt).toLocaleString(
                    lang === "vi" ? "vi-VN" : "en-US"
                  )}
                </p>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    );
  };

  const renderOfficialFlag = () => {
    if (!submitResult?.correct || !submitResult.flag) return null;

    return (
      <Card className="border-primary">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Trophy className="h-5 w-5 text-primary" />
            {lang === "vi" ? "Flag Chính Thức" : "Official Flag"}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="p-4 rounded-md bg-muted font-mono text-sm break-all">
            {submitResult.flag}
          </div>
        </CardContent>
      </Card>
    );
  };

  if (isLoading) {
    return (
      <div className="container mx-auto p-6 flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin" />
      </div>
    );
  }

  return (
    <div className="flex flex-col flex-1 min-h-0 h-full">
      <div 
        className="container mx-auto p-6 space-y-6 overflow-y-auto flex-1 min-h-0" 
        data-testid="page-submit-flag"
      >
        {/* Header Section */}
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <FlagIcon className="h-8 w-8" />
            <h1 className="text-3xl font-bold tracking-tight">
              {lang === "vi" ? "Nộp Flag" : "Submit Flag"}
            </h1>
          </div>
          <p className="text-muted-foreground">
            {lang === "vi" 
              ? "Hoàn thành thử thách và nộp flag của bạn"
              : "Complete the challenge and submit your flag"}
          </p>
        </div>

        {/* Challenge Information */}
        {renderChallengeCard()}

        {/* Flag Input Form */}
        {renderFlagInputForm()}

        {/* Success State */}
        {renderSuccessCard()}

        {/* Official Flag Display */}
        {renderOfficialFlag()}
      </div>
    </div>
  );
}
import { useState } from "react";
import { Flag, Send, Loader2, CheckCircle2, XCircle } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { useLanguage } from "./language-context";

interface FlagSubmissionProps {
  onSubmit: (flag: string) => void;
  isLoading?: boolean;
  result?: { correct: boolean; message: string } | null;
}

export function FlagSubmission({ onSubmit, isLoading = false, result }: FlagSubmissionProps) {
  const { t } = useLanguage();
  const [flag, setFlag] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (flag.trim() && !isLoading) {
      onSubmit(flag);
    }
  };

  return (
    <Card data-testid="card-flag-submission">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Flag className="h-5 w-5 text-primary" />
          {t("submitFlag")}
        </CardTitle>
        <CardDescription>
          Once you've exploited the vulnerability, submit the flag here
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="flag-input" className="text-base font-medium">
              Flag
            </Label>
            <Input
              id="flag-input"
              placeholder={t("flagPlaceholder")}
              value={flag}
              onChange={(e) => setFlag(e.target.value)}
              className="font-mono"
              disabled={isLoading}
              data-testid="input-flag"
            />
          </div>

          {result && (
            <div
              className={`flex items-start gap-3 rounded-md border p-4 ${
                result.correct
                  ? "border-primary/50 bg-primary/5"
                  : "border-destructive/50 bg-destructive/5"
              }`}
              data-testid="flag-result"
            >
              {result.correct ? (
                <CheckCircle2 className="h-5 w-5 flex-shrink-0 text-primary" />
              ) : (
                <XCircle className="h-5 w-5 flex-shrink-0 text-destructive" />
              )}
              <p className="text-sm leading-relaxed">
                {result.message}
              </p>
            </div>
          )}

          <Button
            type="submit"
            className="w-full gap-2"
            disabled={!flag.trim() || isLoading}
            data-testid="button-submit-flag"
          >
            {isLoading ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" />
                Validating...
              </>
            ) : (
              <>
                <Send className="h-5 w-5" />
                {t("submitFlag")}
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

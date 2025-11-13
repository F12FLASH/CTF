import { useState } from "react";
import { Terminal, Send, Loader2 } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { useLanguage } from "./language-context";

interface OracleInterfaceProps {
  onSubmit: (input: string) => void;
  isLoading?: boolean;
}

export function OracleInterface({ onSubmit, isLoading = false }: OracleInterfaceProps) {
  const { t } = useLanguage();
  const [input, setInput] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim() && !isLoading) {
      onSubmit(input);
    }
  };

  return (
    <Card data-testid="card-oracle-interface">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Terminal className="h-5 w-5 text-primary" />
          {t("oracleTitle")}
        </CardTitle>
        <CardDescription className="leading-relaxed">
          {t("oracleDescription")}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="oracle-input" className="text-base font-medium">
              {t("yourInput")}
            </Label>
            <Textarea
              id="oracle-input"
              placeholder={t("inputPlaceholder")}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="min-h-32 font-mono text-sm"
              disabled={isLoading}
              data-testid="input-oracle-query"
            />
          </div>

          <Button
            type="submit"
            className="w-full gap-2"
            disabled={!input.trim() || isLoading}
            data-testid="button-compute-hash"
          >
            {isLoading ? (
              <>
                <Loader2 className="h-5 w-5 animate-spin" />
                {t("computing")}
              </>
            ) : (
              <>
                <Send className="h-5 w-5" />
                {t("computeHash")}
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

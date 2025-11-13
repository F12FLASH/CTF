import { useState } from "react";
import { Copy, Check } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useLanguage } from "./language-context";
import { useToast } from "@/hooks/use-toast";
import type { HashResult } from "@shared/schema";

interface HashDisplayProps {
  result: HashResult | null;
}

export function HashDisplay({ result }: HashDisplayProps) {
  const { t } = useLanguage();
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    if (result?.fullHash) {
      await navigator.clipboard.writeText(result.fullHash);
      setCopied(true);
      toast({
        description: t("copied"),
        duration: 2000,
      });
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (!result || !result.fullHash) {
    return (
      <Card data-testid="card-hash-display">
        <CardHeader>
          <CardTitle>{t("hashResult")}</CardTitle>
          <CardDescription>
            {t("oracleDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex min-h-32 items-center justify-center rounded-md border bg-muted/50 p-6 text-center">
            <p className="text-sm text-muted-foreground">
              Submit an input to see the hash result
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card data-testid="card-hash-display">
      <CardHeader>
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1">
            <CardTitle>{t("hashResult")}</CardTitle>
            <CardDescription>
              {new Date(result.timestamp).toLocaleTimeString()}
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="icon"
            onClick={handleCopy}
            data-testid="button-copy-hash"
            aria-label={t("copyHash")}
          >
            {copied ? (
              <Check className="h-4 w-4 text-primary" />
            ) : (
              <Copy className="h-4 w-4" />
            )}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium text-muted-foreground">
              {t("first4Bytes")}
            </span>
          </div>
          <div className="overflow-visible rounded-md border bg-muted/50 p-6">
            <code
              className="font-mono text-lg font-bold tracking-wide text-primary"
              data-testid="text-first-4-bytes"
            >
              {result.first4Bytes}
            </code>
          </div>
        </div>

        <div className="space-y-2">
          <span className="text-sm font-medium text-muted-foreground">
            {t("remainingBytes")}
          </span>
          <div className="overflow-visible rounded-md border bg-muted/50 p-6">
            <code
              className="break-all font-mono text-sm tracking-wide text-muted-foreground"
              data-testid="text-remaining-bytes"
            >
              {result.fullHash.slice(8)}
            </code>
          </div>
        </div>

        <div className="space-y-2">
          <span className="text-sm font-medium text-muted-foreground">
            Full Hash
          </span>
          <div className="overflow-visible rounded-md border bg-card p-6">
            <code
              className="break-all font-mono text-sm tracking-wide"
              data-testid="text-full-hash"
            >
              {result.fullHash}
            </code>
          </div>
        </div>

        <div className="space-y-2">
          <span className="text-sm font-medium text-muted-foreground">
            Input
          </span>
          <div className="overflow-visible rounded-md border bg-card p-4">
            <p className="break-all text-sm" data-testid="text-input-echo">
              {result.input}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

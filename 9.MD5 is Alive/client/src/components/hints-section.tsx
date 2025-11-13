import { useState } from "react";
import { Lightbulb, Lock, Unlock, Star } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useLanguage } from "./language-context";

interface Hint {
  id: string;
  titleKey: string;
  contentKey: string;
  difficulty: number;
}

const hints: Hint[] = [
  {
    id: "hint1",
    titleKey: "hint1Title",
    contentKey: "hint1Content",
    difficulty: 2,
  },
  {
    id: "hint2",
    titleKey: "hint2Title",
    contentKey: "hint2Content",
    difficulty: 3,
  },
  {
    id: "hint3",
    titleKey: "hint3Title",
    contentKey: "hint3Content",
    difficulty: 4,
  },
];

export function HintsSection() {
  const { t } = useLanguage();
  const [unlockedHints, setUnlockedHints] = useState<Set<string>>(new Set());

  const toggleHint = (hintId: string) => {
    setUnlockedHints((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(hintId)) {
        newSet.delete(hintId);
      } else {
        newSet.add(hintId);
      }
      return newSet;
    });
  };

  return (
    <Card data-testid="card-hints">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Lightbulb className="h-5 w-5 text-primary" />
          {t("hintsTitle")}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {hints.map((hint) => {
          const isUnlocked = unlockedHints.has(hint.id);
          return (
            <div
              key={hint.id}
              className="space-y-2 border-t pt-4 first:border-t-0 first:pt-0"
              data-testid={`hint-${hint.id}`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 space-y-1">
                  <div className="flex items-center gap-2">
                    <h4 className="font-medium">{t(hint.titleKey)}</h4>
                    <div className="flex gap-0.5">
                      {Array.from({ length: 5 }).map((_, i) => (
                        <Star
                          key={i}
                          className={`h-3 w-3 ${
                            i < hint.difficulty
                              ? "fill-primary text-primary"
                              : "text-muted"
                          }`}
                        />
                      ))}
                    </div>
                  </div>
                  {isUnlocked && (
                    <p className="text-sm leading-relaxed text-muted-foreground transition-all duration-200">
                      {t(hint.contentKey)}
                    </p>
                  )}
                </div>
                <Button
                  variant={isUnlocked ? "secondary" : "outline"}
                  size="sm"
                  onClick={() => toggleHint(hint.id)}
                  className="gap-2 whitespace-nowrap"
                  data-testid={`button-toggle-${hint.id}`}
                >
                  {isUnlocked ? (
                    <>
                      <Unlock className="h-4 w-4" />
                      {t("hideHint")}
                    </>
                  ) : (
                    <>
                      <Lock className="h-4 w-4" />
                      {t("unlockHint")}
                    </>
                  )}
                </Button>
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

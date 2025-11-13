import { useState, useEffect, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Lightbulb, Lock, Unlock } from "lucide-react";
import { MathDisplay } from "./math-display";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";

interface Hint {
  id: number;
  level: "Beginner" | "Intermediate" | "Advanced";
  title: string;
  content: string;
  formula?: string;
}

const HINTS: Hint[] = [
  {
    id: 1,
    level: "Beginner",
    title: "Hiểu về Gaussian Integers",
    content: "Gaussian integer có dạng a + bi với a, b ∈ ℤ. Norm được định nghĩa là N(a + bi) = a² + b². Đây là công cụ quan trọng để phân tích các số phức Gaussian.",
    formula: "N(a + bi) = a^2 + b^2",
  },
  {
    id: 2,
    level: "Intermediate",
    title: "Phân tích modulus",
    content: "Để phân tích n thành Gaussian primes p và q, bạn cần tính N(n) trước. Sau đó phân tích N(n) thành các số nguyên tố thông thường. Mỗi prime factor sẽ tương ứng với một Gaussian prime.",
    formula: "N(n) = N(p) \\times N(q)",
  },
  {
    id: 3,
    level: "Advanced",
    title: "Tính φ(n) cho Gaussian integers",
    content: "Euler's totient function cho Gaussian integers được tính bằng công thức: φ(n) = (N(p)-1) × (N(q)-1). Sau đó sử dụng extended Euclidean algorithm để tìm d = e⁻¹ mod φ(n).",
    formula: "\\phi(n) = (N(p)-1) \\times (N(q)-1)",
  },
];

function getOrCreateSessionId(): string {
  if (typeof window === "undefined") {
    return "server-session";
  }
  
  const key = "ctf-session-id";
  let sessionId = localStorage.getItem(key);
  
  if (!sessionId) {
    sessionId = "user-session-" + Math.random().toString(36).substring(7);
    localStorage.setItem(key, sessionId);
  }
  
  return sessionId;
}

export function HintSystem() {
  const { toast } = useToast();
  
  const sessionId = useMemo(() => getOrCreateSessionId(), []);

  const { data: hintProgress, isLoading } = useQuery<{ unlockedHintIds: number[] }>({
    queryKey: [`/api/hints/progress/${sessionId}`],
  });

  const unlockedHintIds = hintProgress?.unlockedHintIds ?? [];

  const updateProgressMutation = useMutation({
    mutationFn: async (newUnlockedIds: number[]) => {
      return await apiRequest("POST", "/api/hints/progress", {
        sessionId,
        unlockedHintIds: newUnlockedIds,
      });
    },
    onMutate: async (newUnlockedIds) => {
      await queryClient.cancelQueries({ queryKey: [`/api/hints/progress/${sessionId}`] });
      
      const previousData = queryClient.getQueryData<{ unlockedHintIds: number[] }>([`/api/hints/progress/${sessionId}`]);
      
      queryClient.setQueryData<{ unlockedHintIds: number[] }>([`/api/hints/progress/${sessionId}`], {
        unlockedHintIds: newUnlockedIds,
      });
      
      return { previousData };
    },
    onSuccess: (data: any) => {
      queryClient.setQueryData([`/api/hints/progress/${sessionId}`], {
        unlockedHintIds: data?.unlockedHintIds || [],
      });
      toast({ description: "Hint unlocked successfully!" });
    },
    onError: (_, __, context) => {
      if (context?.previousData) {
        queryClient.setQueryData([`/api/hints/progress/${sessionId}`], context.previousData);
      }
      toast({ variant: "destructive", description: "Failed to unlock hint" });
    },
  });

  const unlockHint = (hintId: number) => {
    if (!unlockedHintIds.includes(hintId) && !updateProgressMutation.isPending) {
      const newUnlockedIds = Array.from(new Set([...unlockedHintIds, hintId])).sort((a, b) => a - b);
      updateProgressMutation.mutate(newUnlockedIds);
    }
  };

  const isUnlocked = (hintId: number) => unlockedHintIds.includes(hintId);

  const getLevelColor = (level: string) => {
    switch (level) {
      case "Beginner":
        return "bg-green-500/10 text-green-700 dark:text-green-400 border-green-500/20";
      case "Intermediate":
        return "bg-yellow-500/10 text-yellow-700 dark:text-yellow-400 border-yellow-500/20";
      case "Advanced":
        return "bg-red-500/10 text-red-700 dark:text-red-400 border-red-500/20";
      default:
        return "";
    }
  };

  if (isLoading) {
    return (
      <Card className="border rounded-lg">
        <CardContent className="p-6">
          <p className="text-sm text-muted-foreground">Loading hints...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border rounded-lg" data-testid="card-hint-system">
      <CardHeader className="p-6">
        <div className="flex items-center gap-3">
          <Lightbulb className="w-6 h-6 text-primary" />
          <CardTitle className="text-xl">Progressive Hints</CardTitle>
        </div>
        <p className="text-sm text-muted-foreground mt-2">
          Unlock hints to guide you through the challenge ({unlockedHintIds.length}/{HINTS.length} unlocked)
        </p>
      </CardHeader>
      <CardContent className="p-6 pt-0">
        <div className="space-y-4">
          {HINTS.map((hint) => (
            <div
              key={hint.id}
              className={`border rounded-lg transition-all duration-200 ${
                isUnlocked(hint.id) ? "border-primary/30" : "border-border"
              }`}
              data-testid={`hint-${hint.id}`}
            >
              <div className="flex items-center justify-between p-4 border-b">
                <div className="flex items-center gap-3">
                  {isUnlocked(hint.id) ? (
                    <Unlock className="w-5 h-5 text-primary" />
                  ) : (
                    <Lock className="w-5 h-5 text-muted-foreground" />
                  )}
                  <div>
                    <h3 className="text-sm font-semibold">{hint.title}</h3>
                    <Badge className={`mt-1 text-xs ${getLevelColor(hint.level)}`} variant="outline">
                      {hint.level}
                    </Badge>
                  </div>
                </div>
                {!isUnlocked(hint.id) && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => unlockHint(hint.id)}
                    disabled={updateProgressMutation.isPending}
                    data-testid={`button-unlock-hint-${hint.id}`}
                  >
                    {updateProgressMutation.isPending ? "..." : "Unlock"}
                  </Button>
                )}
              </div>
              {isUnlocked(hint.id) && (
                <div className="p-4 space-y-3">
                  <p className="text-sm leading-relaxed">{hint.content}</p>
                  {hint.formula && (
                    <div className="bg-muted/30 p-3 rounded-md">
                      <MathDisplay math={hint.formula} />
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

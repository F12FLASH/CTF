import { useState, useRef } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { HeroSection } from "@/components/hero-section";
import { OracleInterface } from "@/components/oracle-interface";
import { HashDisplay } from "@/components/hash-display";
import { ChallengeInfo } from "@/components/challenge-info";
import { HintsSection } from "@/components/hints-section";
import { AttackMethodology } from "@/components/attack-methodology";
import { StatsDisplay } from "@/components/stats-display";
import { FlagSubmission } from "@/components/flag-submission";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { HashResult, FlagValidationResult, ChallengeStats } from "@shared/schema";

export default function Home() {
  const [currentHash, setCurrentHash] = useState<HashResult | null>(null);
  const [flagResult, setFlagResult] = useState<FlagValidationResult | null>(null);
  const challengeRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  const { data: stats, isLoading: statsLoading, isError: statsError } = useQuery<ChallengeStats>({
    queryKey: ["/api/stats"],
    queryFn: async () => {
      const result = await apiRequest<ChallengeStats>("GET", "/api/stats");
      return result;
    },
  });

  const hashMutation = useMutation({
    mutationFn: async (input: string) => {
      return apiRequest<HashResult>("POST", "/api/hash", { input });
    },
    onSuccess: (data) => {
      setCurrentHash(data);
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
      toast({
        title: "Hash Computed",
        description: `Hash generated for your input. First 4 bytes: ${data.first4Bytes}`,
        duration: 3000,
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to compute hash",
        variant: "destructive",
        duration: 5000,
      });
    },
  });

  const handleStartChallenge = () => {
    challengeRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  const flagMutation = useMutation({
    mutationFn: async (flag: string) => {
      return apiRequest<FlagValidationResult>("POST", "/api/validate-flag", { flag });
    },
    onSuccess: (data) => {
      setFlagResult(data);
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
      toast({
        title: data.correct ? "Success!" : "Incorrect",
        description: data.message,
        variant: data.correct ? "default" : "destructive",
        duration: 5000,
      });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "Failed to validate flag",
        variant: "destructive",
        duration: 5000,
      });
    },
  });

  const handleHashSubmit = (input: string) => {
    hashMutation.mutate(input);
  };

  const handleFlagSubmit = (flag: string) => {
    flagMutation.mutate(flag);
  };

  return (
    <div className="min-h-screen">
      <HeroSection onStartChallenge={handleStartChallenge} />

      <div ref={challengeRef} className="container mx-auto px-4 py-12 md:py-16">
        <div className="mb-8">
          {statsLoading ? (
            <div className="flex gap-3">
              <div className="h-7 w-32 animate-pulse rounded-md bg-muted" />
              <div className="h-7 w-24 animate-pulse rounded-md bg-muted" />
            </div>
          ) : statsError ? (
            <p className="text-sm text-destructive">Failed to load statistics</p>
          ) : stats ? (
            <StatsDisplay
              queryCount={stats.totalQueries || 0}
              attemptCount={stats.totalAttempts || 0}
            />
          ) : null}
        </div>

        <div className="grid gap-8 lg:grid-cols-3">
          <div className="space-y-8 lg:col-span-2">
            <div className="grid gap-8 lg:grid-cols-2">
              <OracleInterface
                onSubmit={handleHashSubmit}
                isLoading={hashMutation.isPending}
              />
              <HashDisplay result={currentHash} />
            </div>

            <FlagSubmission
              onSubmit={handleFlagSubmit}
              isLoading={flagMutation.isPending}
              result={flagResult}
            />

            <ChallengeInfo />
            
            <HintsSection />
          </div>

          <div className="lg:col-span-1">
            <AttackMethodology />
          </div>
        </div>
      </div>
    </div>
  );
}

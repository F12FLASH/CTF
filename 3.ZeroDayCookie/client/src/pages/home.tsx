import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import type { ChallengeInfo, JwtValidationResponse } from "@shared/schema";
import { ChallengeHeader } from "@/components/challenge-header";
import { TokenDisplay } from "@/components/token-display";
import { TokenSubmission } from "@/components/token-submission";
import { HintsSection } from "@/components/hints-section";
import { FlagReveal } from "@/components/flag-reveal";
import { EducationalSidebar } from "@/components/educational-sidebar";
import { useToast } from "@/hooks/use-toast";
import { useState } from "react";

export default function Home() {
  const { toast } = useToast();
  const [capturedFlag, setCapturedFlag] = useState<string | null>(null);

  const { data: challengeInfo, isLoading } = useQuery<ChallengeInfo>({
    queryKey: ["/api/challenge"],
  });

  const validateMutation = useMutation<JwtValidationResponse, Error, { token: string }>({
    mutationFn: async (data) => {
      const response = await apiRequest<JwtValidationResponse>("POST", "/api/validate", data);
      return response;
    },
    onSuccess: (response) => {
      if (response.success && response.flag) {
        setCapturedFlag(response.flag);
        toast({
          title: "Đã Chiếm Flag!",
          description: response.message,
          variant: "default",
        });
      } else {
        toast({
          title: "Xác Thực Thất Bại",
          description: response.message,
          variant: "destructive",
        });
      }
    },
    onError: (error) => {
      toast({
        title: "Lỗi",
        description: error.message || "Không thể xác thực token",
        variant: "destructive",
      });
    },
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-primary font-mono text-lg animate-pulse">
          [ ĐANG TẢI THỬ THÁCH... ]
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="relative">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(0,255,65,0.05),transparent_50%)]" />
        <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,65,0.02)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,65,0.02)_1px,transparent_1px)] bg-[size:50px_50px]" />
        
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <ChallengeHeader
            difficulty={challengeInfo?.difficulty || "CAO THỦ"}
            description={challengeInfo?.description || ""}
          />

          {capturedFlag ? (
            <FlagReveal flag={capturedFlag} />
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mt-8">
              <div className="lg:col-span-2 space-y-6">
                <TokenDisplay 
                  currentToken={challengeInfo?.currentToken || ""} 
                  publicKey={challengeInfo?.publicKey}
                />
                <TokenSubmission
                  onSubmit={(token) => validateMutation.mutate({ token })}
                  isPending={validateMutation.isPending}
                />
              </div>

              <div className="space-y-6">
                <HintsSection hints={challengeInfo?.hints || []} />
                <EducationalSidebar />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

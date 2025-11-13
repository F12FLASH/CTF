import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Download, Lock, Unlock, Terminal, Shield, Flag, CheckCircle, XCircle, ChevronDown, ChevronUp } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { Challenge, FlagSubmission } from "@shared/schema";
import { Link } from "wouter";

type HintWithUnlock = {
  id: string;
  challengeId: string;
  order: number;
  content: string | null;
  pointsCost: number;
  unlocked: boolean;
};

export default function ChallengePage() {
  const [flagInput, setFlagInput] = useState("");
  const [expandedSections, setExpandedSections] = useState({
    description: true,
    hints: true,
    downloads: true,
  });
  const { toast } = useToast();

  const { data: challenge, isLoading: challengeLoading } = useQuery<Challenge>({
    queryKey: ["/api/challenge/stackless-stack"],
  });

  const { data: hints = [] } = useQuery<HintWithUnlock[]>({
    queryKey: ["/api/hints/stackless-stack"],
  });

  const unlockHintMutation = useMutation({
    mutationFn: async ({ challengeId, hintId }: { challengeId: string; hintId: string }) => {
      return apiRequest("POST", "/api/unlock-hint", { challengeId, hintId });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/hints/stackless-stack"] });
      toast({
        title: "ĐÃ MỞ KHÓA GỢI Ý",
        description: "Gợi ý đã được hiển thị",
        className: "border-primary/30 bg-card",
      });
    },
  });

  const submitFlagMutation = useMutation<{ correct: boolean; message: string }, Error, FlagSubmission>({
    mutationFn: async (data: FlagSubmission) => {
      const response = await apiRequest("POST", "/api/submit-flag", data);
      if (!response.ok) {
        throw new Error('Không thể nộp flag');
      }
      return await response.json();
    },
    onSuccess: (data: { correct: boolean; message: string }) => {
      if (data.correct) {
        toast({
          title: "FLAG CHÍNH XÁC",
          description: data.message,
          className: "border-primary/30 bg-card",
        });
        queryClient.invalidateQueries({ queryKey: ["/api/challenge/stackless-stack"] });
      } else {
        toast({
          title: "TRUY CẬP BỊ TỪ CHỐI",
          description: data.message,
          className: "border-destructive/30 bg-card",
        });
      }
    },
  });

  const handleFlagSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!flagInput.trim()) return;
    
    submitFlagMutation.mutate({
      challengeId: "stackless-stack",
      flag: flagInput.trim(),
    });
  };

  const handleUnlockHint = (hintId: string) => {
    unlockHintMutation.mutate({
      challengeId: "stackless-stack",
      hintId,
    });
  };

  const handleDownload = (filename: string) => {
    window.location.href = `/api/download/${filename}`;
  };

  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  if (challengeLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center space-y-4">
          <Terminal className="w-12 h-12 text-primary animate-pulse mx-auto" />
          <p className="font-jetbrains text-muted-foreground">ĐANG KHỞI TẠO THỬ THÁCH...</p>
        </div>
      </div>
    );
  }

  if (!challenge) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4">
        <Card className="max-w-md w-full border-destructive/30">
          <CardHeader>
            <CardTitle className="font-orbitron text-destructive flex items-center gap-2">
              <XCircle className="w-5 h-5" />
              LỖI 404
            </CardTitle>
            <CardDescription className="font-jetbrains">Không tìm thấy thử thách</CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="w-full border-b border-border bg-card/30 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-primary" />
              <h1 className="font-orbitron font-bold text-2xl sm:text-3xl text-foreground">
                CTF<span className="text-primary">_</span>PLATFORM
              </h1>
            </div>
            <Link href="/writeup">
              <Button variant="outline" size="sm" className="font-jetbrains" data-testid="button-view-writeup">
                <Terminal className="w-4 h-4 mr-2" />
                XEM BÀI GIẢI
              </Button>
            </Link>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
        <div className="mb-8 sm:mb-12">
          <div className="flex items-start justify-between flex-wrap gap-4 mb-6">
            <div className="flex-1 min-w-0">
              <h2 className="font-orbitron font-bold text-3xl sm:text-4xl md:text-5xl text-foreground mb-4">
                {challenge.title}
              </h2>
              <div className="flex flex-wrap items-center gap-3">
                <Badge 
                  variant="outline" 
                  className="font-jetbrains text-xs border-destructive/50 text-destructive bg-destructive/10"
                  data-testid="badge-difficulty"
                >
                  {challenge.difficulty.toUpperCase()}
                </Badge>
                <Badge 
                  variant="outline" 
                  className="font-jetbrains text-xs border-primary/50 text-primary bg-primary/10"
                  data-testid="badge-category"
                >
                  {challenge.category}
                </Badge>
                <Badge 
                  variant="outline" 
                  className="font-jetbrains text-xs"
                  data-testid="badge-points"
                >
                  {challenge.points} ĐIỂM
                </Badge>
                <div className="flex items-center gap-2 text-sm text-muted-foreground font-jetbrains">
                  <span>{challenge.solves} lượt giải</span>
                </div>
              </div>
            </div>
          </div>

          <Card className="border-card-border bg-card/50 backdrop-blur-sm">
            <CardHeader 
              className="cursor-pointer hover-elevate active-elevate-2"
              onClick={() => toggleSection('description')}
              data-testid="card-header-description"
            >
              <div className="flex items-center justify-between">
                <CardTitle className="font-orbitron text-xl flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-primary" />
                  MÔ TẢ CHALLENGE
                </CardTitle>
                {expandedSections.description ? 
                  <ChevronUp className="w-5 h-5 text-muted-foreground" /> : 
                  <ChevronDown className="w-5 h-5 text-muted-foreground" />
                }
              </div>
            </CardHeader>
            {expandedSections.description && (
              <CardContent className="space-y-4">
                <div className="prose prose-invert max-w-none">
                  <p className="text-foreground leading-relaxed whitespace-pre-wrap" data-testid="text-description">
                    {challenge.description}
                  </p>
                </div>
                <Separator className="bg-border" />
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                  <div className="space-y-1">
                    <p className="text-muted-foreground font-jetbrains">Tác giả</p>
                    <p className="font-semibold font-jetbrains text-foreground" data-testid="text-author">{challenge.author}</p>
                  </div>
                  <div className="space-y-1">
                    <p className="text-muted-foreground font-jetbrains">Phân loại</p>
                    <p className="font-semibold font-jetbrains text-foreground">{challenge.category}</p>
                  </div>
                </div>
              </CardContent>
            )}
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 sm:gap-8">
          <div className="lg:col-span-2 space-y-6 sm:space-y-8">
            <Card className="border-card-border bg-card/50 backdrop-blur-sm">
              <CardHeader
                className="cursor-pointer hover-elevate active-elevate-2"
                onClick={() => toggleSection('downloads')}
                data-testid="card-header-downloads"
              >
                <div className="flex items-center justify-between">
                  <CardTitle className="font-orbitron text-xl flex items-center gap-2">
                    <Download className="w-5 h-5 text-primary" />
                    TẢI FILE
                  </CardTitle>
                  {expandedSections.downloads ? 
                    <ChevronUp className="w-5 h-5 text-muted-foreground" /> : 
                    <ChevronDown className="w-5 h-5 text-muted-foreground" />
                  }
                </div>
              </CardHeader>
              {expandedSections.downloads && (
                <CardContent className="space-y-4">
                  <div className="bg-muted/30 border border-border rounded-md p-4 font-jetbrains">
                    <div className="flex items-center justify-between flex-wrap gap-4">
                      <div>
                        <p className="font-semibold text-foreground mb-1">stackless_stack.c</p>
                        <p className="text-sm text-muted-foreground">Mã nguồn để phân tích</p>
                      </div>
                      <Button 
                        variant="outline" 
                        size="sm" 
                        className="font-jetbrains"
                        onClick={() => handleDownload('stackless_stack.c')}
                        data-testid="button-download-source"
                      >
                        <Download className="w-4 h-4 mr-2" />
                        TẢI XUỐNG
                      </Button>
                    </div>
                  </div>
                  <div className="bg-muted/30 border border-border rounded-md p-4 font-jetbrains">
                    <div className="flex items-center justify-between flex-wrap gap-4">
                      <div>
                        <p className="font-semibold text-foreground mb-1">README.txt</p>
                        <p className="text-sm text-muted-foreground">Hướng dẫn thử thách</p>
                      </div>
                      <Button 
                        variant="outline" 
                        size="sm" 
                        className="font-jetbrains"
                        onClick={() => handleDownload('README.txt')}
                        data-testid="button-download-readme"
                      >
                        <Download className="w-4 h-4 mr-2" />
                        TẢI XUỐNG
                      </Button>
                    </div>
                  </div>
                </CardContent>
              )}
            </Card>

            <Card className="border-card-border bg-card/50 backdrop-blur-sm">
              <CardHeader
                className="cursor-pointer hover-elevate active-elevate-2"
                onClick={() => toggleSection('hints')}
                data-testid="card-header-hints"
              >
                <div className="flex items-center justify-between">
                  <CardTitle className="font-orbitron text-xl flex items-center gap-2">
                    <Lock className="w-5 h-5 text-primary" />
                    GỢI Ý ({hints.length})
                  </CardTitle>
                  {expandedSections.hints ? 
                    <ChevronUp className="w-5 h-5 text-muted-foreground" /> : 
                    <ChevronDown className="w-5 h-5 text-muted-foreground" />
                  }
                </div>
              </CardHeader>
              {expandedSections.hints && (
                <CardContent className="space-y-4">
                  {hints.length === 0 ? (
                    <p className="text-muted-foreground text-center py-8 font-jetbrains">
                      Không có gợi ý cho thử thách này
                    </p>
                  ) : (
                    hints.map((hint, index) => (
                      <div 
                        key={hint.id} 
                        className="border border-border rounded-md overflow-hidden"
                        data-testid={`hint-${index}`}
                      >
                        <div className="bg-muted/20 p-4">
                          <div className="flex items-center justify-between flex-wrap gap-4">
                            <div className="flex items-center gap-3">
                              {hint.unlocked ? (
                                <Unlock className="w-5 h-5 text-primary" />
                              ) : (
                                <Lock className="w-5 h-5 text-muted-foreground" />
                              )}
                              <span className="font-jetbrains font-semibold text-foreground">
                                Gợi ý #{index + 1}
                              </span>
                            </div>
                            {!hint.unlocked && (
                              <Button
                                variant="default"
                                size="sm"
                                onClick={() => handleUnlockHint(hint.id)}
                                disabled={unlockHintMutation.isPending}
                                className="font-jetbrains"
                                data-testid={`button-unlock-hint-${index}`}
                              >
                                <Lock className="w-4 h-4 mr-2" />
                                MỞ KHÓA (-{hint.pointsCost} ĐIỂM)
                              </Button>
                            )}
                          </div>
                        </div>
                        {hint.unlocked && hint.content && (
                          <div className="p-4 bg-accent/10 border-t border-border">
                            <p className="font-jetbrains text-sm text-accent-foreground" data-testid={`text-hint-content-${index}`}>
                              {hint.content}
                            </p>
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </CardContent>
              )}
            </Card>
          </div>

          <div className="lg:col-span-1">
            <div className="sticky top-24">
              <Card className="border-primary/30 bg-card/50 backdrop-blur-sm">
                <CardHeader>
                  <CardTitle className="font-orbitron text-xl flex items-center gap-2">
                    <Flag className="w-5 h-5 text-primary" />
                    NỘP CỜ
                  </CardTitle>
                  <CardDescription className="font-jetbrains">
                    Nhập flag để hoàn thành thử thách
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleFlagSubmit} className="space-y-4">
                    <div className="space-y-2">
                      <div className="relative">
                        <div className="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none">
                          <Terminal className="w-4 h-4 text-primary" />
                        </div>
                        <Input
                          type="text"
                          placeholder="VNFLAG{...}"
                          value={flagInput}
                          onChange={(e) => setFlagInput(e.target.value)}
                          className="pl-10 font-jetbrains bg-background border-input focus:border-primary"
                          data-testid="input-flag"
                        />
                      </div>
                    </div>
                    <Button 
                      type="submit" 
                      className="w-full font-orbitron font-semibold"
                      disabled={submitFlagMutation.isPending || !flagInput.trim()}
                      data-testid="button-submit-flag"
                    >
                      {submitFlagMutation.isPending ? (
                        <>
                          <Terminal className="w-4 h-4 mr-2 animate-pulse" />
                          ĐANG KIỂM TRA...
                        </>
                      ) : (
                        <>
                          <Flag className="w-4 h-4 mr-2" />
                          NỘP CỜ
                        </>
                      )}
                    </Button>
                  </form>
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

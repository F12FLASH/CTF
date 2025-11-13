import { useState, useEffect } from "react";
import { Terminal, Lock, Cpu, Flag, Lightbulb } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { useToast } from "@/hooks/use-toast";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";

interface ChallengeData {
  encryptedFlag: string;
  keyRotationCount: number;
  isTimeHooked: boolean;
}

interface FrozenKeyData {
  frozenKey: string;
  message: string;
}

interface HintData {
  id: string;
  order: number;
  title: string;
  content: string;
  isRevealed: boolean;
}

export default function Home() {
  const { toast } = useToast();
  const [hasStarted, setHasStarted] = useState(false);
  const [frozenTimestamp, setFrozenTimestamp] = useState<number | null>(null);
  const [frozenKey, setFrozenKey] = useState<string>("");
  const [wasmStatus, setWasmStatus] = useState<"idle" | "compiling" | "running" | "paused">("idle");
  const [wasmProgress, setWasmProgress] = useState(0);
  const [wasmLogs, setWasmLogs] = useState<string[]>([]);
  const [flagInput, setFlagInput] = useState("");
  const [solved, setSolved] = useState(false);
  
  // Fetch hints
  const { data: hints = [] } = useQuery<HintData[]>({
    queryKey: ["/api/hints"],
    enabled: hasStarted,
  });

  // Fetch challenge data
  const { data: challengeData } = useQuery<ChallengeData>({
    queryKey: ["/api/challenge-data"],
    enabled: hasStarted,
    refetchInterval: hasStarted ? 100 : false,
  });

  // Start challenge mutation
  const startChallengeMutation = useMutation({
    mutationFn: async () => {
      return apiRequest("POST", "/api/start-challenge", {});
    },
    onSuccess: () => {
      setHasStarted(true);
      setWasmStatus("compiling");
      setWasmProgress(0);
      setWasmLogs([
        "> Đang khởi tạo môi trường WASM sandbox...",
        "> Đang tải binary bytecode...",
        "> Đang dịch lệnh x86 sang WASM...",
      ]);
      queryClient.invalidateQueries({ queryKey: ["/api/challenge-data"] });
    },
  });

  // Hook time mutation
  const hookTimeMutation = useMutation({
    mutationFn: async (hook: boolean) => {
      const response = await apiRequest("POST", "/api/hook-time", { hook });
      return await response.json();
    },
    onSuccess: async (data: any) => {
      if (data.isHooked) {
        setFrozenTimestamp(Date.now());
        setWasmStatus("paused");
        setWasmLogs(prev => [...prev, "> PHÁT HIỆN TIME HOOK! Xoay vòng khóa đã đóng băng."]);
        setWasmLogs(prev => [...prev, "> Đang capture khóa mã hóa..."]);
        
        // Fetch the frozen key
        try {
          const response = await apiRequest("GET", "/api/get-frozen-key");
          const keyData = await response.json() as FrozenKeyData;
          setFrozenKey(keyData.frozenKey);
          setWasmLogs(prev => [...prev, `> Khóa đã capture: ${keyData.frozenKey.substring(0, 16)}...`]);
          toast({
            title: "Time Đã Hook!",
            description: "Xoay vòng khóa đã đóng băng. Khóa mã hóa đã được capture và hiển thị.",
          });
        } catch (error) {
          setWasmLogs(prev => [...prev, "> LỖI: Không thể capture khóa"]);
        }
      } else {
        setFrozenTimestamp(null);
        setFrozenKey("");
        setWasmStatus("running");
        setWasmLogs(prev => [...prev, "> Time hook đã được giải phóng. Tiếp tục xoay vòng khóa."]);
        toast({
          title: "Hook Đã Giải Phóng",
          description: "Xoay vòng khóa đã tiếp tục. Khóa đóng băng đã xóa.",
        });
      }
      queryClient.invalidateQueries({ queryKey: ["/api/challenge-data"] });
    },
  });

  // Submit flag mutation
  const submitFlagMutation = useMutation({
    mutationFn: async (flag: string) => {
      const response = await apiRequest("POST", "/api/submit-flag", { submittedFlag: flag });
      return await response.json();
    },
    onSuccess: (data: any) => {
      if (data.success) {
        setSolved(true);
        toast({
          title: "Flag Đã Capture!",
          description: "Chúc mừng! Bạn đã hoàn thành thử thách The Mimic thành công.",
        });
      } else {
        toast({
          title: "Flag Sai",
          description: "Flag không đúng. Tiếp tục phân tích...",
          variant: "destructive",
        });
      }
    },
  });

  // Reveal hint mutation
  const revealHintMutation = useMutation({
    mutationFn: async (hintId: string) => {
      return apiRequest("POST", `/api/hints/${hintId}/reveal`, {});
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/hints"] });
    },
  });

  // WASM compilation simulation
  useEffect(() => {
    if (wasmStatus === "compiling") {
      const interval = setInterval(() => {
        setWasmProgress(prev => {
          if (prev >= 100) {
            clearInterval(interval);
            setWasmStatus("running");
            setWasmLogs(prev => [...prev, "> Binary đã dịch thành công sang WASM"]);
            setWasmLogs(prev => [...prev, "> Module WASM đã load vào sandbox"]);
            setWasmLogs(prev => [...prev, "> Đang thực thi routine flag đã mã hóa..."]);
            return 100;
          }
          return prev + 2;
        });
      }, 20);
      return () => clearInterval(interval);
    }
  }, [wasmStatus]);

  const handleStartChallenge = () => {
    startChallengeMutation.mutate();
  };

  const handleHookTime = () => {
    if (!hasStarted) {
      toast({
        title: "Chưa Bắt Đầu Thử Thách",
        description: "Vui lòng khởi động thử thách trước",
        variant: "destructive",
      });
      return;
    }
    
    const currentlyHooked = challengeData?.isTimeHooked || false;
    hookTimeMutation.mutate(!currentlyHooked);
  };

  const handleSubmitFlag = () => {
    submitFlagMutation.mutate(flagInput.trim());
  };

  const isTimeHooked = challengeData?.isTimeHooked || false;
  const encryptedFlag = challengeData?.encryptedFlag || "";
  const keyRotationCount = challengeData?.keyRotationCount || 0;

  return (
    <div className="min-h-screen bg-background">
      {/* Hero Section */}
      <section className="relative h-[60vh] flex items-center justify-center overflow-hidden border-b-2 border-primary/30 bg-gradient-to-b from-card to-background">
        <div className="absolute inset-0 bg-grid-pattern opacity-5"></div>
        <div className="relative z-10 text-center max-w-4xl mx-auto px-6">
          <div className="flex items-center justify-center gap-3 mb-6">
            <div className="w-6 h-6 rounded-sm bg-primary/20 border border-primary flex items-center justify-center">
              <div className="w-3 h-3 bg-primary rounded-sm"></div>
            </div>
            <h1 className="font-orbitron text-5xl md:text-6xl font-bold tracking-wider text-foreground">
              THE MIMIC
            </h1>
          </div>
          
          <div className="font-mono text-base md:text-lg text-muted-foreground mb-6 space-y-1">
            <div className="flex items-center justify-center gap-2">
              <span className="text-primary">$</span>
              <span>Tự dịch Binary → Thực thi WASM sandbox</span>
            </div>
            <div className="flex items-center justify-center gap-2">
              <span className="text-primary">$</span>
              <span>Mã hóa XOR với khóa xoay vòng 10ms</span>
            </div>
            <div className="flex items-center justify-center gap-2">
              <span className="text-primary">$</span>
              <span>Hook time() để đóng băng khóa mã hóa</span>
            </div>
          </div>

          <div className="flex items-center justify-center gap-4 mb-8">
            <Badge variant="outline" className="border-destructive text-destructive font-mono px-4 py-2" data-testid="badge-difficulty">
              HACKER CAO THỦ
            </Badge>
            <Badge variant="outline" className="border-primary text-primary font-mono px-4 py-2" data-testid="badge-category">
              REVERSE ENGINEERING
            </Badge>
          </div>

          {!hasStarted && (
            <Button
              size="lg"
              onClick={handleStartChallenge}
              className="font-mono text-base px-8"
              disabled={startChallengeMutation.isPending}
              data-testid="button-start-challenge"
            >
              <Terminal className="mr-2 h-5 w-5" />
              {startChallengeMutation.isPending ? "Đang Khởi Động..." : "Bắt Đầu Thử Thách"}
            </Button>
          )}
        </div>

        <div className="absolute bottom-8 left-1/2 -translate-x-1/2">
          <div className="font-mono text-primary animate-pulse">▼</div>
        </div>
      </section>

      {/* Main Challenge Area */}
      {hasStarted && (
        <div className="max-w-7xl mx-auto px-6 py-12">
          {/* Challenge Sections Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-12">
            {/* WASM Sandbox Viewer */}
            <Card className="p-6 border-2 font-mono" data-testid="card-wasm-sandbox">
              <div className="flex items-center gap-2 mb-4">
                <Cpu className="h-5 w-5 text-primary" />
                <h2 className="font-orbitron text-xl font-semibold">WASM Sandbox</h2>
              </div>
              
              <div className="space-y-4">
                <div>
                  <div className="flex items-center justify-between text-sm mb-2">
                    <span className="text-muted-foreground">Trạng Thái:</span>
                    <Badge 
                      variant={wasmStatus === "running" ? "default" : "secondary"}
                      className="font-mono"
                      data-testid="badge-wasm-status"
                    >
                      {wasmStatus === "running" ? "ĐANG CHẠY" : wasmStatus === "compiling" ? "ĐANG BIÊN DỊCH" : wasmStatus === "paused" ? "TẠM DỪNG" : "NGHỈ"}
                    </Badge>
                  </div>
                  
                  {wasmStatus === "compiling" && (
                    <div className="space-y-2">
                      <Progress value={wasmProgress} className="h-2" data-testid="progress-wasm" />
                      <div className="text-xs text-muted-foreground text-right">{wasmProgress}%</div>
                    </div>
                  )}
                </div>

                <Separator />

                <div className="bg-muted/30 rounded-md p-3 h-48 overflow-y-auto border border-border" data-testid="container-wasm-logs">
                  <div className="space-y-1 text-xs">
                    {wasmLogs.map((log, i) => (
                      <div key={i} className="text-muted-foreground" data-testid={`text-wasm-log-${i}`}>
                        {log}
                      </div>
                    ))}
                  </div>
                </div>

                <Button
                  variant="outline"
                  size="sm"
                  className="w-full font-mono"
                  onClick={() => {
                    setWasmLogs([]);
                    setWasmStatus("idle");
                    setWasmProgress(0);
                  }}
                  data-testid="button-reset-wasm"
                >
                  Đặt Lại Sandbox
                </Button>
              </div>
            </Card>

            {/* Encryption Monitor */}
            <Card className="p-6 border-2 font-mono" data-testid="card-encryption-monitor">
              <div className="flex items-center gap-2 mb-4">
                <Lock className="h-5 w-5 text-primary" />
                <h2 className="font-orbitron text-xl font-semibold">Giám Sát Mã Hóa</h2>
              </div>
              
              <div className="space-y-4">
                <div>
                  <div className="text-sm text-muted-foreground mb-2">Flag Đã Mã Hóa:</div>
                  <div className="bg-muted/30 rounded-md p-3 border border-border break-all text-xs" data-testid="text-encrypted-flag">
                    {encryptedFlag || "---"}
                  </div>
                </div>

                <Separator />

                <div>
                  <div className="text-sm text-muted-foreground mb-2">Khóa Mã Hóa:</div>
                  <div className="bg-muted/30 rounded-md p-3 border border-border break-all text-xs" data-testid="text-current-key">
                    {frozenKey ? frozenKey : (isTimeHooked ? "Hook time() để hiện khóa" : "Khóa đang xoay vòng (ẩn)")}
                  </div>
                </div>

                <Separator />

                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Số Lần Xoay Vòng:</span>
                  <Badge variant="outline" className="font-mono" data-testid="badge-rotation-count">
                    {keyRotationCount}
                  </Badge>
                </div>

                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Tốc Độ Xoay Vòng:</span>
                  <Badge variant="outline" className="font-mono" data-testid="badge-rotation-rate">
                    {isTimeHooked ? "ĐÓNG BĂNG" : "100/giây"}
                  </Badge>
                </div>
              </div>
            </Card>

            {/* Time Hook Interface */}
            <Card className="p-6 border-2 font-mono" data-testid="card-time-hook">
              <div className="flex items-center gap-2 mb-4">
                <Terminal className="h-5 w-5 text-primary" />
                <h2 className="font-orbitron text-xl font-semibold">Time Hook</h2>
              </div>
              
              <div className="space-y-4">
                <div>
                  <div className="text-sm text-muted-foreground mb-2">Trạng Thái Hook:</div>
                  <Badge 
                    variant={isTimeHooked ? "default" : "outline"}
                    className="font-mono w-full justify-center py-2"
                    data-testid="badge-hook-status"
                  >
                    {isTimeHooked ? "ĐÃ HOOK" : "CHƯA HOOK"}
                  </Badge>
                </div>

                <Separator />

                <Button
                  variant={isTimeHooked ? "destructive" : "default"}
                  className="w-full font-mono"
                  onClick={handleHookTime}
                  disabled={hookTimeMutation.isPending}
                  data-testid="button-hook-time"
                >
                  {hookTimeMutation.isPending ? "Đang Xử Lý..." : (isTimeHooked ? "Giải Phóng Hook" : "Hook time()")}
                </Button>

                {isTimeHooked && !frozenKey && (
                  <Button
                    variant="outline"
                    className="w-full font-mono"
                    onClick={async () => {
                      try {
                        const response = await apiRequest("GET", "/api/get-frozen-key");
                        const keyData = await response.json() as FrozenKeyData;
                        
                        if (keyData.frozenKey) {
                          setFrozenKey(keyData.frozenKey);
                          setWasmLogs(prev => [...prev, `> Khóa đã capture: ${keyData.frozenKey.substring(0, 16)}...`]);
                          toast({
                            title: "Khóa Đã Lấy!",
                            description: keyData.message || "Khóa mã hóa đã được capture.",
                          });
                        } else {
                          throw new Error("Invalid key data");
                        }
                      } catch (error: any) {
                        const errorMsg = error?.message || "Không thể lấy khóa";
                        setWasmLogs(prev => [...prev, `> LỖI: ${errorMsg}`]);
                        toast({
                          title: "Lỗi Lấy Khóa",
                          description: error?.error || error?.hint || "Đảm bảo đã hook time() trước.",
                          variant: "destructive",
                        });
                      }
                    }}
                    data-testid="button-get-frozen-key"
                  >
                    Get Frozen Key
                  </Button>
                )}

                <Separator />

                <div className="bg-muted/30 rounded-md p-3 border border-border" data-testid="container-function-signature">
                  <div className="text-xs space-y-1">
                    <div className="text-muted-foreground"># Signature Hàm</div>
                    <div className="text-primary">time_t time(time_t *arg)</div>
                    <div className="text-muted-foreground mt-2"># Trả Về</div>
                    <div>{frozenTimestamp ? frozenTimestamp : "Unix timestamp hiện tại"}</div>
                    {frozenKey && (
                      <>
                        <div className="text-muted-foreground mt-2"># Khóa Đã Capture</div>
                        <div className="text-primary font-semibold">{frozenKey}</div>
                      </>
                    )}
                  </div>
                </div>

                <div className="text-xs text-muted-foreground bg-accent/50 p-3 rounded-md border border-accent-foreground/20" data-testid="text-hook-tip">
                  Mẹo: Hook time() sẽ đóng băng khóa mã hóa, cho phép bạn giải mã flag.
                </div>
              </div>
            </Card>
          </div>

          {/* Flag Submission Section */}
          <Card className="max-w-2xl mx-auto p-8 border-2 mb-12" data-testid="card-flag-submission">
            <div className="flex items-center gap-2 mb-6">
              <Flag className="h-6 w-6 text-primary" />
              <h2 className="font-orbitron text-2xl font-semibold">Nộp Flag</h2>
            </div>

            <div className="space-y-4">
              <div>
                <Input
                  placeholder="VNFLAG{...}"
                  value={flagInput}
                  onChange={(e) => setFlagInput(e.target.value)}
                  className="font-mono text-base"
                  disabled={solved}
                  data-testid="input-flag"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !submitFlagMutation.isPending && !solved) {
                      handleSubmitFlag();
                    }
                  }}
                />
              </div>

              <Button
                className="w-full font-mono"
                onClick={handleSubmitFlag}
                disabled={submitFlagMutation.isPending || solved || !flagInput.trim()}
                data-testid="button-submit-flag"
              >
                {submitFlagMutation.isPending ? "Đang Kiểm Tra..." : solved ? "Đã Giải" : "Nộp Flag"}
              </Button>

              {solved && (
                <div className="bg-primary/10 border border-primary rounded-md p-4 text-center" data-testid="container-success">
                  <div className="font-orbitron text-lg font-semibold text-primary mb-2">
                    Hoàn Thành Thử Thách!
                  </div>
                  <div className="text-sm text-muted-foreground">
                    Bạn đã reverse engineering thành công The Mimic và capture flag.
                  </div>
                </div>
              )}
            </div>
          </Card>

          {/* Hints Panel */}
          <Card className="max-w-4xl mx-auto p-8 border-2" data-testid="card-hints">
            <div className="flex items-center gap-2 mb-6">
              <Lightbulb className="h-6 w-6 text-primary" />
              <h2 className="font-orbitron text-2xl font-semibold">Gợi Ý</h2>
            </div>

            <Accordion type="single" collapsible className="w-full">
              {hints.map((hint, i) => (
                <AccordionItem key={hint.id} value={`hint-${i}`} data-testid={`accordion-hint-${i}`}>
                  <AccordionTrigger className="font-mono text-sm" data-testid={`button-hint-${i}`}>
                    Gợi Ý {i + 1}: {hint.title}
                  </AccordionTrigger>
                  <AccordionContent className="text-sm text-muted-foreground bg-muted/30 p-4 rounded-md border border-border" data-testid={`text-hint-content-${i}`}>
                    {hint.isRevealed ? hint.content : (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => revealHintMutation.mutate(hint.id)}
                        disabled={revealHintMutation.isPending}
                        className="font-mono"
                        data-testid={`button-reveal-hint-${i}`}
                      >
                        {revealHintMutation.isPending ? "Đang Hiện..." : "Hiện Gợi Ý"}
                      </Button>
                    )}
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          </Card>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t-2 border-border mt-16 py-8 bg-card/50">
        <div className="max-w-7xl mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="font-mono text-sm text-muted-foreground" data-testid="text-footer-title">
              <span className="text-primary">VNFLAG</span> • Thử Thách Reverse Engineering • The Mimic
            </div>
            
            <div className="flex items-center gap-4">
              <Badge variant="outline" className="font-mono" data-testid="badge-powered-by">
                Powered by WASM
              </Badge>
              <Badge variant="outline" className="font-mono" data-testid="badge-solves">
                {solved ? 1 : 0} Lần Giải
              </Badge>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}

import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { ChallengeHeader } from "@/components/ChallengeHeader";
import { TerminalEmulator } from "@/components/TerminalEmulator";
import { CodeViewer } from "@/components/CodeViewer";
import { ProgressTracker } from "@/components/ProgressTracker";
import { ToolsPanel } from "@/components/ToolsPanel";
import { FlagSubmission } from "@/components/FlagSubmission";
import { EducationalCards } from "@/components/EducationalCards";
import { Shield, Target, Cpu, Loader2 } from "lucide-react";
import { INITIAL_PROGRESS, UB_TYPES } from "@shared/schema";
import { apiRequest, queryClient } from "@/lib/queryClient";
import type { Progress, Hint, FlagResponse } from "@shared/schema";

function getSessionId(): string {
  let sessionId = localStorage.getItem('ctf-session-id');
  if (!sessionId) {
    sessionId = `session-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    localStorage.setItem('ctf-session-id', sessionId);
  }
  return sessionId;
}

export default function Challenge() {
  const [sessionId] = useState(getSessionId());
  const [attempts, setAttempts] = useState(0);
  const [success, setSuccess] = useState(false);
  const [message, setMessage] = useState('');

  const { data: progress = INITIAL_PROGRESS, isLoading: progressLoading } = useQuery<Progress>({
    queryKey: ['/api/progress', sessionId],
  });

  const { data: hints = [], isLoading: hintsLoading } = useQuery<Hint[]>({
    queryKey: ['/api/hints', sessionId],
  });

  const { data: attemptsData, isLoading: attemptsLoading } = useQuery<{ attempts: number }>({
    queryKey: ['/api/attempts', sessionId],
  });

  useEffect(() => {
    if (attemptsData) {
      setAttempts(attemptsData.attempts);
    }
  }, [attemptsData]);

  const flagMutation = useMutation({
    mutationFn: async (flag: string) => {
      return apiRequest<FlagResponse>('POST', `/api/submit-flag/${sessionId}`, { flag });
    },
    onSuccess: (data) => {
      setAttempts(data.attempts);
      setSuccess(data.success);
      setMessage(data.message);

      queryClient.invalidateQueries({ queryKey: ['/api/progress', sessionId] });
      queryClient.invalidateQueries({ queryKey: ['/api/hints', sessionId] });
      queryClient.invalidateQueries({ queryKey: ['/api/attempts', sessionId] });
    },
    onError: () => {
      setMessage('Lỗi kết nối. Vui lòng thử lại!');
    },
  });

  const handleFlagSubmit = (flag: string) => {
    flagMutation.mutate(flag);
  };

  if (progressLoading || hintsLoading || attemptsLoading) {
    return (
      <div 
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: '#0a0e14' }}
        data-testid="loading-screen"
      >
        <div className="text-center">
          <Loader2 className="w-12 h-12 text-terminal-cyan animate-spin mx-auto mb-4" />
          <p className="text-terminal-text font-mono">Loading challenge...</p>
        </div>
      </div>
    );
  }

  return (
    <div 
      className="min-h-screen"
      style={{ backgroundColor: '#0a0e14' }}
    >
      <ChallengeHeader startTime={progress.startTime} />

      <main className="max-w-7xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-7 space-y-6">
            <div 
              className="p-6 rounded-md"
              style={{
                backgroundColor: '#1a1f2e',
                border: '1px solid rgba(34, 211, 238, 0.2)',
              }}
              data-testid="section-challenge-description"
            >
              <h2 className="text-2xl font-bold text-terminal-cyan mb-4 flex items-center gap-2">
                <Target className="w-6 h-6" />
                Mô tả thử thách
              </h2>
              
              <div className="space-y-4 text-terminal-text">
                <p className="leading-relaxed">
                  <span className="text-terminal-cyan font-semibold">"The Undefined"</span> là một binary C++ tận dụng Undefined Behavior (UB) để mã hóa flag. Mỗi lần chạy chương trình, flag được mã hóa với một key khác nhau do compiler-generated code không xác định, làm cho việc phân tích tĩnh trở nên vô ích.
                </p>

                <div 
                  className="p-4 rounded-md space-y-3"
                  style={{
                    backgroundColor: 'rgba(0, 0, 0, 0.3)',
                    border: '1px solid rgba(34, 211, 238, 0.2)',
                  }}
                >
                  <div className="flex items-start gap-3">
                    <Cpu className="w-5 h-5 text-terminal-cyan flex-shrink-0 mt-0.5" />
                    <div>
                      <h3 className="font-semibold text-terminal-cyan mb-2">Đặc điểm kỹ thuật:</h3>
                      <ul className="space-y-1 text-sm text-terminal-text-muted">
                        <li><span className="text-terminal-green">•</span> Language: C++ với UB intentional</li>
                        <li><span className="text-terminal-green">•</span> Encryption: XOR-based với key từ UB</li>
                        <li><span className="text-terminal-green">•</span> Behavior: Output khác nhau mỗi execution</li>
                        <li><span className="text-terminal-green">•</span> Protection: ASLR, PIE, Stack Canaries</li>
                      </ul>
                    </div>
                  </div>

                  <div className="flex items-start gap-3">
                    <Shield className="w-5 h-5 text-terminal-warning flex-shrink-0 mt-0.5" />
                    <div>
                      <h3 className="font-semibold text-terminal-warning mb-2">Kỹ thuật khai thác:</h3>
                      <ol className="space-y-1 text-sm text-terminal-text-muted list-decimal list-inside">
                        <li>Phân tích Binary - Xác định vị trí UB trong code</li>
                        <li>Environment Control - Kiểm soát các yếu tố ảnh hưởng</li>
                        <li>Reproducible Execution - Tạo môi trường có thể lặp lại</li>
                        <li>Key Extraction - Trích xuất encryption key</li>
                        <li>XOR Decryption - Giải mã flag với key thu được</li>
                      </ol>
                    </div>
                  </div>
                </div>

                <p className="text-sm text-terminal-text-muted italic">
                  Thử thách này minh họa sự nguy hiểm của Undefined Behavior trong các ứng dụng bảo mật. Hãy sử dụng terminal bên dưới và công cụ phân tích để khám phá binary!
                </p>
              </div>
            </div>

            <CodeViewer />

            <EducationalCards ubTypes={UB_TYPES} />
          </div>

          <div className="lg:col-span-5 space-y-6">
            <div className="lg:sticky lg:top-20 space-y-6">
              <TerminalEmulator />
              
              <ToolsPanel />
              
              <FlagSubmission
                onSubmit={handleFlagSubmit}
                attempts={attempts}
                hints={hints}
                success={success}
                message={message}
              />
              
              <ProgressTracker progress={progress} />
            </div>
          </div>
        </div>
      </main>

      <footer 
        className="border-t py-6 mt-12"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.3)',
          borderColor: 'rgba(34, 211, 238, 0.2)',
        }}
      >
        <div className="max-w-7xl mx-auto px-6 text-center text-sm text-terminal-text-muted">
          <p>The Undefined - CTF Pwn Challenge | Master Level ⭐⭐⭐⭐⭐</p>
          <p className="mt-1">Built with passion for cybersecurity education</p>
        </div>
      </footer>
    </div>
  );
}

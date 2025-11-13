import { Terminal, Clock } from "lucide-react";
import { useEffect, useState } from "react";

interface ChallengeHeaderProps {
  startTime: number;
}

export function ChallengeHeader({ startTime }: ChallengeHeaderProps) {
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);
    return () => clearInterval(interval);
  }, [startTime]);

  const formatTime = (seconds: number) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`;
  };

  return (
    <header 
      className="sticky top-0 z-50 h-16 border-b flex items-center justify-between px-6"
      style={{
        backgroundColor: '#0a0e14',
        borderColor: 'rgba(34, 211, 238, 0.2)',
      }}
    >
      <div className="flex items-center gap-3">
        <Terminal className="w-6 h-6 text-terminal-cyan" data-testid="icon-terminal" />
        <h1 className="text-2xl font-bold font-mono text-terminal-text">
          THE UNDEFINED
        </h1>
      </div>

      <div className="flex items-center gap-6">
        <div className="flex items-center gap-2 text-terminal-warning">
          <span className="text-xs uppercase tracking-wide font-semibold">Độ khó:</span>
          <div className="flex gap-1" data-testid="difficulty-stars">
            {[...Array(5)].map((_, i) => (
              <span key={i} className="text-terminal-warning">⭐</span>
            ))}
          </div>
          <span className="text-xs font-semibold ml-1">Master</span>
        </div>

        <div 
          className="flex items-center gap-2 px-3 py-1.5 rounded-md font-mono text-sm"
          style={{ 
            backgroundColor: 'rgba(34, 211, 238, 0.1)',
            border: '1px solid rgba(34, 211, 238, 0.3)'
          }}
          data-testid="timer-display"
        >
          <Clock className="w-4 h-4 text-terminal-cyan" />
          <span className="text-terminal-cyan">{formatTime(elapsed)}</span>
        </div>
      </div>
    </header>
  );
}

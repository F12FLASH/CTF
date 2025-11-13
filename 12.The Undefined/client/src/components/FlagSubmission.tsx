import { useState } from "react";
import { Flag, Lock, Lightbulb, CheckCircle2, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { Hint } from "@shared/schema";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";

interface FlagSubmissionProps {
  onSubmit: (flag: string) => void;
  attempts: number;
  hints: Hint[];
  success: boolean;
  message: string;
}

export function FlagSubmission({ 
  onSubmit, 
  attempts, 
  hints, 
  success,
  message 
}: FlagSubmissionProps) {
  const [flag, setFlag] = useState('');
  const [openHints, setOpenHints] = useState<Record<string, boolean>>({});

  const handleSubmit = () => {
    if (flag.trim()) {
      onSubmit(flag.trim());
    }
  };

  const toggleHint = (hintId: string) => {
    setOpenHints(prev => ({ ...prev, [hintId]: !prev[hintId] }));
  };

  return (
    <div 
      className="p-6 rounded-md"
      style={{
        backgroundColor: '#1a1f2e',
        border: '1px solid rgba(34, 211, 238, 0.2)',
      }}
    >
      <div className="flex items-center gap-2 mb-4">
        <Flag className="w-5 h-5 text-terminal-cyan" />
        <h3 className="text-lg font-semibold text-terminal-cyan">
          Submit Flag
        </h3>
      </div>

      <div className="space-y-4">
        <div className="space-y-2">
          <label className="text-xs uppercase tracking-wide text-terminal-text-muted font-semibold">
            Flag Format: VNFLAG{'{...}'}
          </label>
          <div className="flex gap-2">
            <Input
              value={flag}
              onChange={(e) => setFlag(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleSubmit();
              }}
              placeholder="VNFLAG{...}"
              className="font-mono text-sm bg-terminal-bg border-terminal-border text-terminal-text placeholder:text-terminal-text-muted focus-visible:ring-terminal-cyan"
              disabled={success}
              data-testid="input-flag"
            />
            <Button
              onClick={handleSubmit}
              disabled={!flag.trim() || success}
              className="font-semibold min-w-24"
              style={{
                backgroundColor: success ? '#4ade80' : '#00ff9f',
                color: '#0a0e14',
              }}
              data-testid="button-submit-flag"
            >
              {success ? (
                <><CheckCircle2 className="w-4 h-4 mr-2" /> Solved!</>
              ) : (
                <><Lock className="w-4 h-4 mr-2" /> Submit</>
              )}
            </Button>
          </div>
        </div>

        {message && (
          <div 
            className={`p-3 rounded-md flex items-start gap-2 ${
              success ? 'bg-terminal-green/10 border border-terminal-green' : 'bg-terminal-danger/10 border border-terminal-danger'
            }`}
            data-testid="message-submission-result"
          >
            {success ? (
              <CheckCircle2 className="w-5 h-5 text-terminal-green flex-shrink-0 mt-0.5" />
            ) : (
              <XCircle className="w-5 h-5 text-terminal-danger flex-shrink-0 mt-0.5" />
            )}
            <p className={`text-sm ${success ? 'text-terminal-green' : 'text-terminal-danger'}`}>
              {message}
            </p>
          </div>
        )}

        <div 
          className="pt-3 border-t flex items-center justify-between text-sm"
          style={{ borderColor: 'rgba(34, 211, 238, 0.2)' }}
        >
          <span className="text-terminal-text-muted">
            Attempts: <span className="text-terminal-text font-semibold" data-testid="text-attempts">{attempts}</span>
          </span>
          <span className="text-terminal-text-muted">
            Hints Unlocked: <span className="text-terminal-cyan font-semibold" data-testid="text-hints-unlocked">
              {hints.filter(h => h.unlocked).length}/{hints.length}
            </span>
          </span>
        </div>

        {hints.some(h => h.unlocked) && (
          <div className="space-y-2 pt-4">
            <div className="flex items-center gap-2 mb-3">
              <Lightbulb className="w-4 h-4 text-terminal-warning" />
              <h4 className="text-sm font-semibold text-terminal-warning uppercase tracking-wide">
                Available Hints
              </h4>
            </div>

            {hints.filter(h => h.unlocked).map((hint) => (
              <Collapsible
                key={hint.id}
                open={openHints[hint.id]}
                onOpenChange={() => toggleHint(hint.id)}
              >
                <CollapsibleTrigger 
                  className="w-full p-3 rounded-md text-left hover-elevate flex items-center justify-between"
                  style={{
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    border: '1px solid rgba(245, 158, 11, 0.3)',
                  }}
                  data-testid={`button-hint-${hint.id}`}
                >
                  <span className="text-sm font-medium text-terminal-warning">
                    {hint.title}
                  </span>
                  <span className="text-terminal-warning">
                    {openHints[hint.id] ? '−' : '+'}
                  </span>
                </CollapsibleTrigger>
                <CollapsibleContent>
                  <div 
                    className="mt-2 p-3 rounded-md text-sm text-terminal-text-muted leading-relaxed"
                    style={{
                      backgroundColor: 'rgba(0, 0, 0, 0.3)',
                      border: '1px solid rgba(245, 158, 11, 0.2)',
                    }}
                    data-testid={`content-hint-${hint.id}`}
                  >
                    {hint.content}
                  </div>
                </CollapsibleContent>
              </Collapsible>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

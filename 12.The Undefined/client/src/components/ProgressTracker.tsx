import { Check } from "lucide-react";
import type { Progress } from "@shared/schema";

interface ProgressTrackerProps {
  progress: Progress;
}

export function ProgressTracker({ progress }: ProgressTrackerProps) {
  return (
    <div 
      className="p-6 rounded-md"
      style={{
        backgroundColor: '#1a1f2e',
        border: '1px solid rgba(34, 211, 238, 0.2)',
      }}
      data-testid="progress-tracker"
    >
      <h3 className="text-lg font-semibold text-terminal-cyan mb-6">
        Progress Tracker
      </h3>

      <div className="space-y-6">
        {progress.steps.map((step, idx) => {
          const isCompleted = step.completed;
          const isCurrent = idx === progress.currentStep;
          const isPast = idx < progress.currentStep;

          return (
            <div key={step.id} className="flex items-start gap-4">
              <div className="flex flex-col items-center">
                <div 
                  className={`w-10 h-10 rounded-full border-2 flex items-center justify-center transition-all ${
                    isCompleted 
                      ? 'bg-terminal-green border-terminal-green' 
                      : isCurrent
                      ? 'border-terminal-cyan bg-terminal-cyan/10 animate-glow-pulse'
                      : 'border-terminal-text-muted bg-transparent'
                  }`}
                  data-testid={`step-indicator-${step.id}`}
                >
                  {isCompleted ? (
                    <Check className="w-5 h-5 text-terminal-bg" />
                  ) : (
                    <span 
                      className={`text-sm font-bold ${
                        isCurrent ? 'text-terminal-cyan' : 'text-terminal-text-muted'
                      }`}
                    >
                      {idx + 1}
                    </span>
                  )}
                </div>
                
                {idx < progress.steps.length - 1 && (
                  <div 
                    className={`w-0.5 h-12 mt-2 ${
                      isPast || isCompleted
                        ? 'bg-terminal-cyan'
                        : 'bg-terminal-text-muted/30'
                    }`}
                  />
                )}
              </div>

              <div className="flex-1 pt-1">
                <h4 
                  className={`font-semibold ${
                    isCompleted 
                      ? 'text-terminal-green' 
                      : isCurrent
                      ? 'text-terminal-cyan'
                      : 'text-terminal-text-muted'
                  }`}
                  data-testid={`step-title-${step.id}`}
                >
                  {step.title}
                </h4>
                <p className="text-sm text-terminal-text-muted mt-1">
                  {step.description}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

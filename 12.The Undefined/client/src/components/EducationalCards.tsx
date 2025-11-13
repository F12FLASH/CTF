import { BookOpen, AlertTriangle } from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { useState } from "react";
import type { UBType } from "@shared/schema";

interface EducationalCardsProps {
  ubTypes: UBType[];
}

const COLOR_MAP = {
  orange: {
    bg: 'rgba(251, 146, 60, 0.1)',
    border: 'rgba(251, 146, 60, 0.3)',
    text: '#fb923c',
  },
  purple: {
    bg: 'rgba(168, 85, 247, 0.1)',
    border: 'rgba(168, 85, 247, 0.3)',
    text: '#a855f7',
  },
  red: {
    bg: 'rgba(239, 68, 68, 0.1)',
    border: 'rgba(239, 68, 68, 0.3)',
    text: '#ef4444',
  },
  blue: {
    bg: 'rgba(59, 130, 246, 0.1)',
    border: 'rgba(59, 130, 246, 0.3)',
    text: '#3b82f6',
  },
};

export function EducationalCards({ ubTypes }: EducationalCardsProps) {
  const [openCards, setOpenCards] = useState<Record<string, boolean>>({});

  const toggleCard = (id: string) => {
    setOpenCards(prev => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div 
      className="p-6 rounded-md"
      style={{
        backgroundColor: '#1a1f2e',
        border: '1px solid rgba(34, 211, 238, 0.2)',
      }}
    >
      <div className="flex items-center gap-2 mb-6">
        <BookOpen className="w-5 h-5 text-terminal-cyan" />
        <h3 className="text-lg font-semibold text-terminal-cyan">
          Undefined Behavior Types
        </h3>
      </div>

      <div className="space-y-3">
        {ubTypes.map((ub) => {
          const colors = COLOR_MAP[ub.color as keyof typeof COLOR_MAP];
          
          return (
            <Collapsible
              key={ub.id}
              open={openCards[ub.id]}
              onOpenChange={() => toggleCard(ub.id)}
            >
              <CollapsibleTrigger 
                className="w-full p-4 rounded-md text-left hover-elevate flex items-start gap-3"
                style={{
                  backgroundColor: colors.bg,
                  border: `1px solid ${colors.border}`,
                }}
                data-testid={`button-ub-${ub.id}`}
              >
                <AlertTriangle 
                  className="w-5 h-5 flex-shrink-0 mt-0.5" 
                  style={{ color: colors.text }}
                />
                <div className="flex-1">
                  <h4 
                    className="font-semibold mb-1"
                    style={{ color: colors.text }}
                  >
                    {ub.title}
                  </h4>
                  <p className="text-sm text-terminal-text-muted">
                    {ub.description}
                  </p>
                </div>
                <span 
                  className="text-lg font-bold flex-shrink-0"
                  style={{ color: colors.text }}
                >
                  {openCards[ub.id] ? '−' : '+'}
                </span>
              </CollapsibleTrigger>

              <CollapsibleContent>
                <div 
                  className="mt-2 p-4 rounded-md space-y-4"
                  style={{
                    backgroundColor: 'rgba(0, 0, 0, 0.3)',
                    border: `1px solid ${colors.border}`,
                  }}
                  data-testid={`content-ub-${ub.id}`}
                >
                  <div>
                    <h5 className="text-sm font-semibold text-terminal-cyan mb-2">
                      Giải thích:
                    </h5>
                    <p className="text-sm text-terminal-text leading-relaxed">
                      {ub.explanation}
                    </p>
                  </div>

                  <div>
                    <h5 className="text-sm font-semibold text-terminal-cyan mb-2">
                      Ví dụ code:
                    </h5>
                    <pre 
                      className="p-3 rounded-md font-mono text-xs leading-relaxed overflow-x-auto"
                      style={{
                        backgroundColor: '#0a0e14',
                        color: '#e5e7eb',
                      }}
                    >
                      {ub.codeExample}
                    </pre>
                  </div>
                </div>
              </CollapsibleContent>
            </Collapsible>
          );
        })}
      </div>

      <div 
        className="mt-6 p-4 rounded-md"
        style={{
          backgroundColor: 'rgba(34, 211, 238, 0.05)',
          border: '1px solid rgba(34, 211, 238, 0.2)',
        }}
      >
        <p className="text-sm text-terminal-text-muted leading-relaxed">
          <span className="text-terminal-cyan font-semibold">Lưu ý:</span> Undefined Behavior không chỉ gây ra lỗi mà còn có thể được khai thác để tạo ra các hành vi không thể đoán trước, làm phức tạp hóa việc phân tích và reverse engineering. Đây là bài học quan trọng về việc viết code an toàn.
        </p>
      </div>
    </div>
  );
}

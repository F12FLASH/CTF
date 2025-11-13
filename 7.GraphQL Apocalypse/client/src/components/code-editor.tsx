import { useEffect, useRef, useState } from "react";

interface CodeEditorProps {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
  "data-testid"?: string;
}

export function CodeEditor({ value, onChange, placeholder, className, "data-testid": testId }: CodeEditorProps) {
  const [lineNumbers, setLineNumbers] = useState<number[]>([1]);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const highlightRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const lines = value.split('\n').length;
    setLineNumbers(Array.from({ length: lines }, (_, i) => i + 1));
  }, [value]);

  const handleScroll = (e: React.UIEvent<HTMLTextAreaElement>) => {
    if (highlightRef.current) {
      highlightRef.current.scrollTop = e.currentTarget.scrollTop;
      highlightRef.current.scrollLeft = e.currentTarget.scrollLeft;
    }
  };

  const escapeHtml = (text: string) => {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  };

  const highlightSyntax = (code: string) => {
    const escaped = escapeHtml(code);
    return escaped
      .replace(/\b(query|mutation|subscription|fragment|type|input|interface|enum|scalar|union|schema|extend|implements)\b/g, '<span class="text-primary">$1</span>')
      .replace(/\b(String|Int|Float|Boolean|ID|true|false|null)\b/g, '<span class="text-secondary">$1</span>')
      .replace(/&quot;([^&quot;]*)&quot;/g, '<span class="text-chart-1">&quot;$1&quot;</span>')
      .replace(/#.*/g, '<span class="text-muted-foreground">$&</span>')
      .replace(/\{|\}/g, '<span class="text-accent-foreground">$&</span>')
      .replace(/\(|\)/g, '<span class="text-chart-2">$&</span>');
  };

  return (
    <div className={`relative ${className}`}>
      <div className="flex h-full border border-border rounded-md overflow-hidden bg-card/50">
        <div className="flex-none bg-muted/30 border-r border-border px-3 py-3 select-none">
          <div className="font-mono text-xs text-muted-foreground text-right space-y-[1px]">
            {lineNumbers.map((num) => (
              <div key={num} className="h-5 leading-5">
                {num}
              </div>
            ))}
          </div>
        </div>
        
        <div className="flex-1 relative">
          <div
            ref={highlightRef}
            className="absolute inset-0 p-3 font-mono text-sm pointer-events-none overflow-hidden whitespace-pre-wrap break-words"
            dangerouslySetInnerHTML={{
              __html: highlightSyntax(value || placeholder || ''),
            }}
          />
          
          <textarea
            ref={textareaRef}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onScroll={handleScroll}
            placeholder={placeholder}
            className="absolute inset-0 p-3 font-mono text-sm bg-transparent text-transparent caret-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-0 resize-none selection:bg-primary/30"
            spellCheck={false}
            data-testid={testId}
          />
        </div>
      </div>
    </div>
  );
}

import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import { forwardRef } from "react";

interface CodeEditorProps extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {
  value: string;
  onValueChange?: (value: string) => void;
}

export const CodeEditor = forwardRef<HTMLTextAreaElement, CodeEditorProps>(
  ({ value, onValueChange, className, ...props }, ref) => {
    const lines = value.split("\n");
    const lineCount = Math.max(lines.length, 5);
    
    return (
      <div className="relative rounded-md border bg-muted/30 overflow-hidden">
        <div className="flex">
          <div className="flex flex-col items-end pr-3 pl-2 py-3 bg-muted/50 border-r select-none">
            {Array.from({ length: lineCount }, (_, i) => (
              <div
                key={i}
                className="text-xs font-mono text-muted-foreground leading-6"
              >
                {i + 1}
              </div>
            ))}
          </div>
          
          <div className="flex-1 relative">
            <Textarea
              ref={ref}
              value={value}
              onChange={(e) => onValueChange?.(e.target.value)}
              className={cn(
                "min-h-[180px] border-0 bg-transparent font-mono text-sm leading-6 resize-none focus-visible:ring-0 rounded-none",
                className
              )}
              style={{ lineHeight: "1.5rem" }}
              {...props}
            />
          </div>
        </div>
        
        <div className="absolute top-2 right-2">
          <div className="px-2 py-0.5 rounded text-xs font-mono bg-muted border text-muted-foreground">
            JavaScript
          </div>
        </div>
      </div>
    );
  }
);

CodeEditor.displayName = "CodeEditor";
